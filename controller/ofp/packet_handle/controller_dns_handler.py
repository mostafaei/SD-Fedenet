import pickle
from ryu.ofproto.ofproto_v1_3 import OFP_NO_BUFFER
from ryu.lib.packet import packet
from packet_handler import PacketHandler
from ryu.ofproto import ofproto_v1_3, ether
from scapy.all import DNS, DNSQR, DNSRR, dnsqtypes
from ryu.lib.packet import udp, arp, ethernet, ipv4
from model.customer import Customer
from model.node import Controller
from netaddr import *
import socket

__author__='Habib Mostafaei'

#This class manages the DNS queries which one controller wants to send to other controller in order to ask 
#the right name server for the query 
class ControllerDNSHandlerAlg2(object):
    def __init__(self,pkt,controller):
        self._controller = controller
        self._pkt =pkt
        #index=None
	
    def handle_socket_msg(self):
        pkt_eth=self._pkt.get_protocols(ethernet.ethernet)[0]
        pkt_ip =self._pkt.get_protocols(ipv4.ipv4)[0]
        pkt_udp =self._pkt.get_protocols(udp.udp)[0]
        pkt_dns=DNS(self._pkt[-1])
        if pkt_udp.dst_port==53 or pkt_udp.src_port==53:
            #print 'A DNS query for controller is received'
            if pkt_dns:
                cs=self._controller.get_customers()
                #print( '----------------Sent query with ID', pkt_dns.id,pkt_dns)
                #print('---len(cs)---',len(cs))
                for c in range(len(cs)):
                    print('---c---',c,cs[c].get_private_ip_subnet(),'---ar--',pkt_dns.ar.rdata)
                    if IPAddress(pkt_dns.ar.rdata) in IPNetwork(cs[c].get_private_ip_subnet()):
                        print('---index--',c)
                        index=c
                        self._controller.set_current_customer_id(index)
                        #c_list.append(cs[c].get_private_ip_subnet())
                #index=self._controller.get_current_customer_id()
                #print'---cs index--',index
                d_mac= cs[index].get_next_hop_mac()
                #print'---cs d_mac--',d_mac
                pkt_dns.qr=0 
                 
                new_pkt=packet.Packet()
                e=ethernet.ethernet(dst=d_mac,src=pkt_eth.src)
                new_pkt.add_protocol(e)
                new_pkt.add_protocol(ipv4.ipv4(src=self._controller.get_ip(),dst=cs[index].get_name_server(),proto=17))
                new_pkt.add_protocol(udp.udp(src_port=pkt_udp.dst_port, dst_port=pkt_udp.src_port))
                new_dns=DNS(rd=0,id=pkt_dns.id,qd=DNSQR(qname=pkt_dns.qd.qname),ns=DNSRR(rrname=pkt_dns.ar.rrname,type=1,ttl=60000,rdata=cs[index].get_name_server()))
                new_pkt.add_protocol(new_dns)
                new_pkt.serialize()
                self.send_dns_packet(new_pkt,cs[index].get_datapath(),cs[index].get_ingress_port())
    

    def send_dns_packet(self,pkt,datapath,port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        #print( '***pkt inside send***', pkt)
        data =pkt.data
        actions = [parser.OFPActionOutput(port=int(port))]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=data)
        datapath.send_msg(out)

        self._controller.set_port_number(None)
        self._controller.set_transaction_id(None)

#this class is responsibe for handling the received DNS responses from the target name server
#it has to forward this response to other controller which asked a DNS query       
class ControllerDNSResponseHandlerAlg2(object):
    def __init__(self,pkt,controller):
        self._controller = controller
        self._pkt =pkt
	
    def handle_socket_msg(self):
        pkt_eth=self._pkt.get_protocols(ethernet.ethernet)[0]
        pkt_ip =self._pkt.get_protocols(ipv4.ipv4)[0]
        pkt_udp =self._pkt.get_protocols(udp.udp)[0]
        dns=DNS(self._pkt[-1])
        print '---- I received final DNS answer----', dns.id
        dnsrr = dns.an[0]
        if dns.qr==1 and self._controller.get_transaction_id() is not None:
            
            pool=self._controller.get_pool_fittizio()
            ip=IPNetwork(pool)            
            ip_list=list(ip)
            cs=self._controller.get_customers() 
            index1=self._controller.get_current_customer_id()
            customer_ip=cs[index1].get_private_ip_subnet()
            print('---------INDEX--',index1)
            #if IPAddress(dnsrr.rdata) in IPNetwork(customer_ip):
                
            if IPAddress(dnsrr.rdata) is not None:
                new_response=str(ip_list[1]) 
                responseIP=dnsrr.rdata
                if IPAddress(responseIP) in IPNetwork(cs[index1].get_private_ip_subnet()):
                    myip=list(responseIP.split('.'))
                    index=myip[-1]
                    responseIP=str(ip_list[int(index)])
                dns.ns[0].rrname='.'
                dns.ns[0].rrdata='.'
                dns.id=self._controller.get_transaction_id()
                new_pkt=packet.Packet()
                new_pkt.add_protocol(ethernet.ethernet(src='10:00:00:00:10:ff',dst=cs[int(index1)].get_next_hop_mac()))
                new_pkt.add_protocol(ipv4.ipv4(src=self._controller.get_packet_ip(),dst=cs[int(index1)].get_name_server(),proto=17))
                new_pkt.add_protocol(udp.udp(src_port=53, dst_port=self._controller.get_port_number()))
                dns.an[0].rdata=str(responseIP)
                dns.ar[0].rdata=str(ip_list[1]) 
                print('-----FINAL DNS-----',dns)
                new_pkt.add_protocol(dns)
                print ('----------------The Number of Exchanged PACKETS between Controllers-----',self._controller.get_packet_counter()) 
                dnsrr = dns.an[0]
                new_pkt.serialize()
                self.send_dns_packet(new_pkt,cs[int(index1)].get_datapath(),cs[int(index1)].get_ingress_port())
    
                #A rule to change the change made by SDNS to original one-->fake private ip address to real private ip address
                #find dst fake private ip and then create the original private ip--> the opposite of SDNS
                dns=DNS(self._pkt[-1])
                dnsrr = dns.an[0]
                rIP=responseIP
                print'------get_pool_fittizio--------',self._controller.get_pool_fittizio(), responseIP
                if IPAddress(responseIP) in IPNetwork(self._controller.get_pool_fittizio()):
                   pool=cs[index1].get_private_ip_subnet()
                   ip=IPNetwork(pool)
                   ip_list=list(ip)
                   myip=list(rIP.split('.'))
                   index=myip[-1]
                   rIP=str(ip_list[int(index)])
                   datapath=cs[index1].get_datapath()
                   ofproto = datapath.ofproto
                   parser = datapath.ofproto_parser
                   print'-------NAT IP after SDNS----',rIP
                   match_fake = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_dst=(responseIP))
                   actions_fake = [parser.OFPActionSetField(ipv4_dst=rIP),parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,ofproto.OFPCML_NO_BUFFER)]
                   inst_fake = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions_fake)]
                   mod_fake = parser.OFPFlowMod(datapath=datapath, match=match_fake, instructions=inst_fake, priority=150)
                   datapath.send_msg(mod_fake)
                
    def send_dns_packet(self,pkt,datapath,port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        data =pkt.data
        self._controller.set_transaction_id(None)
        actions = [parser.OFPActionOutput(port=int(port))]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=data)
        datapath.send_msg(out)


#This class manages the DNS queries which one controller wants to send to other controller in order to ask 
#the right name server for the query
class ControllerDNSHandler(object):
    def __init__(self,pkt,controller):
        self._controller = controller
        self._pkt =pkt
        self._index=None
        print'------------ControllerDNSHandlerAlg1------'	
    def handle_socket_msg(self):
        pkt_eth=self._pkt.get_protocols(ethernet.ethernet)[0]
        pkt_ip =self._pkt.get_protocols(ipv4.ipv4)[0]
        pkt_udp =self._pkt.get_protocols(udp.udp)[0]
        pkt_dns=DNS(self._pkt[-1])
        if pkt_udp.dst_port==53:
            #print ('A DNS query for controller is received,',pkt_dns)
            #print ('--pkt---',self._pkt)
            #query=pkt_dns.qd.qname.split('.')
            #new_query=query[1]+'.'+query[2]
            #print'---query--',new_query
            cs=self._controller.get_customers()
            cr_list=[]
            
            #index=0
            for i in range(len(cs)):
                print('--pkt_ip.dst---',pkt_ip.dst,'--cs[i].get_name_server()---',cs[i].get_name_server())
                if pkt_ip.dst in cs[i].get_name_server():
                    self._index=i
               
            print('--index---',self._index)
            if pkt_dns:
                cs=self._controller.get_customers() 
                #create a new DNS packet to send to the name server                
                new_pkt=packet.Packet()
                print('--dst.mac--',cs[self._index].get_next_hop_mac(),self._controller.get_ip())
                new_pkt.add_protocol(ethernet.ethernet(src='00:00:00:00:00:ff',dst=cs[self._index].get_next_hop_mac()))
                new_pkt.add_protocol(ipv4.ipv4(src=self._controller.get_ip(),dst=cs[self._index].get_name_server(),proto=17))
                new_pkt.add_protocol(udp.udp(src_port=22345, dst_port=53))
                new_pkt.add_protocol(self._pkt[-1])
                new_pkt.serialize()
                self.send_dns_packet(new_pkt,cs[self._index].get_datapath(),cs[self._index].get_ingress_port())
    
         
    #Send the DNS packet to the destination name server
    def send_dns_packet(self,pkt,datapath,port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        data =pkt.data
        actions = [parser.OFPActionOutput(port=int(port))]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=data)
        datapath.send_msg(out)

#this class is responsibe for handling the received DNS responses from the target name server
#it has to forward this response to other controller which asked a DNS query
class ControllerDNSResponseHandler(object):
    def __init__(self,pkt,controller):
        self._controller = controller
        self._pkt =pkt
        print'------------ControllerDNSResponseHandlerAlg1------'	
	
    def handle_socket_msg(self):
        pkt_eth=self._pkt.get_protocols(ethernet.ethernet)[0]
        pkt_ip =self._pkt.get_protocols(ipv4.ipv4)[0]
        pkt_udp =self._pkt.get_protocols(udp.udp)[0]
        dns=DNS(self._pkt[-1])
        #print '--------I received a response with ID-------', dns.id
        dnsrr = dns.an[0]
        index1=self._controller.get_current_customer_id()
        if dns.qr==1 and index1 is not None and self._controller.get_destination_customer() is None and self._controller.get_port_number() is not None:
            pool=self._controller.get_pool_fittizio()
            ip=IPNetwork(pool)            
            ip_list=list(ip)
            #print( '-----pkt--------',self._pkt)
            cs=self._controller.get_customers() 
            #for c in range(len(cs)):
                #if 
            print('------------------------cs index------------',index1)
            #customer_ip=cs[index1].get_private_ip_subnet()
            #responseIP=dnsrr.rdata 
            #if IPAddress(dnsrr.rdata) in IPNetwork(customer_ip):
            if dnsrr.rdata is not None:
                new_response=str(ip_list[1]) 
                responseIP=dnsrr.rdata
                responseIP2=dnsrr.rdata
                
                #check wheather the response IP overlaps with src or not? if so, do NAT
                if IPAddress(responseIP) in IPNetwork(cs[index1].get_private_ip_subnet()):
                    myip=list(responseIP.split('.'))
                    index=myip[-1]
                    responseIP=str(ip_list[int(index)])
                #print('--DNS before---',dns) 
                if dns.nscount>=1:
                    dns.ns[0].rrname='ROOT-SERVER.'
                    dns.ns[0].rdata='10.1.0.18'
                if dns.arcount>=1:
                    dns.ar.rrname='ROOT-SERVER.'
                    dns.ar.rdata='10.1.0.18'
                
                dns.id=self._controller.get_transaction_id()
                cs=self._controller.get_customers()
                print'--len(cs)--',len(cs),'----------',cs[index1].get_next_hop_mac(),'-port-',self._controller.get_port_number() 
                new_pkt=packet.Packet()
                new_pkt.add_protocol(ethernet.ethernet(src='10:00:00:00:10:ff',dst=cs[index1].get_next_hop_mac()))
                #new_pkt.add_protocol(ipv4.ipv4(src='10.1.0.18',dst=cs[index1].get_name_server(),proto=17))
                new_pkt.add_protocol(ipv4.ipv4(src=IPAddress('10.1.0.18'),dst=cs[index1].get_name_server(),proto=17))
                new_pkt.add_protocol(udp.udp(src_port=53, dst_port=self._controller.get_port_number()))
                #new_dns=DNS(rd=0,id=pkt_dns.id,qd=DNSQR(qname=dns.qd.qname),ns=DNSRR(rrname=dns.ar.rrname,type=1,ttl=60000,rdata=cs[index1].get_name_server()))
                #new_pkt.add_protocol(new_dns)
                dns.an[0].rdata=str(responseIP)
                #dns1=DNS(rd=0, id=dns.id, qr=1L, qd=dns.qd, ancount=1, nscount=1, arcount=1, an=(DNSRR(rrname=dnsrr.rrname, type='A', rclass='IN', ttl=60000, rdata=str(responseIP))), ns=(DNSRR(rrname='ROOT-SERVER.', type='NS',rclass='IN', ttl=3600, rdata='.')), ar=DNSRR(rrname='ROOT-SERVER.', type='A', rclass='IN' ,ttl=60000, rdata='10.1.0.18'))

                #print('-----FINAL DNS-----',dns)
                new_pkt.add_protocol(dns)
                new_pkt.serialize()
                #print('--akher packet---',new_pkt) 
                #print'---final values ID=%i, cs-ID=%s, udp-port=%i'% (self._controller.get_transaction_id(),self._controller.get_current_customer_id(),self._controller.get_port_number())
                self.send_dns_packet(new_pkt,cs[index1].get_datapath(),cs[index1].get_ingress_port())
                print'---------final pkt is sent--------------------------------------------'
 
                 
                #A rule to change the change made by SDNS to original one-->fake private ip address to real private ip address
                #find dst fake private ip and then create the original private ip--> the opposite of SDNS
                dns=DNS(self._pkt[-1])
                dnsrr = dns.an[0]
                rIP=responseIP
                print'------get_pool_fittizio--------',self._controller.get_pool_fittizio(), responseIP
                if IPAddress(responseIP) in IPNetwork(self._controller.get_pool_fittizio()):
                   pool=cs[index1].get_private_ip_subnet()
                   ip=IPNetwork(pool)
                   ip_list=list(ip)
                   myip=list(rIP.split('.'))
                   index=myip[-1]
                   rIP=str(ip_list[int(index)])
                   datapath=cs[index1].get_datapath()
                   ofproto = datapath.ofproto
                   parser = datapath.ofproto_parser
                   print'-------NAT IP after SDNS----',rIP
                   match_fake = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_dst=(responseIP))
                   actions_fake = [parser.OFPActionSetField(ipv4_dst=rIP),parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,ofproto.OFPCML_NO_BUFFER)]
                   inst_fake = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions_fake)]
                   mod_fake = parser.OFPFlowMod(datapath=datapath, match=match_fake, instructions=inst_fake, priority=150)
                   datapath.send_msg(mod_fake)
                

    #Send the DNS packet to the destination name server
    def send_dns_packet(self,pkt,datapath,port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        data =pkt.data
        #print '------------port-----------',port
        actions = [parser.OFPActionOutput(port=int(port))]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=data)
        datapath.send_msg(out)
        self._controller.set_transaction_id(None)
        self._controller.set_port_number(None)
        self._controller.set_current_customer_id(None)
        #self._controller.set_destination_customer(None)
        print'-----the Query is DONE-------- and T-ID set to',self._controller.get_transaction_id(), '--customer-ID set to ', self._controller.get_current_customer_id()
