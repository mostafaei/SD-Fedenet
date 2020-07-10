
import pickle
from ryu.ofproto.ofproto_v1_3 import OFP_NO_BUFFER
from ryu.lib.packet import packet
from packet_handler import PacketHandler
from ryu.ofproto import ofproto_v1_3, ether
from scapy.all import DNS, DNSQR, DNSRR, dnsqtypes
from ryu.lib.packet import udp, arp, ethernet, ipv4
import struct
from utils.communication import Client, Server
#from model.customer import Customer, CustomerRemote
from model.node import Controller
from netaddr import *
from utils.connection import Connection


__author__='Habib Mostafaei'

#This class is responsible to handle all DNS queries in SDNS.
class DNSQueryHandlerAlg2(PacketHandler):
    def __init__(self, pkt, in_port, data, datapath,controller,federazione,public_to_private_a,
                       public_to_private_b):
        PacketHandler.__init__(self, pkt)
        self._pkt = pkt
        self._datapath = datapath
        self._in_port = in_port
        self._data=data
        self._controller=controller
        self._federation=federazione
        self._public_to_private_a=public_to_private_a
        self._public_to_private_b=public_to_private_b
        print'------------DNSQueryHandlerAlg2------'	
	
    def handle_packet(self):
        #print "controller",self._controller, "federation ip",self._federation[0].get_ip()
        pkt_ip =self._pkt.get_protocols(ipv4.ipv4)[0]
        pkt_udp =self._pkt.get_protocols(udp.udp)[0]
        """
        Handle DNS packet inside Controller. Each DNS packet carries with a udp packet. We used the DNS class of Scapy library to decode
        DNS queries.
        """
        cs=self._controller.get_customers() 
        csR=self._controller.get_customers_remote()
        name_customer=None
        name_list=[]
        cr_list=[]
        cs_list=[]
        name_server_list=[]
        pkt_dns=DNS(self._pkt[-1])
        for c in range(len(cs)):
            name_list=cs[c].get_name()
            name_server_list.append(cs[c].get_name_server())
        for c in range(len(csR)):
            name=csR[c].get_name_server()
            cs_list.append(csR[c].get_name())
            if pkt_dns.ar.rrname==name[0]:
                name_customer=csR[c].get_name()
        for cr in range(len(csR)):
           if csR[cr].get_ip() is not None:
               cr_list.append(csR[cr].get_ip())
        for c in range(len(cs)):
            if IPAddress(pkt_ip.src) in IPNetwork(cs[c].get_private_ip_subnet()):
                index=c
                self._controller.set_current_customer_id(index)
        index=self._controller.get_current_customer_id()
        print('-----3--------',pkt_ip.dst,name_server_list)
        for c in range(len(cs)):
            if cs[c].get_name_server()==pkt_ip.dst:
                index_new=c
        #if (pkt_udp.dst_port==53 and self._controller.get_transaction_id() is None) and pkt_dns.qd.qtype==1 and pkt_dns.qd.qname!=cs[index].get_ns_domain_name():
        if (pkt_udp.dst_port==53 and self._controller.get_transaction_id() is None) and pkt_dns.qd.qtype==1 and pkt_ip.dst not in name_server_list:
        #if (pkt_udp.dst_port==53 and self._controller.get_transaction_id() is None) and pkt_dns.qd.qtype==1 and pkt_dns.qd.qname not in c_list:
            self._controller.set_port_number(pkt_udp.src_port)
            self._controller.set_transaction_id(pkt_dns.id)
            self._controller.set_packet_ip(pkt_ip.dst)
            ofp =self._datapath.ofproto
            parser =self._datapath.ofproto_parser
            
            output = ofp.OFPP_TABLE
            match = parser.OFPMatch()
            actions=[parser.OFPActionOutput(output)]
            #print('--cs[index].get_as_pe_mac()--',cs[0].get_as_pe_mac(),'index=',index) 
            new_pkt=packet.Packet()
            new_pkt.add_protocol(ethernet.ethernet(src='00:aa:00:00:0f:11',dst=cs[0].get_as_pe_mac()))
            new_pkt.add_protocol(pkt_ip)
            new_pkt.add_protocol(pkt_udp)
            new_pkt.add_protocol(self._pkt[-1])
            new_pkt.serialize()
            out = parser.OFPPacketOut(datapath=self._datapath, buffer_id=ofp.OFP_NO_BUFFER,in_port=5, actions=actions, data=new_pkt.data)
            self._datapath.send_msg(out)
           
        if pkt_ip.dst in name_server_list:
            print('---------SALAM------FINAL-----',index_new)
            self._controller.set_port_number(pkt_udp.src_port)
            self._controller.set_transaction_id(pkt_dns.id)
            self._controller.set_packet_ip(pkt_ip.dst)
            self._controller.set_destination_nat(index_new)
            new_pkt=packet.Packet()
            new_pkt.add_protocol(ethernet.ethernet(src='00:aa:bb:00:0f:11',dst=cs[index_new].get_next_hop_mac()))
            new_pkt.add_protocol(ipv4.ipv4(dst=cs[index_new].get_name_server(),src=pkt_ip.src,proto=17))
            new_pkt.add_protocol(udp.udp(src_port=self._controller.get_port_number(),dst_port=53))
            new_pkt.add_protocol(pkt_dns)
            self.send_dns_packet(new_pkt,cs[index_new].get_datapath(),cs[index_new].get_ingress_port())
            print(cs[index_new].get_next_hop_mac(),cs[index_new].get_name_server(),cs[index_new].get_ingress_port())

    def send_dns_packet(self,pkt, datapath,port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        data =pkt.data
        actions = [parser.OFPActionOutput(port=int(port))]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=data)
        datapath.send_msg(out)

class DNSResponseHandlerAlg2(PacketHandler):
    def __init__(self, pkt, in_port, data, datapath,controller,federazione,public_to_private_a,public_to_private_b,pkt_dns):
        PacketHandler.__init__(self, pkt)
        self._pkt = pkt
        self._pkt_dns = pkt_dns
        self._datapath = datapath
        self._in_port = in_port
        self._data=data
        self._controller=controller
        self._federation=federazione
        self._public_to_private_a=public_to_private_a
        self._public_to_private_b=public_to_private_b
        print'-------DNSResponseHandlerAlg2--------'

    def handle_packet(self):
        pkt_eth =self._pkt.get_protocols(ethernet.ethernet)[0]
        pkt_ip =self._pkt.get_protocols(ipv4.ipv4)[0]
        pkt_udp =self._pkt.get_protocols(udp.udp)
        dns=DNS(self._pkt[-1])
        cs=self._controller.get_customers()
        csR=self._controller.get_customers_remote()
        cs_list=[]
        cr_list=[]
        name_customer=None
        name_list=[]
        name_server_list=[]
        for c in range(len(cs)):
            name_list.append(cs[c].get_name())
            name_server_list.append(cs[c].get_name_server())
        for c in range(len(csR)):
            name=csR[c].get_name_server()
            #print'--name--',name
            cr_list.append(name[0])
            if dns.ar.rrname==name[0]:
                name_customer=csR[c].get_name()
        index=self._controller.get_current_customer_id() 
        nsdomain=cs[index].get_ns_domain_name()
        #print('--dns--',dns)
        print('--name_server_list--',name_server_list)
        print('--cs_list--',cs_list)
        print('--cr_list--',cr_list)
        print('--name_list--',name_list)
        print('---name-customer--',name_customer,dns.ar.rrname) 
        for c in range(len(cs)):
            if cs[c].get_name()==name_customer:
                index_new=c
        #print('-------dns.----',dns)
        #if dns.qr==1 and dns.ar.rrname!=cs[0].get_ns_domain_name():
        if dns.qr==1 and dns.ar.rrname not in cr_list and name_customer is None:
            dns.id=self._controller.get_transaction_id()
            new_pkt=packet.Packet()
            new_pkt.add_protocol(ethernet.ethernet(src='00:aa:bb:00:0f:11',dst=cs[index].get_next_hop_mac()))
            new_pkt.add_protocol(ipv4.ipv4(dst=cs[index].get_name_server(),src=pkt_ip.src,proto=17))
            new_pkt.add_protocol(udp.udp(src_port=53, dst_port=self._controller.get_port_number()))
            new_pkt.add_protocol(dns)
            self.send_dns_response_packet(new_pkt,cs[index].get_datapath(),cs[index].get_ingress_port())
        elif dns.qr==1 and name_customer in name_list:
            print('---------SALAM-----------',index_new,pkt_ip)
            dns.id=self._controller.get_transaction_id()
            new_pkt=packet.Packet()
            new_pkt.add_protocol(ethernet.ethernet(src='00:aa:bb:00:0f:11',dst=cs[index].get_next_hop_mac()))
            new_pkt.add_protocol(ipv4.ipv4(dst=cs[index].get_name_server(),src=pkt_ip.src,proto=17))
            new_pkt.add_protocol(udp.udp(src_port=53, dst_port=self._controller.get_port_number()))
            new_pkt.add_protocol(dns)
            self.send_dns_response_packet(new_pkt,cs[index].get_datapath(),cs[index].get_ingress_port())
        
        
        if dns.qr==1 and dns.ar.rrname in cr_list and name_customer not in name_list:
            print '----------I am calling another controller------------'
            self.send_dns_response_to_controller(self._pkt)


    #Send the DNS query to the controller 
    def send_dns_response_to_controller(self,pkt):
        cl=Client()
        #print 'cl', cl
        msg = "dns_query_sep_" + pickle.dumps(pkt)
        cl.send_message(msg,self._federation[0].get_ip(),10000) 

    def send_dns_response_packet(self,pkt, datapath,port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        data =pkt.data
        actions = [parser.OFPActionOutput(port=int(port))]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=data)
        datapath.send_msg(out)
        self._controller.set_port_number(None)
        self._controller.set_transaction_id(None)
        self._controller.set_packet_ip(None)

class DNSResponseHandlerAlg2_2(PacketHandler):
    def __init__(self, pkt, in_port, data, datapath,controller,federazione,public_to_private_a,public_to_private_b,pkt_dns):
        PacketHandler.__init__(self, pkt)
        self._pkt = pkt
        self._pkt_dns = pkt_dns
        self._datapath = datapath
        self._in_port = in_port
        self._data=data
        self._controller=controller
        self._federation=federazione
        self._public_to_private_a=public_to_private_a
        self._public_to_private_b=public_to_private_b
        PacketHandler.__init__(self, pkt)
        self._controller = controller
	print'-------DNSResponseHandlerAlg2_2------'

    def handle_packet(self):
        pkt_ip =self._pkt.get_protocols(ipv4.ipv4)[0]
        pkt_udp =self._pkt.get_protocols(udp.udp)[0]
        cs=self._controller.get_customers()
        index1=self._controller.get_current_customer_id()
        dns=DNS(self._pkt[-1])
        print('------UDP---------',index1,cs[int(index1)].get_next_hop_mac(),self._controller.get_transaction_id())
        if self._controller.get_destination_nat() is not None and self._controller.get_transaction_id() is not None:
            new_pkt=packet.Packet()
            new_pkt.add_protocol(ethernet.ethernet(src='10:00:00:00:10:ff',dst=cs[int(index1)].get_next_hop_mac()))
            new_pkt.add_protocol(ipv4.ipv4(src=pkt_ip.src,dst=cs[int(index1)].get_name_server(),proto=17))
            new_pkt.add_protocol(udp.udp(src_port=pkt_udp.src_port,dst_port=pkt_udp.dst_port))
            new_pkt.add_protocol(self._pkt[-1])
            print('---------okt--------',new_pkt)
            new_pkt.serialize()
            print ('----------------The Number of Exchanged PACKETS between Controllers-----',self._controller.get_packet_counter())
            self.send_dns_packet(new_pkt,cs[int(index1)].get_datapath(),cs[int(index1)].get_ingress_port())
        elif self._controller.get_destination_nat() is  None:
            self.send_dns_response_to_controller(self._pkt)

    #Send the DNS query to the controller 
    def send_dns_response_to_controller(self,pkt):
        cl=Client()
        msg = "dns_response_sep_" + pickle.dumps(pkt)
        cl.send_message(msg,self._federation[0].get_ip(),10000)
        
    def send_dns_packet(self,pkt,datapath,port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        data =pkt.data
        self._controller.set_transaction_id(None)
        actions = [parser.OFPActionOutput(port=int(port))]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=data)
        datapath.send_msg(out)

         
#This class is responsible to handle all DNS queries in SDNS.
class DNSQueryHandler(PacketHandler):
    def __init__(self, pkt, in_port, data, datapath,controller,federazione,public_to_private_a,
                       public_to_private_b):
        PacketHandler.__init__(self, pkt)
        self._pkt = pkt
        self._datapath = datapath
        self._in_port = in_port
        self._data=data
        self._controller=controller
        self._federation=federazione
        self._public_to_private_a=public_to_private_a
        self._public_to_private_b=public_to_private_b
	print'------DNSQueryHandlerAlg1-------'
	
    def handle_packet(self):
        pkt_ip =self._pkt.get_protocols(ipv4.ipv4)[0]
        pkt_udp =self._pkt.get_protocols(udp.udp)[0]
        pkt_dns=DNS(self._pkt[-1])
        """
        Handle DNS packet inside Controller. Each DNS packet carries with a udp packet. We used the DNS class of Scapy library to decode
        DNS queries.
        """
        #self._controller.set_current_customer_id(None)
        #self._controller.set_transaction_id(None)
        csR=self._controller.get_customers_remote()
        cs=self._controller.get_customers()
        qq=pkt_dns.qd.qname
        cr_list=[]
        cname=None
        #self._controller.set_destination_customer(None)
        cr_name=[]
        cs_name=[]
        if pkt_udp.dst_port==53 and pkt_dns.qd.qtype==1 and self._controller.get_transaction_id() is None and pkt_dns.qr==0:
            if len(qq)>12:
                query=pkt_dns.qd.qname.split('.')
                new_query=query[1]+'.'+query[2]
                for i in range(len(csR)):
                    #print'--new-query------',new_query,csR[i].get_name_server(),len(csR)
                    if new_query in csR[i].get_name_server():
                        cr_list.append(csR[i].get_ip()) 
                        cr_name.append(csR[i].get_name())
                        dst_ip=cr_list[0]
                        cname=csR[i].get_name()
         
            for c in range(len(cs)):
                cs_name.append(cs[c].get_name())   
                if IPAddress(pkt_ip.src) in IPNetwork(cs[c].get_private_ip_subnet()):
                    #if IPAddress(pkt_ip.src) in IPNetwork(cs[c].get_private_ip_subnet()):
                    self._controller.set_current_customer_id(c)
                    print('--self._controller.get_current_customer_id()--',self._controller.get_current_customer_id()),c,cs[c].get_private_ip_subnet(),pkt_ip.src
            print('---cname---',cname,'---cr_name--',cr_name,'----cs_name--',cs_name)
            index=self._controller.get_current_customer_id()
            self._controller.set_transaction_id(pkt_dns.id)
            self._controller.set_port_number(pkt_udp.src_port)
            if cname in cr_name and cname not in cs_name:
                print '----------------if remote cr-name------------------------',self._controller.get_transaction_id(),self._controller.get_port_number(),index
                #print '-------------Sent query with ID------', pkt_dns.id
                new_pkt=packet.Packet()
                new_pkt.add_protocol(ethernet.ethernet(src='00:00:00:00:0f:11'))
                #new_pkt.add_protocol(ipv4.ipv4(src=self._controller.get_ip(),dst=self._federation[0].get_ip(),proto=17))
                new_pkt.add_protocol(ipv4.ipv4(src=self._controller.get_ip(),dst=dst_ip,proto=17))
                new_pkt.add_protocol(udp.udp(src_port=12345, dst_port=53))
                new_pkt.add_protocol(self._pkt[-1])
                new_pkt.serialize()
                self.send_dns_query_to_controller(new_pkt)
            #send the DNS query to the customer inside the same ISP
            elif cname in cs_name: 
                for c in range(len(cs)):
                    print '----------------if own customer cs-name------------------------',cs[c].get_name()
                    if cname==cs[c].get_name():
                        dst_index=c
                #create a new DNS packet to send to the name server                
                self._controller.set_destination_customer(cname)
                self._controller.set_destination_nat(cname)
                new_pkt=packet.Packet()
                print('--dst.mac--',cs[dst_index].get_next_hop_mac(),self._controller.get_ip())
                new_pkt.add_protocol(ethernet.ethernet(src='00:00:00:00:00:ff',dst=cs[dst_index].get_next_hop_mac()))
                new_pkt.add_protocol(ipv4.ipv4(src=self._controller.get_ip(),dst=cs[dst_index].get_name_server(),proto=17))
                new_pkt.add_protocol(udp.udp(src_port=pkt_udp.src_port, dst_port=53))
                new_pkt.add_protocol(self._pkt[-1])
                new_pkt.serialize()
                self.send_dns_packet(new_pkt,cs[dst_index].get_datapath(),cs[dst_index].get_ingress_port())



 
    #Send the DNS packet to the destination name server
    def send_dns_packet(self,pkt,datapath,port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        data =pkt.data
        actions = [parser.OFPActionOutput(port=int(port))]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=data)
        datapath.send_msg(out)
                
                    
    
    #Send the DNS query to the controller 
    def send_dns_query_to_controller(self,pkt):
        cl=Client()
        msg = "dns_query_sep_" + pickle.dumps(pkt)
        cl.send_message(msg,self._federation[0].get_ip(),10000) 
        print'-----SENT DONE--------------------------'


class DNSResponseHandler(PacketHandler):
    def __init__(self, pkt, in_port, data, datapath,controller,federazione,public_to_private_a,public_to_private_b,pkt_dns):
        PacketHandler.__init__(self, pkt)
        self._pkt = pkt
        self._pkt_dns = pkt_dns
        self._datapath = datapath
        self._in_port = in_port
        self._data=data
        self._controller=controller
        self._federation=federazione
        self._public_to_private_a=public_to_private_a
        self._public_to_private_b=public_to_private_b
    	print'--------DNSResponseHandler-Alg1-----'
    def handle_packet(self):
        pkt_eth=self._pkt.get_protocols(ethernet.ethernet)[0]
        pkt_ip =self._pkt.get_protocols(ipv4.ipv4)
        pkt_udp =self._pkt.get_protocols(udp.udp)
        dns=DNS(self._pkt[-1])
        dnsrr = dns.an[0]
        csR=self._controller.get_customers_remote()
        cs=self._controller.get_customers()
        mac_list=[]
        cname=None
        cr_name=[]
        cs_name=[]
        query=dnsrr.rrname.split('.')
        eth=pkt_eth.src
        new_query=query[1]+'.'+query[2]
        
        dst_index=None
        dst_index=self._controller.get_current_customer_id()
        print(eth,'--------------dst-cust-----------',self._controller.get_destination_customer())
        #send the DNS response to remote controller if the customer is a reomte one
        for i in range(len(cs)):
            cs_name.append(cs[i].get_name())
        print '-------cs-name----------------------------',cs_name,self._controller.get_destination_customer(),'-------dns.qr----',dns.qr
        current=self._controller.get_destination_customer()
        if self._controller.get_destination_customer() is None and dns.qr==1:
        #if current is not None:
            self.send_dns_response_to_controller(self._pkt)
        #send the DNS response to customer ce if the customer is within the current controller ISP
        #for c in range(len(cs)):
            #if new_query in cs[c].get_name_server():
                #cs_name.append(cs[c].get_name())   
                #dst_index=c
        elif self._controller.get_destination_customer() is not None and dns.qr==1:
        #elif eth in mac_list and dst_index is not None:
            print('------------------------cs index------------',dst_index)
            responseIP=dnsrr.rdata
            if dns.nscount>=1:
                dns.ns[0].rrname='ROOT-SERVER.'
                dns.ns[0].rdata='10.1.0.18'
            if dns.arcount>=1:
                dns.ar.rrname='ROOT-SERVER.'
                dns.ar.rdata='10.1.0.18'

            dns.id=self._controller.get_transaction_id()
            cs=self._controller.get_customers()
            #print'--len(cs)--',len(cs),'----------',cs[dst_index].get_next_hop_mac(),'-port-',self._controller.get_port_number()
            new_pkt=packet.Packet()
            new_pkt.add_protocol(ethernet.ethernet(src='10:00:00:00:10:ff',dst=cs[dst_index].get_next_hop_mac()))
            #new_pkt.add_protocol(ipv4.ipv4(src='10.1.0.18',dst=cs[index1].get_name_server(),proto=17))
            new_pkt.add_protocol(ipv4.ipv4(src=IPAddress('10.1.0.18'),dst=cs[dst_index].get_name_server(),proto=17))
            new_pkt.add_protocol(udp.udp(src_port=53, dst_port=self._controller.get_port_number()))
            new_pkt.add_protocol(dns)
            new_pkt.serialize()
            #print'---final values ID=%i, cs-ID=%s, udp-port=%i'% (self._controller.get_transaction_id(),self._controller.get_current_customer_id(),self._controller.get_port_number())
            self.send_dns_packet(new_pkt,cs[dst_index].get_datapath(),cs[dst_index].get_ingress_port())
            print'---------final pkt is sent--------------------------------------------'

       
    #Send the DNS packet to the destination name server
    def send_dns_packet(self,pkt,datapath,port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        data =pkt.data
        actions = [parser.OFPActionOutput(port=int(port))]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=data)
        datapath.send_msg(out)
        self._controller.set_transaction_id(None)
        self._controller.set_port_number(None)
        self._controller.set_current_customer_id(None)
        self._controller.set_destination_customer(None)
        print'-----the Query is DONE-------- and T-ID set to',self._controller.get_transaction_id(), '--customer-ID set to ', self._controller.get_current_customer_id()

            
    #Send the DNS query to the controller 
    def send_dns_response_to_controller(self,pkt):
        cl=Client()
        #print 'cl', cl
        msg = "dns_response_sep_" + pickle.dumps(pkt)
        cl.send_message(msg,self._federation[0].get_ip(),10000) 
        print 'pkt DNS  sent to controller'

#This class is responsible to handle all DNS queries in SDNS.
class DNSQueryHandlerGeneral(PacketHandler):
    def __init__(self, pkt, in_port, data, datapath,controller,federazione,public_to_private_a,
                       public_to_private_b):
        PacketHandler.__init__(self, pkt)
        self._pkt = pkt
        self._datapath = datapath
        self._in_port = in_port
        self._data=data
        self._controller=controller
        self._federation=federazione
        self._public_to_private_a=public_to_private_a
        self._public_to_private_b=public_to_private_b
	print'------DNSQueryHandlerGeneral-------'
	
    def handle_packet(self):
        pass



#This class is responsible to handle all DNS queries in SDNS.
class DNSQueryHandlerNS(PacketHandler):
    def __init__(self, pkt, in_port, data, datapath,controller,federazione,public_to_private_a,public_to_private_b,pport):
        PacketHandler.__init__(self, pkt)
        self._pkt = pkt
        self._datapath = datapath
        self._in_port = in_port
        self._data=data
        self._controller=controller
        self._federation=federazione
        self._public_to_private_a=public_to_private_a
        self._public_to_private_b=public_to_private_b
        self._pport=pport
	print'------DNSQueryHandler for .-------'
	
    def handle_packet(self):
        pkt_eth =self._pkt.get_protocols(ethernet.ethernet)[0]
        pkt_ip =self._pkt.get_protocols(ipv4.ipv4)[0]
        pkt_udp =self._pkt.get_protocols(udp.udp)
        dns=DNS(self._pkt[-1])
        cs=self._controller.get_customers()

        for c in range(len(cs)):
            if IPAddress(pkt_ip.src) in IPNetwork(cs[c].get_private_ip_subnet()):
                index=c
                #print'---##################INEX#############',index
                #self._controller.set_current_customer_id(index)
        #index=self._controller.get_current_customer_id()
        if pkt_udp is not None and self._pport is not None: 
            new_pkt=packet.Packet()
            new_pkt.add_protocol(ethernet.ethernet(src='10:00:00:00:10:ff',dst=cs[index].get_next_hop_mac()))
            new_pkt.add_protocol(ipv4.ipv4(src='10.1.0.18',dst=cs[index].get_name_server(),proto=17))
            #print '********index********',pkt_udp,'*******PORT********',self._pport,'######################'
            new_pkt.add_protocol(udp.udp(src_port=53, dst_port=self._pport))
            #print'---pkt is created---til udp'
            #new_dns=DNS(rd=0,id=pkt_dns.id,qd=DNSQR(qname=pkt_dns.qd.qname),ns=DNSRR(rrname=pkt_dns.ar.rrname,type=1,ttl=60000,rdata=cs[index].get_name_server()))
            dns=DNS(rd=0, id=dns.id, qr=1L, qd=dns.qd, ancount=1, nscount=1, arcount=1, an=(DNSRR(rrname='ROOT-SERVER.', type='A', rclass='IN', ttl=60000, rdata='10.1.0.18')), ns=(DNSRR(rrname='ROOT-SERVER.', type='NS',rclass='IN', ttl=3600, rdata='.')), ar=DNSRR(rrname='ROOT-SERVER.', type='A', rclass='IN' ,ttl=60000, rdata='10.1.0.18'))
            #print('---DNS fo . SENT----',dns)
            new_pkt.add_protocol(dns)
            new_pkt.serialize()
            self.send_dns_packet(new_pkt,cs[index].get_datapath(),cs[index].get_ingress_port())
            self._pport=None
    #Send the DNS packet to the destination name server
    def send_dns_packet(self,pkt,datapath,port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        data =pkt.data
        actions = [parser.OFPActionOutput(port=int(port))]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=data)
        datapath.send_msg(out)
