from ryu.ofproto.ofproto_v1_3 import OFP_NO_BUFFER
from ryu.lib.packet import packet
from ryu.ofproto import ofproto_v1_3, ether
from packet_handler import PacketHandler
from model.customer import Customer
from ryu.lib.packet import arp, ethernet, ipv4

__author__ = 'Habib Mostafaei'



class ArpHandler(PacketHandler):
    def __init__(self, pkt, datapath, in_port,controller):
        PacketHandler.__init__(self, pkt)
        self._pkt = pkt
        self._datapath = datapath
        self._in_port = in_port
        self._controller=controller

    def handle_packet(self):

        arp_pkt= self._pkt.get_protocol(arp.arp)
        ip_src=arp_pkt.src_ip
        ip_dst=arp_pkt.dst_ip
        mac_src=arp_pkt.src_mac
        cs=self._controller.get_customers()
        #print'----ip_src--',ip_src
        for c in range(len(cs)):
            if ip_src==cs[c].get_next_hop():
                index=c
                #print'--cs',c
                self._controller.set_current_customer_id(index)
        index=self._controller.get_current_customer_id()

        csR=self._controller.get_customers_remote()
        cr_list=[]
        a=1
        for cr in range(len(csR)):
            if csR[cr].get_ip() is  not None:
                cr_list.append(csR[cr].get_ip())
        #print('-----------cr_list--------',cr_list)
        #if len(cr_list)>=1:
        #if cs[index].get_ns_domain_name() is None:
	        #cs=self._controller.get_customers()
            #cs[index].set_next_hop_mac(mac_src)
            #print "An ARP packet received from port : ",self._in_port
            #actions = [self._datapath.ofproto_parser.OFPActionOutput(self._datapath.ofproto.OFPP_FLOOD)]
            #out = self._datapath.ofproto_parser.OFPPacketOut(datapath=self._datapath, buffer_id=OFP_NO_BUFFER, in_port=self._in_port, actions=actions, data=self._pkt.data)
            #self._datapath.send_msg(out)
            #print"ARP packet forwarded on all ports"
            for cc in range(len(cs)):
                #print "---,cs[%i].get_router()=%s,ip_src=%s,cs[%i].get_next_hop()=%s" % (cc,cs[cc].get_router(),ip_src,cc,cs[cc].get_next_hop())
	        if cs[cc].get_router()==ip_src:
	            cs[cc].set_as_pe_mac(mac_src)
                    #print'---cs[%s].get_as_pe_mac()--',cc,cs[cc].get_as_pe_mac()
                    
                    #This part is needed to send ARP reply from openFlow switch to PE in order to forward traffic from pe to switch
	            d=self._datapath.ports
	            for keys in d.keys():
	                v=d.get(keys)
	                if str(keys)==str(cs[cc].get_out_port()):
	                    src_mac_addr=v.hw_addr
	                    new_pkt=packet.Packet()
	                    new_pkt.add_protocol(ethernet.ethernet(ethertype=ether.ETH_TYPE_ARP,src=src_mac_addr, dst=mac_src))
	                    new_pkt.add_protocol(arp.arp(hwtype=1,proto=0x800,hlen=6,plen=4,opcode=arp.ARP_REPLY,src_mac=src_mac_addr,dst_mac=mac_src,src_ip=cs[cc].get_datapath_to_router_ip(),dst_ip=ip_src))
                            #print('----new ARP-pkt--',new_pkt)
                            new_pkt.serialize() 
                            #print'----ARP--inside if-----',mac_src,keys,cs[cc].get_out_port()
	                    self.send_arp_packet(self._datapath,new_pkt,cs[cc].get_out_port())
                            #print'----SENT ARP--'
                     
	        elif cs[cc].get_next_hop()==ip_src:     
	            cs[cc].set_next_hop_mac(mac_src)
                    #print'---cs[%s].get_next_hop_mac()--',cc,cs[cc].get_next_hop_mac()
                    #print'---mac_src_ce--',cc,cs[cc].get_next_hop_mac(),cs[cc].get_next_hop() 
	        #print "An ARP packet received from port : ",self._in_port
	        actions = [self._datapath.ofproto_parser.OFPActionOutput(self._datapath.ofproto.OFPP_FLOOD)]
	        out = self._datapath.ofproto_parser.OFPPacketOut(datapath=self._datapath, buffer_id=OFP_NO_BUFFER,in_port=self._in_port, actions=actions,data=self._pkt.data)
	        self._datapath.send_msg(out)
	    #print"ARP packet forwarded on all ports"

    #Send the DNS packet to the destination name server
    def send_arp_packet(self, datapath,pkt,port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        #print'---send_arp_packet--'
        data = pkt.data
        actions = [parser.OFPActionOutput(port=int(port))]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=data)
        datapath.send_msg(out)
