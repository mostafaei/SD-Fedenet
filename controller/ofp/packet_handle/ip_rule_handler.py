import pickle
from ryu.ofproto.ofproto_v1_3 import OFP_NO_BUFFER
from ryu.lib.packet import packet
from packet_handler import PacketHandler
from ryu.ofproto import ofproto_v1_3, ether
from ryu.lib.packet import udp, arp, ethernet, ipv4
from model.customer import Customer
from model.node import Controller
from netaddr import *
import socket

__author__='Habib Mostafaei'

#This class manages the DNS queries which one controller wants to send to other controller in order to ask 
#the right name server for the query 
class IpRuleHandler(object):
    def __init__(self,pkt,controller):
        self._controller = controller
        self._pkt =pkt
        self._datapath=None

	
    def handle_socket_msg(self):
        src, dst = self._pkt.split(",")
        src, private_address_src, public_address_src = src.split(":")
        dst, private_address_dst, public_address_dst = dst.split(":")
        out_port=None
        cs=self._controller.get_customers()
        self._datapath=cs[0].get_datapath()
        ofp = self._datapath.ofproto
        parser = self._datapath.ofproto_parser
        print'-----MSG-INSIDE-IPRuleHANDLER---------------',self._pkt, '--len(cs)=',len(cs),private_address_dst
        #print'-----src-----------------',src
        #print'-----dst-----------------',dst
        for c in range(len(cs)):
            if IPAddress(private_address_dst) in IPNetwork(cs[c].get_private_ip_subnet()):
                print'--------cs[c].get_out_port()------',cs[c].get_out_port(),'-cs[c].get_as_pe_mac()-',cs[c].get_as_pe_mac()
                '''
                actions = [parser.OFPActionSetField(ipv4_src=public_address_src), parser.OFPActionSetField(eth_dst= cs[c].get_as_pe_mac()) ,parser.OFPActionSetField(ipv4_dst=public_address_dst), parser.OFPActionOutput(int(cs[c].get_out_port()))]
                out = parser.OFPPacketOut(datapath=self._datapath,  in_port=cs[c].get_ingress_port(), actions=actions, buffer_id=OFP_NO_BUFFER)
                self._datapath.send_msg(out)
                '''  
                #Inserisco un flow-entry per i pacchetti in uscita
                match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_src=public_address_src, ipv4_dst=public_address_dst)
                actions = [parser.OFPActionSetField(ipv4_src=public_address_dst),parser.OFPActionSetField(eth_dst= cs[c].get_next_hop_mac()),parser.OFPActionSetField(ipv4_dst=private_address_dst), parser.OFPActionOutput(int(cs[c].get_ingress_port()))]

                inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
                mod = parser.OFPFlowMod(datapath=self._datapath, match=match, instructions=inst, priority=200)
                self._datapath.send_msg(mod)

            # Inserisco una flow-entry per i pacchetti in entrata

            # Verifico la porta di uscita del datapath in funzione della subnet privata dei miei customer
            # Assunzione: customer sotto lo stesso datapath devono avere subnet private differenti

        for customer in self._controller.get_customers():
            if customer.get_datapath() == self._datapath and customer.get_private_ip_subnet().__contains__(IPAddress(private_address_dst)):
                out_port = int(customer.get_out_port())
        if out_port is not None:
            match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_dst=public_address_dst, ipv4_src=private_address_dst)
            actions = [parser.OFPActionSetField(eth_dst= cs[0].get_as_pe_mac()), parser.OFPActionSetField(ipv4_src=public_address_dst), parser.OFPActionSetField(ipv4_dst=public_address_src), parser.OFPActionOutput(out_port)]
            inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
            mod = parser.OFPFlowMod(datapath=self._datapath, match=match, instructions=inst, priority=200)
            self._datapath.send_msg(mod)
            print('----The rules are installed on SWITCH inside IP-RuleHandlerv--')
