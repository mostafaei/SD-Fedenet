from ryu.lib.packet import ipv4
from ryu.lib.packet import udp
from ryu.lib.packet import arp
from arp_handler import ArpHandler
from ip_handler import IpHandler
from dns_handler import DNSQueryHandlerAlg2, DNSResponseHandlerAlg2, DNSResponseHandlerAlg2_2, DNSQueryHandler, DNSResponseHandler, DNSQueryHandlerNS, DNSQueryHandlerGeneral
from scapy.all import DNS, DNSQR, DNSRR, dnsqtypes
import struct

__author__ = 'robertodilallo-HabibMostafaei'


class FactoryPacketHandler(object):
    __instance = None

    def __init__(self):
        self._handler = None

    @classmethod
    def get_instance(cls):
        if cls.__instance is None:
            cls.__instance = FactoryPacketHandler()
        return cls.__instance

    def create_handler(self, pkt, dp_to_customer, in_port, data, datapath, controller, federazione, public_to_private_a,
                       public_to_private_b):
        print 'publice to private a',public_to_private_a,'publice to private',public_to_private_b
        cs=controller.get_customers() 
        arp_header = pkt.get_protocol(arp.arp)
        #print('--arp---',arp_header)
        ip_header = pkt.get_protocol(ipv4.ipv4)
        udp_header = pkt.get_protocol(udp.udp)

        if arp_header is not None:
            self._handler = ArpHandler(pkt, datapath, in_port,controller) 
        elif udp_header is not None:
            #print ('------------------I am inside UDP part',udp_header.src_port)
            pport=udp_header.src_port
            #print('------pkt-------',pkt)
            dns_pkt=DNS(pkt[-1])
            #print('------DNS-pkt-Q------',dns_pkt)
            print('------DNS-pkt-Q-type-----',dns_pkt.qd.qtype)
            csR=controller.get_customers_remote()
            cr_list=[]
            cr_ns_list=[]
            for cr in range(len(csR)):
                if csR[cr].get_ip() is not None:
                    cr_list.append(csR[cr].get_ip())
                    #name=csR[cr].get_name_server()
                    #name=name.split('.')
                    #new_sub=name[1]+'.'+name[2]+'.'+name[3]+'.'
                    #print'-----name[1:]--',new_sub
                #cr_ns_list.append(new_sub)
            if len(cr_list)>=1:
                query=dns_pkt.qd.qname
                print '--calling alg1---, ',dns_pkt.qd.qname
                if dns_pkt.qr==0:
                    self._handler = DNSQueryHandler(pkt, in_port, data, datapath, controller, federazione,public_to_private_a, public_to_private_b)
                elif dns_pkt.qr==1:
                    self._handler = DNSResponseHandler(pkt, in_port, data, datapath, controller, federazione,public_to_private_a, public_to_private_b,pkt[-1])
            else:
                print '--calling alg2---'
                if dns_pkt.ancount==1:
                    print'--I have final answer--'
                    controller.set_packet_ip(ip_header.src)
                    self._handler = DNSResponseHandlerAlg2_2(pkt, in_port, data, datapath, controller, federazione,public_to_private_a, public_to_private_b,pkt[-1])
                elif dns_pkt.qr==0 and dns_pkt.qd.qtype==1:
                    self._handler = DNSQueryHandlerAlg2(pkt, in_port, data, datapath, controller, federazione,public_to_private_a, public_to_private_b)
                elif dns_pkt.qr==1:
                    #print ('--dns.id------',dns_pkt.id,'----udp_dst_port_--',udp_header.dst_port,'----udp_src_port_--',udp_header.src_port)
                    self._handler = DNSResponseHandlerAlg2(pkt, in_port, data, datapath, controller, federazione,public_to_private_a, public_to_private_b,pkt[-1])
        
        elif ip_header is not None:
            print ('------------------I am inside IP part-----------')
            
            self._handler = IpHandler(pkt, dp_to_customer, in_port, data, datapath, controller, federazione,public_to_private_a, public_to_private_b)
            #self._handler = IpHandler(pkt, dp_to_customer, in_port, data, datapath, controller, federazione,public_to_private_a,public_to_private_b)
        
        return self._handler
