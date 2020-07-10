from netaddr import *
from ryu.lib.packet import ipv4
from ryu.ofproto import ether
from ryu.ofproto.ofproto_v1_3 import OFP_NO_BUFFER
import pickle
from packet_handler import PacketHandler

__author__ = 'Andrea and Habib'

from utils.communication import Client
from utils.connection import Connection


class IpHandler(PacketHandler):
    def __init__(self, pkt, dp_to_customer, in_port, data, datapath, controller, federazione, public_to_private_a,
                 public_to_private_b):
        PacketHandler.__init__(self, pkt)
        self._pkt = pkt
        self._dp_to_customer = dp_to_customer
        self._federazione = federazione
        self._controller = controller
        self._in_port = in_port
        self._datapath = datapath
        self._data = data
        self._public_to_private_a = public_to_private_a
        self._public_to_private_b = public_to_private_b
        self._public_address_src = None
        self._public_address_dst = None
        print'----IPHandler--------'

    def handle_packet(self):

        # Divido la gestione dei pacchetti dalla porta di ingresso dello switch
        # e dalla tipologia del pacchetto VPN o Ip pubblico
        pkt_ip = self._pkt.get_protocol(ipv4.ipv4)


        print( pkt_ip.src, self._in_port , pkt_ip.dst)
        cs=self._controller.get_customers()
        print('----self._controller.get_destination_customer_nat()--',type(self._controller.get_destination_nat()))
        dst_nat=self._controller.get_destination_nat()
        #check for destination for IP traffic either to NAT or not
        for c in range(len(cs)):
            if cs[c].get_name()==dst_nat:
                index_nat=cs[c].get_next_hop_mac()
        for c in range(len(cs)):
            print('----CS[%s].private_subnet--',c, cs[c].get_private_ip_subnet())
            if IPAddress(pkt_ip.src) in IPNetwork(cs[c].get_private_ip_subnet()):
                index=c
        print'-----index from IPHandler--',index,'--self._in_port--',self._in_port,'---cs[index].get_ingress_port()--',cs[index].get_ingress_port()
        if self._in_port != cs[index].get_ingress_port() and IPAddress(self._pkt.get_protocol(ipv4.ipv4).dst).is_private() and not IPAddress(self._pkt.get_protocol(ipv4.ipv4).src).is_private():
            print'-----if 1--'
            self.from_df_gw(self._pkt)
            #self.from_cs_to_private(self._pkt)

        elif self._in_port !=cs[index].get_ingress_port()  and IPAddress(self._pkt.get_protocol(ipv4.ipv4).dst).is_private() and dst_nat is None:

            print'-----if 2--'
            self.from_cs_to_private(self._pkt)

        elif self._in_port !=cs[index].get_ingress_port()  and IPAddress(self._pkt.get_protocol(ipv4.ipv4).dst).is_private() and dst_nat is not None:

            print'-----if 2 for IP traffic within the customers inside the same ISP--'
            self.from_cs_to_private_same_isp(self._pkt)

        elif self._in_port != cs[index].get_ingress_port() and not IPAddress(self._pkt.get_protocol(ipv4.ipv4).dst).is_private():
            print'-----if 3--'
            self.from_cs_to_public(self._pkt)

        if self._in_port == cs[index].get_ingress_port() and self._pkt.get_protocol(ipv4.ipv4).src in self._public_to_private_b.keys():

            print'-----if 4--'
            self.to_cs_from_private(self._pkt)

        elif self._in_port == cs[index].get_ingress_port() and self._pkt.get_protocol(ipv4.ipv4).src not in self._public_to_private_b.keys():
            print "reply from :", self._pkt.get_protocol(ipv4.ipv4).src
            self.to_cs_from_public(self._pkt)




    #Install the rules for NATING beween the customers within the same ISP
    def from_cs_to_private_same_isp(self, pkt):
        print'----------HI from same isp------'
        ip_src = pkt.get_protocol(ipv4.ipv4).src
        ip_dst = pkt.get_protocol(ipv4.ipv4).dst


        cs=self._controller.get_customers()
        print('----',cs[0].get_ingress_port(),cs[0].get_out_port())
        for c in range(len(cs)):
            if IPAddress(ip_dst) in IPNetwork(cs[c].get_private_ip_subnet()):
                out_port=cs[c].get_ingress_port()
                index_dst=c 
        for c in range(len(cs)):
            if IPAddress(ip_src) in IPNetwork(cs[c].get_private_ip_subnet()):
                int_port=cs[c].get_ingress_port()
                index_src=c
        print('--------before the rule---------',out_port)
        ofp = self._datapath.ofproto
        parser = self._datapath.ofproto_parser

        match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, in_port=int(int_port) , ipv4_src=ip_src, ipv4_dst=ip_dst)
        actions = [parser.OFPActionSetField(eth_dst= cs[index_dst].get_next_hop_mac()), parser.OFPActionOutput(int(cs[index_dst].get_ingress_port()))]
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=self._datapath, match=match, instructions=inst, priority=90)
        self._datapath.send_msg(mod)



        match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, in_port=int(out_port) , ipv4_src=ip_dst, ipv4_dst=ip_src)
        actions = [parser.OFPActionSetField(eth_dst= cs[index_src].get_next_hop_mac()), parser.OFPActionOutput(int(cs[index_src].get_ingress_port()))]
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=self._datapath, match=match, instructions=inst, priority=90)
        self._datapath.send_msg(mod)
        self._controller.set_destination_nat(None)
        print('----The rules for NAT within customers inside the same ISP are installed on SWITCH--')



    #Install the rules for NATING beween the customers within different ISPs
    def from_cs_to_private(self, pkt):

        private_address_src = pkt.get_protocol(ipv4.ipv4).src
        ip_dst = pkt.get_protocol(ipv4.ipv4).dst

        # Verifico se la destinazione e^ un ip fittizio (indirizzamento sovrapposto)
        if ip_dst in self._controller.get_fittizio_to_private().keys():
            private_address_dst = self._controller.get_fittizio_to_private()[ip_dst]
        else:
            private_address_dst = ip_dst

        # Verifico se ho gia^ un mapping (pubblico<-->privato) per l'ip del MIO customer
        if private_address_src in self._public_to_private_a.values():

            for public, private in self._public_to_private_a.items():
                if private_address_src == private:
                    self._public_address_src = public
        else:

            ip_iterator_src = self._controller.get_public_subnet().iter_hosts()
            self._public_address_src = ip_iterator_src.next().__str__()

            # Genero un ip non in uso dal "MIO" pool per la sorgente.
            while self._public_address_src in self._public_to_private_a.keys():
                self._public_address_src = ip_iterator_src.next().__str__()

            self._public_to_private_a[self._public_address_src] = private_address_src
            # Aggiungo una rotta statica per il ip pubblico scelto per gestire il traffico di ritorno
            customer = self._dp_to_customer[self._datapath.id, str(self._in_port)]
            #connection = Connection()
            #connection.addStaticRoute(customer.get_router(),
                                      #"sudo route add -host " + self._public_address_src + " gw " + customer.get_next_hop() + " dev eth2",
                                      #self._public_address_src)




        # Verifico se ho gia^ un mapping (pubblico<-->privato) per l'ip del customer federato
        if private_address_dst in self._public_to_private_b.values():
            for public1, private1 in self._public_to_private_b.items():
                if private_address_dst == private1:
                    self._public_address_dst = public1

        else:
            # Devo individuare da quale federato (pool) devo prendere un ip per la destinazione.
            # Con l'implementazione della risoluzione dei nomi il controller sa individuare il federato a partitre dal nome.
            # Per ora so che esiste un solo federato con cui ho instaurato delle VPN ed utilizzo lui

            ip_iterator_dst = self._federazione[0].get_public_subnet().iter_hosts()
            self._public_address_dst = ip_iterator_dst.next().__str__()

            # Genero un ip non in uso dal pool di c2 per la destinazione
            while self._public_address_dst in self._public_to_private_b.keys():
                self._public_address_dst = ip_iterator_dst.next().__str__()

            self._public_to_private_b[self._public_address_dst] = private_address_dst

            # Segnalo l'associazio pubblico<-->privato
            client = Client()
            msg="binding_sep_src:" + private_address_src + ":" + self._public_address_src + ",dst:" + private_address_dst + ":" + self._public_address_dst
            print'-----MSG--',msg
            #pkt = "_sep_" + pickle.dumps(msg)
            #print'-----MSG-pickle-',pkt
            client.send_message(msg,self._federazione[0].get_ip(), self._federazione[0].get_port())

       # print "from_cs_to_private dst :", ip_dst, " src: ", private_address_src




       
        cs=self._controller.get_customers()
        for c in range(len(cs)):
            ofp = self._datapath.ofproto
            parser = self._datapath.ofproto_parser
            actions = [parser.OFPActionSetField(ipv4_src=self._public_address_src), parser.OFPActionSetField(eth_dst= cs[c].get_as_pe_mac()) ,parser.OFPActionSetField(ipv4_dst=self._public_address_dst), parser.OFPActionOutput(int(cs[c].get_out_port()))]
            out = parser.OFPPacketOut(datapath=self._datapath, data=self._data, in_port=self._in_port, actions=actions, buffer_id=OFP_NO_BUFFER)
            self._datapath.send_msg(out)

            #Inserisco un flow-entry per i pacchetti in uscita
            match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_src=private_address_src, ipv4_dst=ip_dst)
            actions = [parser.OFPActionSetField(ipv4_src=self._public_address_src),parser.OFPActionSetField(eth_dst= cs[c].get_as_pe_mac()),parser.OFPActionSetField(ipv4_dst=self._public_address_dst), parser.OFPActionOutput(int(cs[c].get_out_port()))]
            inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
            mod = parser.OFPFlowMod(datapath=self._datapath, match=match, instructions=inst, priority=200)
            self._datapath.send_msg(mod)

            print'--------cs[c].get_out_port()------',cs[c].get_out_port()
            # Inserisco una flow-entry per i pacchetti in entrata

            # Verifico la porta di uscita del datapath in funzione della subnet privata dei miei customer
            # Assunzione: customer sotto lo stesso datapath devono avere subnet private differenti

        for c in range(len(cs)):
            if IPAddress(private_address_src) in IPNetwork(cs[c].get_private_ip_subnet()):
                cindex=c
        print('---cindex--',cindex)
        pool=self._controller.get_pool_fittizio()
        ip=IPNetwork(pool)
        ip_list=list(ip)
        print('--IPAddress(ip_dst)',IPAddress(ip_dst),'---cs[cindex].get_private_ip_subnet()--',cs[cindex].get_private_ip_subnet())
        #check wheather the response IP overlaps with src or not? if so, do NAT
        if IPAddress(ip_dst) in IPNetwork(cs[cindex].get_private_ip_subnet()):
            myip=list(ip_dst.split('.'))
            index=myip[-1]
            responseIP=str(ip_list[int(index)])
        else:
            responseIP=ip_dst
        print'----RESPONSE-IP---',responseIP
        for customer in self._controller.get_customers():
            if customer.get_datapath() == self._datapath and customer.get_private_ip_subnet().__contains__(IPAddress(private_address_src)):
                out_port = int(customer.get_ingress_port())
        match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_dst=self._public_address_src, ipv4_src=self._public_address_dst)
        #print('---match---',match)
        actions = [parser.OFPActionSetField(ipv4_src=responseIP), parser.OFPActionSetField(ipv4_dst=private_address_src), parser.OFPActionSetField(eth_dst= cs[cindex].get_next_hop_mac()), parser.OFPActionOutput(out_port)]
        #print('---actions---',actions)
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=self._datapath, match=match, instructions=inst, priority=200)
        self._datapath.send_msg(mod)
        print('----The rules are installed on SWITCH--')

    def to_cs_from_private(self, pkt):

        public_address_dst = pkt.get_protocol(ipv4.ipv4).dst
        public_address_src = pkt.get_protocol(ipv4.ipv4).src

        private_address_dst = self._public_to_private_a[public_address_dst]
        private_address_src = self._public_to_private_b[public_address_src]

        if private_address_src == private_address_dst:
            for fittizio, private in self._controller.get_fittizio_to_private().items():
                if private == private_address_src:
                    private_address_src = fittizio

        for customer in self._controller.get_customers():
            if customer.get_datapath() == self._datapath and customer.get_private_ip_subnet().__contains__(
                    IPAddress(private_address_dst)):
                out_port = int(customer.get_ingress_port())

        ofp = self._datapath.ofproto
        parser = self._datapath.ofproto_parser

        actions = [
            parser.OFPActionSetField(ipv4_src=private_address_src),
            parser.OFPActionSetField(ipv4_dst=private_address_dst),
            parser.OFPActionOutput(out_port)
        ]
        out = parser.OFPPacketOut(datapath=self._datapath, data=self._data, in_port=self._in_port, actions=actions,
                                  buffer_id=OFP_NO_BUFFER)
        self._datapath.send_msg(out)

    def from_cs_to_public(self, pkt):
        private_address_src = pkt.get_protocol(ipv4.ipv4).src
        pkt_ip=pkt.get_protocol(ipv4.ipv4)
        cs=self._controller.get_customers()
        for c in range(len(cs)):
            if IPAddress(pkt_ip.src) in IPNetwork(cs[c].get_private_ip_subnet()):
                index=c

        if private_address_src in self._public_to_private_a.values():
            for public, private in self._public_to_private_a.items():
                if private_address_src == private:
                    self._public_address_src = public
        else:

            ip_iterator_src = self._controller.get_public_subnet().iter_hosts()
            self._public_address_src = ip_iterator_src.next().__str__()

            # Genero un ip non in uso dal "MIO" pool per la sorgente.    DA VERIFICARE IL PUNTATORE SU IP_ITERATOR!!!!
            while self._public_address_src in self._public_to_private_a.keys():
                self._public_address_src = ip_iterator_src.next().__str__()

            self._public_to_private_a[self._public_address_src] = private_address_src
            customer = self._dp_to_customer[self._datapath.id, str(self._in_port)]
            #connection = Connection()
            #connection.addStaticRoute(customer.get_router(),
                                      #"sudo route add -host " + self._public_address_src + " gw " + customer.get_next_hop() + " dev eth2",
                                      #self._public_address_src)
        ofp = self._datapath.ofproto
        parser = self._datapath.ofproto_parser
        print'-----Before installing the rule in IP Handler--if 3  customer index',index,cs[index].get_as_pe_mac(),self._public_address_src,cs[index].get_out_port()
        actions = [parser.OFPActionSetField(eth_dst= cs[index].get_as_pe_mac()),parser.OFPActionSetField(ipv4_src=self._public_address_src),parser.OFPActionOutput(int(cs[index].get_out_port()))]
        #print('------before out---',self._in_port,self._datapath,self._data)
        out = parser.OFPPacketOut(datapath=self._datapath, data=self._data, in_port=self._in_port, actions=actions, buffer_id=OFP_NO_BUFFER)
        #print('------out if 3---',out)
        self._datapath.send_msg(out)
        print'-----if 3 DONE--,index',index, '--pe-mac--',cs[index].get_as_pe__mac()
        #print('-----A rule in IP Handler installed--',out)

    def from_df_gw(self, pkt):
        ip_dst = pkt.get_protocol(ipv4.ipv4).dst
        ip_src = pkt.get_protocol(ipv4.ipv4).src
        cs=self._controller.get_customer()
        for c in range(len(cs)):
            if IPAddress(ip_src) in IPNetwork(cs[c].get_private_ip_subnet()):
                index=c
        out_port=int(cs[index].get_out_port())
        if ip_dst in self._controller.get_fittizio_to_private().keys():
            private_address_dst = self._controller.get_fittizio_to_private()[ip_dst]
        else:
            private_address_dst = ip_dst

        for public, private in self._public_to_private_b.items():
            if private_address_dst == private:
                self._public_address_dst = public

        ofp = self._datapath.ofproto
        parser = self._datapath.ofproto_parser
        actions = [
            parser.OFPActionSetField(ipv4_dst=self._public_address_dst),
            parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(datapath=self._datapath, data=self._data, in_port=self._in_port, actions=actions,
                                  buffer_id=OFP_NO_BUFFER)
        self._datapath.send_msg(out)
        print'------from_df_gw-----DONE-----'


    def to_cs_from_public(self, pkt):

        public_address_dst = pkt.get_protocol(ipv4.ipv4).dst
        print('-----to-cs_from_public--',self._public_to_private_a,'-----public_address_dst--',public_address_dst)
        private_address_dst = self._public_to_private_a[public_address_dst]
        
        print "dst :", private_address_dst
        for customer in self._controller.get_customers():
            if customer.get_datapath() == self._datapath and customer.get_private_ip_subnet().__contains__(
                    IPAddress(private_address_dst)):
                out_port = int(customer.get_ingress_port())

        ofp = self._datapath.ofproto
        parser = self._datapath.ofproto_parser

        actions = [
            parser.OFPActionSetField(ipv4_dst=private_address_dst),
            parser.OFPActionOutput(out_port)
        ]
        out = parser.OFPPacketOut(datapath=self._datapath, data=self._data, in_port=self._in_port, actions=actions,
                                  buffer_id=OFP_NO_BUFFER)

        self._datapath.send_msg(out)

    def request_stats(self, datapath):
        print 'send stats request: %016x', datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)
