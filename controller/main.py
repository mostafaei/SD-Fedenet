from ryu import utils
from ryu.controller import ofp_event
from ryu.lib.packet import packet

from netaddr import *
from ryu.lib.packet import udp

__author__ = 'gab'

"""
Main class for VPN controller
"""

from ryu.base import app_manager

# OpenFlow specification 1.3
from ryu.ofproto import ofproto_v1_3, ether

# To handle OpenFlow and controller events
from ryu.controller.handler import set_ev_cls, MAIN_DISPATCHER, HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER

# To handle link event
from ryu.topology import event
from ryu import cfg
# System
from system import System

#CONF = cfg.CONF
#CONF.register_cli_opts([cfg.StrOpt('federation', default='', help='Configuration file for federated networks')])

class VPNController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    app_manager.require_app('ryu.topology.switches')

    def __init__(self, *args, **kwargs):
        super(VPNController, self).__init__(self, *args, **kwargs)
        CONF = cfg.CONF
        #CONF.register_cli_opts([cfg.StrOpt('federation', default='', help='Configuration file for federated networks')])
	#Inserire --main-config + nome-file
        #print '####################################', CONF.federated
        #file =  CONF['config']['file']
        file =  CONF.federated
        #print '--------------------------____ Config file:', file
        # Start the System
        self._system = System(10000, file)
        # Load configuration (included VPNs configuration) into the system
        self._system.load_system_configuration()
        # Initialize system
        self._public_to_private_a = {} #Mapping pubblico<-->privato per i miei customer
        self._public_to_private_b = {} #Mapping pubblico<-->privato per customer federati
        self._system.init(self._public_to_private_a,self._public_to_private_b)
        self._public_ip=None

    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
        # When a switch is added, then add it to the Customer
        datapath = ev.switch.dp
        ip, port = datapath.address
       # print "switch detected: " + ip, port
        self._system.add_node(datapath, ip)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        controller=self._system.get_controller_info() 
        cs=controller.get_customers()
        csR=controller.get_customers_remote()
        cr_list=[]
        #Send IP packets to controller in order to handle STRANAT
         
        print'--private-ip-subnet-----',cs[0].get_private_ip_subnet()
        cs_port=[]
        for cp in range(len(cs)):
            if cs[cp].get_ingress_port() is not None:
                cs_port.append(cs[cp].get_out_port())
                match= parser.OFPMatch(eth_type=ether.ETH_TYPE_IP,in_port=int(cs[cp].get_ingress_port()),ipv4_src=(cs[cp].get_private_ip_subnet(),'255.255.0.0'))
                actions=[parser.OFPActionOutput(ofp.OFPP_CONTROLLER,ofp.OFPCML_NO_BUFFER)]
                self.add_flow(datapath,80 , match, actions)
        
        '''
        #A rule to change the change made by SDNS to original one-->fake private ip address to real private ip address
        #find dst fake private ip and then create the original private ip--> the opposite of SDNS
        if     
        pool=self._controller.get_pool_fittizio()
            ip=IPNetwork(pool)
            ip_list=list(ip)

 
        match_fake = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_dst=(controller.get_pool_fittizio(),'255.255.0.0'))
        actions_fake = [parser.OFPActionSetField(ipv4_dst=self._public_address_dst), parser.OFPActionOutput(int(cs[c].get_out_port()))]
        inst_fake = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions_fake)]
        mod_fake = parser.OFPFlowMod(datapath=self._datapath, match=match_fake, instructions=inst_fake, priority=200)
        self._datapath.send_msg(mod_fake)
        '''

        for cr in range(len(csR)):
            if csR[cr].get_ip() is  not None:
                cr_list.append(csR[cr].get_ip())
        print('-----------cr_list--------',cr_list)      
 
        if len(cr_list)>=1:
            #Send Arp packets to Controller --Habib
            print('-----------Rules for alg1--------')       
            match11 = parser.OFPMatch(eth_type=ether.ETH_TYPE_ARP)
            actions11=[parser.OFPActionOutput(ofp.OFPP_CONTROLLER,ofp.OFPCML_NO_BUFFER)]
            self.add_flow(datapath,90 , match11, actions11)
            
            for cp in range(len(cs)):
                #Send DNS packets to controller in order to handle them--> Habib
                match12= parser.OFPMatch(eth_type=ether.ETH_TYPE_IP,in_port=int(cs[cp].get_ingress_port()),ip_proto=17,udp_dst=53)
                actions12=[parser.OFPActionOutput(ofp.OFPP_CONTROLLER,ofp.OFPCML_NO_BUFFER)]
                self.add_flow(datapath,100 , match12, actions12)
                match13= parser.OFPMatch(eth_type=ether.ETH_TYPE_IP,in_port=int(cs[cp].get_ingress_port()),ip_proto=17,udp_src=53)
                actions13=[parser.OFPActionOutput(ofp.OFPP_CONTROLLER,ofp.OFPCML_NO_BUFFER)]
                self.add_flow(datapath,100 , match13, actions13)
	    
	        
        elif len(cr_list)==0:
            for c in range(len(cs)):
                pool=controller.get_public_subnet()
	        ip=IPNetwork(pool)            
	        ip_list=list(ip)
	        oport= cs[c].get_out_port()
	        self._public_ip=ip_list[1]
                print'---cs.get_name_server--',cs[c].get_name_server()
	        match3 = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP,ipv4_src=(cs[c].get_name_server(),'255.255.0.0'),in_port=5)
	        actions3=[parser.OFPActionSetField(ipv4_src=self._public_ip)]
	        actions3.append(parser.OFPActionOutput(port=int(oport)))
	        inst3 = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions3)]
	        mod3 = parser.OFPFlowMod(datapath=datapath, priority=0, match=match3, instructions=inst3)
	        datapath.send_msg(mod3)
	        # Send DNS packets to controller in order to handle them--> Habib
	        match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP,ip_proto=17,in_port=int(cs[c].get_ingress_port()))
	        actions=[parser.OFPActionOutput(ofp.OFPP_CONTROLLER,ofp.OFPCML_NO_BUFFER)]
	        self.add_flow(datapath,100 , match, actions)

	    #Send the recevied DNS packets to the controller
	    match4 = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP,ipv4_dst=(self._public_ip,'255.255.255.0'))
	    actions4 = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
	    inst4 = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions4)]
	    mod4 = parser.OFPFlowMod(datapath=datapath, priority=0, match=match4, instructions=inst4)
	    datapath.send_msg(mod4)

	    match = parser.OFPMatch()
	    actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
	    inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
	    mod = parser.OFPFlowMod(datapath=datapath, priority=0, match=match, instructions=inst)
	    #datapath.send_msg(mod)
	    #print "installo flow-entry per non droppare"
	     
	    #Send Arp packets to Controller --Habib
	    match1 = parser.OFPMatch(eth_type=ether.ETH_TYPE_ARP)
	    actions1=[parser.OFPActionOutput(ofp.OFPP_CONTROLLER,ofp.OFPCML_NO_BUFFER)]
	    self.add_flow(datapath,90 , match1, actions1)
    ''''
    Add flow method for DNS packets when a DNS packet received--> Habib
    '''
    def add_flow(self, datapath, priority, match, actions):
        ofproto=datapath.ofproto
        #print 'hi from add flow'
        parser=datapath.ofproto_parser
        inst=[parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod=parser.OFPFlowMod(datapath=datapath,priority=priority,match=match,instructions=inst)
        datapath.send_msg(mod)
        #print'---a rule installed-----'

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        print "a packet-in is received"
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        pkt = packet.Packet(msg.data)
        #print('------packet-in---',pkt)
        in_port = msg.match['in_port']
        self._system.handle_packet(pkt, dpid, in_port, msg.data, datapath,self._public_to_private_a,self._public_to_private_b)

    @set_ev_cls(ofp_event.EventOFPErrorMsg, [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def error_msg_handler(self, ev):
        msg = ev.msg

        self.logger.info('OFPErrorMsg received: type=0x%02x code=0x%02x '
                         'message=%s',
                         msg.type, msg.code, utils.hex_array(msg.data))
