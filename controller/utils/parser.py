__author__ = 'gab'

import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

import ConfigParser

from model.node import Controller
from model.customer import Customer, CustomerRemote
import xml.etree.ElementTree as XmlParser


class Parser(object):
    def __init__(self, listen_port):
        self._config = ConfigParser.ConfigParser()
        # The controllers in the configuration file
        self._federazione = []
        self._vpns = {}
        self._customers = []
        self._customers_remote = []
        self._controller = None
        # The association between each customer and the datapath. It will be used for setting
        # the ryu.controller.Datapath instance when Ryu will detect that datapath.

        # This values is used for avoiding to store the information about this controller
        # Being all controllers on localhost, I can use only one (shared) configuration.
        self._listen_port = listen_port

    #    self._datapaths={}   #chiave: id datapath valore: Datapath model.node

    def get_federazione(self):
        return self._federazione

    def get_controller(self):
        return self._controller

    def get_customers(self):
        return self._customers

    def get_customers_remote(self):
        return self._customers_remote

    # def load(self, config_file):
    #     # Load the configuration file
    #     self._config.readfp(open(config_file))
    #     # Load controllers; each controller has to connect to each other in order to create
    #     # a virtual track.
    #     federazione = self._config.items('Federazione')
    #     for controller in federazione:
    #         c_name = controller[0]
    #         c_ip, public_pool = controller[1].split(',')
    #         c_port = self._listen_port
    #         c = Controller(c_name, c_ip, c_port, public_pool)
    #         # Add the new controller to the list of controllers
    #         self._federazione.append(c)
    #         # For this controller, load all customer
    #     isp = self._config.items("Controller")
    #     for provider in isp:
    #         name = provider[0]
    #         ip, pub, fitt = provider[1].split(',')
    #         self._controller = Controller(name, ip, self._listen_port, pub)
    #         self._controller.set_pool_fittizzi(fitt)
    #         self._controller.set_fittizio("192.168.1.1", "10.1.0.1")
    #         self._load_customers(self._controller)
    #         self._load_customers_remote(self._controller)

    def load(self, config_file):
        # Load the configuration file
        conf = XmlParser.parse(config_file)
        # Load controllers; each controller has to connect to each other in order to create
        # a virtual track.
        root = conf.getroot()
        isps = root.find('federation').find('isps')
        for isp in isps:
            controller = isp.find('controller')
            name = controller.attrib.get('name')
            ip = controller.attrib.get('ip')
            nat = isp.find('nat')
            public = nat.attrib.get('public')
            c_port = self._listen_port
            c = Controller(name, ip, c_port, public)
            # Add the new controller to the list of controllers
            self._federazione.append(c)
            # For this controller, load all customer
        myself = root.find('federation').find('myself')
        controller = myself.find('isp').find('controller')
        name = controller.attrib.get('name')
        ip = controller.attrib.get('ip')
        nat = myself.find('isp').find('nat')
        pub = nat.attrib.get('public')
        fitt = nat.attrib.get('fake')
        self._controller = Controller(name, ip, self._listen_port, pub)
        self._controller.set_pool_fittizzi(fitt)
        self._controller.set_fittizio("192.168.1.1", "10.1.0.1")
        self._load_federated_vpns(config_file)
        self._load_customers(self._controller, config_file)
        self._load_customers_remote(self._controller, config_file)

    # Load customers for controller identified by controller_name
    # def _load_customers(self, controller):
    #     customers = self._config.items("Customers")
    #
    #     for customer in customers:
    #         citems = customer[1].split(',')
    #         if len(citems) > 7:
    #             customer_name = customer[0]
    #             (private_ip_subnet, ingress_interface, ip_datapath, router, next_hop, name_server, out_port,
    #              datapath_to_router_ip, datapath_to_router_interface) = citems
    #             c = Customer(customer_name, private_ip_subnet, ingress_interface, ip_datapath, router, next_hop,
    #                          out_port=out_port, datapath_to_router_ip=datapath_to_router_ip,
    #                          datapath_to_router_interface=datapath_to_router_interface)
    #             if name_server != "":
    #                 print name_server + "NS"
    #                 c.set_name_server(name_server)
    #         else:
    #             customer_name = customer[0]
    #             (private_ip_subnet, ingress_interface, ip_datapath, router, next_hop, name_server) = citems
    #             c = Customer(customer_name, private_ip_subnet, ingress_interface, ip_datapath, router, next_hop)
    #             if name_server != "":
    #                 print name_server + "NS"
    #                 c.set_name_server(name_server)
    #
    #         self._customers.append(c)
    #         controller.set_customers(c)

    def _load_federated_vpns(self, config_file):
        conf = XmlParser.parse(config_file)
        root = conf.getroot()
        vpns = root.find('federation').find('vpns').findall('vpn')
        for vpn in vpns:
            self._vpns[vpn.attrib.get('id')] = []

    # Load customers for controller identified by controller_name
    def _load_customers(self, controller, config_file):
        conf = XmlParser.parse(config_file)
        root = conf.getroot()
        myself = root.find('federation').find('myself').find('isp')
        myself_id =  myself.attrib.get('id')
        vpns = root.find('federation').find('vpns')
        for vpn in vpns:
            vpn_id = vpn.attrib.get('id')
            # Take all customers in this vpn
            isps = vpn.findall('isp')
            #isp = isps[0]
            for isp in isps:
                if myself_id == isp.attrib.get('id'):
                    customers = isp.findall('customer')
                    for customer in customers:
                        c = Customer(
                            customer.attrib.get('name'),
                            customer.find('site').find('subnet').attrib.get('private_network'),
                            customer.find('site').find('datapath').attrib.get('in_port'),
                            customer.find('site').find('datapath').attrib.get('ip'),
                            customer.attrib.get('pe'),
                            customer.find('site').attrib.get('ce'),
                            #customer.attrib.get('of_port'),
                            customer.attrib.get('of_ip'),
                            out_port=customer.find('site').find('datapath').attrib.get('out_port')
                        )
                        ns_ip=customer.find('site').find('ns').attrib.get('ip')
                        if ns_ip == '':
                            ns_ip=None
                        c.set_name_server(ns_ip)
                        ns_domain=customer.find('site').find('ns').attrib.get('domain')
                        if ns_domain == '':
                            ns_domain=None
                        c.set_ns_domain_name(ns_domain)
                        # Add to the list of vpns
                        self._vpns.get(vpn_id).append(c)
                        self._customers.append(c)
                        controller.set_customers(c)

    # Load customers for controller identified by controller_name
    # def _load_customers_remote(self, controller):
    #     customers_remote = self._config.items("CustomersRemote")
    #     for customer in customers_remote:
    #         citems = customer[1].split(',')
    #         if len(citems) == 2:
    #             customer_name = customer[0]
    #             (name_server, ip) = citems
    #             c = CustomerRemote(customer_name, name_server, ip=ip)
    #         else:
    #             customer_name = customer[0]
    #             (name_server) = citems
    #             c = CustomerRemote(customer_name, name_server)
    #
    #         self._customers_remote.append(c)
    #         controller.set_customers_remote(c)

    # Load customers for controller identified by controller_name
    def _load_customers_remote(self, controller, config_file):

        conf = XmlParser.parse(config_file)
        root = conf.getroot()
        remote_isps = root.find('federation').find('isps')#.find('vpn')
        remote_isps_list = self._to_list(remote_isps)
        
        vpns = root.find('federation').find('vpns')
        for vpn in vpns:
            vpn_id = vpn.attrib.get('id')
            # Take remote customers
            isps = vpn.findall('isp')
            isps_list = self._to_list(isps)

            for isp in isps_list:
                if isp in remote_isps_list:
                    for i in isps:
                        if i.attrib.get('id') == isp:
                            customers = i.findall('customer')
                            for customer in customers:
                                c = CustomerRemote(
                                    customer.attrib.get('name'),
                                    customer.find('site').find('ns').attrib.get('domain'),
                                    ip=customer.find('site').find('ns').attrib.get('ip'),
                                )
                                # Add to the list of vpns
                                self._vpns.get(vpn_id).append(c)
                                self._customers_remote.append(c)
                                controller.set_customers_remote(c)

    def _to_list(self, to_convert):
        to_return = []
        for item in to_convert:
            item_id = item.attrib.get('id')
            to_return.append(item_id)
        return to_return


    def print_results(self):
        print 'Parser results.'
        print ' - Federation: %s' % self._federazione
        print ' - VPNs: %s' % self._vpns
        print ' - Controllers: %s' % self._controller
        print ' - Customers: %s' % self._customers
        print ' - Remote Customers: %s' % self._customers_remote
        #print ' - CustomersRemote: %s' % self._customers_remote
        #print ' - Customer -> CE: %s' % self._dp_to_customer


p = Parser(1000)
p.load('../conf/conf_c2_2vpns.xml')
p.print_results()
#print p._federazione
#print p._customers
