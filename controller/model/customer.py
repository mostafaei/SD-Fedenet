__author__ = 'gab-Habib'

from netaddr import *

"""
A customer is an object that models a subnet behind a datapath that needs to be natted in order
to reach a remote customer in another AS. Each customer is identified by a name, a private IP 
subnet, a public IP subnet (or just address) and the datapath's port connected to the rest of the 
AS.
"""


class Customer(object):
    #def __init__(self, name, private_ip_subnet , ingress_port, ip_datapath,router,next_hop,out_port,datapath_to_router_ip,datapath_to_router_interface):
    def __init__(self, name, private_ip_subnet , ingress_port, ip_datapath,router,next_hop,*args, **kwargs):
        self._ingress_port = ingress_port
        self._out_port = kwargs.get('out_port')
        self._ip_datapath = ip_datapath
        self._name_server = None
        self._datapath_to_router_ip= kwargs.get('datapath_to_router_ip')
        self._datapath_to_router_interface =kwargs.get('datapath_to_router_interface')
        self._name = name
        self._private_ip_subnet = IPNetwork(private_ip_subnet)
        self._datapath = None
        self._router = router
        self._next_hop = next_hop
        self._next_hop_mac = None
        self._as_pe_mac= None
        self._ns_domain_name=None
        #self._params=kwargs
    

    def __hash__(self):
        return hash(self.dpid)

    def __repr__(self):
        return "Customer(Name=%s, Ingress_port=%s)" % (
            self._name, self._ingress_port)

    def get_name(self):
        return self._name
    
    def get_ns_domain_name(self):
        return self._ns_domain_name

    def get_private_ip_subnet(self):
        return self._private_ip_subnet

    def set_datapath(self, datapath):
        self._datapath = datapath

    def get_datapath(self):
        return self._datapath

    def get_router(self):
        return self._router

    def get_datapath_to_router_ip(self):
        return self._datapath_to_router_ip
    
    def get_datapath_to_router_interface(self):
        return self._datapath_to_router_interface
    def set_as_pe_mac(self,mac):
        self._as_pe_mac=mac

    def get_as_pe_mac(self):
        return self._as_pe_mac

    def set_next_hop_mac(self,mac):
        self._next_hop_mac=mac

    def get_next_hop_mac(self):
        return self._next_hop_mac

    def get_next_hop(self):
        return self._next_hop

    def set_name_server(self, name_server):
        self._name_server = name_server

    def get_name_server(self):
        return self._name_server

    def get_ingress_port(self):
        return self._ingress_port

    def get_out_port(self):
        return self._out_port

    def get_ip_datapath(self):
        return self._ip_datapath


#A class for the remote customers of an ISP in a federation
#This class determines the differences between two approaches by initializing the ip filed or not.
class CustomerRemote(object):
    #def __init__(self, name, name_server,ip):
    def __init__(self, name, name_server,*args, **kwargs):
        self._name_server = name_server
        self._name = name
        ip = kwargs.get('ip')
        if ip == '':
            ip = None
        self._ip = ip

    def __repr__(self):
        return "Customer_remote(Name=%s, IP=%s)" % (
            self._name, self._ip)

    def get_name(self):
        return self._name

    def set_name_server(self, name_server):
        self._name_server = name_server

    def get_name_server(self):
        return self._name_server

    def get_ip(self):
        return self._ip

    def set_ip(self,ip):
        self._ip=ip
