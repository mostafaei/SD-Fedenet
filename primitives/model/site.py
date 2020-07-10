__author__ = 'rdl'


class Site(object):
    def __init__(self, id, name, subnet_private_net, ns, ip_dp, port_dp):
        self._id = id
        self._name = name
        self._subnet_private_net =subnet_private_net
        self._ns = ns
        self._ip_dp = ip_dp
        self._port_dp = port_dp

    def set_id(self, id):
        self._id = id

    def get_id(self):
        return self._id

    def set_name(self, name):
        self._name = name

    def get_name(self):
        return self._name

    def set_subnet_private_net(self, subnet_private_net):
        self._subnet_private_net = subnet_private_net

    def get_subnet_private_net(self):
        return self._subnet_private_net

    def set_ns(self,ns):
        self._ns = ns

    def get_ns(self):
        return self._ns

    def set_ip_dp(self, ip_dp):
        self._ip_dp = ip_dp

    def get_ip_dp(self):
        return self._ip_dp

    def set_port_dp(self, port_dp):
        self._port_dp = port_dp

    def get_port_dp(self):
        return self._port_dp