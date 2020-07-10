__author__ = 'rdl'


class Ns(object):
    def __init__(self, domain, ip):
        self._domain = domain
        self._ip = ip

    def set_domain(self, domain):
        self._domain = domain

    def get_domain(self):
        return self._domain

    def set_ip(self, ip):
        self._ip = ip

    def get_ip(self):
        return self._ip
