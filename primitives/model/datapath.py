__author__ = 'rdl'


class Datapath(object):
    def __init__(self, ip, sites):
        self._ip = ip
        self._sites = sites


    def set_ip(self, ip):
        self._ip = ip

    def get_ip(self):
        return self._ip

    def add_site(self,site):
        self._sites.append(site)

    def get_sites(self):
        return self._sites

