__author__ = 'rdl'

import sys
import os
import json

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
import communication.client as client

class Customer(object):
    def __init__(self, id, name, isp):
        self._id = id
        self._name = name
        self._sites = []
        self._isp = isp

    def set_id(self, id):
        self._id = id

    def get_id(self):
        return self._id

    def set_name(self, name):
        self._name = name

    def get_name(self):
        return self._name

    def add_site(self, site):
        self._isps.append(site)

    def get_sites(self):
        return self._sites

    def set_isp(self, isp):
        self._isp = isp

    def get_isp(self):
        return self._isp

    def send_insert(self,msg):
        c = client.Client()
        op = "INSERT"
        data = {
            'op': op,
            'msg': msg
        }
        data = json.dumps(data)

        c.send(data, '127.0.0.1', 10001)

def main():

    c = Customer("123", "cliente", "sapienza")
    msg= {
        'name':'pino',
        'subnet':'192.168.0.0',
        'of_port_dp':'1',
        'ip_dp_customer':'192.168.0.10',
        'ip_pe':'1.2.3.4',
        'customer_edge': '5.6.7.8',
        'ip_local_ns': '2.4.7.8',
        'of_port_router':'3',
        'ip_dp_pe':'7.6.5.4'
    }
    c.send_insert(msg)



main()
