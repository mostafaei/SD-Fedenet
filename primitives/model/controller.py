__author__ = 'rdl'

import json
import sys
import os
import ConfigParser

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

import communication.server as server

class Controller(object):
    def __init__(self, id, name, ip, isp):
        self._id = id
        self._name = name
        self._ip = ip
        self._isp = isp
        self._config = ConfigParser.ConfigParser()

    def set_id(self, id):
        self._id = id

    def get_id(self):
        return self._id

    def set_name(self, name):
        self._name = name

    def get_name(self):
        return self._name

    def set_ip(self, ip):
        self._ip = ip

    def get_ip(self):
        return self._ip

    def set_isp(self, isp):
        self._isp = isp

    def get_isp(self):
        return self._isp

    def listen(self):

        address = "127.0.0.1"
        port = 10001
        s = server.Server(address, port)
        print 'in ascolto su 1001'
        while True:
            data = s.receive()
            print data
            op = json.loads(data)['op']
            msg = json.loads(data)['msg']

            if op == "INSERT":
                print 'insert from int'
                self.insert(msg)

    def insert(self, msg):
        cp = ConfigParser.ConfigParser()
        
        name=str(msg['name'])
        subnet=str(msg['subnet'])
        of_port_dp=str(msg['of_port_dp'])
        ip_dp_customer=str(msg['ip_dp_customer'])
        ip_pe=str(msg['ip_pe'])
        customer_edge=str(msg['customer_edge'])
        ip_local_ns=str(msg['ip_local_ns'])
        of_port_router=str(msg['of_port_router'])
        ip_dp_pe=str(msg['ip_dp_pe'])

        values = subnet+','+of_port_dp+','+ip_dp_customer+','+ip_pe+','+customer_edge+','+ip_local_ns+','+of_port_router+','+ip_dp_pe
        cp.readfp(open('../../controller/system.conf'))

        cp.set('Customers',name,values)
        with open('../../controller/system.conf', 'wb') as configfile:
            cp.write(configfile)





def main():

    c = Controller('12', 'controllore', '127.0.0.1', 'roma3')
    c.listen()

main()



