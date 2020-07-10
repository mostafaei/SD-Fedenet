__author__ = 'rdl'


class Isp(object):
    def __init__(self, id, name, fake_net, public_net, controller):
        self._id = id
        self._name = name
        self._fake_net = fake_net
        self._public_net = public_net
        self._federations = []
        self._vpns = []
        self._controller = controller
        self._customers = []


    def set_id(self, id):
        self._id = id

    def get_id(self):
        return self._id

    def set_name(self, name):
        self._name = name

    def get_name(self):
        return self._name

    def set_fake_net(self, fake_net):
        self._fake_net = fake_net

    def get_fake_net(self):
        return self._fake_net

    def set_public_net(self, public_net):
        self._public_net = public_net

    def get_public_net(self):
        return self._public_net

    def add_federation(self, federation):
        self._federations.append(federation)

    def get_federations(self):
        return self._federations

    def add_vpn(self, vpn):
        self._vpns.append(vpn)

    def get_vpns(self):
        return self._vpns

    def set_controller(self, controller):
        self._controller = controller

    def get_controller(self):
        return self._controller

    def add_customer(self, customer):
        self._customers.append(customer)

    def get_customers(self):
        return self._customers