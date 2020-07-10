__author__ = 'rdl'

class Federation(object):
    def __init__(self,id , name):
        self._id = id
        self._name = name
        self._isps = []


    def set_id(self, id):
        self._id = id

    def get_id(self):
        return self._id

    def set_name(self, name):
        self._name = name

    def get_name(self):
        return self._name

    def add_isp(self,isp):
        self._isps.append(isp)

    def get_isps(self):
        return self._isps