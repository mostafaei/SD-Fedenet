__author__ = 'rdl'

import socket


class Server(object):
    def __init__(self, address, port):
        self._address = address
        self._port = port
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Create a TCP/IP socket
        #self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to the port
        self._sock.bind((self._address,self._port))

    # Listen for incoming connections
        self._sock.listen(1)

    def receive(self):

        while True:
            # Wait for a connection
            connection, client_address = self._sock.accept()

            try:
                data = connection.recv(2048)
                return data
            finally:
             # Clean up the connection
                connection.close()