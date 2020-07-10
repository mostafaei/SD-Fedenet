__author__ = 'rdl'

import socket
class Client(object):

    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def send(self,msg,address,port):

        # Connect the socket to the port where the server is listening
        self.sock.connect((address,port))

        try:

            # Send data
            self.sock.sendall(msg)



        finally:
            self.sock.close()


