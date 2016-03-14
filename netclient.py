#!/usr/bin/python3

import socket               	# Import socket module

import elliptic_curves as ec
import eccalgo as ecc
from Crypto.Cipher import AES

curve = ec.nistCurves[0]
ecdh = ecc.ECDHInstance(curve)

s = socket.socket()         	# Create a socket object
host = socket.gethostname() 	# Get local machine name
port = 8004                		# Reserve a port for your service.
print('Connecting on ' + str(host) + ':' + str(port))
s.connect((host, port))

s.close()                    	# Close the socket when done

print('')
