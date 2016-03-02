#!/usr/bin/python3

import socket

s = socket.socket()
host = socket.gethostname()		# Get local machine name
port = 8004                		# Reserve a port for your service.
s.bind((host, port))
print('Hosting on ' + str(host) + ':' + str(port))
s.listen(0)

# On ne fait qu'une seule connection...
c, addr = s.accept()  		# Establish connection with client.
print('Connected with ', addr)
loop_continue = True
while loop_continue:
	textSizeBytes = c.recv(8)
	if textSizeBytes == (b'\x00' * 8) or textSizeBytes == b'':
		break
	else:
		textSize = int.from_bytes(textSizeBytes, byteorder='big')
		textString = c.recv(textSize).decode('UTF-8')
		print("→ " + textString)
print('Client quitted. Stopping the server...')
c.close()
s.close()
