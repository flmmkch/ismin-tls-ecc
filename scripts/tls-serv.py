#!/usr/bin/python3

import socket

s = socket.socket()
host = socket.gethostname() # Get local machine name
port = 8004                # Reserve a port for your service.
s.bind((host, port))
print('Hosting on ' + str(host) + ':' + str(port))
s.listen()
while True:
	c, addr = s.accept() # Establish connection with client.
	print('Connected with ', addr)
	loop_continue = True
	while loop_continue:
		test = s.recv(4096)
		if test == b'\x00':
			loop_continue = False
		else:
			print(test.decode('UTF-8'))
	c.close()  
