#!/usr/bin/python3

import socket               # Import socket module

s = socket.socket()         # Create a socket object
host = socket.gethostname() # Get local machine name
port = 8004                # Reserve a port for your service.
print('Connecting on ' + str(host) + ':' + str(port))
s.connect((host, port))
loop_continue = True
while loop_continue:
	try:
		text = input('> ')
		if text == '' or text == '\0':
			loop_continue = False
			s.send(b'\x00')
		else:
			s.send(text.encode('UTF-8'))
	except EOFError:
		loop_continue = False
		s.send(b'\x00')
s.close()                     # Close the socket when done
