#!/usr/bin/python3

import socket               	# Import socket module

s = socket.socket()         	# Create a socket object
host = socket.gethostname() 	# Get local machine name
port = 8004                		# Reserve a port for your service.
print('Connecting on ' + str(host) + ':' + str(port))
s.connect((host, port))
loop_continue = True
while loop_continue:
	try:
		text = input('> ')
		if text == '' or text == '\0':
			s.send(b'\x00' * 8)
			break
		else:
			textBytes = text.encode('UTF-8')
			sizeBytes = len(textBytes).to_bytes(8, byteorder='big')
			s.send(sizeBytes)
			s.send(textBytes)
	except EOFError:
		s.send(b'\x00')
		break
s.close()                    	# Close the socket when done

print('')
