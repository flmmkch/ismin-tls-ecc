#!/usr/bin/python3

class common:
		HELLO_REQUEST = b'\x00'  # server-originated initiation of the negotiation process
		CLIENT_HELLO = b'\x01'
		SERVER_HELLO = b'\x02'
		CERTIFICATE = b'\x0B'
		SERVER_KEY_EXCHANGE = b'\x0C'
		CERTIFICATE_REQUEST = b'\x0D'
		CERTIFICATE_VERIFY = b'\x0E'
		SERVER_HELLO_DONE = b'\x0F'
		CLIENT_KEY_EXCHANGE = b'\x10'
		HANDSHAKE_FINISHED = b'\x20'


class client:
	def __init__(self, hostname='localhost', portnumber=8034):
		return


