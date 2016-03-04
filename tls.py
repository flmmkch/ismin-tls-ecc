#!/usr/bin/python3

# Just using the random module isn't enough
# Use SystemRandom() for a cryptographically secure RNG

from random import SystemRandom as SR
import struct

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
		STRUCT_FMT_PROTOCOLVERSION = 'BB'
		STRUCT_FMT_CLIENTHELLO_RANDOM = 'I28s'
		# What's in a clientHello:
		# - ProtocolVersion
		# - Random {uint32 unix_time, byte[28] random_bytes}
		# - SessionID
		# - CipherSuite cipher_suites
		# - CompressionMethod compression_methods
		# - Extension extensions
		STRUCT_FMT_CLIENTHELLO = '!' + STRUCT_FMT_PROTOCOLVERSION + STRUCT_FMT_CLIENTHELLO_RANDOM


class client:
	def __init__(self, hostname='localhost', portnumber=8034):
		self.hostname = hostname
		self.portnumber = portnumber



