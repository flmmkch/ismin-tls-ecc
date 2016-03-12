#!/usr/bin/python3

# Just using the random module isn't enough
# Use SystemRandom() for a cryptographically secure RNG

from random import SystemRandom as SR
import struct

# TLS 1.2

from enum import Enum

import math

class DataElem:
	defaultvalue = 0
	order = 'big'

	def __init__(self, length, value=defaultvalue):
		# length in bytes
		self.length = length
		self.value = value

	def read(self, newvalue):
		if isinstance(newvalue, DataElem):
			self.value = newvalue.value[:self.length]
		else:
			self.value = bytes(newvalue)[:self.length]
		# return the number of bytes read
		return self.length

	def to_bytes(self):
		if isinstance(self.value, bytes):
			return self.value[:self.length]
		return self.value.to_bytes(self.length, byteorder=DataElem.order)


class DataArray(DataElem):
	def __init__(self, size, elemlength):
		self.size = size
		self.value = (DataElem(elemlength),) * self.size

	def read(self, newvalue):
		i = 0
		for elem in range(self.size):
			bytesread = self.value[elem].read(newvalue[i:])
			i += bytesread
		return i

	def to_bytes(self):
		s = b''
		for elem in range(self.size):
			s += self.value[s].to_bytes()
		return s


class DataStruct(DataElem):
	def __init__(self, elements, elemnames=()):
		self.value = tuple(elements)
		self.elemnames = tuple(elemnames)
		for i in range(len(self.elemnames)):
			setattr(self, elemnames[i], self.value[i])

	def read(self, newvalue):
		i = 0
		for elem in self.value:
			i += elem.read(newvalue[i:])
		return i

	def to_bytes(self):
		s = b''
		for elem in self.value:
			s += elem.to_bytes()
		return s


def nbytes(e):
	if e == 0:
		return 1
	return int(math.ceil(e.bit_length() / 8))


class DataVector(DataElem):
	def __init__(self, dtype, ceiling, floor=0):
		assert(issubclass(dtype, DataElem))
		self.ceiling = ceiling
		self.floor = floor
		self.dtype = dtype
		self.sizerange = ceiling - floor
		self.size = 0
		self.value = []

	def read(self, newvalue):
		i = 0
		# first read the size
		i += nbytes(self.sizerange)
		self.size = self.floor + int.from_bytes(newvalue[:i], byteorder=DataElem.order)
		# then read the elements
		self.value = []
		for elem in range(self.size):
			elem = self.dtype()
			i += elem.read(newvalue[i:])
			self.value.append(elem)
		return i

	def to_bytes(self):
		s = b''
		# first write the size
		s += (self.size - self.floor).to_bytes(nbytes(self.sizerange), byteorder=DataElem.order)
		# then write the elements
		for elem in range(self.size):
			s += elem.to_bytes()
		return s


class Common:
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
		# What's in a clientHello:
		# - ProtocolVersion
		# - Random {uint32 unix_time, byte[28] random_bytes}
		# - SessionID
		# - CipherSuite cipher_suites
		# - CompressionMethod compression_methods
		# - Extension extension


class ConnectionEnd(Enum):
	server = 0
	client = 1


class PRFAlgorithm(Enum):
	tls_prf_sha256 = 0


class PRFAlgorithm(Enum):
	tls_prf_sha256 = 0


class BulkCipherAlgorithm(Enum):
	null = 0
	rc4 = 1
	tripledes = 2
	aes = 3


class CipherType(Enum):
	stream = 0
	block = 1
	aead = 2


class MACAlgorithm(Enum):
	null = 0
	hmac_md5 = 1
	hmac_sha1 = 2
	hmac_sha256 = 3
	hmac_sha384 = 4
	hmac_sha512 = 5


class CompressionMethod(Enum):
	null = 0


# cf. RFC 5246 p. 18
class ConnectionState:
	def __init__(self, connectionend):
		assert(isinstance(connectionend, ConnectionEnd))
		self.connectionEnd = connectionend
		self.PRFalgo = PRFAlgorithm()  # cf. RFC 5246 p. 16
		self.cipherType = CipherType()
		self.blockCipher = BulkCipherAlgorithm()
		self.enc_key_length = 0  # uint8
		self.block_length = 0  # uint8
		self.fixed_iv_length = 0  # uint8
		self.record_iv_length = 0  # uint8
		self.MACalgo = MACAlgorithm()
		self.mac_length = 0  # uint8
		self.mac_key_length = 0  # uint8
		self.compressionalgo = CompressionMethod()  # idem ^
		self.masterSecret = b''  # secret partagé de 48 octets
		self.clientRandom = b''  # fourni par le client
		self.serverRandom = b''  # fourni par le serveur


class Uint8(DataElem):
	def __init__(self, value=0):
		super().__init__(1, value)


class Uint16(DataElem):
	def __init__(self, value=0):
		super().__init__(2, value)


class Uint24(DataElem):
	def __init__(self, value=0):
		super().__init__(3, value)


class Uint32(DataElem):
	def __init__(self, value=0):
		super().__init__(4, value)


class Uint64(DataElem):
	def __init__(self, value=0):
		super().__init__(8, value)


class Opaque(DataArray):
	def __init__(self, size=1):
		super().__init__(1, size)


class ProtocolVersion(DataStruct):
	def __init__(self):
		super().__init__((Uint8(), Uint8()), ('major', 'minor'))
		# default: TLS 1.2
		# TLS 1.2 → (3, 3)
		self.major.value = 3
		self.minor.value = 3


class RecordContentType(DataElem):
	change_cipher_spec = 20
	alert = 21
	handshake = 22
	application_data = 23

	def __init__(self, value=None):
		super().__init__(1)
		if value:
			self.value = value


class TLSPlainText(DataStruct):
	def __init__(self, length):
		super().__init__((RecordContentType(), ProtocolVersion(), Uint16(length), Opaque(length)),
						('type', 'version', 'length', 'fragment'))


class TLSCompressed(DataStruct):
	def __init__(self, length):
		super().__init__((RecordContentType(), ProtocolVersion(), Uint16(length), Opaque(length)),
						('type', 'version', 'length', 'fragment'))


class TLSCipherText(DataStruct):
	def __init__(self, length):
		super().__init__((RecordContentType(), ProtocolVersion(), Uint16(length), Opaque(length)),
						('type', 'version', 'length', 'fragment'))

#class RecordLayerMsg(DataArray):


class Client:
	def __init__(self, hostname='localhost', portnumber=8034):
		self.hostname = hostname
		self.portnumber = portnumber
		self.state = ConnectionState(ConnectionEnd.client)
