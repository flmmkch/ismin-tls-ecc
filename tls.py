#!/usr/bin/python3

# Just using the random module isn't enough
# Use SystemRandom() for a cryptographically secure RNG

# TLS 1.2

import os
import time
import math
from tests import singletest

class DataElem:
	defaultvalue = 0
	order = 'big'

	def __init__(self, arg, value=defaultvalue):
		if isinstance(arg, int):
			# arg is the length in bytes
			self.length = arg
			self.value = value
		elif isinstance(arg, bytes):
			self.length = len(arg)
			self.value = arg

	def read(self, newvalue):
		if isinstance(newvalue, DataElem):
			self.value = newvalue.value[:self.length]
		else:
			self.value = bytes(newvalue)[:self.length]
		# return the number of bytes read
		return self.length

	def to_bytes(self):
		# Ne retourner que le nombre d'octets donné
		if isinstance(self.value, bytes):
			if len(self.value) < self.length:
				return self.value + b'\x00' * (self.length - len(self.value))  # padding (en big endian)
			# sinon, on retourne le bon nombre
			return self.value[:self.length]
		elif isinstance(self.value, int):
			return self.value.to_bytes(self.length, byteorder=DataElem.order)

	def __bytes__(self):
		return self.to_bytes()

	def __eq__(self, other):
		s = self.to_bytes()
		if isinstance(other, DataElem):
			return s == other.to_bytes()
		elif isinstance(other, bytes):
			return s == other
		elif isinstance(other, int):
			return s == int.from_bytes(s, byteorder=DataElem.order)

	def size(self):
		return self.length


class DataArray(DataElem):
	def __init__(self, size, elemlength):
		self.arraysize = size
		self.value = (DataElem(elemlength),) * self.arraysize

	def read(self, newvalue):
		i = 0
		for elem in range(self.arraysize):
			bytesread = self.value[elem].read(newvalue[i:])
			i += bytesread
		return i

	def to_bytes(self):
		s = b''
		for elem in range(self.arraysize):
			s += self.value[elem].to_bytes()
		return s

	def size(self):
		s = 0
		for elem in self.value:
			s += elem.size()
		return s


class DataStruct(DataElem):
	def __init__(self, elements, elemnames=()):
		object.__setattr__(self, 'elemnames', tuple(elemnames))
		object.__setattr__(self, 'value', tuple(elements))

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

	def size(self):
		s = 0
		for elem in self.value:
			s += elem.size()
		return s

	def __getattr__(self, item):
		if item in self.elemnames:
			index = self.elemnames.index(item)
			return self.value[index]
		else:
			return object.__getattr__(self, item)

	def __setattr__(self, key, value):
		if key in self.elemnames:
			index = self.elemnames.index(key)
			self.value = self.value[:index] + (value, ) + self.value[index+1:]
		else:
			object.__setattr__(self, key, value)


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
		self.vectsize = 0
		self.value = []

	def read(self, newvalue):
		i = 0
		# first read the size
		i += nbytes(self.sizerange)
		self.vectsize = self.floor + int.from_bytes(newvalue[:i], byteorder=DataElem.order)
		# then read the elements
		self.value = []
		for elem in range(self.vectsize):
			elem = self.dtype()
			i += elem.read(newvalue[i:])
			self.value.append(elem)
		return i

	def to_bytes(self):
		s = b''
		# first write the size
		s += (self.vectsize - self.floor).to_bytes(nbytes(self.sizerange), byteorder=DataElem.order)
		# then write the elements
		for elem in range(self.vectsize):
			s += self.value[elem].to_bytes()
		return s

	def size(self):
		s = nbytes(self.sizerange)
		for elem in self.value:
			s += elem.size()
		return s


class Uint(DataElem):
	def __init__(self, size, value=0):
		super().__init__(size, value)

	def __int__(self):
		if isinstance(self.value, int):
			return self.value
		return int.from_bytes(bytes(self.value), byteorder=DataElem.order, signed=False)


class Uint8(Uint):
	def __init__(self, value=0):
		super().__init__(1, value)


class Uint16(Uint):
	def __init__(self, value=0):
		super().__init__(2, value)


class Uint24(Uint):
	def __init__(self, value=0):
		super().__init__(3, value)


class Uint32(Uint):
	def __init__(self, value=0):
		super().__init__(4, value)


class Uint64(Uint):
	def __init__(self, value=0):
		super().__init__(8, value)


class Opaque(DataArray):
	def __init__(self, arg=1):
		if isinstance(arg, int):  # arg represents the size of the byte array to initiate
			super().__init__(1, arg)
		elif isinstance(arg, bytes):  # arg is the initial byte array
			size = len(arg)
			super().__init__(1, size)
			self.read(arg)


class ConnectionEnd(Uint8):
	server = 0
	client = 1


class PRFAlgorithm(Uint8):
	tls_prf_sha256 = 0


class PRFAlgorithm(Uint8):
	tls_prf_sha256 = 0


class BulkCipherAlgorithm(Uint8):
	null = 0
	rc4 = 1
	tripledes = 2
	aes = 3


class CipherType(Uint8):
	stream = 0
	block = 1
	aead = 2


class MACAlgorithm(Uint8):
	null = 0
	hmac_md5 = 1
	hmac_sha1 = 2
	hmac_sha256 = 3
	hmac_sha384 = 4
	hmac_sha512 = 5


class CompressionMethod(Uint8):
	null = 0


class HashAlgorithm(Uint8):
	null = 0
	md5 = 1
	sha1 = 2
	sha224 = 3
	sha256 = 4
	sha384 = 5
	sha512 = 6


class SignatureAlgorithm(Uint8):
	anonymous = 0
	rsa = 1
	dsa = 2
	ecdsa = 3


class SignatureAndHashAlgorithm(DataStruct):
	def __init__(self, hashval=HashAlgorithm.null, sigval=SignatureAlgorithm.anonymous):
		super().__init__((HashAlgorithm(hashval), SignatureAlgorithm(sigval)), ('hash', 'signature'))


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


class Entity:
	def __init__(self, cend):
		self.state = ConnectionState(cend)


class Client(Entity):
	def __init__(self):
		super().__init__(ConnectionEnd(ConnectionEnd.client))


class Server(Entity):
	def __init__(self):
		super().__init__(ConnectionEnd(ConnectionEnd.server))


# Data structure for cryptographic attributes

class DigitallySigned(DataStruct):
	def __init__(self):
		super().__init__((SignatureAndHashAlgorithm(), DataVector(Uint8, (2**16-1))), ('algorithm', 'signature'))


# TLS data structures
class ProtocolVersion(DataStruct):
	def __init__(self, major, minor):
		super().__init__((Uint8(), Uint8()), ('major', 'minor'))
		# default: TLS 1.2
		# TLS 1.2 → (3, 3)
		self.major.value = major
		self.minor.value = minor


# TLS extension description
class ExtensionType(Uint16):
	signature_algorithms = 13


class Extension(DataStruct):
	# TODO: initialisation avec les données de l'extension
	def __init__(self):
		extension_data = DataVector(Uint8, 2**16-1)
		super().__init__((ExtensionType(), extension_data), ('extension_type', 'extension_data'))


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
	def __init__(self, arg):
		if isinstance(arg, bytes):
			length = len(arg)
			fragment = Opaque(length)
			fragment.read(arg)
		elif isinstance(arg, DataElem):
			length = DataElem.size()
			fragment = arg
		super().__init__((RecordContentType(), ProtocolVersion(), Uint16(length), fragment),
						('type', 'version', 'length', 'fragment'))


class TLSCompressed(DataStruct):
	def __init__(self, arg):
		if isinstance(arg, bytes):
			length = len(arg)
			fragment = Opaque(length)
			fragment.read(arg)
		elif isinstance(arg, DataElem):
			length = DataElem.size()
			fragment = arg
		super().__init__((RecordContentType(), ProtocolVersion(), Uint16(length), fragment),
						('type', 'version', 'length', 'fragment'))


# Classes de cipher: a corriger au niveau des structures de données cryptographiques...
class GenericStreamCipher(DataStruct):
	def __init__(self, content: DataElem, entity: Entity):
		super().__init__((content, Opaque(entity.state.mac_length)),
						('content', 'MAC'))


class GenericBlockCipher(DataStruct):
	def __init__(self, content: DataElem, entity: Entity):
		super().__init__((Opaque(entity.state.record_iv_length), content, DataArray(entity.state.mac_length, 1),
																				Uint8()),
						('IV', 'content', 'MAC', 'padding', 'padding_length'))


class GenericAEADCipher(DataStruct):
	def __init__(self, content: DataElem, entity: Entity):
		super().__init__((Opaque(entity.state.record_iv_length), content),
						('nonce_explicit', 'content'))


class TLSCipherText(DataStruct):
	def __init__(self, arg, entity: Entity):
		if isinstance(arg, bytes):
			length = len(arg)
			fragment = Opaque(length)
			fragment.read(arg)
		elif isinstance(arg, DataElem):
			length = arg.size()
			fragment = arg
		if entity.state.cipherType == CipherType.stream:
			fragment = GenericStreamCipher(fragment, entity)
		elif entity.state.cipherType == CipherType.block:
			fragment = GenericBlockCipher(fragment, entity)
		elif entity.state.cipherType == CipherType.aead:
			fragment = GenericAEADCipher(fragment, entity)
		else:
			raise Exception("Invalid cipher type")
		super().__init__((RecordContentType(), ProtocolVersion(), Uint16(length), fragment),
						('type', 'version', 'length', 'fragment'))


class ChangeCipherSpec(DataStruct):
	change_cipher_spec = 1

	def __init__(self):
		super().__init__((Uint8(ChangeCipherSpec.change_cipher_spec),), ('type',))


class AlertLevel(Uint8):
	warning = 1
	fatal = 2

	def __init__(self, value=warning):
		super().__init__(value)


class AlertDescription(Uint8):
	close_notify = 0
	unexpected_message = 10
	bad_record_mac = 20
	decryption_failed_RESERVED = 21
	handshake_failure = 40
	no_certificated_RESERVED = 41
	bad_certificate = 42
	unsupported_certificate = 43
	certificate_revoked = 44
	certificate_expired = 45
	certificate_unknown = 46
	illegal_parameter = 47
	unknown_ca = 48
	access_denied = 49
	decode_error = 50
	decrypt_error = 51
	export_restriction_RESERVED = 60
	protocol_version = 70
	insufficient_security = 71
	internal_error = 80
	user_canceled = 90
	no_renegotiation = 100
	unsupported_extension = 110

	def __init__(self, value=internal_error):
		super().__init__(value)


class Alert(DataStruct):
	def __init__(self, level=AlertLevel.warning, description=AlertDescription.internal_error):
		super().__init__((AlertLevel(level), AlertDescription(description)), ('level', 'description'))


class RandomStruct(DataStruct):
	def __init__(self, gut=0, randb=(b'\x00' * 28)):
		super().__init__((Uint32(gut), Opaque(28)), ('gmt_unix_time', 'random_bytes'))
		self.random_bytes.read(randb)

	@staticmethod
	def generate():
		gut = int(time.time())
		randb = os.urandom(28)
		return RandomStruct(gut, randb)


class SessionID(DataVector):
	def __init__(self):
		super().__init__(Uint8, 32)


class HandshakeType(Uint8):
	hello_request = 0
	client_hello = 1
	server_hello = 2
	certificate = 11
	server_key_exchange = 12
	certificate_request = 13
	server_hello_done = 14
	certificate_verify = 15
	client_key_exchange = 16
	finished = 20

	def __init__(self, value=hello_request):
		super().__init__(value)


class CipherSuite(DataElem):
	def __init__(self, val=b'\x00\x00'):
		super().__init__(2, val)

# default cipher suites
# See RFC 5246 A. 5. (p. 75)

# TLS_NULL_WITH_NULL is the initial state of a TLS connection during the first handshake on that channel,
# but it must not be negotiated, as it provides no protection
TLS_NULL_WITH_NULL = CipherSuite(b'\x00\x00')

# The following defintions require that the server provide an RSA certificate that can be used for key excahnge
TLS_RSA_WITH_NULL_SHA = CipherSuite(b'\x00\x02')
TLS_RSA_WITH_NULL_SHA256 = CipherSuite(b'\x00\x3B')
TLS_NULL_WITH_RC4_128_MD5 = CipherSuite(b'\x00\x04')
TLS_NULL_WITH_RC4_128_SHA = CipherSuite(b'\x00\x05')
TLS_NULL_WITH_3DES_EDE_CBC_SHA = CipherSuite(b'\x00\x0A')
TLS_NULL_WITH_AES_128_CBC_SHA = CipherSuite(b'\x00\x2F')
TLS_NULL_WITH_AES_256_CBC_SHA = CipherSuite(b'\x00\x35')
TLS_NULL_WITH_AES_128_CBC_SHA256 = CipherSuite(b'\x00\x3C')
TLS_NULL_WITH_AES_256_CBC_SHA256 = CipherSuite(b'\x00\x3D')

# The following definitions are used for server-authenticated (and optionally client-authenticated) Diffie-Hellman.
TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA = CipherSuite(b'\x00\x0D')
TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA = CipherSuite(b'\x00\x10')
TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA = CipherSuite(b'\x00\x13')
TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA = CipherSuite(b'\x00\x16')
TLS_DH_DSS_WITH_AES_128_CBC_SHA = CipherSuite(b'\x00\x30')
TLS_DH_RSA_WITH_AES_128_CBC_SHA = CipherSuite(b'\x00\x31')
TLS_DHE_DSS_WITH_AES_128_CBC_SHA = CipherSuite(b'\x00\x32')
TLS_DHE_RSA_WITH_AES_128_CBC_SHA = CipherSuite(b'\x00\x33')
TLS_DH_DSS_WITH_AES_256_CBC_SHA = CipherSuite(b'\x00\x36')
TLS_DH_RSA_WITH_AES_256_CBC_SHA = CipherSuite(b'\x00\x37')
TLS_DHE_DSS_WITH_AES_256_CBC_SHA = CipherSuite(b'\x00\x38')
TLS_DHE_RSA_WITH_AES_256_CBC_SHA = CipherSuite(b'\x00\x39')
TLS_DH_DSS_WITH_AES_128_CBC_SHA256 = CipherSuite(b'\x00\x3E')
TLS_DH_RSA_WITH_AES_128_CBC_SHA256 = CipherSuite(b'\x00\x3F')
TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 = CipherSuite(b'\x00\x40')
TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = CipherSuite(b'\x00\x67')
TLS_DH_DSS_WITH_AES_256_CBC_SHA256 = CipherSuite(b'\x00\x68')
TLS_DH_RSA_WITH_AES_256_CBC_SHA256 = CipherSuite(b'\x00\x69')
TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 = CipherSuite(b'\x00\x6A')
TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = CipherSuite(b'\x00\x6B')

# The following definitions are used for completely anonymous Diffie-Hellman communications in which neither party is
# authenticated
TLS_DH_anon_WITH_RC4_128_MD5 = CipherSuite(b'\x00\x18')
TLS_DH_anon_WITH_3DES_EDE_CBC_SHA = CipherSuite(b'\x00\x1B')
TLS_DH_anon_WITH_AES_128_CBC_SHA = CipherSuite(b'\x00\x34')
TLS_DH_anon_WITH_AES_256_CBC_SHA = CipherSuite(b'\x00\x3A')
TLS_DH_anon_WITH_AES_128_CBC_SHA256 = CipherSuite(b'\x00\x6C')
TLS_DH_anon_WITH_AES_256_CBC_SHA256 = CipherSuite(b'\x00\x6D')

class HelloRequest(DataStruct):
	def __init__(self):
		super().__init__(())  # structure vide (cf RFC5246, p. 39)


class ClientHello(DataStruct):
	def __init__(self, entity):
		ciphersuites = DataVector(CipherSuite, (2**16-2), 2)
		compressionmethods = DataVector(Uint8, (2**8-1), 1)
		super().__init__((ProtocolVersion(), RandomStruct.generate(), SessionID(), ciphersuites, compressionmethods),
						('client_version', 'random', 'session_id', 'cipher_suites', 'compression_methods'))
		# TODO: cas avec les extensions
		# extensions: cf RFC p. 44


class ServerHello(Uint8):
	def __init__(self):
		ciphersuites = DataVector(CipherSuite, (2**16-2), 2)
		compressionmethods = DataVector(Uint8, (2**8-1), 1)
		super().__init__((ProtocolVersion(), RandomStruct.generate(), SessionID(), ciphersuites, compressionmethods),
						('server_version', 'random', 'session_id', 'cipher_suites', 'compression_methods'))


class Certificate(Uint8):
	def __init__(self):
		super().__init__(0)


class ServerKeyExchange(Uint8):
	def __init__(self):
		super().__init__(0)


class CertificateRequest(Uint8):
	def __init__(self):
		super().__init__(0)


class ServerHelloDone(Uint8):
	def __init__(self):
		super().__init__(0)


class CertificateVerify(Uint8):
	def __init__(self):
		super().__init__(0)


class ClientKeyExchange(Uint8):
	def __init__(self):
		super().__init__(0)


class Finished(Uint8):
	def __init__(self):
		super().__init__(0)


class Handshake(DataStruct):
	def __init__(self, entity, hstype, length):
		# Placeholder: TODO
		if hstype == HandshakeType.hello_request:
			body = HelloRequest()
		elif hstype == HandshakeType.client_hello:
			body = ClientHello()
		elif hstype == HandshakeType.server_hello:
			body = ServerHello()
		elif hstype == HandshakeType.certificate:
			body = Certificate()
		elif hstype == HandshakeType.server_key_exchange:
			body = ServerKeyExchange()
		elif hstype == HandshakeType.certificate_request:
			body = CertificateRequest()
		elif hstype == HandshakeType.server_hello_done:
			body = ServerHelloDone()
		elif hstype == HandshakeType.certificate_verify:
			body = CertificateVerify()
		elif hstype == HandshakeType.client_key_exchange:
			body = ClientKeyExchange()
		elif hstype == HandshakeType.finished:
			body = Finished()
		else:
			raise Exception("Invalid handshake type")
		super().__init__((HandshakeType(hstype), Uint24(length), body),
						('msg_type', 'length', 'body'))


class Client:
	def __init__(self, hostname='localhost', portnumber=8034):
		self.hostname = hostname
		self.portnumber = portnumber
		self.state = ConnectionState(ConnectionEnd.client)


def datatests():
	test = DataStruct((DataElem(1, 3), Opaque(b'\x08BASEDGOD'), Uint32(100000)), ('kon', 'ban', 'wa'))
	singletest('t.size() == 14 and isinstance(t.value, tuple) and len(t.value) == 3', t=test)
	singletest('bytes(t) == right_value', t=test, right_value=b'\x03\x08BASEDGOD\x00\x01\x86\xa0')
	test.ban = Uint8(5)
	singletest('bytes(t) == right_value', t=test, right_value=b'\x03\x05\x00\x01\x86\xa0')
	singletest('int(t.wa.value) == right_value', t=test, right_value=100000)
	return True