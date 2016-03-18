import tls
import socket
import elliptic_curves as ec
import eccalgo as ecc
import sys
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import data
from tests import  singletest

function = sys.argv[1]


class SimpleByteStr(data.DataElemVector):
	def __init__(self, v=None):
		if v:
			super().__init__(1, 512, 0, v)
		else:
			super().__init__(1, 512, 0)


# Structures de données nécessaires
class MsgPublicKey(data.DataStruct):
	def __init__(self, entity: ecc.ECEntity=None):
		if entity:
			pkx = data.DataElemVector(1, 1024, 0, bytes(entity.pubkey[0]))
			pky = data.DataElemVector(1, 1024, 0, bytes(entity.pubkey[1]))
		else:
			pkx = data.DataElemVector(1, 1024, 0)
			pky = data.DataElemVector(1, 1024, 0)
		super().__init__((pkx, pky), ('pkx', 'pky'))

	def pubkey(self):
		return bytes(self.pkx.value), bytes(self.pky.value)


class MsgSession(data.DataStruct):
	def __init__(self):
		# Si quit est à 1, on quitte
		super().__init__((data.Uint8(0), data.DataElemVector(1, 1024)), ('quit', 'm'))


def scripttests():
	testcurve = ec.nistCurves[0]
	e1 = ecc.ECEntity(testcurve)
	e2 = ecc.ECEntity(testcurve)
	m1 = MsgPublicKey(e1)
	m2 = MsgPublicKey()
	m2.read(bytes(m1))
	pk1 = m2.pubkey()
	m1 = MsgPublicKey(e2)
	m2.read(bytes(m1))
	pk2 = m2.pubkey()
	singletest('pk1 == e1.pubkey', pk1=pk1, e1=e1)
	singletest('pk2 == e2.pubkey', pk2=pk2, e2=e2)
	singletest('e1.sharedsecret(e2.pubkey) == e2.sharedsecret(e1.pubkey)', e1=e1, e2=e2)
	singletest('e1.sharedsecret(pk2) == e2.sharedsecret(pk1)', e1=e1, e2=e2, pk1=pk1, pk2=pk2)

if function == 'test' or function == 'tests':
	print('Début des tests')
	ec.fieldtests()
	ec.curvetests()
	ecc.ecdhtests()
	ecc.ecdsatests()
	data.datatests()
	scripttests()
	print('Fin des tests')
	exit()

curve = ec.nistCurves[0]


class ComEntity:
	defaultport = 14140

	def __init__(self, host=socket.gethostname(), port=defaultport):
		# Partie réseau
		self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.host = host
		self.port = port
		self.netobj = self.s

		# Partie courbes elliptiques
		self.ece = ecc.ECEntity(curve)

		# Partie crypto
		self.otherpk = None
		self.mastersecret = None

	def sendpubkey(self):
		pkobj = MsgPublicKey(self.ece)
		self.netobj.sendall(bytes(pkobj))

	def recpubkey(self):
		pkobj = MsgPublicKey()
		rbytes = self.netobj.recv(4096)
		pkobj.read(rbytes)
		self.otherpk = (pkobj.pkx.value, pkobj.pky.value)
		self.mastersecret = self.ece.sharedsecret(self.otherpk)

	def close(self):
		print('Closing connection')
		if self.s:
			self.s.close()


class Client(ComEntity):
	def connect(self):
		self.s.connect((self.host, self.port))
		print('Connected')

	def loop(self):
		aescipher = AES.new(self.mastersecret[:32], AES.MODE_CFB, self.mastersecret[:AES.block_size])
		loop_continue = True
		while loop_continue:
			msg = MsgSession()
			try:
				text = input('> ')
				if text == '' or text == '\0':
					msg.quit = data.Uint8(1)
					self.s.sendall(bytes(msg))
					break
				else:
					textb = text.encode('UTF-8')

					cipherb = aescipher.encrypt(textb)
					msg.m.setvalue(cipherb)
					self.s.sendall(bytes(msg))
			except EOFError:
				msg.quit = data.Uint8(1)
				self.s.sendall(bytes(msg))
				break


class Server(ComEntity):
	def __init__(self, host=socket.gethostname(), port=ComEntity.defaultport):
		super().__init__(host, port)
		self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.c = None
		self.raddr = None

	def connect(self):
		self.s.bind((self.host, self.port))
		print('Hosting on ' + str(self.host) + ':' + str(self.port))
		self.s.listen(0)
		# On ne fait qu'une seule connection ici
		self.c, self.raddr = self.s.accept()
		self.netobj = self.c
		print('Connected to ', self.raddr)

	def loop(self):
		aescipher = AES.new(self.mastersecret[:32], AES.MODE_CFB, self.mastersecret[:AES.block_size])
		loop_continue = True
		while loop_continue:
			msg = MsgSession()
			msg.read(self.c.recv(4096))
			if int(msg.quit) > 0:
				loop_continue = False
			else:
				textstr = aescipher.decrypt(bytes(msg.m.value)).decode('UTF-8')
				print("→ " + textstr)

	def close(self):
		if self.c:
			self.c.close()
		super().close()


if function == 'client':
	client = Client()
	try:
		client.connect()
		client.sendpubkey()
		client.recpubkey()
		client.loop()
	finally:
		client.close()
	exit()

if function == 'server':
	server = Server()
	try:
		server.connect()
		server.recpubkey()
		server.sendpubkey()
		server.loop()
	finally:
		server.close()
	exit()
