import tls
import socket
import elliptic_curves as ec
import eccalgo as ecc
import sys
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import data
from tests import singletest

function = sys.argv[1]


class SimpleByteStr(data.DataElemVector):
	def __init__(self, v=None):
		if v:
			super().__init__(1, 2048, 0, v)
		else:
			super().__init__(1, 2048, 0)


class SignedStr(data.DataStruct):
	def __init__(self):
		signature = data.DataStruct((data.DataElemVector(1, 2048, 0), data.DataElemVector(1, 1024, 0)), ('r', 's'))
		super().__init__((SimpleByteStr(), signature), ('string', 'signature'))


class MsgRecord(data.DataStruct):
	TYPE_QUIT = 0
	TYPE_SIMPLE = 1
	TYPE_ECDSA = 2

	def __init__(self, t = TYPE_SIMPLE):
		super().__init__((data.Uint8(t), data.DataElemVector(1, 4096)), ('type', 'content'))
		self.ece = None

	def getstr(self):
		if int(self.type) == MsgRecord.TYPE_SIMPLE:
			string = SimpleByteStr()
			string.read(self.content.value)
			return bytes(string.value)
		elif int(self.type) == MsgRecord.TYPE_ECDSA:
			string = SignedStr()
			string.read(self.content.value)
			return bytes(string.string.value)

	def getsignature(self):
		if int(self.type) == MsgRecord.TYPE_ECDSA:
			signedstr = SignedStr()
			signedstr.read(self.content.value)
			return ecc.bytes2int(signedstr.signature.r.value), ecc.bytes2int(signedstr.signature.s.value)

	def setstr(self, string, signature=None):
		if int(self.type) == MsgRecord.TYPE_SIMPLE:
			self.content.setvalue(bytes(SimpleByteStr(string)))
		elif int(self.type) == MsgRecord.TYPE_ECDSA:
			signedstr = SignedStr()
			signedstr.string.setvalue(string)
			signedstr.signature.r.setvalue(ecc.int2bytes(signature[0]))
			signedstr.signature.s.setvalue(ecc.int2bytes(signature[1]))
			self.content.setvalue(bytes(signedstr))


# Structures de données nécessaires
class MsgPublicKey(data.DataStruct):
	def __init__(self, pubkey=None):
		if pubkey:
			pkx = data.DataElemVector(1, 1024, 0, bytes(pubkey[0]))
			pky = data.DataElemVector(1, 1024, 0, bytes(pubkey[1]))
		else:
			pkx = data.DataElemVector(1, 1024, 0)
			pky = data.DataElemVector(1, 1024, 0)
		super().__init__((pkx, pky), ('pkx', 'pky'))

	def pubkey(self):
		return bytes(self.pkx.value), bytes(self.pky.value)


def scripttests():
	testcurve = ec.nistCurves[0]
	for i in range(10):
		print('Script test', i)
		e1 = ecc.ECEntity(testcurve)
		e2 = ecc.ECEntity(testcurve)
		m1 = MsgPublicKey(e1.pubkey)
		m2 = MsgPublicKey()
		m2.read(bytes(m1))
		pk1 = m2.pubkey()
		m1 = MsgPublicKey(e2.pubkey)
		m2.read(bytes(m1))
		pk2 = m2.pubkey()
		singletest('pk1 == e1.pubkey', pk1=pk1, e1=e1)
		singletest('pk2 == e2.pubkey', pk2=pk2, e2=e2)
		singletest('e1.sharedsecret(e2.pubkey) == e2.sharedsecret(e1.pubkey)', e1=e1, e2=e2)
		singletest('e1.sharedsecret(pk2) == e2.sharedsecret(pk1)', e1=e1, e2=e2, pk1=pk1, pk2=pk2)
		print('')

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


class ComEntity:
	defaultport = 14140

	def __init__(self, host=socket.gethostname(), port=defaultport):
		# Partie réseau
		self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.host = host
		self.port = port
		self.netobj = self.s

		# Partie courbes elliptiques
		self.ece = None
		self.curve = None

		# Partie crypto
		self.otherpk = None
		self.mastersecret = None

	def initec(self, entitycurve):
		self.curve = entitycurve
		self.ece = ecc.ECEntity(entitycurve)

	def sendpubkey(self):
		pkobj = MsgPublicKey(self.ece.pubkey)
		self.netobj.sendall(bytes(pkobj))

	def recpubkey(self):
		pkobj = MsgPublicKey()
		rbytes = self.netobj.recv(8192)
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
		print('Envoyez un message commençant par le caractère $ pour qu\'il soit signé')

	def loop(self):
		# le cipher AES utilise une partie du secret partagé comme vecteur d'initialisation
		# ce n'est pas terrible, TODO: meilleure méthode pour déterminer un IV
		aescipher = AES.new(self.mastersecret[:32], AES.MODE_CFB, self.mastersecret[:AES.block_size])
		loop_continue = True
		while loop_continue:
			msg = MsgRecord()
			try:
				text = input('> ')
				if text == '' or text == '\0':
					msg.type.value = MsgRecord.TYPE_QUIT
					self.s.sendall(bytes(msg))
					break
				else:
					# Si le texte commence par $, signer le message
					signature = None
					if text[0] == '$':
						msg.type.value = MsgRecord.TYPE_ECDSA
						text = text[1:].strip()
						signature = ecc.sign(self.ece, text, SHA256)
					else:
						msg.type.value = MsgRecord.TYPE_SIMPLE
					textb = text.encode('UTF-8')
					cipherb = aescipher.encrypt(textb)
					msg.setstr(cipherb, signature)
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
		print('Connected to', self.raddr)

	def loop(self):
		aescipher = AES.new(self.mastersecret[:32], AES.MODE_CFB, self.mastersecret[:AES.block_size])
		loop_continue = True
		while loop_continue:
			msg = MsgRecord()
			msg.read(self.c.recv(8192))
			if int(msg.type) == MsgRecord.TYPE_QUIT:
				loop_continue = False
			else:
				textstr = aescipher.decrypt(msg.getstr())
				textstr = textstr.decode('UTF-8')
				print('→', textstr)
				if int(msg.type) == MsgRecord.TYPE_ECDSA:
					signature = msg.getsignature()
					if ecc.verifysignature(self.curve, self.otherpk, signature, textstr, SHA256):
						validity = 'verified'
					else:
						validity = 'invalid signature'
					print('    Message signed with ECDSA: ' + validity)

	def close(self):
		if self.c:
			self.c.close()
		super().close()

curve = ec.nistCurves[4]

if function == 'client':
	if len(sys.argv) > 2:
			client = Client(sys.argv[2])
	else:
		client = Client()
	try:

		client.initec(curve)
		client.connect()
		client.sendpubkey()
		client.recpubkey()
		client.loop()
	finally:
		client.close()
	exit()

if function == 'server':
	if len(sys.argv) > 2:
			server = Server(sys.argv[2])
	else:
		server = Server()
	try:
		server.initec(curve)
		server.connect()
		server.recpubkey()
		server.sendpubkey()
		server.loop()
	finally:
		server.close()
	exit()
