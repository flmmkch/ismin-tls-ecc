import tls
import socket
import elliptic_curves as ec
import eccalgo as ecc
import sys
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import data
from data import DataElem, DataStruct, DataArray, DataVector, DataElemVector, Uint8, Uint16, Uint24, Uint32, Opaque

function = sys.argv[1]

if function == 'test' or function == 'tests':
	print('Début des tests')
	ec.fieldtests()
	ec.curvetests()
	ecc.ecdhtests()
	ecc.ecdsatests()
	data.datatests()
	print('Fin des tests')
	exit()

curve = ec.nistCurves[0]


# Structures de données nécessaires
class MsgPublicKey(DataStruct):
	def __init__(self, entity: ecc.ECEntity=None):
		if entity:
			pkx = DataElemVector(1, 1024, 0, bytes(entity.pubkey[0]))
			pky = DataElemVector(1, 1024, 0, bytes(entity.pubkey[1]))
		else:
			pkx = DataElemVector(1, 1024, 0)
			pky = DataElemVector(1, 1024, 0)
		super().__init__((pkx, pky), ('pkx', 'pky'))


class ComEntity:
	defaultport = 14140

	def __init__(self, host=socket.gethostname(), port=defaultport):
		# Partie réseau
		self.s = socket.socket()
		self.host = host
		self.port = port
		self.netobj = self.s

		# Partie courbes elliptiques
		self.ece = ecc.ECEntity(curve)

		# Partie crypto
		self.mastersecret = None

	def sendpubkey(self):
		self.netobj.send(bytes(MsgPublicKey(self.ece)))

	def recpubkey(self):
		pkstruct = MsgPublicKey()
		pkstruct.read(self.netobj.recv(4096))
		self.mastersecret = self.ece.sharedsecret((pkstruct.pkx.value, pkstruct.pky.value))

	def close(self):
		self.s.close()


class Client(ComEntity):
	def connect(self):
		self.s.connect((self.host, self.port))


class Server(ComEntity):
	def __init__(self, host=socket.gethostname(), port=ComEntity.defaultport):
		super().__init__(host, port)
		self.c = None
		self.raddr = None

	def connect(self):
		self.s.bind((self.host, self.port))
		print('Hosting on ' + str(self.host) + ':' + str(self.port))
		self.s.listen(0)
		# On ne fait qu'une seule connection ici
		self.c, self.raddr = self.s.accept()
		self.netobj = self.c

	def close(self):
		self.c.close()
		super().close()


if function == 'client':
	client = Client()
	client.connect()
	client.sendpubkey()
	client.recpubkey()
	print(bytes(client.mastersecret))
	client.close()
	exit()

if function == 'server':
	server = Server()
	server.connect()
	server.recpubkey()
	server.sendpubkey()
	print(bytes(server.mastersecret))
	server.close()
	exit()
