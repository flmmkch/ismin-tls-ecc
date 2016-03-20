#!/usr/bin/python3

# Package des algorithmes de crypto basés sur courbes elliptiques

# Just using the random module isn't enough
# Use SystemRandom() for a cryptographically secure RNG
from random import SystemRandom as Sr

import elliptic_curves as ec

from Crypto.Hash import SHA
import gmpy2
from gmpy2 import mpz

from tests import singletest


def curvebits(curve: ec.EllipticCurveJ):
	return curve.params.order.bit_length()


def int2bytes(e, fixedsize=None):
	if fixedsize:
		size = int(fixedsize)
	else:
		size = int(e).bit_length() // 8 + 1
	return int.to_bytes(int(e), size, byteorder='big')
	# return gmpy2.to_binary(e)


def bytes2int(e):
	return int.from_bytes(e, byteorder='big')
	# return gmpy2.from_binary(e)


class ECEntity:
	def __init__(self, curve, secret=None):
		assert(type(curve) == ec.EllipticCurveJ)
		if not secret:
			n = len(mpz(curve.params.order))
			secretint = Sr().randint(1 << (n - 3), (curve.params.order - 1))
			secret = mpz(secretint)
		self.secret = mpz(secret)
		affinecoord = (curve.g * secret).affine()
		self.pubkey = (int2bytes(affinecoord[0]), int2bytes(affinecoord[1]))
		self.curve = curve

	def sharedsecret(self, pubkey):
		pkobj = (bytes2int(pubkey[0]), bytes2int(pubkey[1]))
		ss_int = (ec.PointJ(self.curve, pkobj) * self.secret).affine()[0]
		return int2bytes(ss_int)


def sign(entity: ECEntity, message, hashalgo=SHA):
	if isinstance(message, str):
		message = message.encode('UTF-8')
	h = hashalgo.new(message).digest()
	n = entity.curve.params.order
	e = mpz(int.from_bytes(h[:n.bit_length()], byteorder='big'))  # bits de gauche de e
	while True:
		k = Sr().randint(1, n-1)
		p1 = entity.curve.g * k
		r = p1.affine()[0] % n
		if r == 0:
			continue
		s = gmpy2.divm(e + entity.secret * r, k, n)
		if s == 0:
			continue
		return int(r), int(s)


# Renvoie True si la signature est valide, False sinon
def verifysignature(curve, pubkey, signature, message, hashalgo=SHA):
	pkobj = (bytes2int(pubkey[0]), bytes2int(pubkey[1]))
	publickeypoint = ec.PointJ(curve, pkobj)
	n = curve.params.order
	if isinstance(message, str):
		message = message.encode('UTF-8')
	h = hashalgo.new(message).digest()
	e = mpz(int.from_bytes(h[:n.bit_length()], byteorder='big'))  # bits de gauche de e
	r, s = signature
	u1 = gmpy2.divm(e, s, n)
	u2 = gmpy2.divm(r, s, n)
	resultpoint = curve.g * u1 + publickeypoint * u2
	v = resultpoint.affine()[0] % n
	return v == r  # on doit avoir r ≡ x1 (mod n)


def ecdhtests(curve=ec.nistCurves[0], npairs=10, nchecks=3):
	# test multiple times
	for i in range(npairs):
		partya = ECEntity(curve)
		partyb = ECEntity(curve)
		sharedsecret1 = partya.sharedsecret(partyb.pubkey)
		sharedsecret2 = partyb.sharedsecret(partya.pubkey)
		if sharedsecret1 != sharedsecret2:
			print('ECDH test failed')
			return False
	print('ECDH test OK!')
	return True


def ecdsatests(message='Bonjour, ceci est un test', curve=ec.nistCurves[0]):
	partya = ECEntity(curve)
	sigtest = sign(partya, message)
	# on vérifie qu'une signature valide est bel et bien validée
	singletest('verifysignature(curve, pka, sigtest, message)', curve=curve, pka=partya.pubkey, sigtest=sigtest,
				message=message, verifysignature=verifysignature)
	partyb = ECEntity(curve)
	# on s'assure que ce sont des clés secrètes différentes (sinon les tests ne fonctionneront pas)
	while partyb.secret == partya.secret:
		partyb = ECEntity(curve)
	# on vérifie qu'une signature invalide (par rapport à une certaine clé publique) est bel et bien invalidée
	singletest('not verifysignature(curve, pkb, sigtest, message)', curve=curve, pkb=partyb.pubkey, sigtest=sigtest,
				message=message, verifysignature=verifysignature)
	return True

