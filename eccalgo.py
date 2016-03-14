#!/usr/bin/python3

# Package des algorithmes de crypto basés sur courbes elliptiques

# Just using the random module isn't enough
# Use SystemRandom() for a cryptographically secure RNG
from random import SystemRandom as Sr

import elliptic_curves as ec

from Crypto.Hash import SHA256
import gmpy2
from gmpy2 import mpz


class ECEntity:
	def __init__(self, curve, secret=None):
		assert(type(curve) == ec.EllipticCurveJ)
		if not secret:
			secret = Sr().randint(1, (curve.params.order - 1))
		self.secret = secret
		self.pubkey = (curve.g * secret).affine()
		self.curve = curve

	def sharedsecret(self, otherpubkey):
		return (ec.PointJ(self.curve, otherpubkey) * self.secret).affine()[0]


def sign(entity: ECEntity, message, hashalgo=SHA256):
	if isinstance(message, str):
		message = message.encode('UTF-8')
	e = hashalgo.new(message).digest()
	n = entity.curve.params.order
	z = int.from_bytes(e[:n.bit_length()], byteorder='big')  # bits de gauche de e
	while True:
		k = Sr().randint(1, n-1)
		p1 = entity.curve.g * k
		r = int(p1.affine()[0])
		if r == 0:
			continue
		s = gmpy2.divm(z + r * entity.secret, k, n)
		if s == 0:
			continue
		return r, s


def verifysignature(curve, pubkey, signature, message, hashalgo=SHA256):
	publickeypoint = ec.PointJ(curve, pubkey)
	# D'abord verifier que le point est valide
	# Ensuite
	for i in [0, 1]:
		if signature[i] < 0 or signature[i] >= curve.params.order:
			return False
	if isinstance(message, str):
		message = message.encode('UTF-8')
	e = hashalgo.new(message).digest()
	n = curve.params.order
	z = int.from_bytes(e[:n.bit_length()], byteorder='big')  # bits de gauche de e
	r, s = pubkey
	w = gmpy2.divm(1, int(s), n)
	u1 = (z * w) % n
	u2 = (int(r) * w) % n
	resultpoint = curve.g * u1
	resultpoint += publickeypoint * u2
	x1 = resultpoint.affine()[0].v
	r = r.v
	return (x1 - r) % n == 0  # on doit avoir r ≡ x1 (mod n)


def ecdhtests(curve=ec.nistCurves[0]):
	partya = ECEntity(curve)
	partyb = ECEntity(curve)
	sharedsecret1 = partya.sharedsecret(partyb.pubkey)
	sharedsecret2 = partyb.sharedsecret(partya.pubkey)
	return sharedsecret1 == sharedsecret2


def ecdsatests(message='Bonjour ceci est un test ok bye', curve=ec.nistCurves[0]):
	partya = ECEntity(curve)
	test = sign(partya, message)
	return verifysignature(curve, partya.pubkey, test, message)
