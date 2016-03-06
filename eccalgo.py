#!/usr/bin/python3

# Package des algorithmes de crypto basés sur courbes elliptiques

# Just using the random module isn't enough
# Use SystemRandom() for a cryptographically secure RNG
from random import SystemRandom as Sr

import elliptic_curves as ec


class ECDHInstance:
	def __init__(self, secret, curve):
		assert(type(secret) == int)
		assert(type(curve) == ec.EllipticCurveJ)
		self.secret = secret
		self.pubkey = curve.g * secret

	def sharedsecret(self, otherpubkey):
		return (otherpubkey * self.secret).affine()[0]


class ECDH:
	@staticmethod
	def initiate(curve):
		assert(type(curve) == ec.EllipticCurveJ)
		secret = Sr().randint(1, (curve.params.order - 1))
		return ECDHInstance(secret, curve)


def basicTests(curveid = 0):
	curve = ec.nistCurves[curveid]
	partyA = ECDH.initiate(curve)
	partyB = ECDH.initiate(curve)
	sharedsecret1 = partyA.sharedsecret(partyB.pubkey)
	sharedsecret2 = partyB.sharedsecret(partyA.pubkey)
	return sharedsecret1 == sharedsecret2
