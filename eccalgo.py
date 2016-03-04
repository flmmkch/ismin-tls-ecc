#!/usr/bin/python3

# Package des algorithmes de crypto basés sur courbes elliptiques

# Just using the random module isn't enough
# Use SystemRandom() for a cryptographically secure RNG
from random import SystemRandom as Sr

import elliptic_curves


class ECDHInstance:
	def __init__(self, secret, curve):
		assert(type(secret) == int)
		assert(type(curve) == elliptic_curves.EllipticCurveJ)
		self.secret = secret
		self.pubkey = curve.g * secret

	def sharedsecret(self, otherpubkey):
		return (otherpubkey * self.secret).x


class ECDH:
	@staticmethod
	def initiate(curve):
		assert(type(curve) == elliptic_curves.EllipticCurveJ)
		secret = Sr().randint(1, (curve.params.order - 1))
		return ECDHInstance(secret, curve)
