#!/usr/bin/python3

# Package des algorithmes de crypto basés sur courbes elliptiques

# Just using the random module isn't enough
# Use SystemRandom() for a cryptographically secure RNG
from random import SystemRandom as Sr

import elliptic_curves as ec


class ECDHInstance:
	def __init__(self, curve, secret=None):
		assert(type(curve) == ec.EllipticCurveJ)
		if secret:
			assert(type(secret) == int)
		else:
			secret = Sr().randint(1, (curve.params.order - 1))
		self.secret = secret
		self.pubkey = curve.g * secret

	def sharedsecret(self, otherpubkey):
		return (otherpubkey * self.secret).affine()[0]


def ecdhtests(curveid=0):
	curve = ec.nistCurves[curveid]
	partya = ECDHInstance(curve)
	partyb = ECDHInstance(curve)
	sharedsecret1 = partya.sharedsecret(partyb.pubkey)
	sharedsecret2 = partyb.sharedsecret(partya.pubkey)
	return sharedsecret1 == sharedsecret2
