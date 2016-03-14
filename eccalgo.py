#!/usr/bin/python3

# Package des algorithmes de crypto basés sur courbes elliptiques

# Just using the random module isn't enough
# Use SystemRandom() for a cryptographically secure RNG
from random import SystemRandom as Sr

import elliptic_curves as ec


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


def ecdhtests(curve=ec.nistCurves[0]):
	partya = ECEntity(curve)
	partyb = ECEntity(curve)
	sharedsecret1 = partya.sharedsecret(partyb.pubkey)
	sharedsecret2 = partyb.sharedsecret(partya.pubkey)
	return sharedsecret1 == sharedsecret2


def ecdsatests(curve=ec.nistCurves[0]):
	partya = ECEntity(curve)
	partyb = ECEntity(curve)
