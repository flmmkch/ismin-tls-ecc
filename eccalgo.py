#!/usr/bin/python3

# Package des algorithmes de crypto basés sur courbes elliptiques

# Just using the random module isn't enough
# Use SystemRandom() for a cryptographically secure RNG
from random import SystemRandom as SR

import elliptic_curves


class ECDH:
	@staticmethod
	def initiate(curve):
		assert(type(curve) == elliptic_curves.EllipticCurveJ)
		secret = SR().randint(1, (curve.params.order - 1))
		message = curve.g * j
		return secret, message