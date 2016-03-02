#!/bin/python3

# Just using the random module isn't enough
# Use SystemRandom() for a cryptographically secure RNG
from random import SystemRandom as sr

# Command to generate a prime number:
# openssl prime -generate -bits 521 -hex

import gmpy2
from gmpy2 import mpz, mpfr

def random_bits(n):
	return sr().getrandbits(n)

def mod_inverse(n, modulo):
	if (n == 0):
		return 0
	n = n % modulo
	# extended Euclidean algorithm
	# u * n + v * modulo = r
	u = [0, 1]
	v = [1, 0]
	r = [modulo, n]
	q = [0]
	i = 1
	while r[i] > 0:
		q.append(r[i-1] // r[i]) # integral quotient
		r.append(r[i - 1] - q[i] * r[i])
		if r[i+1] > 0:
			u.append(u[i - 1] - q[i] * u[i])
		i += 1
	return u[-1]

# Courbe elliptique, implementation naive
# ici ce n'est pas sur un corps fini en particulier
class elliptic_curve:
	# Définie par l'équation suivante
	# y^2 = x^3 + a * x + b ou x, y, a, b sont des elements de Fp
	# et le discriminant n'est pas nul
	def __init__(self, a, b, precision = 64):
		self.a = mpz(a)
		self.b = mpz(b)
		self.precision = precision
		# Calcul du discriminant
		self.discriminant = 4 * self.a ** 3 + 27 * self.b ** 2 # opérateur **: exponentiation
	def random_point(self):
		# On trouve un x aleatoire
		x = mpz(random_bits(self.precision))
		# On calcule y^2
		y2 = x ** 3 + self.a * x + self.b
		y = gmpy2.isqrt(y2)
		if random_bits(1): # on prend aleatoirement l'oppose de y
			y = -y
		return (x,y)
	def double(self, m):
		if m == None or m[1] == 0: # si y est nul
			return None
		# sinon si y non nul
		x = ((3 * m[0] ** 2 + self.a) / (2 * m[1])) ** 2 - 2 * m[0]
		y = (m[0] - m[1]) * (3 * m[0] ** 2 + self.a) / (2 * m[1]) - m[1]
		return (mpz(x),mpz(y))
	def add(self, m, n):
		if m == None: # le point a l'infini (représenté ici par None.. à améliorer TODO) est l'élément neutre du groupe additif
			return n
		if n == None:
			return m
		if m != n: # si deux points differents
			if m[0] == n[0]: # et x1 == x2
				return None
			# sinon, dans le cas ou x1 =/= x2
			x3 = ((n[1] - m[1]) / (n[0] - m[0])) ** 2 - n[0] - m[0]
			y3 = (m[0] - x3) * (n[1] - m[1]) / (n[0] - m[0]) - m[1]
			return (mpz(x3), mpz(y3))
		# sinon, si les deux points sont égaux
		return self.double(m)
	def mul(self, m, e): # algorithme square & multiply: e est ici "l'exponent"
		if e == 0 or m == None:
			return None
		s = None
		while e > 0:
			s = self.double(s)
			if e & 1:
				s = self.add(s, m)
			e >>= 1
		return s

class ecc_paramset:
	# Voir section 3.3 du RFC6090
	# nombre premier p qui indique l'ordre du corps fini Fp
	# constante a utilisee pour définir l'équation
	def __init__(self, p, a, b, g, n):
		self.p = mpz(p)
		self.a = mpz(a)
		self.b = mpz(b)
		self.g = mpz(g)
		self.n = mpz(n)

#  TODO: Implémentation avec un autre système de coordonnées: homogènes ? jacobiennes ?
