#!/bin/python3

# Just using the random module isn't enough
# Use SystemRandom() for a cryptographically secure RNG
from random import SystemRandom as SR

# Command to generate a prime number:
# openssl prime -generate -bits 521 -hex

import gmpy2
from gmpy2 import mpz


def random_bits(n):
	return SR().getrandbits(n)


def mod_inverse(n, modulo):
	if n == 0:
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
		q.append(r[i-1] // r[i])  # integral quotient
		r.append(r[i - 1] - q[i] * r[i])
		if r[i+1] > 0:
			u.append(u[i - 1] - q[i] * u[i])
		i += 1
	return u[-1]


# Courbe elliptique, implementation naive
# ici ce n'est pas sur un corps fini en particulier
class EllipticCurveCartesian:
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
		return x, y

	def double(self, m):
		if m is None or m[1] == 0: # si y est nul
			return None
		# sinon si y non nul
		x = ((3 * m[0] ** 2 + self.a) / (2 * m[1])) ** 2 - 2 * m[0]
		y = (m[0] - m[1]) * (3 * m[0] ** 2 + self.a) / (2 * m[1]) - m[1]
		return mpz(x), mpz(y)

	def add(self, m, n):
		if m is None: # le point a l'infini (représenté ici par None.. à améliorer) est l'élément neutre du groupe additif
			return n
		if n is None:
			return m
		if m != n:  # si deux points differents
			if m[0] == n[0]: # et x1 == x2
				return None
			# sinon, dans le cas ou x1 =/= x2
			x3 = ((n[1] - m[1]) / (n[0] - m[0])) ** 2 - n[0] - m[0]
			y3 = (m[0] - x3) * (n[1] - m[1]) / (n[0] - m[0]) - m[1]
			return mpz(x3), mpz(y3)
		# sinon, si les deux points sont égaux
		return self.double(m)

	def mul(self, m, e):  # algorithme square & multiply: e est ici "l'exponent"
		if e == 0 or m is None:
			return None
		s = None
		while e > 0:
			s = self.double(s)
			if e & 1:
				s = self.add(s, m)
			e >>= 1
		return s


class ParamSet:
	# Voir section 3.3 du RFC6090
	# nombre premier p qui indique l'ordre du corps fini Fp
	# constante a utilisee pour définir l'équation
	# p: nombre premier qui définit le module
	# a: constante a de l'équation de la courbe
	# b: constante b de l'équation de la courbe
	# g: générateur du sous-groupe
	# n: ordre du sous-groupe généré par g
	def __init__(self, p, a, b, g, n):
		self.p = mpz(p)
		self.a = mpz(a)
		self.b = mpz(b)
		self.g = (mpz(g[0]), mpz(g[1]))
		self.n = mpz(n)


class ECPoint:
	def __init__(self, x, y, curve):
		self.x = x
		self.y = y
		self.curve = curve

class PointJ:
	INFINITY = -1
	def __init__(self, curve, point = None):
		if point is None:
			self.curve = curve
			self.x = curve.g.x
			self.y = curve.g.y
			self.z = curve.g.z
		elif point == PointJ.INFINITY:
			self.inf = True
			self.curve = curve
		elif type(point) == tuple and type(curve) == EllipticCurveJ:
			self.curve = curve
			if len(point) == 2:
				affine_x = point[0]
				affine_y = point[1]
				self.x = mpz(affine_x)
				self.y = mpz(affine_y)
				self.z = 1
			elif len(point) == 3:
				self.x = mpz(point[0])
				self.y = mpz(point[1])
				self.z = mpz(point[2])
			else:
				raise Exception()
	def __eq__(self, other):
		if isinstance(other, PointJ):
			if other.inf:
				return self.inf
			if self.inf:
				return other.inf
			# si aucun des deux points n'est l'infini
			# alors...
			u1 = self.x * (other.z ** 2)
			u2 = other.x * (self.z ** 2)
			s1 = self.y * (other.z ** 3)
			s2 = other.x * (self.y ** 3)
			return (u1 == u2) and (s1 == s2)
		return False
	def __add__(self, other):
		if isinstance(other, PointJ):
			u1 = self.x * (other.z ** 2)
			u2 = other.x * (self.z ** 2)
			s1 = self.y * (other.z ** 3)
			s2 = other.x * (self.y ** 3)
			if u1 == u2:
				if (s1 != s2):
					return PointJ(self.curve, PointJ.INFINITY)
				else:
					return self.double()
			# sinon
			h = u2 - u1
			r = s2 - s1
			x = r ** 2 - h ** 3 - 2 * u1 * (h ** 2)
			y = r * (u1 * (h ** 2) - x) - s1 * (h ** 3)
			z = h * self.z * other.z
			return PointJ(self.curve, x, y, z)
 		else:
			return None
	# double and add algorithm
	def __mul__(self, other):
		if type(other) is int:
			if other == 0:
				return PointJ(self.curve, PointJ.INFINITY)
			s = self
			while other > 0:
				s = self.double()
				if other & 1:
					s += self
				other >>= 1
			return s
	def double(self):
		if self.y == 0 or self.inf:
			return PointJ(self.curve, PointJ.INFINITY)
		s = 4 * self.x * (self.y ** 2)
		m = 3 * (self.x ** 2) + a * (self.z ** 4)
		x2 = (m ** 2) - 2 * s
		y2 = m * (s - x2) - 8 * (y ** 4)
		z2 = 2 * self.y * self.z
		return PointJ(self.curve, (x2, y2, z2))

class EllipticCurveJ:  # Courbes elliptiques, implémentation avec les coordonnées jacobiennes
	def __init__(self, params):
		assert type(params) is ParamSet
		self.params = params
		self.g = PointJ(self, params.g)
		self.infinity = PointJ(self, PointJ.INFINITY)

rfcExample = [ParamSet(mpz('0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF'),
						mpz('-3'),
						mpz('0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B'),
						(mpz('0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296'), mpz('0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5')),
						mpz('0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551'))]

exampleCurve = EllipticCurveJ(rfcExample[0])







