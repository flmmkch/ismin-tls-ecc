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
	def __init__(self, p, a, b, g, order):
		self.p = mpz(p)
		self.a = mpz(a)
		self.b = mpz(b)
		self.g = (mpz(g[0]), mpz(g[1]))
		self.order = mpz(order)


class ECPoint:
	def __init__(self, x, y, curve):
		self.x = x
		self.y = y
		self.curve = curve


class PointJ:
	INFINITY = -1

	def __init__(self, curve, point=None):
		self.inf = False
		if point is None:
			self.curve = curve
			self.x = curve.g.x
			self.y = curve.g.y
			self.z = curve.g.z
		elif point == PointJ.INFINITY:
			self.inf = True
			self.curve = curve
		elif type(curve) == EllipticCurveJ and type(point) == tuple:
			self.curve = curve
			if len(point) == 2:
				self.x = mpz(point[0]) % self.curve.params.p
				self.y = mpz(point[1]) % self.curve.params.p
				self.z = mpz(1)
			elif len(point) == 3:
				self.x = mpz(point[0]) % self.curve.params.p
				self.y = mpz(point[1]) % self.curve.params.p
				self.z = mpz(point[2]) % self.curve.params.p
			else:
				raise Exception()

	def __eq__(self, other):
		p = self.curve.params.p
		if isinstance(other, PointJ):
			if other.inf:
				return bool(self.inf)
			if self.inf:
				return bool(other.inf)
			# si aucun des deux points n'est l'infini
			# alors...
			u1 = (self.x * gmpy2.powmod(other.z, 2, p)) % p
			u2 = (other.x * gmpy2.powmod(self.z, 2, p)) % p
			s1 = (self.y * gmpy2.powmod(other.z, 3, p)) % p
			s2 = (other.y * gmpy2.powmod(self.z, 3, p)) % p
			return (u1 == u2) and (s1 == s2)
		return False

	def __add__(self, other):
		p = self.curve.params.p
		if isinstance(other, PointJ):
			if bool(self.inf):
				return other.copy()
			elif bool(other.inf):
				return self.copy()
			u1 = (self.x * gmpy2.powmod(other.z, 2, p)) % p
			u2 = (other.x * gmpy2.powmod(self.z, 2, p)) % p
			s1 = (self.y * gmpy2.powmod(other.z, 3, p)) % p
			s2 = (other.y * gmpy2.powmod(self.z, 3, p)) % p
			if u1 == u2:
				if s1 != s2:
					return PointJ(self.curve, PointJ.INFINITY)
				else:
					return self.double()
			# sinon
			h = u2 - u1
			r = s2 - s1
			x = r ** 2 - h ** 3 - 2 * u1 * (h ** 2)
			y = r * (u1 * (h ** 2) - x) - s1 * (h ** 3)
			z = h * self.z * other.z
			return PointJ(self.curve, (x, y, z))
		else:
			return None

	# Double & Add algorithm
	def __mul__(self, other):
		if type(other) is int:
			s = PointJ(self.curve, PointJ.INFINITY)
			if other == 0:
				return s
			m = self.copy()
			while other > 0:
				if other & 1:
					s += m
				m = m.double()
				other >>= 1
			return s

	def __neg__(self):
		return PointJ(self.curve, (self.x, -self.y, self.z))

	def __sub__(self, other):
		return self + (- other)

	def copy(self):
		return PointJ(self.curve, (self.x, self.y, self.z))

	def double(self):
		if self.inf or self.y == 0:
			return PointJ(self.curve, PointJ.INFINITY)
		s = 4 * self.x * (self.y ** 2)
		m = 3 * (self.x ** 2) + self.curve.params.a * (self.z ** 4)
		x2 = (m ** 2) - 2 * s
		y2 = m * (s - x2) - 8 * (self.y ** 4)
		z2 = 2 * self.y * self.z
		return PointJ(self.curve, (x2, y2, z2))

	def __repr__(self):
		if bool(self.inf):
			return '∞'
		s = ''
		s += 'x: ' + str(self.x) + '; '
		s += 'y: ' + str(self.y) + '; '
		s += 'z: ' + str(self.z)
		return s

	# Obtenir les coordonnées affines
	def affine(self):
		x = gmpy2.divexact(self.x, self.z ** 2)
		y = gmpy2.divexact(self.y, self.z ** 3)
		return x, y


class EllipticCurveJ:  # Courbes elliptiques, implémentation avec les coordonnées jacobiennes
	def __init__(self, params):
		assert type(params) is ParamSet
		self.params = params
		self.g = PointJ(self, params.g)
		self.infinity = PointJ(self, PointJ.INFINITY)

	def __repr__(self):
		s = ''
		s += 'p : ' + str(self.params.p) + '\n'
		s += 'a : ' + str(self.params.a) + '\n'
		s += 'b : ' + str(self.params.b) + '\n'
		s += 'g : ' + str(self.g) + '\n'
		s += 'ordre : ' + str(self.params.order) + '\n'
		return s

rfcParams = ParamSet(mpz('0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF'),
						mpz('-3'),
						mpz('0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B'),
						(mpz('0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296'), mpz('0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5')),
						mpz('0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551'))

# Du document "RECOMMENDED ELLIPTIC CURVES FOR FEDERAL GOVERNMENT USE"
nistParams = {'P-192': ParamSet(mpz('6277101735386680763835789423207666416083908700390324961279'),
						mpz('-3'),
						mpz('0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1'),
						(mpz('0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012'), mpz('0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811')),
						mpz('6277101735386680763835789423176059013767194773182842284081')),
			   'P-224': ParamSet(mpz(' 26959946667150639794667015087019630673557916260026308143510066298881'),
						mpz('-3'),
						mpz('0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4'),
						(mpz('0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21'), mpz('0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34')),
						mpz('26959946667150639794667015087019625940457807714424391721682722368061')),
			   'P-256': ParamSet(mpz(' 115792089210356248762697446949407573530086143415290314195533631308867097853951'),
						mpz('-3'),
						mpz('0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b'),
						(mpz('0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296'), mpz('0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5')),
						mpz('115792089210356248762697446949407573529996955224135760342422259061068512044369')),
			   'P-384': ParamSet(mpz('39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319'),
						mpz('-3'),
						mpz('0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef'),
						(mpz('0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7'), mpz('0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f')),
						mpz('39402006196394479212279040100143613805079739270465446667946905279627659399113263569398956308152294913554433653942643')),
			   'P-521': ParamSet(mpz('6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151'),
						mpz('-3'),
						mpz('0x051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00'),
						(mpz('0xc6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66'), mpz('0x11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650')),
						mpz('6864797660130609714981900799081393217269435300143305409394463459185543183397655394245057746333217197532963996371363321113864768612440380340372808892707005449'))
			   }

nistCurves = []
for i in nistParams:
	nistCurves.append(EllipticCurveJ(nistParams[i]))

def singleTest(test, **kwargs):
	for key, value in kwargs.items():
		locals()[str(key)] = value
	testresult = bool(eval(test))
	if not testresult:
		raise Exception('Test failed: ' + str(test))
	return testresult

def basicTests():
	p = nistCurves[0].g
	singleTest('g == g', g=p)
	singleTest('g + g != g', g=p)
	singleTest('g + g == g.double()', g=p)
	singleTest('g + g + g == g.double() + g', g=p)
	singleTest('g + g + g == g * 3', g=p)
	singleTest('g + g != g * 3', g=p)
	singleTest('(g + g + g).double() == g * 6', g=p)
	singleTest('g * 4 == g + g + g + g', g=p)
	singleTest('g * 4 != g + g + g + g + g', g=p)
	return True








