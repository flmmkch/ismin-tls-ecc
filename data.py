#!/usr/bin/python3

import math


class DataElem:
	defaultvalue = 0
	order = 'big'

	def __init__(self, arg, value=defaultvalue):
		if isinstance(arg, int):
			# arg is the length in bytes
			self.length = arg
			self.value = value
		elif isinstance(arg, bytes):
			self.length = len(arg)
			self.value = arg

	def read(self, newvalue):
		if isinstance(newvalue, DataElem):
			self.value = newvalue.value[:self.length]
		else:
			self.value = bytes(newvalue)[:self.length]
		# return the number of bytes read
		return self.length

	def to_bytes(self):
		# Ne retourner que le nombre d'octets donné
		if isinstance(self.value, bytes):
			if len(self.value) < self.length:
				return self.value + b'\x00' * (self.length - len(self.value))  # padding (en big endian)
			# sinon, on retourne le bon nombre
			return self.value[:self.length]
		elif isinstance(self.value, int):
			return self.value.to_bytes(self.length, byteorder=DataElem.order)

	def __bytes__(self):
		return self.to_bytes()

	def __eq__(self, other):
		s = self.to_bytes()
		if isinstance(other, DataElem):
			return s == other.to_bytes()
		elif isinstance(other, bytes):
			return s == other
		elif isinstance(other, int):
			return s == int.from_bytes(s, byteorder=DataElem.order)

	def size(self):
		return self.length


class DataArray(DataElem):
	def __init__(self, size, elemlength):
		self.arraysize = size
		self.value = (DataElem(elemlength),) * self.arraysize

	def read(self, newvalue):
		i = 0
		for elem in range(self.arraysize):
			bytesread = self.value[elem].read(newvalue[i:])
			i += bytesread
		return i

	def to_bytes(self):
		s = b''
		for elem in range(self.arraysize):
			s += self.value[elem].to_bytes()
		return s

	def size(self):
		s = 0
		for elem in self.value:
			s += elem.size()
		return s


class DataStruct(DataElem):
	def __init__(self, elements, elemnames=()):
		object.__setattr__(self, 'elemnames', tuple(elemnames))
		object.__setattr__(self, 'value', tuple(elements))

	def read(self, newvalue):
		i = 0
		for elem in self.value:
			i += elem.read(newvalue[i:])
		return i

	def to_bytes(self):
		s = b''
		for elem in self.value:
			s += elem.to_bytes()
		return s

	def size(self):
		s = 0
		for elem in self.value:
			s += elem.size()
		return s

	def __getattr__(self, item):
		if item in self.elemnames:
			index = self.elemnames.index(item)
			return self.value[index]
		else:
			return object.__getattr__(self, item)

	def __setattr__(self, key, value):
		if key in self.elemnames:
			index = self.elemnames.index(key)
			self.value = self.value[:index] + (value, ) + self.value[index+1:]
		else:
			object.__setattr__(self, key, value)


def nbytes(e):
	if e == 0:
		return 1
	return int(math.ceil(e.bit_length() / 8))


class DataVector(DataElem):
	def __init__(self, dtype, ceiling, floor=0):
		assert(issubclass(dtype, DataElem))
		self.ceiling = ceiling
		self.floor = floor
		self.dtype = dtype
		self.vectsize = floor
		self.value = [self.dtype()] * self.vectsize

	def read(self, newvalue):
		i = 0
		# first read the size
		i += nbytes(self.ceiling)
		self.vectsize = int.from_bytes(newvalue[:i], byteorder=DataElem.order)
		# then read the elements
		self.value = []
		for elem in range(self.vectsize):
			elem = self.dtype()
			i += elem.read(newvalue[i:])
			self.value.append(elem)
		return i

	def to_bytes(self):
		s = b''
		# first write the size
		s += self.vectsize.to_bytes(nbytes(self.ceiling), byteorder=DataElem.order)
		# then write the elements
		for elem in range(self.vectsize):
			s += self.value[elem].to_bytes()
		return s

	def size(self):
		s = nbytes(self.ceiling)
		for elem in self.value:
			s += elem.size()
		return s


class Uint(DataElem):
	def __init__(self, size, value=0):
		super().__init__(size, value)

	def __int__(self):
		if isinstance(self.value, int):
			return self.value
		return int.from_bytes(bytes(self.value), byteorder=DataElem.order, signed=False)


class Uint8(Uint):
	def __init__(self, value=0):
		super().__init__(1, value)


class Uint16(Uint):
	def __init__(self, value=0):
		super().__init__(2, value)


class Uint24(Uint):
	def __init__(self, value=0):
		super().__init__(3, value)


class Uint32(Uint):
	def __init__(self, value=0):
		super().__init__(4, value)


class Uint64(Uint):
	def __init__(self, value=0):
		super().__init__(8, value)


class Opaque(DataArray):
	def __init__(self, arg=1):
		if isinstance(arg, int):  # arg represents the size of the byte array to initiate
			super().__init__(1, arg)
		elif isinstance(arg, bytes):  # arg is the initial byte array
			size = len(arg)
			super().__init__(1, size)
			self.read(arg)