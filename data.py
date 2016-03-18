#!/usr/bin/python3

import math
from tests import singletest


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
		self.elemlength = elemlength
		self.value = b'\x00' * elemlength * size

	def read(self, newvalue):
		i = 0
		size = self.elemlength * self.arraysize
		self.value = newvalue[:size] + self.value[len(newvalue):]
		i += len(newvalue[:size])
		return i

	def to_bytes(self):
		return self.value

	def size(self):
		return self.elemlength * self.arraysize

	def __getitem__(self, item):
		if isinstance(item, int) and 0 <= item < self.arraysize:
			s = DataElem(self.value[self.elemlength * item: self.elemlength * (item + 1)])
			return s

	def valuewithoutitem(self, key):
		valuebefore = self.value[:self.elemlength * key]
		valueafter = self.value[self.elemlength * (key+1):]
		return valuebefore, valueafter

	def __setitem__(self, key, value):
		if isinstance(key, int) and 0 <= key < self.arraysize:
			if (isinstance(value, DataElem) and value.size() == self.elemlength) or isinstance(value, bytes):
				valuebefore, valueafter = self.valuewithoutitem(key)
				self.value = valuebefore + bytes(value) + valueafter
			elif isinstance(value, int):
				valuebefore, valueafter = self.valuewithoutitem(key)
				if value.bit_length() > self.elemlength:
					return  # Cas invalide
				b = value.to_bytes(self.elemlength, byteorder=DataElem.order)
				self.value = valuebefore + b + valueafter


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

	def __dir__(self):
		return object.__dir__(self) + list(self.elemnames)


def nbytes(e):
	if e == 0:
		return 1
	return int(math.ceil(e.bit_length() / 8))


class DataVector(DataElem):
	def __init__(self, dtype, ceiling, floor=0):
		self.ceiling = ceiling
		self.floor = floor
		if issubclass(dtype, DataElem):
			self.dtype = dtype
		else:
			self.dtype = DataElem(int(dtype))  # on considère dtype comme la taille de l'élément
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

	def __getitem__(self, item):
		if isinstance(item, int) and 0 <= item < self.vectsize:
			s = DataElem(self.value[item])
			return s

	def valuewithoutitem(self, key):
		valuebefore = self.value[:key]
		valueafter = self.value[(key+1):]
		return valuebefore, valueafter

	def __setitem__(self, key, value):
		if isinstance(key, int) and 0 <= key < self.arraysize:
			if (isinstance(value, DataElem) and value.size() == self.elemlength) or isinstance(value, bytes):
				valuebefore, valueafter = self.valuewithoutitem(key)
				newitem = self.dtype()
				newitem.read(value)
				self.value = valuebefore + newitem + valueafter
			elif isinstance(value, int):
				valuebefore, valueafter = self.valuewithoutitem(key)
				if value.bit_length() > self.elemlength:
					return  # Cas invalide
				b = value.to_bytes(self.elemlength, byteorder=DataElem.order)
				newitem = self.dtype()
				newitem.read(b)
				self.value = valuebefore + newitem + valueafter


class DataElemVector(DataElem):
	def __init__(self, elemsize, ceiling, floor=0, value=None):
		self.elemsize = elemsize
		self.ceiling = ceiling
		self.floor = floor
		if value:
			self.value = bytes(value)[:self.ceiling]
			self.vectsize = len(self.value) // self.elemsize
			if (self.elemsize * self.vectsize) < len(self.value):
				self.vectsize += 1
				self.value += b'\x00' * ((self.elemsize * self.vectsize) - len(value))
		else:
			self.vectsize = floor
			self.value = b'\x00' * self.elemsize * self.vectsize

	def read(self, newvalue):
		i = 0
		# first read the size
		i += nbytes(self.ceiling)
		self.vectsize = int.from_bytes(bytes(newvalue)[:i], byteorder=DataElem.order)
		# then read the elements
		self.value = bytes(newvalue)[i:i+(self.vectsize * self.elemsize)]
		if len(self.value) < self.vectsize * self.elemsize:
			self.value += b'\x00' * (self.vectsize * self.elemsize - len(self.value))
		i += self.vectsize * self.elemsize
		return i

	def to_bytes(self):
		s = b''
		# first write the size
		s += self.vectsize.to_bytes(nbytes(self.ceiling), byteorder=DataElem.order)
		# then write the elements
		s += self.value
		return s

	def size(self):
		return nbytes(self.ceiling) + len(self.value)

	def __getitem__(self, item):
		if isinstance(item, int) and 0 <= item < self.vectsize:
			s = DataElem(self.value[self.elemsize * item:self.elemsize * (item + 1)])
			return s

	def valuewithoutitem(self, key):
		valuebefore = self.value[:self.elemsize * key]
		valueafter = self.value[self.elemsize * (key+1):]
		return valuebefore, valueafter

	def __setitem__(self, key, value):
		if isinstance(key, int) and 0 <= key < self.vectsize:
			if (isinstance(value, DataElem) and value.size() == self.elemsize) or isinstance(value, bytes):
				valuebefore, valueafter = self.valuewithoutitem(key)
				newitem = bytes(value)[:self.elemsize]
				self.value = valuebefore + newitem + valueafter
			elif isinstance(value, int):
				valuebefore, valueafter = self.valuewithoutitem(key)
				if value.bit_length() > self.elemsize:
					return  # Cas invalide
				newitem = value.to_bytes(self.elemsize, byteorder=DataElem.order)
				self.value = valuebefore + newitem + valueafter


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


def datatests():
	test = DataStruct((DataElem(1, 3), Opaque(b'\x08BASEDGOD'), Uint32(100000)), ('kon', 'ban', 'wa'))
	singletest('t.size() == 14 and isinstance(t.value, tuple) and len(t.value) == 3', t=test)
	singletest('bytes(t) == right_value', t=test, right_value=b'\x03\x08BASEDGOD\x00\x01\x86\xa0')
	test.ban = Uint8(5)
	singletest('bytes(t) == right_value', t=test, right_value=b'\x03\x05\x00\x01\x86\xa0')
	singletest('int(t.wa.value) == right_value', t=test, right_value=100000)
	fixedvect = DataElemVector(2, 46, 3, b'\x00ABCDEFGH\x04\x06')
	singletest('bytes(v) == right_value', v=fixedvect, right_value=b'\x06\x00ABCDEFGH\x04\x06\x00')
	singletest('v.size() == 13', v=fixedvect)
	singletest('v.vectsize == 6', v=fixedvect)
	fixedvect[4] = b'HI'
	fixedvect[5] = b'JK'
	singletest('bytes(v) == right_value', v=fixedvect, right_value=b'\x06\x00ABCDEFGHIJK')
	return True

