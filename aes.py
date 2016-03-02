#!/usr/bin/python

import numpy as np
import numpy.matlib

# "Traduction" des fonctions de l'énoncé en Python (Python 3.5)
# Une différence importante par rapport à Matlab est que les indices de tableau commencent ici à 0 et non à 1

def poly_mult (a, b, mod_pol):
	#Polynomial modulo multiplication in GF(2^8)
	ab = 0
	#Loop over every bit of the first factor ("a") starting with the least significant bit.
	#This loop multiplies "a" and "b" modulo 2
	for i_bit in range(8):
		if np.any(a & (1 << i_bit)):
			b_shift = b << i_bit
			ab = ab ^ b_shift
	#Loop over the 8 most significant bits of the "ab"-product.
	#This loop reduces the 16-bit-product back to the 8 bits of a GF(2^8) element by the use of the irreducible modulo polynomial of degree 8.
	for i_bit in range(15,7,-1):
		if ab & (1 << i_bit):
			mod_pol_shift = mod_pol << i_bit - 8;
			ab = ab ^ mod_pol_shift
	return ab

# def find_inverse (b_in, pol_mod):
# 	for i in range(1,256):
# 		prod = poly_mult(b_in, i, pol_mod)
# 		if prod == 1:
# 			return i
# 	# sinon
# 	return 0

def find_inverse(n, modulo):
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

def aff_trans (b_in):
	#Apply an affine transformation over GF(2^8)
	mod_pol = 0b100000001
	mult_pol = 0b00011111
	add_pol = 0b01100011
	temp = poly_mult (b_in, mult_pol, mod_pol)
	return temp ^ add_pol

def s_box_gen ():
	mod_pol = 0b100011011
	inverse = [0]
	for i in range(256):
		inverse.append(find_inverse(i, mod_pol))
	s_box = np.array([], np.uint8)
	for i in range(1,257):
		s_box = np.append(s_box, aff_trans(inverse[i]))
	return s_box

def s_box_inversion (s_box):
	inv_s_box = np.zeros(s_box.shape, np.uint8)
	for i in range(256):
		inv_s_box[s_box[i]] = i
	return inv_s_box

def rcon_gen ():
	# Création des constantes de rondes:
	# 10 rounds et 14 constantes
	mod_pol = 0b100011011
	rcon = np.zeros((10,), np.int)
	rcon[0] = 1
	for i in range(1, 10):
		rcon[i] = poly_mult(rcon[i-1], 2, mod_pol)
	# The other (LSB) three bytes of all round constants are zeros
	rcon = np.concatenate((np.matrix(rcon).T, np.zeros((10,3), np.int)), axis=1)
	return rcon

def sub_bytes (bytes_in, s_box):
	in_array = np.array(bytes_in, ndmin=2)
	return s_box[in_array]

def cycle (matrix_in, **dict):
	# direction: -1 = gauche, 1 = droite
	if 'direction' in dict and dict['direction'] in [-1,1]:
		direction = dict['direction']
	else:
		direction = -1 # gauche par défaut
	matrix_out = np.array(matrix_in)
	for i in range(4): # boucle sur le nombre de lignes
		matrix_out[i] = np.roll(matrix_out[i], i * direction)
	return matrix_out

def poly_mat_gen ():
	row = [ 0x2, 0x3, 0x1, 0x1]
	rows = np.matlib.repmat(row, 4, 1)
	poly_mat = cycle(rows, direction=1)
	return poly_mat

def inv_poly_mat_gen ():
	row = [ 0xe, 0xb, 0xd, 0x9]
	rows = np.matlib.repmat(row, 4, 1)
	inv_poly_mat = cycle(rows, direction=1)
	return inv_poly_mat

def key_expansion (key, s_box, rcon):
	# creates the 44x4-byte expanded key W
	key = np.array(key)
	if ( not isinstance(key,np.ndarray)) | key.size != 16 :
		raise Exception('Key has to be a vector (not a cell array) with 16 elements.')
	if np.any(key < 0) | np.any(key > 255):
		raise Exception('Elements of key vector have to be bytes (0 <= key(i) <= 255).')
	w = np.reshape(key, (4, 4))
	#Loop over the rest of the 44 rows of the expanded key
	for i in range(4, 44):
		temp = np.array(w[i - 1])
		if i % 4 == 0:
			# Rotation cyclique de 1 vers la gauche
			temp = np.roll(temp, -1)
			# Substitutions des octets par la S-box
			temp = sub_bytes (temp, s_box)
			r = rcon[i/4 - 1]
			temp = temp ^ r
		to_add = np.matrix(w[i - 4] ^ temp)
		w = np.concatenate((w, to_add))
	return w

def add_round_key (state_in, round_key):
	return state_in ^ round_key

def shift_rows (state_in):
	return cycle(state_in, direction=-1)

def inv_shift_rows (state_in):
	return cycle(state_in, direction=1)

def mix_columns (state_in, poly_mat):
	mod_pol = 0b100011011
	state_out = np.zeros((4,4), np.int)
	for i_col_state in range(4):
		for i_row_state in range(4):
			temp_state = 0
			for i_inner in range(4):
				temp_prod = poly_mult(poly_mat[i_row_state, i_inner], state_in[i_inner, i_col_state], mod_pol)
				temp_state = temp_state ^ temp_prod
			state_out[i_row_state, i_col_state] = temp_state
	return state_out

def cipher (plaintext, w, s_box, poly_mat, nb_ronde_max=9, **dict):
	if 'verbose' in dict and dict['verbose'] == True:
		verbose = True
	else:
		verbose = False
	if ( not isinstance(plaintext,np.ndarray)) | plaintext.size != 16 :
		raise Exception('Plaintext has to be a vector (not a cell array) with 16 elements.')
	if np.any(plaintext < 0) | np.any(plaintext > 255):
		raise Exception('Elements of plaintext vector have to be bytes (0 <= plaintext(i) <= 255).')
	if ( not isinstance(w, np.ndarray) ) | ( w.shape != (44, 4) ) :
		raise Exception('w is of shape: ' + str(w.shape))
	if np.any(w < 0) | np.any(w > 255):
		raise Exception('Elements of key array w have to be bytes (0 <= w(i,j) <= 255).')
	state = np.reshape(plaintext, (4, 4)).T # On transpose pour avoir les memes resultats que dans Matlab
	if verbose:
		print('État initial: ' + str(state))
	round_key = w[0:4].T
	state = add_round_key(state, round_key)
	for i_round in range(1, nb_ronde_max + 1):
		if verbose:
			print('Round ' + str(i_round) + ' initial: ' + str(state))
		state = sub_bytes(state, s_box)
		if verbose:
			print('Round ' + str(i_round) + ' après sub_bytes: ' + str(state))
		state = shift_rows(state)
		if verbose:
			print('Round ' + str(i_round) + ' après shift_rows: ' + str(state))
		state = mix_columns (state, poly_mat)
		if verbose:
			print('Round ' + str(i_round) + ' après mix_columns: ' + str(state))
		round_key = w[np.arange(4) + 4*i_round].T
		if verbose:
			print('Round ' + str(i_round) + ' clé: ' + str(round_key))
		state = add_round_key(state, round_key)
	# Dernier round:
	if verbose:
		print('Round ' + str(nb_ronde_max + 1) + ' initial: ' + str(state))
	state = sub_bytes(state, s_box)
	if verbose:
		print('Round ' + str(nb_ronde_max + 1) + ' après sub_bytes: ' + str(state))
	state = shift_rows (state)
	if verbose:
		print('Round ' + str(nb_ronde_max + 1) + ' après shift_rows: ' + str(state))
	round_key = w[40:44].T
	state = add_round_key(state, round_key)
	if verbose:
		print('État final: ' + str(state))
	return np.reshape(np.array(state.T), (16,)) # On reprend la transposée pour contrebalancer le debut

def inv_cipher(ciphertext, w, inv_s_box, inv_poly_mat, **dict):
	if 'verbose' in dict and dict['verbose'] == True:
		verbose = True
	else:
		verbose = False
	if ( not isinstance(ciphertext,np.ndarray)) | ciphertext.size != 16 :
		raise Exception('Plaintext has to be a vector (not a cell array) with 16 elements.')
	if np.any(ciphertext < 0) | np.any(ciphertext > 255):
		raise Exception('Elements of ciphertext vector have to be bytes (0 <= ciphertext(i) <= 255).')
	if ( not isinstance(w, np.ndarray) ) | ( w.shape != (44, 4) ) :
		raise Exception('w is of shape: ' + str(w.shape))
	if np.any(w < 0) | np.any(w > 255):
		raise Exception('Elements of key array w have to be bytes (0 <= w(i,j) <= 255).')
	state = np.reshape(ciphertext, (4, 4)).T # On transpose pour avoir les memes resultats que dans Matlab
	round_key = w[40:44].T
	state = add_round_key(state, round_key)
	for i_round in range(9, 0, -1):
		state = inv_shift_rows (state)
		state = sub_bytes (state, inv_s_box)
		round_key = w[np.arange(4) + 4*i_round].T
		state = add_round_key(state, round_key)
		state = mix_columns (state, inv_poly_mat)
	# Dernier round:
	state = inv_shift_rows (state)
	state = sub_bytes(state, inv_s_box)
	round_key = w[0:4].T
	state = add_round_key(state, round_key)
	return np.reshape(np.array(state.T), (16,)) # On reprend la transposée pour contrebalancer le debut

def chiffrement (plaintext, key, R=9):
	s_box = s_box_gen()
	rcon = rcon_gen()
	poly_mat = poly_mat_gen()
	k = key_expansion (key, s_box, rcon)
	return cipher(plaintext, k, s_box, poly_mat, R)

def dechiffrement (ciphertext, key):
	s_box = s_box_gen()
	rcon = rcon_gen()
	inv_s_box = s_box_inversion(s_box)
	inv_poly_mat = inv_poly_mat_gen()
	k = key_expansion (key, s_box, rcon)
	return inv_cipher(ciphertext, k, inv_s_box, inv_poly_mat)
