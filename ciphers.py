# -*- coding: utf-8 -*-

# This file is a part of adso, which uses PySkein, which is licensed under the 
# GPL. As far as I can understand, this means that this code must also be 
# released under the GPL. Since I don't believe in the value of copyright, I 
# would like apologize to later users for that fact. Nonetheless: 
# 
#     Copyright 2010 Chris Drost
#     
#     adso is free software: it can be redistributed and modified under the 
#     terms of the GNU General Public License, version 3, as published by the 
#     Free Software Foundation. adso is distributed WITHOUT ANY WARRANTIES; 
#     this includes the implied warranties of MERCHANTABILITY and FITNESS FOR A 
#     PARTICULAR PURPOSE. See the license for more details. You should have 
#     received a copy of the license text along with adso, in a text document 
#     named 'COPYING'. If you have not, visit http://www.gnu.org/licenses/ .


import skein
from array import array

supported = []
encryptors = {}
decryptors = {}

def encrypt(cipher, key, iv, data):
	"Encrypts a string of data according to the cipher."
	if cipher in supported:
		return encryptors[cipher](key, iv, data)
	else:
		raise ValueError('Cipher "%s" is not supported by this adso instance.' \
			% cipher)

def decrypt(cipher, key, iv, data):
	"Decrypts a string of data according to the cipher."
	if cipher in supported:
		return decryptors[cipher](key, iv, data)
	else:
		raise ValueError('Cipher "%s" is not supported by this adso instance.' \
			% cipher)


# Cipher names in 'supported' should contain a namespace and a cipher specification.
# They should 

_bytes = lambda x: x.encode('utf-8') if type(x) == str else x
def register(name, enc, dec):
	supported.append(name)
	encryptors[name] = lambda key, iv, data: enc(_bytes(key), _bytes(iv), _bytes(data))
	decryptors[name] = lambda key, iv, data: dec(_bytes(key), _bytes(iv), _bytes(data))
	
def derive_key(key, message, length):
	"Hashes a message with a key to produce a <length>-bit derived key. This function is adso-specific."
	s = skein.skein512(digest_bits=length, mac=key, pers=b'20100914 spam@drostie.org adso/key_derivation')
	s.update(message);
	return s.digest()

__little_endian = not array("L", [1]).tostring()[0]
def _tf_tweak_ctr(i):
	# tweak counter goes 0, 1, 2, ..., not 0, 64. 128, ...
	arr = array('L', [0, i >> 6])
	if not __little_endian:
		arr.byteswap()
	return arr.tostring()

def _tf_encrypt(key, iv, data):
	# adso always uses JSON, so we pad the message with JSON whitespace.
	while len(data) % 64 != 0:
		data += b' '
	cipher = skein.threefish(derive_key(key, iv, 512), _tf_tweak_ctr(0))
	output = b''
	for k in range(0, len(data), 64):
		cipher.tweak = _tf_tweak_ctr(k) 
		output += cipher.encrypt_block(data[k : k + 64])
	return output

def _tf_decrypt(key, iv, data):
	cipher = skein.threefish(derive_key(key, iv, 512), _tf_tweak_ctr(0))
	output = b''
	for k in range(0, len(data), 64):
		cipher.tweak = _tf_tweak_ctr(k)
		output += cipher.decrypt_block(data[k : k + 64])
	return output.strip()

register('adso-threefish512/tctr', _tf_encrypt, _tf_decrypt)

def _skein512stream(key, iv, data):
	stream = array('B', skein.skein512(digest_bits=8 * len(data), mac=key, nonce=iv).digest())
	for i in range(0, len(data)):
		stream[i] ^= data[i]
	return stream.tostring()

# I would label this as stream-skein512, but the above breaks the spec in a 
# subtle way: in the Skein spec, digest_bits should be set to a special value, 
# since you don't always know the length of the message in advance.
register('adso-skein512', _skein512stream, _skein512stream)
