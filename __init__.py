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

from os import urandom
from adso import ciphers
from random import randint
import skein
import time
import re
from array import array
from datetime import datetime
import base64
from getpass import getpass
import json

## Version identifiers :: gen.syn.vers
# Just to get out my present thinking and why there are three of them:
# The generation number `gen` indicates a limit towards backwards-compatibility
# of the crypto-file syntax: version 1.a.b cannot in general read version 0.c.d. 
# The syntax number `syn` indicates that the syntax has changed, but past versions
# are still supported within that generation. The version number `vers` indicates
# any further change in the API or codebase. 
__version__ = "1.0.0"

_bytes    = lambda x: x.encode('utf-8') if type(x) == str else x
_to_b64   = lambda x: base64.b64encode(_bytes(x)).decode('utf-8')
_from_b64 = lambda x: base64.b64decode(_bytes(x))

def _hash(message, length, pers, **kwargs):
	for key in kwargs:
		kwargs[key] = _bytes(kwargs[key])
	pers = b'20100914 spam@drostie.org adso/' + pers.encode('utf-8')
	s = skein.skein512(digest_bits=length, pers=pers, **kwargs)
	s.update(_bytes(message))
	return s.digest()

def _mac(message, key, nonce):
	return _to_b64(_hash(message, 512, 'mac', mac=key, nonce=nonce))

__prng_state = urandom(64)
def randstring(bits):
	"Produces a random base64-encoded string with the adso PRNG."
	global __prng_state
	nonce = "atime:" + str(time.clock()) + ",systime:" + str(time.time())
	h = _hash(__prng_state, 512 + bits, 'randstring', nonce=nonce)
	__prng_state = h[0:64]
	return _to_b64(h[64:])

def encrypt(cipher, key, iv, data):
	if cipher in ciphers.supported:
		return ciphers.encryptors[cipher](key, iv, data)
	else:
		raise ValueError('Cipher "%s" not supported by this adso instance.' % cipher)

def decrypt(cipher, key, iv, data):
	if cipher in ciphers.supported:
		return ciphers.decryptors[cipher](key, iv, data)
	else:
		raise ValueError('Cipher "%s" not supported by this adso instance.' % cipher)

class adsoSyntaxError(ValueError):
	def __init__(self, message, data):
		self.data = data
		self.message = message
	def __str__(self):
		return repr(self.message)

class PasswordIncorrect(ValueError):
	def __init__(self):
		self.message = "Incorrect password specified."
	def __str__(self):
		return repr(self.message)

class PasswordUnavailable(ValueError):
	def __init__(self):
		self.message = "No password was available to do the encryption/decryption."
	def __str__(self):
		return repr(self.message)

class adso:
	def __init__(self, data={}, cipher=ciphers.supported[0], password=None, prompts=True, description="<No description provided.>"):
		self.prompts = prompts
		self.password = password
		self.cipher = cipher
		self.data = data
		self.description = description
	
	def __repr__(self):
		return '<adso.adso(%s, cipher="%s", prompts=%s)>' % \
			(json.dumps(self.description), self.cipher, str(self.prompts))
	
	@classmethod
	def fromfile(c, filename, **kwargs):
		#We let any IOErrors propagate to the end user.
		with open(filename, "r") as f:
			return adso.fromstring(f.read(), **kwargs)
	
	@classmethod
	def fromstring(c, source, **kwargs):
		try:
			data = json.loads(source)
		except ValueError:
			raise adsoSyntaxError('Not a JSON string', source)
		return adso.fromdict(data, **kwargs)
	
	@classmethod
	def fromdict(c, source, prompts=True, password=None):
		# we do a bunch of quick checks to make sure that the data is ok
		if 'adso' not in source:
			raise adsoSyntaxError('Not an adso object', source)
		
		data = source['adso']
		
		if 'version' not in data:
			raise adsoSyntaxError('No version identifier', source)
		
		version_split = lambda s: map(int, s.split("."))
		refgen = version_split(__version__).__next__()
		try:
			(gen, syn, vers) = version_split(data['version'])
		except ValueError:
			raise adsoSyntaxError('Invalid version identifier', source)
		if gen != refgen:
			raise adsoSyntaxError('Expected version %s.x.y, instead saw %s' % (refgen, data['version']), source)
		
		# Parse rules for this generation of syntax. At this point we assume
		# that the syntax is correct and allow the user to debug whatever invalid
		# syntax errors exist by hand. This tool should never produce them.
		if password == None:
			if prompts: 
				password = getpass('Please provide the password for this adso object: ')
			else:
				raise PasswordUnavailable()
		
		if syn == 0:
			obj = decrypt(data['cipher'], password, data['nonce'], _from_b64(data['crypt']))
			mac = _mac(obj, password, data['nonce'])
			if mac != data['mac']:
				print(obj); print(mac); print(data['mac'])
				raise PasswordIncorrect()
			obj = json.loads(obj.decode('utf-8'))['data']
			return adso(
				data = obj, cipher = data['cipher'], password = password, 
				prompts = prompts, description = source['description'], 
			)
		
		else:
			raise adsoSyntaxError('Unexpected syntax version: %s.%s' % (gen, syn))
	
	def to_file(self, filename):
		with open(filename, 'w') as f:
			f.write(self.to_str())
	
	# I have made the string representation fundamental because I want the JSON 
	# strings generated by adso to have a certain human-intuitive order which 
	# dictionaries don't need to provide. This is also why there are numbers in
	# the adso keys. The dict representation is just a JSON parse of this.
	def to_str(self):
		if self.password != None:
			password = self.password
		elif self.prompts: 
			password = getpass('Please provide the password for this adso object: ')
		else:
			raise PasswordUnavailable()
		self.password = password
		
		nonce = randstring(256)
		# include a padding string to disguise length changes in the document.
		pad = "".join(map(lambda x: str(x % 10), range(0, randint(0, 500))))
		core = json.dumps({'pad': pad, 'data': self.data})
		
		#The numbers are just to preserve the sort order; they get removed.
		basis = json.dumps({
			"1description": self.description,
			"2last modified": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%fZ"),
			"3adso": {
				"1version": __version__,
				"2cipher": self.cipher,
				"3nonce": nonce,
				"4mac": _mac(core, password, nonce),
				"5crypt": _to_b64(encrypt(self.cipher, password, nonce, core))
			}
		}, sort_keys=True, indent=4)
		
		return re.sub(r'(\n {4,8}")\d', r'\1', basis)
	
	def to_dict(self):
		return json.loads(self.to_str())