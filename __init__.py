# -*- coding: utf-8 -*-
from os import urandom
import skein
import time
from array import array
from datetime import datetime
import base64
from getpass import getpass
import json

__supported_ciphers = [ "skein512/-" ]

## Version identifiers :: gen.syn.vers
# Just to get out my present thinking and why there are three of them:
# The generation number `gen` indicates a limit towards backwards-compatibility
# of the crypto-file syntax: version 1.a.b cannot in general read version 0.c.d. 
# The syntax number `syn` indicates that the syntax has changed, but past versions
# are still supported within that generation. The version number `vers` indicates
# any further change in the API or codebase. 
__version__ = "0.0.0"

# general purpose format conversion methods.
def _converter(switch_dict):
	def output(o):
		t = type(o).__name__
		return switch_dict[t](o) if t in switch_dict else switch_dict['default'](o)
	return output

_bytes = _converter({
	'default': lambda t: array('B', t),
	'dict':    lambda t: array('B', json.dumps(t).encode('utf-8')),
	'str':     lambda t: array('B', t.encode('utf-8'))
})
_to_b64 = _converter({
	'bytes':   lambda t: base64.b64encode(t).decode('utf-8'),
	'str':     lambda t: base64.b64encode(t.encode('utf-8')).decode('utf-8'),
	'default': lambda t: base64.b64encode(array('B', t).tostring()).decode('utf-8')
})
_from_b64 = _converter({
	'str':     lambda t: base64.b64decode(t.encode('utf-8')),
	'default': lambda t: base64.b64decode(t)
})

def _shash(length, msg, nonce, purpose):
	"Produces a salted hash with the given nonce and purpose."
	s = skein.skein512(
		digest_bits = length,
		nonce = nonce.encode('utf-8'),
		pers = b'20100812 spam@drostie.org adso/' + purpose.encode('utf-8')
	)
	s.update(msg)
	return s.digest()

def encrypt(cipher, key, iv, data):
	if cipher == 'skein512/-':
		bytes = _bytes(data)
		stream = _bytes(skein.skein512(
			digest_bits = 8 * len(bytes),
			mac = key.encode('utf-8'),
			nonce = iv.encode('utf-8')
		).digest())
		for i in range(0, len(bytes)):
			stream[i] ^= bytes[i]
		return stream.tostring()
	else:
		raise ValueError('Cipher "%s" not supported by this adso instance.')


def decrypt(cipher, key, iv, bytes):
	if cipher == 'skein512/-':
		# stream ciphers are their own inverses.
		return encrypt(cipher, key, iv, bytes)
	else:
		raise ValueError('Cipher "%s" not supported by this adso instance.')

__prng_state = urandom(64)
def randstring(bits):
	"Produces a random base64-encoded string with the adso PRNG."
	global __prng_state
	t = "atime:" + str(time.clock()) + ",systime:" + str(time.time())
	h = _shash(512 + bits, __prng_state, t, 'rand')	
	__prng_state = h[0:64]
	return _to_b64(h[64:])

class adsoSyntaxError(ValueError):
	def __init__(self, message, data):
		self.data = data
		self.message = message
	def __str__(self):
		return repr(self.message)

class adso:
	def __init__(self, data={}, cipher="skein512/-", password=None, prompts=True, description=None):
		self.prompts = prompts
		self.password = password
		self.cipher = cipher
		self.data = data
		self.description = description
	
	@classmethod
	def fromdict(c, source, prompts=True, password=None):
		# we do a bunch of quick checks to make sure that the data is ok
		if 'adso' not in source:
			raise adsoSyntaxError('Not an adso object', source)
		doc = source['adso']
		if 'version' not in doc:
			raise adsoSyntaxError('No version identifier', source)
		
		version_split = lambda s: map(int, s.split("."))
		refgen = version_split(__version)
		try:
			(gen, syn, vers) = version_split(doc['version'])
		except ValueError:
			raise adsoSyntaxError('Invalid version identifier', source)
		if gen != refgen:
			raise adsoSyntaxError('Expected version %s.x.y, instead saw %s' % (refgen, source['version']), source)
		
		# Parse rules for this generation of syntax. At this point we assume
		# that the syntax is correct and allow the user to debug whatever invalid
		# syntax errors exist by hand.
		if password == None:
			if prompts: 
				password = getpass('Please provide the password for this adso object: ')
			else:
				raise ValueError('No password available to decrypt with.')
		if syn == 0:
			obj = decrypt(
				doc['cipher'], password, 
				doc['nonce'], _from_b64(doc['crypt'])
			)
			try:
				obj = json.loads(obj.decode('utf-8'))
			except ValueError:
				raise ValueError("Incorrect password.")
			return adso(obj, doc['cipher'], password, prompts, source['description'])
		else:
			raise adsoSyntaxError('Unexpected syntax version: %s.%s' % (gen, syn))
	
	def serialize(self):
		if self.password == None:
			if self.prompts: 
				password = getpass('Please provide the password for this adso object: ')
			else:
				raise ValueError('No password available to serialize with.')
		else:
			password = self.password
		self.password = password
		nonce = randstring(240)
		return json.dumps({
			"description": self.description,
			"last modified": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%fZ"),
			"adso": {
				"version": __version__,
				"cipher": self.cipher,
				"nonce": nonce,
				"crypt": _to_b64(encrypt(self.cipher, password, nonce, json.dumps(self.data)))
			}
		}, indent=4);

# Speculation on future file formats:
# {
#     "description": "<<insert arbitrary descriptive data here>>",
#     "last modified": "2010-08-10 00:42:25.658",
#     "adso": {
#         "cipher": "skein512/stream",
#         "version": "0.1",
#         "nonce": "YcYlaxnfPsepRJn686zhENWsiSUvBabqQe/fo6Uo",
#         "salt": "KvUPILdNan5ox7+O/9pv",
#         "verifier": "NpT87UA4P2C3W2WbbbY/In9Xw0c5NLY075xTpVkS/U4="
#         "crypt": encrypt({
#             "padding": "YcYlaxnfPsepRJn686zhENWsiSUvBabqQe/fo6UoYcYlaxnfPsepRJn686zhENWsiSUvBabqQe/fo6UoYcYlaxnfPsepRJn686zhENWsiSUvBabqQe/fo6Uo",
#             "data": {}
#         })
#     }
# }