# -*- coding: utf-8 -*-

# This file of utilities for adso was written by Chris Drost of drostie.org 
# in the year 2010. To the extent possible by law, I hereby waive all 
# copyright and any related rights to this code under the Creative Commons 
# Zero waiver/license, which you may read online at:
#
#     http://creativecommons.org/publicdomain/zero/1.0/legalcode
#
# This means that you may copy, distribute, modify, and use my code without any 
# fear of lawsuits from me. As it says at the above URL, my code is provided 
# with NO WARRANTIES OF ANY KIND. I do humbly request that you provide me some 
# sort of attribution or credit if you use it; but I leave that decision up to 
# you. 

from array import array
from sys import stdout
from termios import TIOCGWINSZ as window_size
from fcntl import ioctl 
from math import ceil
import re

lmap = lambda fn, ls: list(map(fn, ls))

def _terminal_width():
	four_bytes = b'\x00\x00\x00\x00'
	return array('H', ioctl(stdout, window_size, four_bytes))[1]

def terminal_display(string_list):
	w = _terminal_width()
	def flatten(str_list, pad):
		L = max(map(len, str_list)) + pad
		for i in range(0, len(str_list)):
			while len(str_list[i]) < L:
				str_list[i] += " "
		return str_list
	
	def arrange(cols):
		i = 0
		rows = lmap(lambda x: "    ", range(0, ceil(len(string_list) / cols)))
		for string in string_list:
			rows[i] += string
			i = (i + 1) % len(rows)
			if i == 0:
				flatten(rows, 2)
		return flatten(rows, 0)
	
	base = max(1, w // max(map(len, string_list)))
	base_out = arrange(base)
	while True:
		if base > len(string_list):
			print("\n".join(base_out))
			return
		base += 1
		test = arrange(base)
		if len(test[0]) > w:
			print("\n".join(base_out))
			return
		else:
			base_out = test

def walk(tree, fn):
	"""Processes every element in `tree` with `fn`, replacing it.
	
	This function is substantially similar to JSON "revivers", except that 
	Python does not have an ancillary "undefined" type to use, as distinct from 
	`None`, to delete a key. This implementation uses the empty tuple `()` as 
	an undefined type for this purpose: if your function returns `()` then the
	key will be deleted.
	
	"""
	def recurse(obj, key, val):
		# first we recurse over the children of obj[key] == value:
		if isinstance(val, dict):
			for subkey in val:
				recurse(val, subkey, val[subkey])
		elif isinstance(val, list):
			for subkey in range(0, len(list)):
				recurse(val, subkey, val[subkey])
		# then we replace obj[key] with fn(obj, key, val)
		val = fn(obj, key, val)
		if type(val) == tuple and len(val) == 0:
			del obj[key]
			return None
		else:
			obj[key] = val
			return val
	
	return recurse({"": tree}, "", tree)

class traversible:
	"""A dict-like class which implements traversal by POSIX-style paths.
	
	Basically, you can easily create them from dicts:
		x = traversible.from_tree({"abc": { "a": 0 }, "def": {"b": 1}})
	At which point you can then refer to:
		x['abc']['/def']['../abc/a']
	On a bash shell, this would look like:
		cd abc
		cd /def
		echo ../abc/a
	You can also request the traversible to make new subtrees and such:
		x.mkdir("ghi")
		x["/ghi/c"] = 2
	The flexibility comes at a simple cost: keys can no longer contain forward 
	slashes, and cannot be '.', '..', or ''. 
	"""
	def _absorb_dict(self, d):
		"""Inserts key-value pairs from the given dict into this traversible. 
		If a dict is encountered as a child of d, that dict is also converted 
		into a traversible with this method. An improper state may result if 
		you absorb a dict which contains keys that you already have."""
		for key in d:
			if '/' in key or key in ('', '.', '..'):
				raise ValueError("Non-traversible key in dictionary: '%s'" % key)
			if key in self.contents:
				del self[key]
			if isinstance(d[key], dict):
				self[key] = traversible(d[key], key, self)
			else:
				self[key] = d[key]
	
	def ls(self, pretty_print=False):
		dir_postfix = lambda s: s + '/' if isinstance(self.contents[s], traversible) else s
		keys = sorted([dir_postfix(key) for key in self.contents.keys()])
		if pretty_print:
			print(self.path + " :: ")
			terminal_display(keys)
		else:
			return keys
	
	def __init__(self, from_dict=None, key="<?>", parent=None):
		if parent == None:
			self.parent = self
			self.root = self
			self.path = '/' 
		else:
			self.parent = parent
			self.root = parent.root
			if parent.path == '/':
				self.path = '/' + key
			else:
				self.path = parent.path + '/' + key
		self.contents = {}
		if from_dict != None:
			self._absorb_dict(from_dict)
	
	def _as_dict(self, recurse=True):
		output = {}
		for key in self.contents:
			if recurse and isinstance(self.contents[key], traversible):
				output[key] = self.contents[key]._as_dict()
			else:
				output[key] = self.contents[key]
		return output
	
	def __repr__(self):
		return "adso.utils.traversible(from_dict=%s)" % repr(self._as_dict())
	
	def traverse(self, path):
		"""Traverses a set of adso.utils.traversible objects with a POSIX-style path."""
		if path == '':
			return self
		# leading / starts at root:
		current = self.root if path[0] == "/" else self  
		path = path.split('/')
		end = len(path) - 1
		subpath = lambda k: '/'.join(path[0:k])
		for i in range(0, len(path)):
			key = path[i]
			if not isinstance(current, traversible):
				raise KeyError("Is not traversible: '%s'" % subpath(i))
		
			if key == "..":
				current = current.parent
			elif key in ("", "."):
				pass
			else: 
				if key not in current.contents:
					raise KeyError("Does not exist: '%s'" % subpath(i + 1))
				current = current.contents[key]
		return current
	
	def mkdir(self, path):
		"""Makes a subdirectory which is also traversible."""
		(container, name) = self._get_dir(path)
		if name in container.contents:
			raise ValueError("Already exists: '%s/%s'" % (container.path, name))
		elif '/' in name or name in ('', '.', '..'):
			raise KeyError("Invalid path label: '%s'" % name)
		else:
			container.contents[name] = traversible(key=name, parent=self)
			return container.contents[name]
	
	def remove(self, item_name):
		"""Removes an item from this directory. All other methods which might 
		remove an item from a directory tree ultimately call this method on the 
		containing directory, so that overriding this method will also allow 
		you to "catch" items as they are removed from the directory tree. This 
		method occurs *after* POSIX-style path resolution has occurred."""
		del self.contents[item_name]
	
	def __getitem__(self, path):
		return self.traverse(path)
	
	def __setitem__(self, path, value):
		(container, name) = self._get_dir(path)
		if name not in container.contents:
			container.contents[name] = value
		elif isinstance(container.contents[name], traversible):
			raise ValueError("Is a directory: %s" % path )
		elif '/' in name or name in ('', '.', '..'):
			raise ValueError("Invalid path label: '%s'" % name)
		else:
			container.remove(name)
			container.contents[name] = value
	
	def __delitem__(self, path):
		(container, name) = self._get_dir(path)
		container.remove(name)
	
	def __iter__(self):
		return self.contents.__iter__()
	
	def keys(self):
		return self.contents.keys()
	
	def __contains__(self, val):
		return val in self.contents
	
	def _get_dir(self, path):
		"""Returns (directory, filename) [types:: (traversible, str)]. 
		
		This does not follow the last segment of the path because in cases like 
		__setitem__ and mkdir(), where that path doesn't yet exist, this would 
		raise an error, and in cases where you .remove() something, you want to 
		call the containing directory's .remove() function.

		"""
		# in self.mkdir('/dir/subdir/abc/'), name = 'abc', data[0] = 'abc/' 
		data = re.search(r"([^/]*)/?$", path)
		name = data.group(1)
		# we strip off data[0] to create '/dir/subdir/', and travel there.
		container_path = path[:-len(data.group(0))]
		container = self.traverse(container_path)
		if not isinstance(container, traversible):
			raise ValueError("Not a directory: %s" % container_path)
		return (container, name)
