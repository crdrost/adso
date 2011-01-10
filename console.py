# -*- coding: utf-8 -*-
import sys

running = True

class ParseIncomplete(SyntaxError):
	pass
class ParseError(SyntaxError):
	pass

class DefaultParser:
	def __init__(self, text):
		self.line = text
		self.at = 0
		self.end = len(text)
	def peek(self):
		return self.line[self.at] if self.at < self.end else None
	def next(self):
		k = self.peek()
		self.at += 1
		return k
	def done(self):
		return self.at >= self.end
	def parse_single_quote(self):
		token = ""
		self.next() # ignore leading quote.
		while self.peek() != "'":
			if self.done(): 
				raise ParseIncomplete()
			token += self.next()
		self.next() # skip trailing single quote
		return token
	def parse_double_quote(self):
		token = ""
		self.next() # ignore leading double-quote.
		while self.peek() != '"':
			if self.done():
				raise ParseIncomplete()
			elif self.peek() == '\\':
				self.next()
				if self.done():
					raise ParseIncomplete()
				elif self.peek() == '\n':
					self.next() # preceding slash suppresses newlines
				elif self.peek() in '"\\':
					token += self.next()
				else:
					token += '\\'
			else:
				token += self.next()
		self.next() # skip trailing double-quote
		return token
	def skip_whitespace(self):
		while not self.done() and self.peek() in ' \t\n\\':
			if self.peek() == '\\':
				self.next()
				if self.done():
					raise ParseIncomplete() 
				elif self.peek() == "\n":
					# this is the only valid use of a backslash as whitespace.
					self.next()
				else:
					self.at -= 1 # backslash forms part of a token.
					return
			else:
				self.next()
	def parse_token(self):
		token = ""
		while not self.done() and self.peek() not in ' \t\n':
			current = self.peek()
			if current == '\\':
				self.next()
				if self.done():
					raise ParseIncomplete()
				elif self.peek() in " \t\\'\"":
					token += self.next()
				elif self.peek() == '\n':
					self.next()
				else:
					token += '\\'
			elif current == "'":
				token += self.parse_single_quote()
			elif current == '"':
				token += self.parse_double_quote()
			else:
				token += self.next()
		return token
	
	@classmethod
	def parse(cls, line, context=None):
		parser = DefaultParser(line)
		parser.skip_whitespace()
		tokens = []
		while not parser.done():
			tokens.append(parser.parse_token())
			parser.skip_whitespace()
		return tokens
	
	@classmethod
	def is_incomplete(cls, line, context):
		try:
			cls.parse(line, context)
			return False
		except ParseIncomplete:
			return True
		except ParseError:
			return False

def list_commands(commands):
	def out_fn(tokens, context):
		"""
		This is the default help prompt that comes with the adso.console. It 
		mostly just echoes Python docstrings when you type something like:
			> help command
		Thus, it is up to 
		"""
		if len(tokens) == 1:
			message = "The following commands are defined:\n"
			c_list = list(commands.keys())
			c_list.sort()
			for key in c_list:
				message += "    %s\n" % key
			message += "Type `%s command` for more information on that command." % tokens[0]
			return message
		if len(tokens) == 2:
			if tokens[1] in commands:
				doc = commands[tokens[1]].__doc__
				return doc if doc != None else \
					"No documentation is available for '%s'." % tokens[1]
			else:
				return "The command '%s' is not defined in this console." % tokens[1]
		
		return "Error: %s takes 0 or 1 arguments." % token[0]
	return out_fn

def console_exit(tokens, context):
	"""This is the default quit function that comes with adso.console."""
	raise EOFError()

def init(commands, context={}, parser=DefaultParser):
	"""Initializes an adso.console. 
	
	The adso.console module is a helper module for the adso.passwords module; it 
	provides a clean shell with a familiar user-interface for issuing python 
	commands to an underlying process. The first argument, commands, is a 
	dictionary of functions which can be referred to by name; all of them should
	accept two arguments: an array of string tokens and a context dictionary. 
	They should also have a docstring, which will be echoed when the built-in 
	help command is run on them. 
	
	The context dictionary may optionally be defined before init() and passed in 
	as the second argument. It has one built-in key, context['prompt'], which 
	gives the initial prompt to be echoed before the user types in a command. 
	Finally, the parser itself appears as another optional argument.
	"""
	# We initialize some basic commands: help and quit:
	if 'help' not in commands:
		commands['help'] = list_commands(commands)
		print("Type 'help' for a list of commands.")
	if 'quit' not in commands:
		commands['quit'] = console_exit
		print("Type 'quit' to exit this prompt.")
	# We also initialize some basic context variables:
	if 'prompt' not in context:
		context['prompt'] = '$'
	# the current line, in case people want to use multi-line commands.
	# whether a command is multi-line depends upon the parser's judgment.
	current_line = "" 
	try: 
		# This loop continues until an EOFError is thrown, this allows you to 
		# use Python's Ctrl-D to exit a console. The quit() command will also
		# provide this error if it is not overridden by the calling script.
		while True:
			try: 
				# read input and enable line continuations:
				prompt = context['prompt'] if current_line == "" else ">"
				current_line += input(prompt + " ")
				if parser.is_incomplete(current_line, context):
					current_line += "\n"
					continue
				# then try to evaluate it, if there are no parsing errors:
				try: 
					tokens = parser.parse(current_line, context)
					if len(tokens) == 0:
						current_line = ""
						continue
					if tokens[0] not in commands:
						print("'%s' is not recognized as a command at this prompt." % tokens[0])
					else:
						print(commands[tokens[0]](tokens, context))
				except ParseError as p:
					print("Syntax error: %s" % p)
			except KeyboardInterrupt:
				print("^C")
			current_line = ""
	except EOFError:
		print()
		return
