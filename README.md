# d.o adso

adso is a modular JSON encryptor and password archive based upon [PySkein][1]. The immediate goal of adso is to be able to have code like this:

	>>> import adso
	>>> p = adso.pwfile('/home/drostie/.passwords')
	Please input the master password for this file:
	Password OK.
	>>> p.grep('drostie.org').grep('email')[0].copy()
	Password for site 'drostie.org', user 'chris' copied to clipboard.
	>>> p.random()
	New random password string copied to clipboard.
	>>> p.add(group='drostie.org', user='newuser', tags='temp', pass='chop suey!')
	New password added. Don't forget to .save() !
	>>> p.grep('temp')[0].delete()
	Password for site 'drostie.org', user 'newuser' moved into the deletion queue.
	See .undelete(). Don't forget to .save() !
	>>> p.save()
	Password file successfully saved.

At present, the above code is *totally speculative*, but that's the general idea.

It is planned to be modular, so that the `adso.adso()` class provides an interface to the generic *adso data serialization objects* which the password archiver uses:

	>>> from adso import adso
	>>> a = adso({'a': 'b', 'c': ['d', 'e', 'f']})
	>>> a.tofile('/tmp/test.adso')
	Please input the master password for this file:
	Saved to '/tmp/test.adso'.
	>>> adso.fromfile('/tmp/test.adso').data
	Please input the master password for this file:
	{'a': 'b', 'c': ['d', 'e', 'f']}

This project can thus act as an Python encryptor for arbitrary JSON data. It is designed to be suitably encrypted for revision control: a git-tracked adso password file would enable you to go back and say "what was my old password, again?" without compromising the security of either copy -- both instances are encrypted with totally separate parameters, and even the precise length of the JSON object is obscured with a random-length string. 

It might be possible to get a nice GUI interface acting atop the underlying python program. In particular, there are keywords and properties for disabling the prompts and `getpass()` calls, so that a GUI program can be written without being interrupted by such things. For now, adso is meant to be used with the python3 interactive console.

The package was named after a monk ("Adso of Melk") in Umberto Eco's book, *The Name of the Rose*. The encryption objects created can also be called adsos in a recursive fashion; they are 'adso data storage objects'.

## License ##
adso uses PySkein, which is licensed under the GPL. As far as I can understand, this means that this code must also be released under the GPL. Since I don't believe in the value of copyright, I would like apologize to later users for that fact. Nonetheless: 

	Copyright 2010 Chris Drost
	adso is free software: it can be redistributed and modified under the 
	terms of the GNU General Public License, version 3, as published by the 
	Free Software Foundation. adso is distributed WITHOUT ANY WARRANTIES; 
	this includes the implied warranties of MERCHANTABILITY and FITNESS FOR A 
	PARTICULAR PURPOSE. See the license for more details. You should have 
	received a copy of the license text along with adso, in a text document 
	named 'COPYING'. If you have not, visit http://www.gnu.org/licenses/ .

[1]: http://packages.python.org/pyskein/ "PySkein"
