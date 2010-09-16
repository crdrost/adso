# d.o adso

adso is a modular JSON encryptor and password archive based upon [PySkein][1]. The package was named after a monk ("Adso of Melk") in Umberto Eco's book, *The Name of the Rose*. It is designed to, at its lowest level, provide *adso data storage objects* for storing arbitrary encrypted JSON, which can be done as follows:

	>>> from adso import adso
	>>> obj = adso({'some sort of': 'encrypted data', 'in': ['JSON', 'formats', 123]})
	>>> obj.description = "Test adso file. Password is 'abba'."
	>>> obj.to_file('/tmp/test.adso')
	Please provide the password for this adso object:
	Saved to '/tmp/test.adso'.
	>>> x = obj.from_file('/tmp/test.adso')
	Please provide the password for this adso object:
	>>> x
	<adso.adso("Test adso file. Password is 'abba'.", cipher="adso-threefish512/tctr", prompts=True)>
	>>> x.data
	{'some sort of': 'encrypted data', 'in': ['JSON', 'formats', 123]}

Aside from encrypted data-storage, which is already working, the immediate goal is to have a python-prompt password archiver which works something like this:

	>>> import adso
	>>> p = adso.pwfile('.passwords')
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

At present, this last code is *totally speculative*, but that's the general idea. I am not directly planning a GUI for this project at this moment, but I have designed it to be GUI-friendly, so that if you pass into adso `prompts=False` you turn off the native `getpass()` calls and `print()` statements, so that a GUI can disable them and provide its own interface for setting passwords etc.

The adso objects are designed to be suitably encrypted for revision control: a git-tracked adso password file would enable you to go back and say "what was my old password, again?" without compromising the security of either copy -- both instances are encrypted with totally separate parameters, and even the precise length of the JSON object is obscured with a random-length string. A block cipher `adso-threefish512/tctr` and a stream cipher `adso-skein512` are both available for encryption; the block cipher is used by default above.

It might be possible to get a nice GUI interface acting atop the underlying python program. In particular, there are keywords and properties for disabling the prompts and `getpass()` calls, so that a GUI program can be written without being interrupted by such things. For now, adso is meant to be used with the python3 interactive console.

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
