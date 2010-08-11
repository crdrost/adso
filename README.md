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

It was named after a monk in *The Name of the Rose*, Adso of Melk. In principle, the underlying classes in adso should be able to serialize arbitrary Python dictionaries, via JSON, into an encrypted file. For the immediate future I will probably just use Skein as a stream cipher, but the possibility of using the Threefish block cipher in a tweak-counter chaining mode (64-bit nonce + 64-bit counter as tweak input) should not be discounted. It might be possible to get a nice GUI interface acting atop the underlying python program.

[1]: http://packages.python.org/pyskein/
