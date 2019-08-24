# boxcryptor-decryptor
Single file decryption for Boxcryptor. There is also a [Go version](https://github.com/janiko71/boxcryptor-decryptor-go).

## What is Boxcryptor
Boxcryptor is a commercial software (though you can use it freely with limitations) that encrypts files in the cloud in its largest a  acceptance, that means OneDrive (Microsoft), Google Drive, iCloud (Apple), ownCloud, Box, Dropbox, etc.
All compatibles products are listed [here](https://www.boxcryptor.com/fr/providers/).

## Why this program?
Because I'm paranoid (I'm working in a big european bank as security officer/expert), and I wanted to understand the crypto process of the Boxcryptor solution (zero-knowledge based). The best way to do that is to write my own decrypting program, in Python 3 (because I like Python 3).
Secondly, like every commercial program, you can't access the source code to audit it, and the documentation is often too incomplete for auditing purpose. 
And, at last, in the unlikely case of the company disapear, or if the executable files are lost or too old to be used, you may want a program to decrypt your files. That's what is done here.

### Is there an official program for that?
Of course, the Boxcryptor solution encrypts and decrypts the files _on the fly_, and seems to work well. But as I've said, you can't audit the code. To prevent this, the editor published a decryptor (in Java and C++) here:
* https://github.com/secomba/boxcryptor-single-file-decryptor

Like my work, their programs are not really intended to be production-grade programs, but having this source code is a good way to understand how their crypto process works. As a challenge, I wanted to do a decryptor by myself, and because I have no relation with the editor, you have here an independant way of understanding it and to decrypt your files.

## How to use it?

### First, get the crown jewels: the crypto keys 
You need to get a copy of the crypto information stored by Boxcryptor, 
More information  here:
* https://www.boxcryptor.com/en/key-management/
* https://www.boxcryptor.com/en/help/boxcryptor-account/windows/#export-your-keys/

You'll get a .bckey file. This file is very important and need some protection, even if you still need your Boxcryptor account's password  to decrypt your files (see below).

### Secondly: your account password
As a zero-knowledge solution, even with the previous file you won't be able to decrypt anything. So always remember your (strong) password, and keep it in a safe place (like [KeePass](https://keepass.info/)).

### Install Python 3 and the requested modules
To be completed, but Python 3 with the [Cryptography](https://cryptography.io/en/latest/) module are mandatory.

## So,what is my conclusion?
First I'm proud of myself: I've understood all the underlying crypto! And coded all that into Python! And it works!

Besides, I can see that Boxcryptor do what they say: they have implemented a zero-knowledge solution. That means that, without your password, nobody can decrypt your files, even them. But as usual, the ultimate proof of confidence would be to assess that your password is stored anywhere... 

With my laptop, I've decrypted an .iso file (1.81Go) in 163 sec.
