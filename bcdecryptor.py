#!/usr/bin/env python3
# ----------------------------------------------------------
#
#                   Boxcryptor Decryptor
#
# ----------------------------------------------------------

#
# This program is intended to decrypt a SINGLE encrypted file (what a surprise!)
# from the Boxcryptor solution.
#

"""
    Standard packages
"""

import os
import sys
import pprint
import json
import base64
import binascii as ba
import getpass
import time

from colorama import Fore, Back, Style 


"""
    Crypto packages
"""

from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import keywrap
from cryptography.hazmat.primitives import asymmetric

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


"""
    My packages
"""

import res.bcexportkeyfile as bckeyfile
import res.bcdatafile as bcdatafile
import res.fnhelper as helper



# ===========================================================================
#
#   main() program
#
# ===========================================================================


# -----------------------------------------------------------------
#
#  Reading arguments (in command line or in some configuration)
#
# -----------------------------------------------------------------

"""
    Here we read the Boxcryptor exported keys.
    The default filepath can be:
        - Passed in command line
        - Read in a config file (filepath : ALT_BCKEY_FILEPATH_CONFIGFILE)
        - Else we use a default one, hard coded in DEFAULT_BCKEY_FILEPATH
"""

DEFAULT_BCKEY_FILEPATH        = "export.bckey"
ALT_BCKEY_FILEPATH_CONFIGFILE = "bckey.txt"

arguments = helper.check_arguments(sys.argv)

if (arguments == None):
    exit()

"""
    Checking .bckey file argument (filepath)
"""    
if (arguments.get("bckey")):
    
    # If the .bckey file is provided in command line, we use it
    bckey_filepath = arguments.get("bckey")
    
else:
    
    # no bckey file path provided. Let's check if there's one in a special config
    # file; or else we use the default one.
    if (os.path.isfile(ALT_BCKEY_FILEPATH_CONFIGFILE)):
        
        with open(ALT_BCKEY_FILEPATH_CONFIGFILE,"r",encoding="utf8") as f:
            bckey_filepath = f.read()
            print("Using .bckey filepath found in \'" + ALT_BCKEY_FILEPATH_CONFIGFILE + "\' (" +
                  bckey_filepath + ")")
            
    else:
        
        print("Using default .bckey filepath (" + DEFAULT_BCKEY_FILEPATH +  ")")
        bckey_filepath = DEFAULT_BCKEY_FILEPATH


"""
    Now reading key file (mandatory)
"""
keyfile = bckeyfile.ExportKeyFile(bckey_filepath)


"""
    Reading data filepath
"""
if (arguments.get("file")):
    
    # Data filepath in commande line
    data_filepath = arguments.get("file")
    
else:
    
    # no => input()
    data_filepath = str(input("Data file: "))


"""
    Constructing output file name
"""
encrypted_data_filename = os.path.basename(data_filepath)
encrypted_data_fileext  = encrypted_data_filename[-3:]
data_directory          = os.path.dirname(data_filepath)

if (encrypted_data_fileext != ".bc"):
    print("Error: the file you want to decrypt has a bad suffix (filename:" + encrypted_data_filename + ")")
    exit(1)
else:    
    new_filename = encrypted_data_filename[:-3]

"""
    Reading data file itself
"""

if (os.path.isfile(data_filepath)):
    
    print("Decrypting \'" + data_filepath + "\' file")
    data_file = bcdatafile.DataFile(data_filepath)
    
else:
    
    print("File \'" + data_filepath + "\' not found!")
    exit()

"""
    Reading user's password
"""
if (arguments.get("pwd")):
    
    # password in command line
    pwd = arguments.get("pwd")
    
else:
    
    # no => input()
    pwd = str(getpass.getpass(prompt="Boxcryptor password :"))


"""
    Printing files info
"""
print('-'*72)
helper.print_parameter("Data directory", data_directory)
helper.print_parameter("File name (input)", encrypted_data_filename)
helper.print_parameter("File name (output)", new_filename)
helper.print_data_file_info(data_file)
 


# -----------------------------------------------------------------
#
#  Constructing crypto elements
#
# -----------------------------------------------------------------

"""
    Crypto init
"""    
backend   = default_backend()


#
# Public key
# ===============
#
# RSA-4096 key is in DER format
# 738 base64 (6-bits) = 123 bytes
#

public_key = serialization.load_der_public_key(
    keyfile.public_key_bytes,
    backend
)
helper.print_parameter("Public key importation", "OK")


#
# Password key
# =================
#
# --> Password key: A "double" AES encryption key derived from your password. The key is created using the key stretching and
#     strengthening function PBKDF2 with HMACSHA512, 10.000 iterations and a 24 byte salt.
#
#     The password key is used to encrypt the user's private key.
#
#     The salt is base64-encode
#     The password should be unicode (UTF8) encoded
#

"""
    Derivation of the user's password
"""
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA512(),
    length=64,
    salt=keyfile.salt_bytes,
    iterations=keyfile.kdf_iterations,
    backend=backend
)

password_key = kdf.derive(pwd.encode())
pwd = None
helper.print_parameter("Password key creation", "OK")


"""
    The result of the derivation function is 64 bytes long.
    
        - The first 32 bytes (256 buts) is used as an AES key
        - The second part is used as a hmac key
"""
crypto_key = password_key[0:32]
hmac_key   = password_key[32:]


#
# Private key
# ===========
#
# --> Private RSA key (encrypted with the user's password)
#     The user’s private key is already encrypted with the user’s password on the client (user device).
#     The encrypted private key is then encrypted again with the database encryption key.
# 
#     The encrypted private key is base64-encoded, and includes:
#
#       . bytes 0->15   : Initialization Vector
#       . bytes 16->47  : Hmac Hash
#       . from byte 48  : Private encrypted key itself
#

given_hmac_hash   = keyfile.encrypted_private_key_bytes[16:48]
private_key_bytes = keyfile.encrypted_private_key_bytes[48:]


"""
    Hmac verification
"""
h = hmac.HMAC(hmac_key, hashes.SHA256(), backend)
h.update(private_key_bytes)
calc_hash = h.finalize()

if (calc_hash == given_hmac_hash):
    
    helper.print_parameter("HMAC verification", "OK")

    
else:
    
    print(Fore.LIGHTWHITE_EX + 'HMAC verification KO' + Fore.RESET)
    print(
        "Problem in HMAC verification; the file may be spoofed waiting"
        +" for {}, found {})\nYou may also mistyped the password.".format(given_hmac_hash.hex(), calc_hash.hex())
    )
    exit()


"""
    Get the init vector
"""
init_vector       = keyfile.encrypted_private_key_bytes[0:16]
helper.print_parameter("Init vector", init_vector.hex())

#
# Now we have everything we need to decrypt the private key
#

cipher = Cipher(algorithms.AES(crypto_key), modes.CBC(init_vector), backend=backend)
decryptor = cipher.decryptor()
the_private_key_bytes = decryptor.update(private_key_bytes)
decryptor.finalize()

the_private_key = serialization.load_der_private_key(
    base64.b64decode(the_private_key_bytes),
    None,
    backend)

helper.print_parameter("Private key decryption and importation", "OK")


#
# --> File key: AES encryption key used to encrypt or decrypt a file. Every file has its own unique and random file key.
#
# file_aes_key_encrypted is the AES key encrypted with the user's public key
#

the_file_aes_key = the_private_key.decrypt(
    data_file.aes_key_encrypted_bytes,
    asymmetric.padding.OAEP(
        mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA1()),
        algorithm=hashes.SHA1(),
        label=None
    )
)
helper.print_parameter("AES file key decryption", "OK")
crypto_key = the_file_aes_key[32:64]
#print_parameter("AES file key", crypto_key.hex()) ==> only if you want it
print('-'*72)




# -----------------------------------------------------------------
#
#  Data file decryption
#
# -----------------------------------------------------------------

#
# Decrypt the encrypted file key using the user’s private key. Decrypt the encrypted data using the file key.
#
#      - Algo AES with a key length of 256 bits,
#      - Mode CBC (Cipher Block Chaining)
#      - Padding PKCS7
#

"""
    Let's calculate the nb of blocks to decrypt. All block are 'data_file.cipher_blocksize', except the last
    which can be shorter, but with cryptography.io module, the padding is automatically done.
"""
offset = 48 + data_file.header_core_length + data_file.header_padding_length
encrypted_data_length = data_file.file_size - offset - data_file.cipher_padding_length
nb_blocks = encrypted_data_length // data_file.cipher_blocksize
if ((encrypted_data_length % data_file.cipher_blocksize) != 0):
    nb_blocks += 1

helper.print_parameter("Encrypted data length", encrypted_data_length)
helper.print_parameter("Offset", offset)
helper.print_parameter("Number of blocks to decrypt", nb_blocks)
print()
print("="*72)
print("Start decrypting...")
print("-"*72)
print()

"""
    Execution time, for information
"""    
t0 = time.time()

"""
    Decrypts all the blocks
"""
f_in  = open(data_filepath, "rb")
f_out = open(new_filename, "wb")   # Yes, we overwrite the output file

# Read the 1st block (header), not used here
f_in.read(offset)

# Now read all the encrypted blocks
for block_nb in range (1, nb_blocks + 1):
    
    block_range = block_nb * data_file.cipher_blocksize
    #block = data_file.raw[block_range:block_range + data_file.cipher_blocksize]
    block = f_in.read(data_file.cipher_blocksize)
    block_length = len(block)
    
    # Compute block IV, derived from IV
    block_iv = helper.compute_block_iv(data_file.cipher_iv, block_nb - 1, crypto_key, backend)

    # Setting parameters for AES decryption (the key and the init vector)
    cipher = Cipher(algorithms.AES(crypto_key), modes.CBC(block_iv), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_block = decryptor.update(block)
    decryptor.finalize()

    # Padding exception for the last block
    progression = (block_nb / nb_blocks * 100)
    print("Fileblock #{}, progression {:6.2f} %".format(block_nb, progression), end="\r", flush=True)
    if (block_nb == nb_blocks):
        decrypted_block = decrypted_block[:-data_file.cipher_padding_length]
    f_out.write(decrypted_block)

f_in.close
f_out.close()

"""
    Execution time, for information
"""    
execution_time = time.time() - t0

print("{} blocks decrypted in {:.2f} seconds".format(nb_blocks, execution_time))

print()
print("-"*72)
print("End of decrypting...")
print("="*72)


#
# Notes:
#
# --> AES keys (encrypted with the user's password / wrapping key)
#
# --> Wrapping key: This key is the root AES key which is used to encrypt all other AES keys stored on our servers.
#
# --> Filename key: This key is used to encrypt filenames if filename encryption is enabled.
