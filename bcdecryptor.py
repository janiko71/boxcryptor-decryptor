# ----------------------------------------------------------
#
#                   BoxCryptor Decryptor
#
# ----------------------------------------------------------

#
# This program is intended to decrypt a SINGLE encrypted file (what a surprise!)
# from the BoxCryptor solution.
#

"""
    Standard packages
"""

import json
import os
import pprint
import base64
import binascii as ba
import getpass


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

import bcexportkeyfile as bckeyfile
import bcdatafile as bcdatafile
import fnhelper




# =================================================================
#
#  main() program
#
# =================================================================

"""
    Here put the BoxCryptor exported keys filepath
"""
BCKEY_FILEPATH = "export.bckey"


"""
    Crypto init
"""    
backend   = default_backend()


"""
    Reading key file
"""
keyfile = bckeyfile.ExportKeyFile(BCKEY_FILEPATH)


"""
    Reading data file
"""    
file_path = str(input("Data file: "))
data_file = bcdatafile.DataFile(file_path)


"""
    Printing files info
"""
fnhelper.print_data_file_info(data_file)



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
print("Public key imported.")


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

pwd     = str(getpass.getpass(prompt="Boxcryptor password :"))


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
print("Password key created.")


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
    print('HMAC verification ok')
else:
    print('HMAC verification KO')
    raise Exception(
        "Problem in HMAC verification; the file may be spoofed waiting for {}, found {})".format(given_hmac_hash.hex(), calc_hash.hex())
    )

"""
    Get the init vector
"""
init_vector       = keyfile.encrypted_private_key_bytes[0:16]
print("Init vector................... " + init_vector.hex())

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

print("Private key decrypted and imported.")


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
print("AES file key decrypted.")
crypto_key = the_file_aes_key[32:64]
#print("AES file key.................. " + crypto_key.hex())
print('-'*72)

#
# DECRYPTION OF DATAS
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

print("Encrypted data length......... "+str(encrypted_data_length))
print("Offset........................ "+str(offset))
print("Number of blocks to decrypt... "+str(nb_blocks))
print()
print("="*72)
print("Start decrypting...")
print("="*72)

for block_nb in range (1, nb_blocks + 1):
    block_range = block_nb * data_file.cipher_blocksize
    block = data_file.raw[block_range:block_range + data_file.cipher_blocksize]
    block_length = len(block)
    
    # Compute block IV, derived from IV
    block_iv = fnhelper.compute_block_iv(data_file.cipher_iv, block_nb - 1, crypto_key, backend)

    # Setting parameters for AES decryption (the key and the init vector)
    cipher = Cipher(algorithms.AES(crypto_key), modes.CBC(block_iv), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_block = decryptor.update(block)
    decryptor.finalize()
    print("(#{}) {}".format(block_nb,decrypted_block))
    print('---')

print("="*72)
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






