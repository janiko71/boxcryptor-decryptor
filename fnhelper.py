import json
import os
import pprint
import base64
import binascii as ba
import getpass

from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives import hashes

# ---------------------------------------------------
#
#     Some useful functions
#
# ---------------------------------------------------



"""
    Unique block init vector calculation
"""
    
def compute_block_iv(cipher_iv, seed, key, backend):

    """
        This function computes the initialization vector for every
        encrypted block in the data file. Every block has its own
        init vector, to prevent cryptoanalyzing.

        The init vector is the first part of a HMAC calculated from
        the data file init vector, a seed (which is simply the block
        number, and the file's AES key)
    """

    tmp_data = bytearray(8)
    tmp_data[0:8] = cipher_iv

    for i in range(0,8):
        b = seed & 255
        tmp_data.append(b)
        seed = seed >> 8

    h = hmac.HMAC(key, hashes.SHA256(), backend=backend)
    h.update(bytes(tmp_data))
    tmp_buffer = h.finalize()

    res = tmp_buffer[0:len(cipher_iv)]
    
    return res



"""
    Printing files info
"""

def print_data_file_info(data_file):

    print('-'*72)
    print("File version.................. " + data_file.version)
    print("File size..................... " + str(data_file.file_size))
    print("Header length................. " + str(data_file.header_core_length))
    print("Header padding length......... " + str(data_file.header_padding_length))
    print("Cipher padding length......... " + str(data_file.cipher_padding_length))
    print('-'*72)
    print(data_file.crypto_json)
    print('-'*72)
    print(data_file.hash) # SHA384 of smth ?
    print('-'*72)

    print("Algo.......................... {} ({} bits)".format(data_file.cipher_algo, data_file.cipher_keysize))
    print("Bloc mode..................... " + data_file.cipher_mode)
    print("Bloc size..................... " + str(data_file.cipher_blocksize))
    print("Padding type.................. " + data_file.cipher_padding_mode)
    print("File init vector.............. " + data_file.cipher_iv.hex())
    print()

    print("Load id....................... {} (type : {})".format(data_file.file_id, data_file.file_type))

    print()

    print("AES file key, encrypted....... " + data_file.aes_key_encrypted_bytes.hex()[0:100] + "...")
    print('-'*72)

    return


