import json
import os
import pprint
import base64
import binascii as ba
import getpass

from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives import hashes

from colorama import Fore, Back, Style 

# ---------------------------------------------------
#
#     Some useful functions
#
# ---------------------------------------------------

TERM_UNDERLINE = '\033[04m'
TERM_RESET     = '\033[0m'

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

    tmp_data = bytearray(16)
    tmp_data[0:16] = cipher_iv

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
    Checking the command line arguments
"""

def check_arguments(arguments):

    """
        Check the arguments (if needed)

        :param arguments: list of arguments
        :type arguments: list
        :return: owner ID
        :rtype: string
    """

    new_arguments = {}
    arg_error = False
    b_ind = p_ind = 0

    if (len(arguments) > 1):
        first_arg = arguments[1]
        if (first_arg[0] != '-'):
            new_arguments["file"] = first_arg

    if ("-h" in arguments) | ("--help" in arguments):
        print_help()
        arg_error = True
        
    if ("-b" in arguments):
        b_ind = arguments.index("-b")
    if ("--bckey" in arguments):
        b_ind = arguments.index("--bckey")
    if (b_ind > 0):
        new_arguments["bckey"] = arguments[b_ind + 1]

    if ("-p" in arguments):
        p_ind = arguments.index("-p")
    if ("--pwd" in arguments):
        p_ind = arguments.index("--pwd")
    if (p_ind > 0):
        new_arguments["pwd"] = arguments[p_ind + 1]

    # Sure it can be smarter code...
    if (arg_error):
        return
    else:
        return new_arguments


"""
    Printing help
"""    

def print_help():

    """
        Just print some help to use the program
    """

    print(Fore.LIGHTWHITE_EX + "USAGE" + Fore.RESET + "\n")
    print("\tpython3 bcdecryptor.py [file] [options]\n")
    print(Fore.LIGHTWHITE_EX + "DESCRIPTION" + Fore.RESET + "\n")
    print("\tBoxcryptor decryptor, unofficial Python version. \n")
    print("\tThis program is for information purpose only, no warranty of any kind (see license).\n")
    print("\tThe file you want to decrypt must be the first argument.\n")
    print("\t" + Fore.LIGHTWHITE_EX + "-b,--bckey " + Fore.RESET + TERM_UNDERLINE + "filepath\n" + TERM_RESET)
    print("\t\tFilepath of the exported keys file (endind with .bckey)")
    print("\t\tIf no filepath provided, we'll use the one configured the \'bcdecryptor.py\' file (" +
          Fore.LIGHTWHITE_EX + "BCKEY_FILEPATH " + Fore.RESET + "constant).\n")
    print("\t" + Fore.LIGHTWHITE_EX + "-p,--pwd " + Fore.RESET + TERM_UNDERLINE + "password\n" + TERM_RESET)
    print("\t\tBoxcryptor's user password. If not provided, it will be asked (through the console input).\n")

    return


"""
    Some nice formatting
"""

def print_parameter(txt, param):

    if (type(param) == int):
        param = str(param)
    txt_format = txt.ljust(40,".") + " " + Fore.LIGHTWHITE_EX + param + Fore.RESET
    print(txt_format)

    return

"""
    Printing files info
"""

def print_data_file_info(data_file):

    print('-'*72)
    print_parameter("File version", data_file.version)
    print_parameter("File size", str(data_file.file_size))
    print_parameter("Header length", str(data_file.header_core_length))
    print_parameter("Header padding length", str(data_file.header_padding_length))
    print_parameter("Cipher padding length", str(data_file.cipher_padding_length))
    print('-'*72)
    print(data_file.crypto_json)
    print('-'*72)
    print(data_file.hash) # SHA384 of smth ?
    print('-'*72)

    fparam = "{} ({} bits)".format(data_file.cipher_algo, data_file.cipher_keysize)
    print_parameter("Algo", fparam)
    print_parameter("Bloc mode", data_file.cipher_mode)
    print_parameter("Bloc size", str(data_file.cipher_blocksize))
    print_parameter("Padding type", data_file.cipher_padding_mode)
    print_parameter("File init vector", data_file.cipher_iv.hex())

    fparam = "{} (type : {})".format(data_file.file_id, data_file.file_type)
    print_parameter("Load id", fparam)

    fparam = data_file.aes_key_encrypted_bytes.hex()[0:100] + "..."
    print_parameter("AES file key, encrypted", fparam)
    print('-'*72)

    return


#
# Hey, doc: we're in a module!
#
if (__name__ == '__main__'):
    print('Module => Do not execute')
