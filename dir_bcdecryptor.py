#!/usr/bin/env python3
# ----------------------------------------------------------
#
#                   Boxcryptor Decryptor
#
# ----------------------------------------------------------

#
# This program is intended to decrypt an encrypted directory (what a surprise again!)
# from the Boxcryptor solution.
#
# You need to have a backup of your key, and of course the associated password.
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
import logging
import shutil
import unicodedata
from datetime import datetime

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
import res.fnnames as fnnames


#
# --> Log level
#
LOG_LEVEL = logging.DEBUG


# ===========================================================================
#
#   Decryption function
#
# ===========================================================================

output_paths_claimed = set()
output_directories_claimed = set()
nb_skipped_files = 0
nb_skipped_dirs = 0

def output_path_key(path):

    """Portable key for detecting output collisions across case- and normalization-insensitive filesystems."""
    normalized = os.path.normcase(os.path.realpath(path))
    return unicodedata.normalize("NFD", normalized).casefold()


def claim_output_path(path):

    """
        Collision / overwrite guard for one output path.

        Two different encrypted names may decrypt to the same plaintext name, or to names that only differ
        by case (which collide on Windows and macOS), and a previous run may have left files behind.
        Unless -f/--overwrite was given, an output path is written at most once per run and never over
        an existing file.
    """

    key = output_path_key(path)
    if (key in output_paths_claimed) or (key in output_directories_claimed):
        return False
    if (os.path.isdir(path)):
        return False
    if (os.path.exists(path) and not overwrite_outputs):
        return False
    output_paths_claimed.add(key)
    return True


def decrypt_file(filename):

    global nb_encrypted_files, nb_decrypted_files, nb_skipped_files

    """
        Constructing output file name
    """

    encrypted_data_filename = os.path.basename(filename)
    encrypted_data_fileext  = encrypted_data_filename[-3:]
    data_directory          = os.path.dirname(filename)

    if (encrypted_data_fileext != ".bc"):
        logging.info("Error: the file you want to decrypt has a bad suffix (filename:" + encrypted_data_filename + ")")
        return

    if (filename_key is None):

        # No filename encryption: decrypt in place, next to the .bc file (historical behaviour)
        new_filename = os.path.join(data_directory, encrypted_data_filename[:-3])

    else:

        # Filename encryption: every path component is encrypted too, so the plaintext tree is written
        # as a sibling of the source root, with every folder and file name decrypted.
        output_dir   = dir_map.get(data_directory, dest_root)     # directories were mapped and created above
        new_filename = os.path.join(output_dir, fnnames.decrypt_filename(encrypted_data_filename, filename_key, keyfile.user_id))

        # Decrypted names are untrusted data: never let one escape the destination tree
        if (not fnnames.is_inside(new_filename, dest_root)):
            logging.error("Refusing to write outside the destination tree: " + encrypted_data_filename)
            print(Fore.RED + "Refusing to write outside the destination tree, skipping: " + encrypted_data_filename + Fore.RESET)
            return

        os.makedirs(output_dir, exist_ok=True)
        logging.info("Decrypted name: " + encrypted_data_filename + " -> " + os.path.relpath(new_filename, dest_root))

    if (not claim_output_path(new_filename)):
        nb_skipped_files = nb_skipped_files + 1
        logging.warning("Output exists or collides with another decrypted file, skipping: " + new_filename)
        print(Fore.YELLOW + "Skipping (output exists or collides, use -f to overwrite): " + os.path.basename(new_filename) + Fore.RESET)
        return

    """
        Reading data file itself
    """

    if (os.path.isfile(filename)):
        
        data_file = bcdatafile.DataFile(filename)
        
    else:
        
        logging.info("File \'" + filename + "\' not found!")
        # exit()
            
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
    logging.info("AES file key decryption OK, decrypting \'" + filename + "\'")
    crypto_key = the_file_aes_key[32:64]
    # ==> only if you want it

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

    logging.debug("Encrypted data length: " + str(encrypted_data_length))
    logging.debug("Offset:" + str(offset))
    logging.debug("Number of blocks to decrypt: " + str(nb_blocks))
  
    t0 = time.time()

    """
        Decrypts all the blocks
    """
    f_in  = open(filename, "rb")
    f_out = open(new_filename, "wb")   # Yes, we overwrite the output file

    # Read the 1st block (header), not used here
    f_in.read(offset)

    overall_progression = nb_decrypted_files / nb_encrypted_files * 100

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
        
        helper.display_progression(encrypted_data_filename[:-3], block_nb, progression, overall_progression)
        if (block_nb == nb_blocks):
            decrypted_block = decrypted_block[:-data_file.cipher_padding_length]
        f_out.write(decrypted_block)

    nb_decrypted_files = nb_decrypted_files + 1
    overall_progression = nb_decrypted_files / nb_encrypted_files * 100
    helper.display_progression(encrypted_data_filename[:-3], nb_blocks + 1, 100, overall_progression)

    f_in.close
    f_out.close()
    
    
    execution_time = time.time() - t0

    logging.debug("{} blocks decrypted in {:.2f} seconds".format(nb_blocks, execution_time))




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
    Logging file
"""

log_directory = "logs"
if not os.path.exists(log_directory):
    os.makedirs(log_directory)

log_filename = os.path.join(log_directory, "log_" + datetime.now().strftime("%Y%m%d%H%M%S") + ".txt")
logging.basicConfig(filename=log_filename, level=LOG_LEVEL, format="%(asctime)s - %(levelname)s: %(message)s", datefmt="%Y-%m-%d %H:%M:%S", encoding='utf-8')


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
    Reading data filepath
"""
if (arguments.get("filepath")):
    
    # Data filepath in commande line
    data_filepath = arguments.get("filepath")
    
else:
    
    # no => input()
    data_filepath = str(input("Data filepath: "))

# Use the same absolute source paths for the destination map and the later file traversal.
data_filepath = os.path.abspath(data_filepath)

"""
    Now reading key file (mandatory)
"""
keyfile = bckeyfile.ExportKeyFile(bckey_filepath)


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
helper.print_parameter("Data directory", data_filepath)
overwrite_outputs = bool(arguments.get("overwrite"))
helper.print_parameter("Overwrite existing outputs", "yes" if overwrite_outputs else "no (use -f/--overwrite)")
 


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
# Filename key (optional)
# =======================
#
# --> Present when filename encryption was enabled. keys.filename in the .bckey is a "wrapped blob"
#     (IV | HMAC-SHA256 | AES-256-CBC) encrypted with the wrapping key, which is itself a wrapped blob
#     encrypted with the password key. The plaintext is a 64-byte AesKey (encryption half | hashing half).
#     Encrypted names are Base4K strings; see res/fnnames.py for the format and the cipher.
#

filename_key = None

if (keyfile.filename_key_wrapped_bytes is not None):

    try:
        wrapping_key = fnnames.decrypt_wrapped(keyfile.wrapping_key_bytes, crypto_key, hmac_key)
        filename_key = fnnames.decrypt_wrapped(keyfile.filename_key_wrapped_bytes, wrapping_key[:32], wrapping_key[32:64])
        wrapping_key = None
        helper.print_parameter("Filename key decryption", "OK")

    except Exception as e:
        helper.print_parameter("Filename key decryption", "KO (" + str(e) + "), names will stay encrypted")

else:

    helper.print_parameter("Filename key", "none in key file (filename encryption was not enabled)")

"""
    Output location
"""
source_root = os.path.abspath(data_filepath.rstrip(os.sep))
dest_root   = None

if (filename_key is not None):

    root_name = fnnames.decrypt_filename(os.path.basename(source_root), filename_key, keyfile.user_id, is_directory=True)
    if (root_name == os.path.basename(source_root)):
        root_name = root_name + "_decrypted"      # root folder name was not encrypted
    dest_root = os.path.join(os.path.dirname(source_root), root_name)
    if (os.path.islink(dest_root)):
        logging.error("Refusing to use a symbolic link as the decrypted destination: " + dest_root)
        print(Fore.RED + "Refusing to write through a symbolic link destination: " + dest_root + Fore.RESET)
        exit(1)
    helper.print_parameter("Decrypted root folder", dest_root)

"""
    Output tree (filename encryption only)

    Every directory of the source tree is recreated under dest_root with its decrypted name, empty ones
    included, and files that are not Boxcryptor containers are copied as they are. FolderKey.bch, the
    per-folder key container, is not copied: it has no meaning outside the encrypted tree.
"""
dir_map = {}            # source directory -> destination directory
nb_plain_copied = 0

if (dest_root is not None):

    dir_map[source_root] = dest_root
    output_directories_claimed.add(output_path_key(dest_root))

    for current_dir, subdirs, files in os.walk(source_root):

        subdirs.sort()
        out_dir = dir_map[current_dir]
        os.makedirs(out_dir, exist_ok=True)

        for d in list(subdirs):
            source_child = os.path.join(current_dir, d)
            target = os.path.join(out_dir, fnnames.decrypt_filename(d, filename_key, keyfile.user_id, is_directory=True))
            if (not fnnames.is_inside(target, dest_root)):
                target = os.path.join(out_dir, "_" + d)

            target_key = output_path_key(target)
            if ((not fnnames.is_inside(target, dest_root))
                    or (target_key in output_directories_claimed)
                    or (target_key in output_paths_claimed)
                    or (os.path.lexists(target) and not os.path.isdir(target))):
                nb_skipped_dirs = nb_skipped_dirs + 1
                logging.warning("Output directory collides or escapes destination, skipping: " + source_child)
                print(Fore.YELLOW + "Skipping directory (output collision): " + d + Fore.RESET)
                subdirs.remove(d)
                continue

            output_directories_claimed.add(target_key)
            dir_map[source_child] = target

        for f in files:
            if (f == "FolderKey.bch") or f.endswith(".bc"):
                continue
            target = os.path.join(out_dir, fnnames.decrypt_filename(f, filename_key, keyfile.user_id))
            if (not fnnames.is_inside(target, dest_root)) or (not claim_output_path(target)):
                nb_skipped_files = nb_skipped_files + 1
                logging.warning("Plain file not copied (exists or collides): " + os.path.join(current_dir, f))
                continue
            shutil.copy2(os.path.join(current_dir, f), target)
            nb_plain_copied = nb_plain_copied + 1

    helper.print_parameter("Directories created", str(len(dir_map)))
    helper.print_parameter("Directories skipped (collision)", str(nb_skipped_dirs))
    helper.print_parameter("Plain (non-.bc) files copied", str(nb_plain_copied))

print('-'*72)



# -----------------------------------------------------------------
#
#  Decrypting files
#
# -----------------------------------------------------------------

"""
    Getting all files
"""
nb_decrypted_files = 0

file_list, nb_encrypted_files, nb_files_read = helper.traverse_directory(data_filepath)
helper.print_parameter("Nb of files inn directory", nb_files_read)
helper.print_parameter("Nb of encrypted files found", nb_encrypted_files)
print('-'*72)

for file in file_list:
    decrypt_file(file)

print()
helper.print_parameter("Nb of files decrypted", nb_decrypted_files)
helper.print_parameter("Nb of files skipped (existing/collision)", nb_skipped_files)

#
# Notes:
#
# --> AES keys (encrypted with the user's password / wrapping key)
#
# --> Wrapping key: This key is the root AES key which is used to encrypt all other AES keys stored on our servers.
#
# --> Filename key: This key is used to encrypt filenames if filename encryption is enabled.
#
