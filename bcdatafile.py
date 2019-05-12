import os
import json
import base64
import binascii as ba


# =======================================================================================================================
#
#   Class for the encrypted file (your file, containing your datas)
#
# =======================================================================================================================

#
# The data file also contains crypto information we need to gather. The file structure depends on the cipher blocksize,
# which is one of the information within the file.
#
# In the file structure, the first block is reserved for the BoxCryptor header. This block size is calculated as
# 'offset', and it's padded with NUL (\x00)
#
# +-------------+-------------+-----------+----------------+----------------+-------...------------+
# | BoxCryptor  | Json with   | Padding   | Encrypted      | Encrypted      |       ...            |
# | header      | crypto info | with \x00 | data block #1  | data block #2  |       ...            |
# | (48 bytes)  |             |           |                |                |       ...            |
# +-------------+-------------+-----------+----------------+----------------+-------...------------+
# |                                       |                |                |                      |
# |<------------------------------------->|<-------------->|<-------------->|                      |
# |                                       |   blocksize    |   blocksize    |                      |
# 0                                    offset                                                 filesize
#

class DataFile:

    def __init__(self, data_filepath):

        """
            The init function is the constructor. All we need is the file path.
            We assume that there is no syntax or structure error in the file, and
            that Boxcryptor developpers don't code with their feet :o)
        """

        self.filepath = data_filepath
        d_file = open(data_filepath, 'rb')
        self.raw = d_file.read()

        # 1st, get the boxcryptor specific header (48 bytes)
        file_header = self.raw[0:48]

        # Header parsing
        self.version               = file_header[0:4].decode("utf-8")
        self.header_core_length    = int.from_bytes(file_header[4:8], byteorder='little')
        self.header_padding_length = int.from_bytes(file_header[8:12], byteorder='little')
        self.cipher_padding_length = int.from_bytes(file_header[12:16], byteorder='little')

        # The 32 last bytes may be hash value
        some_hash     = file_header[16:48]
        self.hash     = some_hash.hex()

        # JSON data (file content and encryption information)
        #crypto_json_txt  = d_file.read(self.header_core_length)
        crypto_json_txt  = self.raw[48:48+self.header_core_length]
        self.crypto_json = json.loads(crypto_json_txt)

        # JSON Parsing
        self.cipher_algo          = self.crypto_json["cipher"]["algorithm"]
        self.cipher_mode          = self.crypto_json["cipher"]["mode"]
        self.cipher_padding_mode  = self.crypto_json["cipher"]["padding"]
        self.cipher_keysize       = self.crypto_json["cipher"]["keySize"]
        self.cipher_blocksize     = self.crypto_json["cipher"]["blockSize"]
        self.cipher_iv            = base64.b64decode(self.crypto_json["cipher"]["iv"])

        efk                       = self.crypto_json["encryptedFileKeys"][0]
        self.file_type            = efk["type"]
        self.file_id              = efk["id"]
        self.file_size            = os.path.getsize(data_filepath)

        self.aes_key_encrypted_bytes = base64.b64decode(efk["value"])

        # EOF
        d_file.close()




    

