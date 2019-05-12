import os
import json
import base64
import binascii as ba


# =======================================================================================================================
#
#   Class for the export keys file (.bckey)
#
# =======================================================================================================================

#
# The .bckey file is the file containing all crypto datas used to encrypt and decrypt your datas,
# except ONE: your password, which is the key to decrypt to most sensitive keys and information.
#
# The file is in plain text and the datas are structured in JSON.
#
# In this first version, we assume there is only one user, and no organization.
#

class ExportKeyFile:

    def __init__(self, bckey_filepath):

        """
            The init function is the constructor. All we need is the file path.
            We assume that there is no syntax or structure error in the file, and
            that Boxcryptor developpers don't code with their feet :o)
        """

        self.filepath = bckey_filepath

        # Read the file
        with open(self.filepath, "r") as f_keys:
            key_list = json.loads(f_keys.read())

        # Get the kindom keys for the first user (we'll look at multiusers later...)
        user = key_list["users"][0]

        # Key Derivation informations
        self.kdf_iterations               = user["kdfIterations"]
        self.salt_bytes                   = base64.b64decode(user["salt"])

        # Base64 encoded datas (mainly crypto keys)
        self.encrypted_private_key_bytes  = base64.b64decode(user["privateKey"])
        self.public_key_bytes             = base64.b64decode(user["publicKey"])
        self.wrapping_key_bytes           = base64.b64decode(user["wrappingKey"])
        self.aes_key_bytes                = base64.b64decode(user["aesKey"])
        

        
