"""End-to-end tests for dir_bcdecryptor.py and bcdecryptor.py on a synthetic vault.

The vault (key export + encrypted tree) is built here with a freshly generated RSA key, following the on-disk
format documented in res/fnnames.py; no real key or data is involved. The tools are run as subprocesses, the
way a user runs them.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as apad, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import res.fnnames as F  # noqa: E402

PASSWORD = "correct horse battery staple"
UID = "8123456789012345678"
BLOCK = 4096
ANSI = re.compile(r"\x1b\[[0-9;]*m")


def aes_cbc(key, iv, data, pad):
    if pad:
        n = 16 - len(data) % 16
        data = data + bytes([n]) * n
    e = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return e.update(data) + e.finalize()


def wrap_blob(plain, aes_key, mac_key):
    """IV | HMAC-SHA256(ct) | AES-256-CBC/PKCS7 ct  (the .bckey 'wrapped blob' layout)."""
    iv = os.urandom(16)
    ct = aes_cbc(aes_key, iv, plain, pad=True)
    return iv + hmac.new(mac_key, ct, hashlib.sha256).digest() + ct


class Vault:

    def __init__(self, base):
        self.base = base
        self.priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        salt = os.urandom(24)
        pk = PBKDF2HMAC(hashes.SHA512(), 64, salt, 1000).derive(PASSWORD.encode())
        pw_aes, pw_mac = pk[:32], pk[32:]
        wrapping = os.urandom(64)
        self.fn_key = os.urandom(64)
        priv_der_b64 = base64.b64encode(self.priv.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        user = {
            "id": UID, "username": "test@example.invalid",
            "publicKey": base64.b64encode(self.priv.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).decode(),
            "privateKey": base64.b64encode(wrap_blob(priv_der_b64, pw_aes, pw_mac)).decode(),
            "aesKey": base64.b64encode(self.rsa_wrap(os.urandom(32) + self.fn_key)).decode(),
            "wrappingKey": base64.b64encode(wrap_blob(wrapping, pw_aes, pw_mac)).decode(),
            "keys": {"filename": base64.b64encode(wrap_blob(self.fn_key, wrapping[:32], wrapping[32:])).decode()},
            "salt": base64.b64encode(salt).decode(), "kdfIterations": 1000, "password": "unused",
        }
        doc = {"artifact": "keyfile", "version": 1, "users": [user], "groups": [], "groupMemberships": [],
               "organization": {"id": "1", "name": "Boxcryptor", "keys": {}}}
        self.key_path = os.path.join(base, "export.bckey")
        with open(self.key_path, "w", encoding="utf-8-sig") as f:     # real exports carry a UTF-8 BOM
            json.dump(doc, f)

    def rsa_wrap(self, data):
        return self.priv.public_key().encrypt(
            data, apad.OAEP(mgf=apad.MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None))

    def enc(self, plain):
        return F.encrypt_name(plain, self.fn_key, UID)

    def container(self, path, header_name, plaintext=None):
        """Write a bc01 container; plaintext=None gives a header-only FolderKey.bch."""
        file_key = os.urandom(96)
        k = file_key[32:64]
        iv = os.urandom(16)
        header = {"artifact": "header", "version": 1,
                  "cipher": {"algorithm": "AES", "mode": "CBC", "padding": "PKCS7", "keySize": 256,
                             "blockSize": BLOCK, "iv": base64.b64encode(iv).decode(), "mac": {"enabled": "false"}},
                  "metadata": {"name": {"value": header_name, "encrypted": True}},
                  "encryptedFileKeys": [{"type": "data", "id": UID,
                                         "value": base64.b64encode(self.rsa_wrap(file_key)).decode()}]}
        core = json.dumps(header).encode()
        pad = BLOCK - 48 - len(core)
        body, cpad = b"", 0
        if plaintext:
            blocks = [plaintext[i:i + BLOCK] for i in range(0, len(plaintext), BLOCK)]
            for i, p in enumerate(blocks):
                biv = hmac.new(k, iv + i.to_bytes(8, "little"), hashlib.sha256).digest()[:16]
                last = i == len(blocks) - 1
                if last:
                    cpad = 16 - len(p) % 16
                body += aes_cbc(k, biv, p, pad=last)
        with open(path, "wb") as f:
            f.write(b"bc01" + struct.pack("<III", len(core), pad, cpad) + os.urandom(32) + core + bytes(pad) + body)

    def bc_file(self, directory, plain_name, data):
        disk = self.enc(plain_name) + ".bc"
        self.container(os.path.join(directory, disk), disk, data)
        return disk


def run_tool(script, args, cwd):
    r = subprocess.run([sys.executable, os.path.join(ROOT, script)] + args, cwd=cwd,
                       stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=600)
    return r.returncode, ANSI.sub("", r.stdout + r.stderr)


def counter(output, label):
    m = re.search(re.escape(label) + r"\.* (\d+)", output)
    return int(m.group(1)) if m else None


class DirDecryptorTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="bcdec-")
        v = self.v = Vault(self.tmp)
        self.root = os.path.join(self.tmp, v.enc("My Backup"))
        photos = os.path.join(self.root, v.enc("Photos 2016"))
        empty = os.path.join(self.root, v.enc("Empty folder"))
        plain_dir = os.path.join(self.root, "archives.bc")          # a plain directory whose name ends in .bc
        for d in (photos, empty, plain_dir):
            os.makedirs(d)
        v.container(os.path.join(self.root, "FolderKey.bch"), os.path.basename(self.root))
        v.container(os.path.join(photos, "FolderKey.bch"), os.path.basename(photos))
        self.expected = {
            "notes.txt": b"hello, world\n",
            "empty.bin": b"",
            "several-blocks.bin": os.urandom(3 * BLOCK + 7),
            "ünïcödé 日本.pdf": os.urandom(1000),
            os.path.join("Photos 2016", "img001.jpg"): os.urandom(2 * BLOCK + 100),
            os.path.join("archives.bc", "inside.txt"): b"inside a plain-named folder\n",
        }
        source_dirs = {"": self.root, "Photos 2016": photos, "archives.bc": plain_dir}   # plaintext -> on-disk
        for rel, data in self.expected.items():
            v.bc_file(source_dirs[os.path.dirname(rel)], os.path.basename(rel), data)
        # Office lock file: "~$" prefix stays in clear, the rest is encrypted
        lock = "~$" + v.enc("lock.docx") + ".bc"
        v.container(os.path.join(self.root, lock), lock, b"lock")
        self.expected["~$lock.docx"] = b"lock"
        # a plain, non-.bc file that must be copied as is
        with open(os.path.join(photos, "desktop.ini"), "wb") as f:
            f.write(b"[plain]\n")
        # a traversal attempt hidden in an encrypted name
        v.bc_file(self.root, "../../escaped.txt", b"must stay inside")
        # two names that differ only by case: a collision on case-insensitive file systems
        v.bc_file(self.root, "Same.txt", b"UPPER")
        v.bc_file(self.root, "same.txt", b"lower")
        self.dest = os.path.join(self.tmp, "My Backup")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_dir(self, *extra):
        return run_tool("dir_bcdecryptor.py", [self.root, "-b", self.v.key_path, "-p", PASSWORD] + list(extra), ROOT)

    def test_full_tree_then_rerun_then_overwrite(self):
        rc, out = self.run_dir()
        self.assertEqual(rc, 0, out)
        self.assertTrue(os.path.isdir(self.dest), out)
        for rel, data in self.expected.items():
            p = os.path.join(self.dest, rel)
            self.assertTrue(os.path.isfile(p), "missing %s\n%s" % (rel, out))
            with open(p, "rb") as f:
                self.assertEqual(f.read(), data, rel)
        # empty directory recreated, plain file copied, folder key not copied, plain .bc dir name kept
        self.assertTrue(os.path.isdir(os.path.join(self.dest, "Empty folder")))
        with open(os.path.join(self.dest, "Photos 2016", "desktop.ini"), "rb") as f:
            self.assertEqual(f.read(), b"[plain]\n")
        self.assertFalse(any(n == "FolderKey.bch" for _, _, fs in os.walk(self.dest) for n in fs))
        self.assertTrue(os.path.isdir(os.path.join(self.dest, "archives.bc")))
        self.assertFalse(os.path.exists(os.path.join(self.dest, "archives")))
        # the traversal attempt landed inside the destination, under a neutralised name
        self.assertTrue(os.path.isfile(os.path.join(self.dest, ".._.._escaped.txt")))
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "escaped.txt")))
        # the case collision: exactly one of the two was written, the other reported
        written = [n for n in os.listdir(self.dest) if n.lower() == "same.txt"]
        self.assertEqual(len(written), 1, out)
        self.assertIn("Skipping", out)
        self.assertEqual(counter(out, "Nb of files skipped (existing/collision)"), 1, out)
        # second run: nothing is overwritten
        rc, out2 = self.run_dir()
        self.assertEqual(rc, 0, out2)
        self.assertEqual(counter(out2, "Nb of files decrypted"), 0, out2)
        # with -f everything is written again (the case collision is still skipped)
        rc, out3 = self.run_dir("-f")
        self.assertEqual(rc, 0, out3)
        self.assertEqual(counter(out3, "Nb of files decrypted"), len(self.expected) + 2, out3)   # + escaped + one of Same/same
        self.assertEqual(counter(out3, "Nb of files skipped (existing/collision)"), 1, out3)

    def test_single_file_tool_names_output_and_refuses_overwrite(self):
        disk = self.v.enc("notes.txt") + ".bc"
        src = os.path.join(self.root, disk)
        workdir = os.path.join(self.tmp, "cwd")
        os.makedirs(workdir)
        rc, out = run_tool("bcdecryptor.py", [src, "-b", self.v.key_path, "-p", PASSWORD], workdir)
        self.assertEqual(rc, 0, out)
        with open(os.path.join(workdir, "notes.txt"), "rb") as f:
            self.assertEqual(f.read(), b"hello, world\n")
        rc, out = run_tool("bcdecryptor.py", [src, "-b", self.v.key_path, "-p", PASSWORD], workdir)
        self.assertNotEqual(rc, 0)
        self.assertIn("refusing to overwrite", out)
        rc, out = run_tool("bcdecryptor.py", [src, "-b", self.v.key_path, "-p", PASSWORD, "-f"], workdir)
        self.assertEqual(rc, 0, out)


if __name__ == "__main__":
    unittest.main()
