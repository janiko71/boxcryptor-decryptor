"""
fnnames.py -- Boxcryptor 2.x filename recovery helpers (offline).

Pieces that are CONFIRMED on real data (see NOTES.md):
  * Base4K decoding of the CJK-looking names (Secomba's open-source encoding, legacy
    alphabet U+5000-U+5FFF for 12-bit groups, U+4000-U+40FF for the trailing partial group).
  * Key chain: PBKDF2-SHA512(password, salt, 10000) -> 64 B = AES key | HMAC key;
    that pair decrypts `privateKey` AND `wrappingKey` (layout IV[16] | HMAC-SHA256[32] | AES-CBC ct);
    the 64 B wrappingKey plaintext (AES | HMAC halves) decrypts every entry under `keys`
    (filename, groupMembership, analytics), each yielding a 64 B double key.
  * Per-file/per-folder keys (RSA-OAEP-SHA1 unwrapped from encryptedFileKeys) are 96 B.

Nothing here prints key material.  Replaces the (wrong, base64-based) _decrypt_method_* in fnhelper.py.
"""
import base64
import json

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, serialization, asymmetric
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
try:  # cryptography >= 48 moved CFB; the client uses AES-CFB128 for names
    from cryptography.hazmat.decrepit.ciphers.modes import CFB as _CFB
except ImportError:  # older cryptography
    _CFB = modes.CFB

_B = default_backend()

# ----------------------------------------------------------------------------------------- Base4K

_B4K_FLAG = 0x4000      # trailing partial group: 0x4000 + byte (or + nibble)
_B4K_FLAG_SIZE = 0x100
_B4K_BASE_V2 = 0x6000   # current alphabet
_B4K_BASE_V1 = 0x5000   # legacy alphabet (what Boxcryptor 2.x used on this vault)
_B4K_SIZE = 0x5000      # the C reference accepts base..base+0x5000 (wider than the 0x1000 actually produced)


class Base4KError(ValueError):
    pass


def _b4k_decode(s, base):
    out = bytearray()
    code = prev = 0
    n = len(s)
    for i, ch in enumerate(s):
        prev = code
        code = ord(ch)
        if not (base <= code < base + _B4K_SIZE):
            if i < n - 1 or not (_B4K_FLAG <= code < _B4K_FLAG + _B4K_FLAG_SIZE):
                raise Base4KError("invalid code point U+%04X at %d" % (code, i))
        if code >= base:
            code -= base
        else:
            code -= _B4K_FLAG
            out.append(code & 0xFF if i % 2 == 0 else ((prev << 4) | (code & 0x0F)) & 0xFF)
            break
        if i % 2 == 0:
            out.append((code >> 4) & 0xFF)
        else:
            out.append(((prev << 4) | ((code & 0x0F00) >> 8)) & 0xFF)
            out.append(code & 0xFF)
    return bytes(out)


def base4k_decode(s):
    """Decode a Base4K string (tries the current alphabet, then the legacy one, like the reference)."""
    try:
        return _b4k_decode(s, _B4K_BASE_V2)
    except Base4KError:
        return _b4k_decode(s, _B4K_BASE_V1)


def base4k_encode(data, legacy=True):
    """Straight port of the C reference encoder (used for self-test / round-trips)."""
    base = _B4K_BASE_V1 if legacy else _B4K_BASE_V2
    out = []
    n = len(data)
    i = 0
    while i < n * 2 - 2:
        if i % 2 == 0:
            off = ((data[i >> 1] << 4) | ((data[(i >> 1) + 1] >> 4) & 0x0F)) & 0x0FFF
        else:
            off = ((data[(i - 1) >> 1] << 8) | (data[(i + 1) >> 1] & 0xFF)) & 0x0FFF
        out.append(chr(off + base))
        i += 3
    if (n << 1) % 3 == 2:
        out.append(chr((data[n - 1] & 0xFF) + _B4K_FLAG))
    elif (n << 1) % 3 == 1:
        out.append(chr((data[n - 1] & 0x0F) + _B4K_FLAG))
    return "".join(out)


# -------------------------------------------------------------------------------------- key chain

def load_keyfile_user(path):
    """key.bckey: JSON with UTF-8 BOM. Refuses anything but a single user with no groups/org keys."""
    with open(path, encoding="utf-8-sig") as f:
        kj = json.load(f)
    users = kj.get("users", [])
    if len(users) != 1 or kj.get("groups") or kj.get("groupMemberships") or kj["organization"].get("keys"):
        raise SystemExit("STOP: unexpected key file content (users=%d) -- refusing to continue" % len(users))
    return users[0]


def derive_password_key(password, salt_b64, iterations):
    """PBKDF2-HMAC-SHA512 -> 64 B: [0:32] AES-256 key, [32:64] HMAC-SHA256 key."""
    kdf = PBKDF2HMAC(algorithm=hashes.SHA512(), length=64, salt=base64.b64decode(salt_b64),
                     iterations=iterations, backend=_B)
    pk = kdf.derive(password.encode("utf-8"))
    return pk[:32], pk[32:]


def decrypt_wrapped(blob, aes_key, mac_key):
    """Boxcryptor 'wrapped' blob: IV[0:16] | HMAC-SHA256(ct)[16:48] | AES-256-CBC/PKCS7 ct[48:]."""
    iv, mac, ct = blob[:16], blob[16:48], blob[48:]
    h = hmac.HMAC(mac_key, hashes.SHA256(), _B)
    h.update(ct)
    h.verify(mac)                      # raises InvalidSignature on wrong key / tampering
    dec = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=_B).decryptor()
    pt = dec.update(ct) + dec.finalize()
    pad = pt[-1]
    if not (1 <= pad <= 16) or pt[-pad:] != bytes([pad]) * pad:
        raise ValueError("bad PKCS7 padding")
    return pt[:-pad]


def unwrap_user_keys(user, password):
    """Returns dict: private_key (RSA object), wrapping (64 B), filename (64 B), ... never log these."""
    aes_k, mac_k = derive_password_key(password, user["salt"], user["kdfIterations"])
    priv_der_b64 = decrypt_wrapped(base64.b64decode(user["privateKey"]), aes_k, mac_k)
    priv = serialization.load_der_private_key(base64.b64decode(priv_der_b64), None, _B)
    pub = serialization.load_der_public_key(base64.b64decode(user["publicKey"]), _B)
    if priv.public_key().public_numbers() != pub.public_numbers():
        raise SystemExit("STOP: decrypted private key does not match publicKey")
    wrapping = decrypt_wrapped(base64.b64decode(user["wrappingKey"]), aes_k, mac_k)
    out = {"private_key": priv, "wrapping": wrapping}
    for name, b64 in user.get("keys", {}).items():
        out[name] = decrypt_wrapped(base64.b64decode(b64), wrapping[:32], wrapping[32:64])
    return out


def unwrap_file_key(priv, header_json, user_id):
    """RSA-OAEP(SHA1) unwrap of encryptedFileKeys[].value for this user -> 96 B."""
    for efk in header_json["encryptedFileKeys"]:
        if efk["id"] == user_id:
            return priv.decrypt(base64.b64decode(efk["value"]),
                                asymmetric.padding.OAEP(mgf=asymmetric.padding.MGF1(hashes.SHA1()),
                                                        algorithm=hashes.SHA1(), label=None))
    raise KeyError("no encryptedFileKeys entry for user %s" % user_id)


def read_bc_header(path):
    """bc01 header: returns (json, header_core_len, header_pad_len, cipher_pad_len, hash32)."""
    import struct
    with open(path, "rb") as f:
        raw = f.read(4096)
    if raw[:4] != b"bc01":
        raise ValueError("not a bc01 container")
    hcl, hpl, cpl = struct.unpack("<III", raw[4:16])
    return json.loads(raw[48:48 + hcl]), hcl, hpl, cpl, raw[16:48]


if __name__ == "__main__":
    # Self-test against the README vectors of secomba/base4k (no secrets involved).
    assert base4k_encode(b"f", legacy=False) == "䁦"
    assert base4k_encode(b"foobar", legacy=False) == "晦潯昦慲"
    assert base4k_decode("晦潯昦慲") == b"foobar"
    for n in range(0, 40):
        d = bytes(range(n))
        assert base4k_decode(base4k_encode(d, legacy=True)) == d, n
        assert base4k_decode(base4k_encode(d, legacy=False)) == d, n
    print("fnnames self-test OK")


# --------------------------------------------------------------------- name cipher (from the client)
# Reverse-engineered (read-only) from Boxcryptor.exe 2.47.1752, class Boxcryptor.Encryption.FilenameCipher
# + Secomba.Common.Cryptography.{AesKey,HashUtils}. Layout of the Base4K-decoded bytes:
#   [0]    tag = 0x01
#   [1]    1-byte XOR-fold hash of the key holder id (UTF-8 of the user id)
#   [2:7]  first 5 bytes of HMAC-SHA256(key.ForHashing, utf8(plain name))
#   [7:]   ciphertext, same length as utf8(plain name)
# Key = the key holder's AesKey (64 B): ForEncryption = [0:32], ForHashing = [32:64].  For a single-user
# vault that is the user's own AES key == plaintext of `keys.filename` in the .bckey.
# Encryption (two passes of AES-256-CFB128, no padding, with XOR-chaining and 64-byte chunk reversal):
#   ivbase = HMAC-SHA256(ForHashing, mac5)[:16];  n = fold64(ivbase)
#   xor_chain(p); c1 = CFB_enc(iv=setivec(ivbase, n), p); rev64(c1); xor_chain(c1); c = CFB_enc(iv=setivec(ivbase, n+1), c1)
#   setivec(iv, seed, k) = HMAC-SHA256(ForEncryption, iv || LE64(seed))[:16]   (same as the data-block IV derivation)

class NameDecryptError(ValueError):
    pass


def _fold_ulong(b):
    arr = bytearray(8)
    for i in range(len(b) - 1):          # sic: the client skips the last byte
        arr[i % 8] ^= b[i]
    return int.from_bytes(arr, "big")


def key_holder_hash(key_holder_id):
    """1-byte XOR fold of the key holder id (byte [1] of every encrypted name)."""
    n = _fold_ulong(key_holder_id.encode("utf-8"))
    n = ((n >> 32) ^ n) & 0xFFFFFFFF
    n = ((n >> 16) ^ n) & 0xFFFF
    return ((n >> 8) ^ n) & 0xFF


def _hmac256(key, data):
    h = hmac.HMAC(key, hashes.SHA256(), _B)
    h.update(data)
    return h.finalize()


def _setivec(ivbase, seed, enc_key):
    return _hmac256(enc_key, ivbase + (seed & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little"))[:16]


def _cfb_dec(enc_key, iv, data):
    d = Cipher(algorithms.AES(enc_key), _CFB(iv), backend=_B).decryptor()
    return d.update(data) + d.finalize()


def _cfb_enc(enc_key, iv, data):
    e = Cipher(algorithms.AES(enc_key), _CFB(iv), backend=_B).encryptor()
    return e.update(data) + e.finalize()


def _xor_chain(b):            # forward: b[i+1] ^= b[i]
    b = bytearray(b)
    for i in range(len(b) - 1):
        b[i + 1] ^= b[i]
    return bytes(b)


def _unxor_chain(b):          # inverse: from the end, b[n] ^= b[n-1]
    b = bytearray(b)
    for n in range(len(b) - 1, 0, -1):
        b[n] ^= b[n - 1]
    return bytes(b)


def _rev64(b):                # reverse every 64-byte chunk in place (self-inverse)
    out = bytearray()
    for i in range(0, len(b), 64):
        out += b[i:i + 64][::-1]
    return bytes(out)


def decrypt_name(encoded, aes_key64, key_holder_id=None, check_mac=True):
    """Base4K string (without the .bc suffix) -> plaintext name. aes_key64 = ForEncryption|ForHashing."""
    if len(aes_key64) != 64:
        raise ValueError("expected a 64-byte AesKey (ForEncryption|ForHashing)")
    enc_k, hash_k = aes_key64[:32], aes_key64[32:]
    raw = base4k_decode(encoded)
    if len(raw) < 8 or raw[0] != 1:
        raise NameDecryptError("not a v1 encrypted name")
    if key_holder_id is not None and raw[1] != key_holder_hash(key_holder_id):
        raise NameDecryptError("key holder hash mismatch (name was encrypted for another key holder)")
    mac5, ct = raw[2:7], raw[7:]
    ivbase = _hmac256(hash_k, mac5)[:16]
    n = _fold_ulong(ivbase)
    p = _cfb_dec(enc_k, _setivec(ivbase, n + 1, enc_k), ct)
    p = _rev64(_unxor_chain(p))
    p = _unxor_chain(_cfb_dec(enc_k, _setivec(ivbase, n, enc_k), p))
    if check_mac and _hmac256(hash_k, p)[:5] != mac5:
        raise NameDecryptError("name MAC mismatch (wrong key)")
    return p.decode("utf-8")


def encrypt_name(plain, aes_key64, key_holder_id, legacy=True):
    """Inverse of decrypt_name; used only to round-trip-test the implementation."""
    enc_k, hash_k = aes_key64[:32], aes_key64[32:]
    p = plain.encode("utf-8")
    mac5 = _hmac256(hash_k, p)[:5]
    ivbase = _hmac256(hash_k, mac5)[:16]
    n = _fold_ulong(ivbase)
    c = _cfb_enc(enc_k, _setivec(ivbase, n, enc_k), _xor_chain(p))
    c = _cfb_enc(enc_k, _setivec(ivbase, n + 1, enc_k), _xor_chain(_rev64(c)))
    return base4k_encode(bytes([1, key_holder_hash(key_holder_id)]) + mac5 + c, legacy=legacy)


def split_affixes(filename):
    """Return (prefix, encoded_core, suffix): keeps MS-Office '~$' prefix and the '.bc' suffix outside the cipher."""
    prefix = suffix = ""
    if filename.startswith("~$"):
        prefix, filename = "~$", filename[2:]
    if filename.endswith(".bc"):
        suffix, filename = ".bc", filename[:-3]
    return prefix, filename, suffix


def decrypt_filename(filename, aes_key64, key_holder_id=None):
    """Convenience for the scripts: on-disk name -> plaintext name.

    Keeps a leading '~$' (MS-Office lock files) in clear, strips a trailing '.bc', and returns the input
    (minus '.bc') unchanged when it is not a decryptable encrypted name (filename encryption off, foreign key
    holder, or not Base4K at all)."""
    prefix, core, suffix = split_affixes(filename)
    try:
        return prefix + decrypt_name(core, aes_key64, key_holder_id).replace("/", "_").replace("\0", "")
    except Exception:
        return prefix + core
