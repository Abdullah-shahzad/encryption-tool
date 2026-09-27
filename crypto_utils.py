"""
crypto_utils.py
----------------
Implements the encryption / decryption / hashing algorithms exposed by the
Text Encryption Tool. Each algorithm follows the same contract so the Flask
route layer (app.py) can stay thin:

    encrypt(plaintext: str, key: str | None) -> str | dict
    decrypt(ciphertext: str, key: str | None) -> str

All binary output (AES/3DES ciphertext, salts, IVs) is base64-encoded so it
can travel safely as JSON text and be pasted back in for decryption.

Built on the `cryptography` package (pyca/cryptography).
"""

import base64
import hashlib
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding as sym_padding, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding

# Newer versions of `cryptography` moved TripleDES into a "decrepit" module
# (it's kept only for legacy interoperability). Import from whichever
# location this installed version provides.
try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
except ImportError:
    from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES


class CryptoError(ValueError):
    """Raised for any user-facing encryption/decryption failure."""


PBKDF2_ITERATIONS = 200_000


# ---------------------------------------------------------------------------
# Caesar Cipher
# ---------------------------------------------------------------------------
def caesar_encrypt(text: str, key: str) -> str:
    shift = _parse_caesar_shift(key)
    return "".join(_shift_char(ch, shift) for ch in text)


def caesar_decrypt(text: str, key: str) -> str:
    shift = _parse_caesar_shift(key)
    return "".join(_shift_char(ch, -shift) for ch in text)


def _parse_caesar_shift(key: str) -> int:
    if key is None or str(key).strip() == "":
        raise CryptoError("Caesar Cipher requires a numeric shift key (e.g. 3).")
    try:
        return int(str(key).strip()) % 26
    except ValueError:
        raise CryptoError("Caesar Cipher key must be a whole number, e.g. 3.")


def _shift_char(ch: str, shift: int) -> str:
    if ch.isupper():
        return chr((ord(ch) - ord("A") + shift) % 26 + ord("A"))
    if ch.islower():
        return chr((ord(ch) - ord("a") + shift) % 26 + ord("a"))
    return ch


# ---------------------------------------------------------------------------
# Vigenère Cipher -- polyalphabetic substitution: each letter is shifted by
# the corresponding letter of a repeating keyword instead of a fixed amount.
# ---------------------------------------------------------------------------
def vigenere_encrypt(text: str, key: str) -> str:
    key = _validate_vigenere_key(key)
    return _vigenere_transform(text, key, sign=1)


def vigenere_decrypt(text: str, key: str) -> str:
    key = _validate_vigenere_key(key)
    return _vigenere_transform(text, key, sign=-1)


def _vigenere_transform(text: str, key: str, sign: int) -> str:
    result = []
    key_index = 0
    for ch in text:
        if ch.isalpha():
            key_shift = ord(key[key_index % len(key)].upper()) - ord("A")
            result.append(_shift_char(ch, sign * key_shift))
            key_index += 1
        else:
            result.append(ch)
    return "".join(result)


def _validate_vigenere_key(key: str) -> str:
    if key is None or str(key).strip() == "":
        raise CryptoError("Vigenère Cipher requires a keyword (letters only, e.g. LEMON).")
    key = str(key).strip()
    if not key.isalpha():
        raise CryptoError("Vigenère Cipher key must contain letters only, e.g. LEMON.")
    return key


# ---------------------------------------------------------------------------
# Atbash Cipher -- fixed mirror-alphabet substitution (A<->Z, B<->Y, ...).
# No key: it's the same fixed substitution every time, and it's its own
# inverse, so encrypt and decrypt do exactly the same transformation.
# ---------------------------------------------------------------------------
def atbash_transform(text: str, key: str | None = None) -> str:
    result = []
    for ch in text:
        if ch.isupper():
            result.append(chr(ord("Z") - (ord(ch) - ord("A"))))
        elif ch.islower():
            result.append(chr(ord("z") - (ord(ch) - ord("a"))))
        else:
            result.append(ch)
    return "".join(result)


atbash_encrypt = atbash_transform
atbash_decrypt = atbash_transform


# ---------------------------------------------------------------------------
# Rail Fence Cipher -- transposition cipher: letters are written in a
# zigzag across a given number of "rails" and read off row by row.
# ---------------------------------------------------------------------------
def rail_fence_encrypt(text: str, key: str) -> str:
    rails = _parse_rail_count(key, len(text))
    fence = [[] for _ in range(rails)]
    rail, direction = 0, 1
    for ch in text:
        fence[rail].append(ch)
        if rail == 0:
            direction = 1
        elif rail == rails - 1:
            direction = -1
        rail += direction
    return "".join("".join(row) for row in fence)


def rail_fence_decrypt(text: str, key: str) -> str:
    rails = _parse_rail_count(key, len(text))
    # Recreate the zigzag pattern of rail indices for each position.
    pattern = []
    rail, direction = 0, 1
    for _ in text:
        pattern.append(rail)
        if rail == 0:
            direction = 1
        elif rail == rails - 1:
            direction = -1
        rail += direction

    counts = [pattern.count(r) for r in range(rails)]
    rails_chars, idx = [], 0
    for count in counts:
        rails_chars.append(list(text[idx: idx + count]))
        idx += count

    cursors = [0] * rails
    result = []
    for r in pattern:
        result.append(rails_chars[r][cursors[r]])
        cursors[r] += 1
    return "".join(result)


def _parse_rail_count(key: str, text_len: int) -> int:
    if key is None or str(key).strip() == "":
        raise CryptoError("Rail Fence Cipher requires a number of rails (e.g. 3).")
    try:
        rails = int(str(key).strip())
    except ValueError:
        raise CryptoError("Rail Fence Cipher key must be a whole number, e.g. 3.")
    if rails < 2:
        raise CryptoError("Rail Fence Cipher needs at least 2 rails.")
    if text_len and rails > text_len:
        raise CryptoError("Rail Fence Cipher's rail count can't exceed the text length.")
    return rails


# ---------------------------------------------------------------------------
# XOR Cipher -- each byte of the message is XORed with a repeating key.
# Symmetric and simple, but only as strong as the key: it's the classic
# "how does a stream cipher work" teaching example.
# ---------------------------------------------------------------------------
def xor_encrypt(text: str, key: str) -> str:
    _require_key(key, "XOR Cipher")
    key_bytes = key.encode("utf-8")
    data = text.encode("utf-8")
    out = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data))
    return base64.b64encode(out).decode("utf-8")


def xor_decrypt(text: str, key: str) -> str:
    _require_key(key, "XOR Cipher")
    try:
        key_bytes = key.encode("utf-8")
        raw = base64.b64decode(text)
        out = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(raw))
        return out.decode("utf-8")
    except CryptoError:
        raise
    except Exception:
        raise CryptoError("XOR decryption failed. Check the key and ciphertext.")


# ---------------------------------------------------------------------------
# Base64 (encoding, not real encryption -- included per the spec's example list)
# ---------------------------------------------------------------------------
def base64_encrypt(text: str, key: str | None = None) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("utf-8")


def base64_decrypt(text: str, key: str | None = None) -> str:
    try:
        return base64.b64decode(text.encode("utf-8")).decode("utf-8")
    except Exception:
        raise CryptoError("That doesn't look like valid Base64 text.")


# ---------------------------------------------------------------------------
# Shared helpers for the symmetric block ciphers (AES / 3DES)
# ---------------------------------------------------------------------------
def _derive_key(passphrase: str, salt: bytes, length: int) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def _require_key(key, algo_name):
    if key is None or str(key).strip() == "":
        raise CryptoError(f"{algo_name} requires a passphrase/key.")


# ---------------------------------------------------------------------------
# AES-256 (CBC mode) -- key derived from the user's passphrase via PBKDF2
# ---------------------------------------------------------------------------
def aes_encrypt(text: str, key: str) -> str:
    _require_key(key, "AES")
    salt = os.urandom(16)
    iv = os.urandom(16)
    derived_key = _derive_key(key, salt, 32)  # AES-256

    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded = padder.update(text.encode("utf-8")) + padder.finalize()

    encryptor = Cipher(algorithms.AES(derived_key), modes.CBC(iv)).encryptor()
    ct_bytes = encryptor.update(padded) + encryptor.finalize()

    payload = salt + iv + ct_bytes  # bundled so decrypt only needs the passphrase
    return base64.b64encode(payload).decode("utf-8")


def aes_decrypt(text: str, key: str) -> str:
    _require_key(key, "AES")
    try:
        raw = base64.b64decode(text)
        salt, iv, ct_bytes = raw[:16], raw[16:32], raw[32:]
        derived_key = _derive_key(key, salt, 32)

        decryptor = Cipher(algorithms.AES(derived_key), modes.CBC(iv)).decryptor()
        padded = decryptor.update(ct_bytes) + decryptor.finalize()

        unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
        pt = unpadder.update(padded) + unpadder.finalize()
        return pt.decode("utf-8")
    except CryptoError:
        raise
    except Exception:
        raise CryptoError("AES decryption failed. Check the key and ciphertext.")


# ---------------------------------------------------------------------------
# Triple DES / 3DES (CBC mode)
# Modern crypto libraries no longer expose single DES because its 56-bit key
# is trivially brute-forced; 3DES (three DES passes on a longer key) is the
# standard drop-in used to demonstrate the same block-cipher family safely.
# ---------------------------------------------------------------------------
def des_encrypt(text: str, key: str) -> str:
    _require_key(key, "Triple DES")
    salt = os.urandom(8)
    iv = os.urandom(8)
    derived_key = _derive_key(key, salt, 24)  # 3DES key size

    padder = sym_padding.PKCS7(TripleDES.block_size).padder()
    padded = padder.update(text.encode("utf-8")) + padder.finalize()

    encryptor = Cipher(TripleDES(derived_key), modes.CBC(iv)).encryptor()
    ct_bytes = encryptor.update(padded) + encryptor.finalize()

    payload = salt + iv + ct_bytes
    return base64.b64encode(payload).decode("utf-8")


def des_decrypt(text: str, key: str) -> str:
    _require_key(key, "Triple DES")
    try:
        raw = base64.b64decode(text)
        salt, iv, ct_bytes = raw[:8], raw[8:16], raw[16:]
        derived_key = _derive_key(key, salt, 24)

        decryptor = Cipher(TripleDES(derived_key), modes.CBC(iv)).decryptor()
        padded = decryptor.update(ct_bytes) + decryptor.finalize()

        unpadder = sym_padding.PKCS7(TripleDES.block_size).unpadder()
        pt = unpadder.update(padded) + unpadder.finalize()
        return pt.decode("utf-8")
    except CryptoError:
        raise
    except Exception:
        raise CryptoError("Triple DES decryption failed. Check the key and ciphertext.")


# ---------------------------------------------------------------------------
# ChaCha20 -- a modern, fast stream cipher (used in TLS 1.3 and WireGuard)
# included alongside AES/3DES as a second family of symmetric cipher.
# ---------------------------------------------------------------------------
def chacha20_encrypt(text: str, key: str) -> str:
    _require_key(key, "ChaCha20")
    salt = os.urandom(16)
    nonce = os.urandom(16)  # cryptography's ChaCha20 takes a 16-byte nonce
    derived_key = _derive_key(key, salt, 32)

    encryptor = Cipher(algorithms.ChaCha20(derived_key, nonce), mode=None).encryptor()
    ct_bytes = encryptor.update(text.encode("utf-8")) + encryptor.finalize()

    payload = salt + nonce + ct_bytes
    return base64.b64encode(payload).decode("utf-8")


def chacha20_decrypt(text: str, key: str) -> str:
    _require_key(key, "ChaCha20")
    try:
        raw = base64.b64decode(text)
        salt, nonce, ct_bytes = raw[:16], raw[16:32], raw[32:]
        derived_key = _derive_key(key, salt, 32)

        decryptor = Cipher(algorithms.ChaCha20(derived_key, nonce), mode=None).decryptor()
        pt = decryptor.update(ct_bytes) + decryptor.finalize()
        return pt.decode("utf-8")
    except CryptoError:
        raise
    except Exception:
        raise CryptoError("ChaCha20 decryption failed. Check the key and ciphertext.")


# ---------------------------------------------------------------------------
# RSA (bonus) -- generates an ephemeral keypair per request since the UI has
# no persistent key storage. The public/private key pair is returned to the
# user so the message can be decrypted later by pasting the private key back.
# ---------------------------------------------------------------------------
_OAEP = asym_padding.OAEP(
    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)


def rsa_encrypt(text: str) -> dict:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    data = text.encode("utf-8")
    max_len = 2048 // 8 - 2 * 32 - 2  # OAEP overhead for SHA-256, 2048-bit key
    if len(data) > max_len:
        raise CryptoError(
            f"RSA can only encrypt short messages (max {max_len} bytes). "
            "Use AES for longer text."
        )

    ct_bytes = public_key.encrypt(data, _OAEP)

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    return {
        "ciphertext": base64.b64encode(ct_bytes).decode("utf-8"),
        "public_key": public_pem,
        "private_key": private_pem,
    }


def rsa_decrypt(ciphertext_b64: str, private_key_pem: str) -> str:
    if not private_key_pem or not private_key_pem.strip():
        raise CryptoError("RSA decryption requires the private key.")
    try:
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode("utf-8"), password=None
        )
        ct_bytes = base64.b64decode(ciphertext_b64)
        pt = private_key.decrypt(ct_bytes, _OAEP)
        return pt.decode("utf-8")
    except CryptoError:
        raise
    except Exception:
        raise CryptoError("RSA decryption failed. Check the private key and ciphertext.")


# ---------------------------------------------------------------------------
# SHA-256 Hashing (bonus) -- one-way, no decryption possible
# ---------------------------------------------------------------------------
def sha256_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
