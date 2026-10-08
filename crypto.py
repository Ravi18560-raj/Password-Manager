"""All cryptography lives in this one file.

RULE: we never invent crypto. We only *call* well-reviewed primitives from the
`cryptography` library (the standard, audited Python crypto package):

  * Scrypt      - password-based key derivation (slow + memory-hard on purpose)
  * AES-256-GCM - authenticated encryption (confidentiality + tamper detection)
  * os.urandom  - OS-provided cryptographically secure random bytes
  * hmac.compare_digest - constant-time comparison

Concepts: see LEARNING.md.
"""
from __future__ import annotations

import base64
import hmac
import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

SALT_LEN = 16      # bytes; unique random salt per vault
NONCE_LEN = 12     # bytes; AES-GCM standard nonce size. NEVER reuse with one key.
KEY_LEN = 32       # 256-bit key


class CryptoError(Exception):
    """Wrong password, or data was corrupted / tampered with."""


@dataclass(frozen=True)
class KdfParams:
    """Scrypt cost settings. Stored in the vault so they can be raised later."""
    n: int = 2**15   # CPU/memory cost (~32 MiB). OWASP-recommended range.
    r: int = 8
    p: int = 1

    def to_dict(self) -> dict:
        return {"n": self.n, "r": self.r, "p": self.p}

    @classmethod
    def from_dict(cls, d: dict) -> "KdfParams":
        return cls(int(d["n"]), int(d["r"]), int(d["p"]))


def random_bytes(n: int) -> bytes:
    return os.urandom(n)


def derive_key(password: str, salt: bytes, params: KdfParams) -> bytes:
    """HASHING for passwords: slow, salted key derivation (not plain SHA-256!)."""
    kdf = Scrypt(salt=salt, length=KEY_LEN, n=params.n, r=params.r, p=params.p)
    return kdf.derive(password.encode("utf-8"))


def make_verifier(key: bytes, salt: bytes) -> bytes:
    """A value we can store to check the master password later.

    We derive a *separate* secret from the key so the stored verifier can't be
    used as the encryption key (standard HMAC-SHA256 over a fixed label).
    """
    h = hmac.new(key, b"pwmanager-verifier" + salt, "sha256")
    return h.digest()


def verify(key: bytes, salt: bytes, verifier: bytes) -> bool:
    # compare_digest avoids timing side-channels that == would leak.
    return hmac.compare_digest(make_verifier(key, salt), verifier)


def encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """AES-256-GCM. Returns nonce || ciphertext+tag. Fresh random nonce each call."""
    nonce = random_bytes(NONCE_LEN)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def decrypt(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    if len(blob) < NONCE_LEN + 16:
        raise CryptoError("Encrypted data is too short / corrupted.")
    nonce, ct = blob[:NONCE_LEN], blob[NONCE_LEN:]
    try:
        return AESGCM(key).decrypt(nonce, ct, aad)
    except InvalidTag as exc:
        raise CryptoError("Decryption failed: wrong password or data tampered with.") from exc


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))
