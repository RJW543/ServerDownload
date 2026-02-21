"""
crypto_utils.py — Cryptographic primitives for OTPMail.

Key Design:
  - Identity keypairs : Ed25519  (authentication / signing)
  - KEM keypairs      : X25519   (OTP delivery encryption)
      NOTE: Production deployments should replace X25519 with Kyber768
            (liboqs-python) for post-quantum security at the application layer.
            The transport layer should use an X25519Kyber768 hybrid TLS stack
            (OQS-OpenSSL or BoringSSL-OQS). This implementation uses standard
            TLS 1.3 + X25519 as a placeholder at both layers.
  - OTP pages         : os.urandom — CSPRNG, never reused
  - Page structure    : [32 B HMAC key | 4060 B encryption pad]
  - OTP encryption    : XOR plaintext with pad; message length stored in 4-B prefix
  - Authentication    : HMAC-SHA256 over ciphertext using HMAC key portion
  - Vault encryption  : AES-256-GCM; key from scrypt(password, salt)
  - KDF               : HKDF-SHA256 for shared secrets → AES keys
"""

import os
import struct
import hashlib
from typing import Tuple, List

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature

# ── OTP page constants ────────────────────────────────────────────────────────
OTP_HMAC_KEY_SIZE  = 32              # bytes reserved at the start of each page
OTP_PAGE_SIZE      = 4096            # total bytes per OTP page
OTP_PAD_SIZE       = OTP_PAGE_SIZE - OTP_HMAC_KEY_SIZE   # 4064 usable pad bytes
OTP_DEFAULT_PAGES  = 500             # pages generated per direction per contact

# ── scrypt parameters for vault password derivation ──────────────────────────
SCRYPT_N       = 1 << 15             # CPU/memory cost parameter (32768)
SCRYPT_R       = 8
SCRYPT_P       = 1
SCRYPT_KEY_LEN = 32
SCRYPT_SALT_LEN = 16


# ─────────────────────────────────────────────────────────────────────────────
# Ed25519 identity keys
# ─────────────────────────────────────────────────────────────────────────────

def generate_identity_keypair() -> Tuple[bytes, bytes]:
    """Generate an Ed25519 identity keypair.
    Returns (private_key_raw, public_key_raw)."""
    priv = Ed25519PrivateKey.generate()
    priv_bytes = priv.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    pub_bytes = priv.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return priv_bytes, pub_bytes


def sign_data(privkey_bytes: bytes, data: bytes) -> bytes:
    """Sign arbitrary data with an Ed25519 private key."""
    priv = Ed25519PrivateKey.from_private_bytes(privkey_bytes)
    return priv.sign(data)


def verify_signature(pubkey_bytes: bytes, data: bytes, signature: bytes) -> bool:
    """Verify an Ed25519 signature. Returns True iff valid."""
    try:
        pub = Ed25519PublicKey.from_public_bytes(pubkey_bytes)
        pub.verify(signature, data)
        return True
    except InvalidSignature:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# X25519 KEM (placeholder for Kyber768)
# ─────────────────────────────────────────────────────────────────────────────

def generate_kem_keypair() -> Tuple[bytes, bytes]:
    """Generate an X25519 KEM keypair.
    Returns (private_key_raw, public_key_raw)."""
    priv = X25519PrivateKey.generate()
    priv_bytes = priv.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    pub_bytes = priv.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return priv_bytes, pub_bytes


def kem_encapsulate(recipient_kem_pubkey: bytes) -> Tuple[bytes, bytes]:
    """
    Ephemeral X25519 ECDH encapsulation.
    Returns (ephemeral_pubkey_bytes, raw_shared_secret).
    Derive a symmetric key from the shared secret via HKDF before use.
    """
    eph_priv = X25519PrivateKey.generate()
    eph_pub = eph_priv.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    peer_pub = X25519PublicKey.from_public_bytes(recipient_kem_pubkey)
    shared = eph_priv.exchange(peer_pub)
    return eph_pub, shared


def kem_decapsulate(kem_privkey: bytes, ephemeral_pubkey: bytes) -> bytes:
    """
    X25519 ECDH decapsulation — mirrors kem_encapsulate on the receiver side.
    Returns the raw shared secret; derive a key via HKDF before use.
    """
    priv = X25519PrivateKey.from_private_bytes(kem_privkey)
    eph = X25519PublicKey.from_public_bytes(ephemeral_pubkey)
    return priv.exchange(eph)


def derive_aes_key(
    shared_secret: bytes,
    salt: bytes,
    info: bytes = b"otpmail-v1-otp-exchange",
) -> bytes:
    """Derive a 32-byte AES-256 key from a raw shared secret using HKDF-SHA256."""
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info)
    return hkdf.derive(shared_secret)


# ─────────────────────────────────────────────────────────────────────────────
# AES-256-GCM symmetric encryption
# ─────────────────────────────────────────────────────────────────────────────

def aes_gcm_encrypt(key: bytes, plaintext: bytes) -> Tuple[bytes, bytes]:
    """AES-256-GCM encrypt.
    Returns (nonce_12B, ciphertext_with_16B_tag)."""
    nonce = os.urandom(12)
    ct    = AESGCM(key).encrypt(nonce, plaintext, None)
    return nonce, ct


def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """AES-256-GCM decrypt. Raises cryptography.exceptions.InvalidTag on failure."""
    return AESGCM(key).decrypt(nonce, ciphertext, None)


# ─────────────────────────────────────────────────────────────────────────────
# Vault key derivation (password → AES key)
# ─────────────────────────────────────────────────────────────────────────────

def derive_vault_key(password: str, salt: bytes) -> bytes:
    """Derive a 32-byte vault encryption key from a user password using scrypt."""
    kdf = Scrypt(salt=salt, length=SCRYPT_KEY_LEN, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(password.encode("utf-8"))


# ─────────────────────────────────────────────────────────────────────────────
# OTP page generation and message encryption / decryption
# ─────────────────────────────────────────────────────────────────────────────

def generate_otp_pages(count: int = OTP_DEFAULT_PAGES) -> List[bytes]:
    """
    Generate `count` OTP pages using os.urandom (CSPRNG).

    Page layout (OTP_PAGE_SIZE bytes total):
      [ 0:32  ] HMAC-SHA256 key
      [32:4096] Encryption pad  (supports messages up to OTP_PAD_SIZE − 4 bytes)
    """
    return [os.urandom(OTP_PAGE_SIZE) for _ in range(count)]


def otp_encrypt_message(message: str, page: bytes) -> Tuple[bytes, bytes]:
    """
    Encrypt a UTF-8 string message using a single OTP page.

    Protocol:
      1. Encode message as UTF-8.
      2. Prepend a 4-byte big-endian length field.
      3. Zero-pad the combined payload to OTP_PAD_SIZE bytes.
      4. XOR the padded payload with the page's pad portion (bytes 32..4095).
      5. Compute HMAC-SHA256 over the ciphertext using the page's HMAC key (bytes 0..31).

    Returns:
      (ciphertext_bytes, hmac_tag_bytes)

    Raises ValueError if the message exceeds the maximum length.
    """
    if len(page) != OTP_PAGE_SIZE:
        raise ValueError(f"Invalid page size: expected {OTP_PAGE_SIZE}, got {len(page)}")

    hmac_key = page[:OTP_HMAC_KEY_SIZE]
    pad      = page[OTP_HMAC_KEY_SIZE:]

    msg_bytes = message.encode("utf-8")
    if len(msg_bytes) > OTP_PAD_SIZE - 4:
        raise ValueError(
            f"Message too long: {len(msg_bytes)} bytes "
            f"(maximum is {OTP_PAD_SIZE - 4} bytes)"
        )

    # 4-byte length prefix + message + zero padding
    payload   = struct.pack(">I", len(msg_bytes)) + msg_bytes
    padded    = payload + bytes(OTP_PAD_SIZE - len(payload))

    ciphertext = bytes(a ^ b for a, b in zip(padded, pad))

    h = hmac.HMAC(hmac_key, hashes.SHA256())
    h.update(ciphertext)
    hmac_tag = h.finalize()

    return ciphertext, hmac_tag


def otp_decrypt_message(ciphertext: bytes, hmac_tag: bytes, page: bytes) -> str:
    """
    Decrypt a message from an OTP page.

    Verifies the HMAC before decryption. A failed HMAC is treated as a
    tampering or desync signal and raises ValueError.

    Returns the original UTF-8 message string.
    """
    if len(page) != OTP_PAGE_SIZE:
        raise ValueError("Invalid page size")
    if len(ciphertext) != OTP_PAD_SIZE:
        raise ValueError(f"Invalid ciphertext size: {len(ciphertext)}")

    hmac_key = page[:OTP_HMAC_KEY_SIZE]
    pad      = page[OTP_HMAC_KEY_SIZE:]

    # Verify HMAC first — always, before touching ciphertext
    h = hmac.HMAC(hmac_key, hashes.SHA256())
    h.update(ciphertext)
    try:
        h.verify(hmac_tag)
    except Exception:
        raise ValueError("HMAC verification failed — possible tampering or page desync")

    # XOR decrypt
    plaintext_padded = bytes(a ^ b for a, b in zip(ciphertext, pad))

    msg_len = struct.unpack(">I", plaintext_padded[:4])[0]
    if msg_len > OTP_PAD_SIZE - 4:
        raise ValueError("Invalid embedded message length — corrupted plaintext")

    return plaintext_padded[4 : 4 + msg_len].decode("utf-8")


# ─────────────────────────────────────────────────────────────────────────────
# Utilities
# ─────────────────────────────────────────────────────────────────────────────

def pubkey_fingerprint(ed25519_pubkey: bytes) -> str:
    """Return a short, human-readable fingerprint for out-of-band key verification.
    Format: XXXX:XXXX:XXXX:XXXX (first 16 hex chars of SHA-256)."""
    digest = hashlib.sha256(ed25519_pubkey).hexdigest()
    return ":".join(digest[i : i + 4] for i in range(0, 16, 4))
