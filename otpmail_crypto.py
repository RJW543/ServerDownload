
import os
import re
import json
import secrets
import hmac as hmac_mod
import threading
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, Tuple, List

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

# ============================================================
#  CONFIGURATION
# ============================================================

PAGE_ID_HEX_LEN = 8          # 4 bytes = 8 hex chars for page identification
HMAC_KEY_BYTES = 32           # 256-bit HMAC key per page
HMAC_KEY_HEX_LEN = 64        # 32 bytes = 64 hex chars
PAGE_HEADER_HEX_LEN = PAGE_ID_HEX_LEN + HMAC_KEY_HEX_LEN  # 72
DEFAULT_PAGE_LENGTH = 3500    # Bytes of OTP content per page
MESSAGE_TTL_HOURS = 48
MESSAGE_SEPARATOR = '\x00'   # Null byte separates subject from body

# Legacy compat alias
PAGE_ID_LENGTH = PAGE_ID_HEX_LEN

_USERNAME_RE = re.compile(r'^[A-Za-z0-9_-]{1,32}$')


def validate_username(username: str) -> bool:
    """
    Validate username to prevent directory traversal and other injection.
    Allows letters, digits, underscore, hyphen. 1-32 characters.
    Rejects: empty, dots, slashes, spaces, special chars.
    """
    return bool(_USERNAME_RE.match(username))


def compute_safety_number(local_x25519_pub_hex: str,
                          remote_x25519_pub_hex: str) -> str:
    """
    Compute a safety number for out-of-band verification of a contact's
    X25519 public key. Both parties compute the same value regardless of
    who is 'local' vs 'remote' (keys are sorted before hashing).

    Returns a 48-digit decimal string formatted in groups of 5 for easy
    verbal comparison.
    """
    import hashlib
    keys = sorted([local_x25519_pub_hex, remote_x25519_pub_hex])
    digest = hashlib.sha256((keys[0] + keys[1]).encode('ascii')).hexdigest()
    # Full SHA-256 gives ~77 decimal digits — take 60 (12 groups of 5)
    numeric = str(int(digest, 16)).zfill(78)[-60:]
    return '  '.join(numeric[i:i+5] for i in range(0, 60, 5))


# ============================================================
#  1. OTP LAYER - Full-Entropy Byte-Based XOR + HMAC Integrity
# ============================================================

def otp_xor_encrypt(plaintext: bytes, pad_content: bytes) -> bytes:
    """
    Encrypt plaintext by XOR with full-entropy pad bytes.
    Both inputs are raw bytes. Returns raw ciphertext bytes.
    """
    if len(plaintext) > len(pad_content):
        raise ValueError(
            f"Message ({len(plaintext)} bytes) exceeds pad page ({len(pad_content)} bytes)")
    return bytes(p ^ k for p, k in zip(plaintext, pad_content))


def otp_xor_decrypt(ciphertext: bytes, pad_content: bytes) -> bytes:
    """Decrypt ciphertext by XOR with pad bytes."""
    if len(ciphertext) > len(pad_content):
        raise ValueError("Ciphertext longer than pad content")
    return bytes(c ^ k for c, k in zip(ciphertext, pad_content))


def compute_otp_hmac(hmac_key: bytes, ciphertext: bytes) -> bytes:
    """Compute HMAC-SHA256 over ciphertext using the page's HMAC key."""
    return hmac_mod.new(hmac_key, ciphertext, 'sha256').digest()


def verify_otp_hmac(hmac_key: bytes, ciphertext: bytes, expected_mac: bytes) -> bool:
    """Constant-time HMAC verification."""
    computed = hmac_mod.new(hmac_key, ciphertext, 'sha256').digest()
    return hmac_mod.compare_digest(computed, expected_mac)


def pack_message(subject: str, body: str) -> bytes:
    """Pack subject + body into bytes for OTP encryption.
    Subject is encrypted alongside the body - never exposed in protocol headers."""
    return (subject + MESSAGE_SEPARATOR + body).encode('utf-8')


def unpack_message(plaintext: bytes) -> Tuple[str, str]:
    """Unpack subject and body from decrypted OTP bytes."""
    text = plaintext.decode('utf-8', errors='replace')
    if MESSAGE_SEPARATOR in text:
        subject, body = text.split(MESSAGE_SEPARATOR, 1)
        return (subject, body)
    return ("(no subject)", text)


# ============================================================
#  2. AES TRANSIT LAYER - Per-Session Keys via HKDF
# ============================================================

def derive_master_key(transit_key_hex: str) -> bytes:
    """
    Derive master key from high-entropy transit key using HKDF.
    HKDF is the correct primitive when the input key material already
    has full entropy (256-bit random transit key), unlike PBKDF2 which
    is designed for low-entropy passwords.
    """
    key_bytes = bytes.fromhex(transit_key_hex)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"OTPMail-MasterKey-v3",
    )
    return hkdf.derive(key_bytes)


def load_transit_key_from_file(filepath) -> str:
    """Read transit key from a file, skipping comment lines."""
    p = Path(filepath)
    if not p.exists():
        return ""
    lines = [l.strip() for l in p.read_text().splitlines()
             if l.strip() and not l.strip().startswith('#')]
    return lines[0] if lines else ""


def generate_transit_key_file(filepath) -> str:
    """Generate a cryptographically strong transit key and save it."""
    key = secrets.token_hex(32)  # 64 hex chars = 256 bits
    Path(filepath).write_text(
        "# OTPMail Transit Key (auto-generated)\n"
        "# Share this key with clients securely. Do NOT use a weak passphrase.\n"
        f"{key}\n"
    )
    return key


def generate_session_salt() -> bytes:
    """Generate a 16-byte random salt for a new session."""
    return secrets.token_bytes(16)


def derive_session_key(master_key: bytes, session_salt: bytes,
                       ecdh_secret: bytes = b"") -> bytes:
    """
    Derive unique session transit key from master key + random salt.
    When ecdh_secret is provided (from ephemeral ECDHE), it's mixed in
    for forward secrecy.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=session_salt,
        info=b"OTPMail-SessionTransit-v3",
    )
    return hkdf.derive(master_key + ecdh_secret)


def generate_ephemeral_x25519() -> Tuple[X25519PrivateKey, bytes]:
    """Generate an ephemeral X25519 keypair for per-session forward secrecy.
    Returns (private_key_object, raw_32_byte_public_key)."""
    private = X25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return private, public


def compute_ecdh_secret(private_key: X25519PrivateKey,
                        peer_public_bytes: bytes) -> bytes:
    """Compute X25519 ECDH shared secret (32 bytes)."""
    peer_public = X25519PublicKey.from_public_bytes(peer_public_bytes)
    return private_key.exchange(peer_public)


def aes_transit_encrypt(plaintext_bytes: bytes, session_key: bytes,
                       aad: bytes = None) -> bytes:
    """Encrypt for transit. Returns: nonce (12B) || ciphertext+tag.
    Optional AAD (additional authenticated data) for sequence binding."""
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(session_key)
    ct = aesgcm.encrypt(nonce, plaintext_bytes, aad)
    return nonce + ct


def aes_transit_decrypt(encrypted_blob: bytes, session_key: bytes,
                        aad: bytes = None) -> bytes:
    """Decrypt transit-encrypted data. AAD must match what was used to encrypt."""
    if len(encrypted_blob) < 13:
        raise ValueError("Encrypted data too short")
    nonce = encrypted_blob[:12]
    ct = encrypted_blob[12:]
    aesgcm = AESGCM(session_key)
    return aesgcm.decrypt(nonce, ct, aad)


# ============================================================
#  3. IDENTITY & AUTHENTICATION - Ed25519 + X25519
# ============================================================

class KeyManager:
    """
    Manages Ed25519 (signing) and X25519 (ECDH) keypairs.

    Ed25519: Challenge-response authentication.
    X25519:  End-to-end encrypting cipher pads (server cannot read).

    Keys stored as PEM files, optionally encrypted with a passphrase.
    Generated on first run (TOFU model).
    """

    def __init__(self, keys_dir: Path, passphrase: str = None):
        self.keys_dir = keys_dir
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        self._passphrase = passphrase

        self.ed25519_private: Ed25519PrivateKey = None
        self.ed25519_public: Ed25519PublicKey = None
        self.x25519_private: X25519PrivateKey = None
        self.x25519_public: X25519PublicKey = None

        self._load_or_generate()

        # Passphrase no longer needed — keys are loaded into memory objects.
        # Scrub the string reference (best-effort; CPython may retain copies).
        self._passphrase = None

    def _get_encryption(self):
        """Return PEM encryption scheme - passphrase-based if available."""
        if self._passphrase:
            return serialization.BestAvailableEncryption(
                self._passphrase.encode('utf-8'))
        return serialization.NoEncryption()

    def _get_password(self):
        """Return password bytes for loading encrypted PEM, or None."""
        if self._passphrase:
            return self._passphrase.encode('utf-8')
        return None

    @staticmethod
    def _pem_is_encrypted(pem_data: bytes) -> bool:
        """Check if a PEM file is passphrase-encrypted."""
        return b'ENCRYPTED' in pem_data

    def _load_or_generate(self):
        ed_priv_path = self.keys_dir / "ed25519_private.pem"
        x_priv_path = self.keys_dir / "x25519_private.pem"

        if ed_priv_path.exists() and x_priv_path.exists():
            password = self._get_password()

            # Load Ed25519
            ed_pem = ed_priv_path.read_bytes()
            if self._pem_is_encrypted(ed_pem):
                # Key IS encrypted — password is required, no fallback
                if not password:
                    raise ValueError(
                        "Ed25519 key is passphrase-encrypted but no passphrase provided")
                self.ed25519_private = serialization.load_pem_private_key(
                    ed_pem, password=password)
            else:
                # Key is NOT encrypted — load without password
                self.ed25519_private = serialization.load_pem_private_key(
                    ed_pem, password=None)
                # If passphrase is set, migrate to encrypted (one-time)
                if password:
                    self._save_key(ed_priv_path, self.ed25519_private)
            self.ed25519_public = self.ed25519_private.public_key()

            # Load X25519 — same logic
            x_pem = x_priv_path.read_bytes()
            if self._pem_is_encrypted(x_pem):
                if not password:
                    raise ValueError(
                        "X25519 key is passphrase-encrypted but no passphrase provided")
                self.x25519_private = serialization.load_pem_private_key(
                    x_pem, password=password)
            else:
                self.x25519_private = serialization.load_pem_private_key(
                    x_pem, password=None)
                if password:
                    self._save_key(x_priv_path, self.x25519_private)
            self.x25519_public = self.x25519_private.public_key()
        else:
            self.ed25519_private = Ed25519PrivateKey.generate()
            self.ed25519_public = self.ed25519_private.public_key()
            self.x25519_private = X25519PrivateKey.generate()
            self.x25519_public = self.x25519_private.public_key()

            self._save_key(ed_priv_path, self.ed25519_private)
            self._save_key(x_priv_path, self.x25519_private)

    def _save_key(self, path: Path, private_key):
        """Save a private key to PEM, encrypted if passphrase is set."""
        path.write_bytes(private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            self._get_encryption(),
        ))

    def get_ed25519_public_hex(self) -> str:
        return self.ed25519_public.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()

    def get_x25519_public_hex(self) -> str:
        return self.x25519_public.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()

    def sign_challenge(self, challenge_bytes: bytes) -> bytes:
        return self.ed25519_private.sign(challenge_bytes)

    @staticmethod
    def verify_signature(ed25519_pub_hex: str, signature: bytes, challenge: bytes) -> bool:
        try:
            pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(ed25519_pub_hex))
            pub.verify(signature, challenge)
            return True
        except Exception:
            return False

    def e2e_encrypt(self, plaintext: bytes, recipient_x25519_pub_hex: str) -> bytes:
        """
        Encrypt with ephemeral-static ECDH + sender authentication.

        Combines:
          1. ephemeral_priv x recipient_static_pub  (forward secrecy)
          2. sender_static_priv x recipient_static_pub  (authentication)

        Blob format: eph_pub(32B) || nonce(12B) || ciphertext+tag

        Forward secrecy: even if the sender's static X25519 key is later
        compromised, past transfers remain secure because the ephemeral
        private key was deleted immediately after use.
        """
        peer_pub = X25519PublicKey.from_public_bytes(
            bytes.fromhex(recipient_x25519_pub_hex))

        # Ephemeral key for forward secrecy
        eph_priv, eph_pub = generate_ephemeral_x25519()
        ecdh_ephemeral = eph_priv.exchange(peer_pub)
        del eph_priv  # Destroy ephemeral private key immediately

        # Static key for sender authentication
        ecdh_static = self.x25519_private.exchange(peer_pub)

        # Derive key from both secrets
        derived_key = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=None,
            info=b"OTPMail-E2E-PadTransfer-v3",
        ).derive(ecdh_ephemeral + ecdh_static)

        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(derived_key)
        ct = aesgcm.encrypt(nonce, plaintext, None)
        return eph_pub + nonce + ct

    def e2e_decrypt(self, encrypted_blob: bytes, sender_x25519_pub_hex: str) -> bytes:
        """
        Decrypt E2E data using ephemeral-static + static-static ECDH.

        Requires sender's static X25519 pub for authentication verification.
        """
        if len(encrypted_blob) < 32 + 12 + 16:
            raise ValueError("E2E data too short")

        eph_pub_bytes = encrypted_blob[:32]
        nonce = encrypted_blob[32:44]
        ct = encrypted_blob[44:]

        eph_pub = X25519PublicKey.from_public_bytes(eph_pub_bytes)
        sender_pub = X25519PublicKey.from_public_bytes(
            bytes.fromhex(sender_x25519_pub_hex))

        # Reverse the two ECDH operations
        ecdh_ephemeral = self.x25519_private.exchange(eph_pub)
        ecdh_static = self.x25519_private.exchange(sender_pub)

        derived_key = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=None,
            info=b"OTPMail-E2E-PadTransfer-v3",
        ).derive(ecdh_ephemeral + ecdh_static)

        aesgcm = AESGCM(derived_key)
        return aesgcm.decrypt(nonce, ct, None)


class ServerIdentity:
    """
    Server-side Ed25519 identity for MITM-proof authentication.

    On first run the server generates a keypair and saves it.
    During the handshake the server sends:
        salt (16B) || server_ed25519_pub (32B) || server_eph_pub (32B)
        || signature(salt || server_eph_pub) (64B) = 144 bytes
    The client verifies the signature and pins the public key via TOFU.

    The PEM file is encrypted with a passphrase if one is provided.
    Set via OTPMAIL_SERVER_PASSPHRASE env var or passed directly.
    If no passphrase is set, falls back to unencrypted (with warning).
    """

    KEY_FILE = "server_identity_ed25519.pem"

    def __init__(self, data_dir: Path, passphrase: str = None):
        self.data_dir = data_dir
        self.data_dir.mkdir(parents=True, exist_ok=True)
        # Prefer explicit passphrase, then env var
        self._passphrase = passphrase or os.environ.get("OTPMAIL_SERVER_PASSPHRASE", "")
        self._private: Ed25519PrivateKey = None
        self._public: Ed25519PublicKey = None
        self._load_or_generate()
        # Passphrase no longer needed after key is loaded
        self._passphrase = None

    def _get_encryption(self):
        if self._passphrase:
            return serialization.BestAvailableEncryption(
                self._passphrase.encode('utf-8'))
        return serialization.NoEncryption()

    def _get_password(self) -> Optional[bytes]:
        if self._passphrase:
            return self._passphrase.encode('utf-8')
        return None

    def _load_or_generate(self):
        key_path = self.data_dir / self.KEY_FILE
        password = self._get_password()

        if key_path.exists():
            pem_data = key_path.read_bytes()
            pem_is_encrypted = b'ENCRYPTED' in pem_data

            if pem_is_encrypted:
                if not password:
                    raise ValueError(
                        "Server identity key is passphrase-encrypted but "
                        "OTPMAIL_SERVER_PASSPHRASE is not set")
                self._private = serialization.load_pem_private_key(
                    pem_data, password=password)
            else:
                self._private = serialization.load_pem_private_key(
                    pem_data, password=None)
                # Auto-migrate: re-encrypt with passphrase if one is now set
                if password:
                    key_path.write_bytes(self._private.private_bytes(
                        serialization.Encoding.PEM,
                        serialization.PrivateFormat.PKCS8,
                        self._get_encryption(),
                    ))
        else:
            self._private = Ed25519PrivateKey.generate()
            if not password:
                import warnings
                warnings.warn(
                    "Server identity key stored WITHOUT encryption. "
                    "Set OTPMAIL_SERVER_PASSPHRASE env var to protect it.",
                    stacklevel=2)
            key_path.write_bytes(self._private.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                self._get_encryption(),
            ))
            # Restrict file permissions (owner-only read/write)
            os.chmod(str(key_path), 0o600)

        self._public = self._private.public_key()

    def get_public_bytes(self) -> bytes:
        return self._public.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def get_public_hex(self) -> str:
        return self.get_public_bytes().hex()

    def get_fingerprint(self) -> str:
        import hashlib
        digest = hashlib.sha256(self.get_public_bytes()).hexdigest()
        return ':'.join(digest[i:i+4] for i in range(0, 32, 4))

    def sign_data(self, data: bytes) -> bytes:
        return self._private.sign(data)

    def sign_salt(self, salt: bytes) -> bytes:
        return self.sign_data(salt)

    @staticmethod
    def verify_server_signature(server_pub_bytes: bytes, signature: bytes,
                                data: bytes) -> bool:
        try:
            pub = Ed25519PublicKey.from_public_bytes(server_pub_bytes)
            pub.verify(signature, data)
            return True
        except Exception:
            return False


# ============================================================
#  4. VAULT LAYER - At-Rest Encrypted Storage
# ============================================================

class EncryptedVault:
    def __init__(self, vault_dir: Path, passphrase: str):
        self.vault_dir = vault_dir
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        self._key = self._derive_vault_key(passphrase)
        self._lock = threading.Lock()

    @staticmethod
    def _safe_filename(filename: str) -> str:
        """
        Defence-in-depth: reject any filename that could escape the vault dir.
        Even though callers currently sanitise inputs, the vault itself must
        not trust them.
        """
        if not filename:
            raise ValueError("Empty vault filename")
        basename = Path(filename).name
        if basename != filename:
            raise ValueError(f"Vault filename contains path components: {repr(filename)}")
        if '..' in filename or '/' in filename or '\\' in filename:
            raise ValueError(f"Vault filename contains illegal characters: {repr(filename)}")
        return filename

    def _derive_vault_key(self, passphrase: str) -> bytes:
        salt_file = self.vault_dir / ".vault_salt"
        if salt_file.exists():
            salt = salt_file.read_bytes()
        else:
            salt = secrets.token_bytes(16)
            salt_file.write_bytes(salt)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32,
            salt=salt, iterations=480_000,
        )
        return kdf.derive(passphrase.encode('utf-8'))

    def encrypt_and_store(self, filename: str, data: dict):
        """
        Atomic + durable vault write.
        Writes to temp file, fsyncs, then renames (atomic on POSIX).
        Thread-safe via internal lock.
        """
        filename = self._safe_filename(filename)
        plaintext = json.dumps(data).encode('utf-8')
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(self._key)
        ct = aesgcm.encrypt(nonce, plaintext, None)
        target = self.vault_dir / filename
        tmp = target.with_suffix('.tmp')
        with self._lock:
            tmp.write_bytes(nonce + ct)
            # fsync the temp file to ensure durability before rename
            fd = os.open(str(tmp), os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
            os.rename(str(tmp), str(target))

    def load_and_decrypt(self, filename: str) -> Optional[dict]:
        filename = self._safe_filename(filename)
        fp = self.vault_dir / filename
        with self._lock:
            if not fp.exists():
                return None
            try:
                blob = fp.read_bytes()
            except Exception:
                return None
        # Decryption outside lock (CPU-bound, doesn't need file access)
        try:
            aesgcm = AESGCM(self._key)
            plaintext = aesgcm.decrypt(blob[:12], blob[12:], None)
            return json.loads(plaintext.decode('utf-8'))
        except Exception:
            return None

    def delete_file(self, filename: str):
        filename = self._safe_filename(filename)
        fp = self.vault_dir / filename
        with self._lock:
            if fp.exists():
                fp.write_bytes(secrets.token_bytes(fp.stat().st_size))
                fp.unlink()

    def list_files(self, prefix: str = "") -> List[str]:
        with self._lock:
            return sorted(f.name for f in self.vault_dir.iterdir()
                          if f.is_file() and not f.name.startswith('.')
                          and f.name.startswith(prefix))


# ============================================================
#  5. PAD MANAGER - Full-Entropy Byte Pads with HMAC Integrity
# ============================================================

class PadManager:
    """
    Indexed One-Time Pad Manager with full-entropy byte pads.
    All pad data is encrypted at rest with AES-256-GCM when a
    passphrase is provided. Legacy plaintext pads are auto-migrated
    to encrypted storage on first access.

    Storage per contact (encrypted):
      pad.enc  - all pages, encrypted. Decrypted form: one hex line per page.
      role.enc - "generator" or "recipient", encrypted.
      used.enc - consumed page indices, encrypted.

    Each page line (decrypted hex):
      [PAGE_ID: 8 hex chars][HMAC_KEY: 64 hex chars][OTP_CONTENT: N hex chars]
      Total per page with default 3500-byte content = 7072 hex chars.

    Sync mechanism:
      Generator sends on EVEN indices (0, 2, 4, ...).
      Recipient sends on ODD indices (1, 3, 5, ...).

    HMAC integrity:
      Each page includes a 32-byte HMAC key. After XOR encryption, an
      HMAC-SHA256 is computed over the ciphertext and included in the
      payload. This detects bitflip attacks against the OTP ciphertext.

    Payload wire format:
      INDEX:PAGE_ID:HMAC_HEX:CIPHERTEXT_HEX
    """

    def __init__(self, pads_dir: Path, passphrase: str = None):
        self.pads_dir = pads_dir
        self.pads_dir.mkdir(parents=True, exist_ok=True)
        # Per-contact locks to prevent race conditions in page destruction
        self._locks: dict = {}
        self._global_lock = threading.Lock()

        # Derive encryption key for pad-at-rest protection
        if passphrase:
            self._pad_key = self._derive_pad_key(passphrase)
        else:
            self._pad_key = None

    def _derive_pad_key(self, passphrase: str) -> bytes:
        """Derive AES-256 key from vault passphrase for pad encryption."""
        salt_file = self.pads_dir / ".pad_salt"
        if salt_file.exists():
            salt = salt_file.read_bytes()
        else:
            salt = secrets.token_bytes(16)
            salt_file.write_bytes(salt)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32,
            salt=salt, iterations=480_000,
        )
        return kdf.derive(passphrase.encode('utf-8'))

    # -- encrypted I/O --

    def _write_encrypted(self, filepath: Path, data: bytes):
        """Encrypt data and write atomically with fsync."""
        if self._pad_key:
            nonce = secrets.token_bytes(12)
            aesgcm = AESGCM(self._pad_key)
            blob = nonce + aesgcm.encrypt(nonce, data, None)
        else:
            blob = data
        tmp = filepath.with_suffix('.tmp')
        tmp.write_bytes(blob)
        fd = os.open(str(tmp), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        os.rename(str(tmp), str(filepath))

    def _read_decrypted(self, filepath: Path) -> bytes:
        """Read file and decrypt. Returns plaintext bytes."""
        blob = filepath.read_bytes()
        if not self._pad_key:
            return blob
        if len(blob) < 13:
            raise ValueError("Encrypted pad file too short")
        aesgcm = AESGCM(self._pad_key)
        return aesgcm.decrypt(blob[:12], blob[12:], None)

    # -- migration from plaintext legacy files --

    def _migrate_contact(self, cid: str):
        """
        Auto-migrate a contact from plaintext (.txt) to encrypted (.enc).
        Idempotent — skips files that are already migrated.
        Securely wipes the plaintext pad file after migration.
        """
        if not self._pad_key:
            return
        d = self._contact_dir(cid)

        for old_name, new_name, wipe in [
            ("pad.txt",  "pad.enc",  True),   # Wipe pad (sensitive key material)
            ("role.txt", "role.enc", False),
            ("used.txt", "used.enc", False),
        ]:
            old_fp = d / old_name
            new_fp = d / new_name
            if old_fp.exists() and not new_fp.exists():
                data = old_fp.read_bytes()
                self._write_encrypted(new_fp, data)
                if wipe:
                    size = old_fp.stat().st_size
                    old_fp.write_bytes(secrets.token_bytes(size))
                old_fp.unlink()

    def _get_contact_lock(self, cid: str) -> threading.Lock:
        """Get or create a threading lock for a specific contact."""
        with self._global_lock:
            if cid not in self._locks:
                self._locks[cid] = threading.Lock()
            return self._locks[cid]

    # -- paths --
    def _contact_dir(self, cid: str) -> Path:
        if not validate_username(cid):
            raise ValueError(f"Invalid contact ID: {repr(cid)}")
        d = self.pads_dir / cid
        d.mkdir(exist_ok=True)
        return d

    def _pad_file(self, cid: str) -> Path:
        return self._contact_dir(cid) / ("pad.enc" if self._pad_key else "pad.txt")

    def _role_file(self, cid: str) -> Path:
        return self._contact_dir(cid) / ("role.enc" if self._pad_key else "role.txt")

    def _used_file(self, cid: str) -> Path:
        return self._contact_dir(cid) / ("used.enc" if self._pad_key else "used.txt")

    # -- role helpers --
    def _get_role(self, cid: str) -> str:
        rf = self._role_file(cid)
        if rf.exists():
            data = self._read_decrypted(rf)
            return data.decode('utf-8').strip()
        return "generator"

    def _set_role(self, cid: str, role: str):
        self._write_encrypted(self._role_file(cid), role.encode('utf-8'))

    def _send_parity(self, cid: str) -> int:
        """Generator sends on even (0), recipient sends on odd (1)."""
        return 0 if self._get_role(cid) == "generator" else 1

    # -- used tracking --
    def _load_used(self, cid: str) -> set:
        uf = self._used_file(cid)
        if not uf.exists():
            return set()
        data = self._read_decrypted(uf)
        used = set()
        for line in data.decode('utf-8').splitlines():
            s = line.strip()
            if s.isdigit():
                used.add(int(s))
        return used

    def _mark_used(self, cid: str, index: int):
        """
        Mark a page as used. Read-modify-write with encryption and fsync.
        Crash-safe: if we crash before write completes, the old file is
        intact (atomic rename) and the page will be re-consumed on next
        attempt — safe because the message was not ACKed yet.
        """
        uf = self._used_file(cid)
        if uf.exists():
            text = self._read_decrypted(uf).decode('utf-8')
        else:
            text = ""
        text += f"{index}\n"
        self._write_encrypted(uf, text.encode('utf-8'))

    def _destroy_page_content(self, cid: str, index: int):
        """
        Replace a consumed page with !USED! marker and re-encrypt.

        With encryption-at-rest the disk never holds plaintext pad data,
        so the two-pass plaintext overwrite is no longer needed. We simply
        decrypt, replace the page line, and write the re-encrypted blob
        atomically.

        MUST be called while holding the contact lock.
        """
        pf = self._pad_file(cid)
        if not pf.exists():
            return
        data = self._read_decrypted(pf)
        lines = data.decode('utf-8').split('\n')
        if lines and lines[-1] == '':
            lines = lines[:-1]
        if index < 0 or index >= len(lines):
            return
        if len(lines[index].strip()) > 6:  # Skip if already !USED!
            lines[index] = '!USED!'
        content = '\n'.join(lines) + '\n'
        self._write_encrypted(pf, content.encode('utf-8'))

    # -- page parsing --
    @staticmethod
    def _parse_page(line: str) -> Optional[Tuple[str, bytes, bytes]]:
        """
        Parse a hex-encoded page line into (page_id_hex, hmac_key, otp_content).
        Returns None if the page is consumed or malformed.
        """
        line = line.strip()
        if len(line) <= PAGE_HEADER_HEX_LEN:
            return None
        try:
            page_id = line[:PAGE_ID_HEX_LEN]
            hmac_key = bytes.fromhex(line[PAGE_ID_HEX_LEN:PAGE_HEADER_HEX_LEN])
            otp_content = bytes.fromhex(line[PAGE_HEADER_HEX_LEN:])
            return (page_id, hmac_key, otp_content)
        except ValueError:
            return None

    # -- page access --
    def _load_pages(self, cid: str) -> List[str]:
        # Auto-migrate from plaintext if needed
        self._migrate_contact(cid)
        pf = self._pad_file(cid)
        if not pf.exists():
            return []
        data = self._read_decrypted(pf)
        lines = data.decode('utf-8').split('\n')
        if lines and lines[-1] == '':
            lines = lines[:-1]
        return lines

    def contact_has_pad(self, cid: str) -> bool:
        try:
            d = self._contact_dir(cid)
            # Check encrypted and legacy plaintext
            for name in ("pad.enc", "pad.txt"):
                fp = d / name
                if fp.exists() and fp.stat().st_size > 0:
                    return True
            return False
        except ValueError:
            return False

    def get_page_count(self, cid: str) -> int:
        """Return number of remaining SEND pages for this side."""
        pages = self._load_pages(cid)
        used = self._load_used(cid)
        parity = self._send_parity(cid)
        count = 0
        for i in range(len(pages)):
            if i % 2 == parity and i not in used:
                if self._parse_page(pages[i]) is not None:
                    count += 1
        return count

    def get_recv_remaining(self, cid: str) -> int:
        """Return number of remaining RECV pages for this side."""
        pages = self._load_pages(cid)
        used = self._load_used(cid)
        parity = self._send_parity(cid)
        recv_parity = 1 - parity
        count = 0
        for i in range(len(pages)):
            if i % 2 == recv_parity and i not in used:
                if self._parse_page(pages[i]) is not None:
                    count += 1
        return count

    def get_total_remaining(self, cid: str) -> int:
        """Total unused pages (send + recv)."""
        pages = self._load_pages(cid)
        used = self._load_used(cid)
        count = 0
        for i in range(len(pages)):
            if i not in used and self._parse_page(pages[i]) is not None:
                count += 1
        return count

    def consume_page(self, cid: str) -> Optional[Tuple[int, str, bytes, bytes]]:
        """
        Pick the next available SEND page (matching our parity).
        Returns (index, page_id_hex, hmac_key, otp_content) or None.

        Thread-safe: holds a per-contact lock to prevent concurrent
        read-modify-write races in _destroy_page_content.
        """
        lock = self._get_contact_lock(cid)
        with lock:
            pages = self._load_pages(cid)
            used = self._load_used(cid)
            parity = self._send_parity(cid)

            for i in range(len(pages)):
                if i % 2 != parity:
                    continue
                if i in used:
                    continue
                parsed = self._parse_page(pages[i])
                if parsed is None:
                    continue

                page_id, hmac_key, otp_content = parsed
                # 1. Durably mark as used BEFORE reading content
                self._mark_used(cid, i)
                # 2. Destroy key material in encrypted file
                self._destroy_page_content(cid, i)
                return (i, page_id, hmac_key, otp_content)
            return None

    def find_page_by_index(self, index: int, cid: str,
                           expected_page_id: str = None) -> Optional[Tuple[bytes, bytes]]:
        """
        Look up a page by its numeric index (for decrypting incoming mail).
        Returns (hmac_key, otp_content) or None.

        If expected_page_id is provided, verifies it matches the stored
        page ID to detect index manipulation by a compromised server.

        Thread-safe: holds per-contact lock.
        """
        lock = self._get_contact_lock(cid)
        with lock:
            pages = self._load_pages(cid)
            used = self._load_used(cid)

            if index < 0 or index >= len(pages):
                return None
            if index in used:
                return None

            parsed = self._parse_page(pages[index])
            if parsed is None:
                return None

            page_id, hmac_key, otp_content = parsed

            # Verify page ID if provided (prevents index manipulation)
            if expected_page_id is not None and page_id != expected_page_id:
                return None

            # 1. Durably mark as used
            self._mark_used(cid, index)
            # 2. Destroy key material in encrypted file
            self._destroy_page_content(cid, index)
            return (hmac_key, otp_content)

    def generate_pad(self, cid: str, num_pages: int,
                     page_length: int = DEFAULT_PAGE_LENGTH) -> int:
        """Generate a new full-entropy byte pad, REPLACING any existing pad."""
        if not validate_username(cid):
            raise ValueError(f"Invalid contact ID: {repr(cid)}")
        self.delete_pad(cid)
        lines = [self._generate_page(page_length) for _ in range(num_pages)]
        content = '\n'.join(lines) + '\n'
        self._write_encrypted(self._pad_file(cid), content.encode('utf-8'))
        self._set_role(cid, "generator")
        return num_pages

    def delete_pad(self, cid: str):
        """Delete all pad data for a contact (encrypted + legacy plaintext)."""
        try:
            d = self._contact_dir(cid)
        except ValueError:
            return
        for fname in ("pad.enc", "role.enc", "used.enc",
                      "pad.txt", "role.txt", "used.txt", "cipher.txt"):
            fp = d / fname
            if fp.exists():
                if fname.startswith("pad"):
                    size = fp.stat().st_size
                    fp.write_bytes(secrets.token_bytes(size))
                fp.unlink()

    def get_shareable_data(self, cid: str) -> str:
        """Return raw pad content (decrypted) for E2E sharing with the contact."""
        # Ensure migration first
        self._migrate_contact(cid)
        pf = self._pad_file(cid)
        if not pf.exists():
            return ""
        data = self._read_decrypted(pf)
        return data.decode('utf-8').strip()

    def import_shared_pad(self, cid: str, pad_data: str) -> int:
        """Import pad received from contact, REPLACING any existing pad."""
        if not validate_username(cid):
            raise ValueError(f"Invalid contact ID: {repr(cid)}")
        pages = [l for l in pad_data.split('\n')
                 if len(l.strip()) > PAGE_HEADER_HEX_LEN]
        if not pages:
            return 0
        self.delete_pad(cid)
        self._contact_dir(cid)  # Ensure directory exists
        content = '\n'.join(p.rstrip('\n') for p in pages) + '\n'
        self._write_encrypted(self._pad_file(cid), content.encode('utf-8'))
        self._set_role(cid, "recipient")
        return len(pages)

    def _generate_page(self, content_length: int) -> str:
        """
        Generate a single pad page as a hex string.

        Layout: PAGE_ID (4 bytes) + HMAC_KEY (32 bytes) + OTP content (content_length bytes)
        All generated from os.urandom - full 256-value entropy per byte.
        """
        total_bytes = (PAGE_ID_HEX_LEN // 2) + HMAC_KEY_BYTES + content_length
        raw = os.urandom(total_bytes)
        return raw.hex()

    def get_all_contacts(self) -> List[str]:
        if not self.pads_dir.exists():
            return []
        contacts = []
        for d in self.pads_dir.iterdir():
            if d.is_dir():
                # Check both encrypted and legacy plaintext
                if (d / "pad.enc").exists() or (d / "pad.txt").exists():
                    contacts.append(d.name)
        return sorted(contacts)


# ============================================================
#  6. MESSAGE STORE
# ============================================================

class MessageStore:
    def __init__(self, vault: EncryptedVault):
        self.vault = vault

    def store_received(self, sender, recipient, subject, body, page_id) -> str:
        ts = datetime.now()
        fname = f"inbox_{ts.strftime('%Y%m%d%H%M%S%f')}_{sender}.msg"
        self.vault.encrypt_and_store(fname, {
            "from": sender, "to": recipient, "subject": subject,
            "body": body, "timestamp": ts.isoformat(), "page_id": page_id,
            "read": False,
        })
        return fname

    def store_sent(self, sender, recipient, subject, body, page_id) -> str:
        ts = datetime.now()
        fname = f"sent_{ts.strftime('%Y%m%d%H%M%S%f')}_{recipient}.msg"
        self.vault.encrypt_and_store(fname, {
            "from": sender, "to": recipient, "subject": subject,
            "body": body, "timestamp": ts.isoformat(), "page_id": page_id,
        })
        return fname

    def get_inbox(self) -> List[dict]:
        msgs = []
        for fn in self.vault.list_files("inbox_"):
            d = self.vault.load_and_decrypt(fn)
            if d:
                d['_filename'] = fn
                msgs.append(d)
        msgs.sort(key=lambda m: m.get('timestamp', ''), reverse=True)
        return msgs

    def get_sent(self) -> List[dict]:
        msgs = []
        for fn in self.vault.list_files("sent_"):
            d = self.vault.load_and_decrypt(fn)
            if d:
                d['_filename'] = fn
                msgs.append(d)
        msgs.sort(key=lambda m: m.get('timestamp', ''), reverse=True)
        return msgs

    def mark_read(self, filename):
        d = self.vault.load_and_decrypt(filename)
        if d:
            d['read'] = True
            self.vault.encrypt_and_store(filename, d)

    def toggle_favourite(self, filename) -> bool:
        d = self.vault.load_and_decrypt(filename)
        if d:
            d['favourite'] = not d.get('favourite', False)
            self.vault.encrypt_and_store(filename, d)
            return d['favourite']
        return False

    def delete_message(self, filename):
        self.vault.delete_file(filename)

    def purge_expired(self) -> int:
        cutoff = datetime.now() - timedelta(hours=MESSAGE_TTL_HOURS)
        purged = 0
        for prefix in ("inbox_", "sent_"):
            for fn in self.vault.list_files(prefix):
                d = self.vault.load_and_decrypt(fn)
                if d:
                    if d.get('favourite', False):
                        continue
                    try:
                        if datetime.fromisoformat(d['timestamp']) < cutoff:
                            self.vault.delete_file(fn)
                            purged += 1
                    except (KeyError, ValueError):
                        self.vault.delete_file(fn)
                        purged += 1
        return purged

    def get_unread_count(self) -> int:
        count = 0
        for fn in self.vault.list_files("inbox_"):
            d = self.vault.load_and_decrypt(fn)
            if d and not d.get('read', False):
                count += 1
        return count
