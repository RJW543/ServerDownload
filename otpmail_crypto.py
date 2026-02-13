
import os
import json
import secrets
import string
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

PAGE_ID_LENGTH = 8
DEFAULT_PAGE_LENGTH = 3500
MESSAGE_TTL_HOURS = 48
MESSAGE_SEPARATOR = '\x00'  # Null byte separates subject from body in OTP plaintext

OTP_CHARSET = string.ascii_uppercase + string.digits + string.punctuation
OTP_CHARSET_LEN = len(OTP_CHARSET)  # 68
OTP_REJECTION_LIMIT = 204           # 68 * 3, unbiased sampling


# ============================================================
#  1. OTP LAYER - XOR Encryption with One-Time Pad
# ============================================================

def otp_xor_encrypt(plaintext: str, pad_content: str) -> str:
    """Encrypt plaintext by XOR with pad content. Returns hex-encoded ciphertext."""
    if len(plaintext) > len(pad_content):
        raise ValueError(f"Message ({len(plaintext)} chars) exceeds pad page ({len(pad_content)} chars)")
    encrypted = []
    for i, char in enumerate(plaintext):
        encrypted.append(ord(char) ^ ord(pad_content[i]))
    return bytes(encrypted).hex()


def otp_xor_decrypt(hex_ciphertext: str, pad_content: str) -> str:
    """Decrypt hex-encoded ciphertext by XOR with pad content."""
    try:
        cipher_bytes = bytes.fromhex(hex_ciphertext)
    except ValueError:
        raise ValueError("Invalid hex ciphertext")
    decrypted = []
    for i, byte_val in enumerate(cipher_bytes):
        if i >= len(pad_content):
            break
        decrypted.append(chr(byte_val ^ ord(pad_content[i])))
    return ''.join(decrypted)


def pack_message(subject: str, body: str) -> str:
    """Pack subject + body into single plaintext for OTP encryption.
    Subject is encrypted alongside the body — never exposed in protocol headers."""
    return subject + MESSAGE_SEPARATOR + body


def unpack_message(plaintext: str) -> Tuple[str, str]:
    """Unpack subject and body from decrypted OTP plaintext."""
    if MESSAGE_SEPARATOR in plaintext:
        subject, body = plaintext.split(MESSAGE_SEPARATOR, 1)
        return (subject, body)
    return ("(no subject)", plaintext)


# ============================================================
#  2. AES TRANSIT LAYER - Per-Session Keys via HKDF
# ============================================================

def derive_master_key(passphrase: str) -> bytes:
    """
    Derive master key from shared passphrase using PBKDF2.
    Done once at startup. Combined with per-session random salt
    via HKDF to produce unique session keys.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"OTPMail-MasterKey-v2",
        iterations=480_000,
    )
    return kdf.derive(passphrase.encode('utf-8'))


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


def derive_session_key(master_key: bytes, session_salt: bytes) -> bytes:
    """
    Derive unique session transit key from master key + random salt.
    Uses HKDF (fast) since master key already has full entropy from PBKDF2.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=session_salt,
        info=b"OTPMail-SessionTransit-v2",
    )
    return hkdf.derive(master_key)


def aes_transit_encrypt(plaintext_bytes: bytes, session_key: bytes) -> bytes:
    """Encrypt for transit. Returns: nonce (12B) || ciphertext+tag."""
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(session_key)
    ct = aesgcm.encrypt(nonce, plaintext_bytes, None)
    return nonce + ct


def aes_transit_decrypt(encrypted_blob: bytes, session_key: bytes) -> bytes:
    """Decrypt transit-encrypted data."""
    if len(encrypted_blob) < 13:
        raise ValueError("Encrypted data too short")
    nonce = encrypted_blob[:12]
    ct = encrypted_blob[12:]
    aesgcm = AESGCM(session_key)
    return aesgcm.decrypt(nonce, ct, None)


# ============================================================
#  3. IDENTITY & AUTHENTICATION - Ed25519 + X25519
# ============================================================

class KeyManager:
    """
    Manages Ed25519 (signing) and X25519 (ECDH) keypairs.

    Ed25519: Challenge-response authentication.
    X25519:  End-to-end encrypting cipher pads (server cannot read).

    Keys stored as PEM files. Generated on first run (TOFU model).
    """

    def __init__(self, keys_dir: Path):
        self.keys_dir = keys_dir
        self.keys_dir.mkdir(parents=True, exist_ok=True)

        self.ed25519_private: Ed25519PrivateKey = None
        self.ed25519_public: Ed25519PublicKey = None
        self.x25519_private: X25519PrivateKey = None
        self.x25519_public: X25519PublicKey = None

        self._load_or_generate()

    def _load_or_generate(self):
        ed_priv_path = self.keys_dir / "ed25519_private.pem"
        x_priv_path = self.keys_dir / "x25519_private.pem"

        if ed_priv_path.exists() and x_priv_path.exists():
            self.ed25519_private = serialization.load_pem_private_key(
                ed_priv_path.read_bytes(), password=None)
            self.ed25519_public = self.ed25519_private.public_key()
            self.x25519_private = serialization.load_pem_private_key(
                x_priv_path.read_bytes(), password=None)
            self.x25519_public = self.x25519_private.public_key()
        else:
            self.ed25519_private = Ed25519PrivateKey.generate()
            self.ed25519_public = self.ed25519_private.public_key()
            self.x25519_private = X25519PrivateKey.generate()
            self.x25519_public = self.x25519_private.public_key()

            ed_priv_path.write_bytes(self.ed25519_private.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ))
            x_priv_path.write_bytes(self.x25519_private.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
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
        """Encrypt with ECDH shared secret. Server cannot decrypt."""
        peer_pub = X25519PublicKey.from_public_bytes(
            bytes.fromhex(recipient_x25519_pub_hex))
        shared_secret = self.x25519_private.exchange(peer_pub)
        derived_key = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=None,
            info=b"OTPMail-E2E-PadTransfer-v2",
        ).derive(shared_secret)
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(derived_key)
        ct = aesgcm.encrypt(nonce, plaintext, None)
        return nonce + ct

    def e2e_decrypt(self, encrypted_blob: bytes, sender_x25519_pub_hex: str) -> bytes:
        """Decrypt E2E data using ECDH shared secret."""
        peer_pub = X25519PublicKey.from_public_bytes(
            bytes.fromhex(sender_x25519_pub_hex))
        shared_secret = self.x25519_private.exchange(peer_pub)
        derived_key = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=None,
            info=b"OTPMail-E2E-PadTransfer-v2",
        ).derive(shared_secret)
        if len(encrypted_blob) < 13:
            raise ValueError("E2E data too short")
        nonce = encrypted_blob[:12]
        ct = encrypted_blob[12:]
        aesgcm = AESGCM(derived_key)
        return aesgcm.decrypt(nonce, ct, None)


class ServerIdentity:
    """
    Server-side Ed25519 identity for MITM-proof authentication.

    On first run the server generates a keypair and saves it.
    During the handshake the server sends:
        salt (16B) || server_ed25519_pub (32B) || signature(salt) (64B)
    The client verifies the signature and pins the public key via TOFU.
    """

    KEY_FILE = "server_identity_ed25519.pem"

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._private: Ed25519PrivateKey = None
        self._public: Ed25519PublicKey = None
        self._load_or_generate()

    def _load_or_generate(self):
        key_path = self.data_dir / self.KEY_FILE
        if key_path.exists():
            self._private = serialization.load_pem_private_key(
                key_path.read_bytes(), password=None)
        else:
            self._private = Ed25519PrivateKey.generate()
            key_path.write_bytes(self._private.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ))
        self._public = self._private.public_key()

    def get_public_bytes(self) -> bytes:
        """Return raw 32-byte public key."""
        return self._public.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def get_public_hex(self) -> str:
        return self.get_public_bytes().hex()

    def get_fingerprint(self) -> str:
        """SHA-256 fingerprint for display / verification."""
        import hashlib
        digest = hashlib.sha256(self.get_public_bytes()).hexdigest()
        return ':'.join(digest[i:i+4] for i in range(0, 32, 4))

    def sign_salt(self, salt: bytes) -> bytes:
        """Sign the session salt. Returns 64-byte Ed25519 signature."""
        return self._private.sign(salt)

    @staticmethod
    def verify_server_signature(server_pub_bytes: bytes, signature: bytes, salt: bytes) -> bool:
        """Client-side: verify the server signed this salt."""
        try:
            pub = Ed25519PublicKey.from_public_bytes(server_pub_bytes)
            pub.verify(signature, salt)
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
        plaintext = json.dumps(data).encode('utf-8')
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(self._key)
        ct = aesgcm.encrypt(nonce, plaintext, None)
        (self.vault_dir / filename).write_bytes(nonce + ct)

    def load_and_decrypt(self, filename: str) -> Optional[dict]:
        fp = self.vault_dir / filename
        if not fp.exists():
            return None
        try:
            blob = fp.read_bytes()
            aesgcm = AESGCM(self._key)
            plaintext = aesgcm.decrypt(blob[:12], blob[12:], None)
            return json.loads(plaintext.decode('utf-8'))
        except Exception:
            return None

    def delete_file(self, filename: str):
        fp = self.vault_dir / filename
        if fp.exists():
            fp.write_bytes(secrets.token_bytes(fp.stat().st_size))
            fp.unlink()

    def list_files(self, prefix: str = "") -> List[str]:
        return sorted(f.name for f in self.vault_dir.iterdir()
                      if f.is_file() and not f.name.startswith('.') and f.name.startswith(prefix))


# ============================================================
#  5. PAD MANAGER
# ============================================================

class PadManager:
    """
    Indexed One-Time Pad Manager.

    Storage per contact:
      pad.txt  — all pages, one per line. Line number = page index (0-based).
      role.txt — "generator" (created the pad) or "recipient" (received it).
      used.txt — indices already consumed, one per line.

    Sync mechanism:
      The generator sends using EVEN-indexed pages (0, 2, 4, …).
      The recipient sends using ODD-indexed pages  (1, 3, 5, …).
      The page index travels UNENCRYPTED at the front of every payload
      so the receiver always knows exactly which page to decrypt with.
      Since each direction draws from non-overlapping indices, desync
      is impossible regardless of message ordering or timing.

    Payload wire format (constructed by client):
      INDEX:PAGE_ID:hex_ciphertext
    """

    def __init__(self, pads_dir: Path):
        self.pads_dir = pads_dir
        self.pads_dir.mkdir(parents=True, exist_ok=True)

    # -- paths --
    def _contact_dir(self, cid: str) -> Path:
        d = self.pads_dir / cid
        d.mkdir(exist_ok=True)
        return d

    def _pad_file(self, cid: str) -> Path:
        return self._contact_dir(cid) / "pad.txt"

    def _role_file(self, cid: str) -> Path:
        return self._contact_dir(cid) / "role.txt"

    def _used_file(self, cid: str) -> Path:
        return self._contact_dir(cid) / "used.txt"

    # kept for legacy compat check
    def _cipher_file(self, cid: str) -> Path:
        return self._contact_dir(cid) / "cipher.txt"

    # -- role helpers --
    def _get_role(self, cid: str) -> str:
        rf = self._role_file(cid)
        if rf.exists():
            return rf.read_text(encoding='utf-8').strip()
        return "generator"

    def _set_role(self, cid: str, role: str):
        self._role_file(cid).write_text(role, encoding='utf-8')

    def _send_parity(self, cid: str) -> int:
        """Generator sends on even (0), recipient sends on odd (1)."""
        return 0 if self._get_role(cid) == "generator" else 1

    # -- used tracking --
    def _load_used(self, cid: str) -> set:
        uf = self._used_file(cid)
        if not uf.exists():
            return set()
        with open(uf, 'r', encoding='utf-8') as f:
            used = set()
            for line in f:
                s = line.strip()
                if s.isdigit():
                    used.add(int(s))
            return used

    def _mark_used(self, cid: str, index: int):
        """Mark a page as used with fsync for crash-safety."""
        uf = self._used_file(cid)
        with open(uf, 'a', encoding='utf-8') as f:
            f.write(f"{index}\n")
            f.flush()
            os.fsync(f.fileno())

    def _destroy_page_content(self, cid: str, index: int):
        """
        Overwrite the page content in pad.txt with a short marker.
        The marker is shorter than PAGE_ID_LENGTH so the page will fail
        the length check and be unreadable even if used.txt is lost.
        """
        pf = self._pad_file(cid)
        if not pf.exists():
            return
        with open(pf, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        if index < 0 or index >= len(lines):
            return
        # Replace with short marker that fails len > PAGE_ID_LENGTH check
        lines[index] = '!USED!\n'
        with open(pf, 'w', encoding='utf-8') as f:
            f.writelines(lines)
            f.flush()
            os.fsync(f.fileno())

    # -- page access --
    def _load_pages(self, cid: str) -> List[str]:
        pf = self._pad_file(cid)
        if not pf.exists():
            return []
        with open(pf, 'r', encoding='utf-8') as f:
            return [l.rstrip('\n') for l in f]

    def contact_has_pad(self, cid: str) -> bool:
        pf = self._pad_file(cid)
        return pf.exists() and pf.stat().st_size > 0

    def get_page_count(self, cid: str) -> int:
        """Return number of remaining SEND pages for this side."""
        pages = self._load_pages(cid)
        used = self._load_used(cid)
        parity = self._send_parity(cid)
        return sum(1 for i in range(len(pages))
                   if i % 2 == parity and i not in used
                   and len(pages[i].strip()) > PAGE_ID_LENGTH)

    def get_recv_remaining(self, cid: str) -> int:
        """Return number of remaining RECV pages for this side."""
        pages = self._load_pages(cid)
        used = self._load_used(cid)
        parity = self._send_parity(cid)
        recv_parity = 1 - parity
        return sum(1 for i in range(len(pages))
                   if i % 2 == recv_parity and i not in used
                   and len(pages[i].strip()) > PAGE_ID_LENGTH)

    def get_total_remaining(self, cid: str) -> int:
        """Total unused pages (send + recv)."""
        pages = self._load_pages(cid)
        used = self._load_used(cid)
        return sum(1 for i in range(len(pages))
                   if i not in used and len(pages[i].strip()) > PAGE_ID_LENGTH)

    def consume_page(self, cid: str) -> Optional[Tuple[int, str, str]]:
        """
        Pick the next available SEND page (matching our parity).
        Returns (index, page_id, page_content) or None.

        Safety order: mark used (fsync) → read content → destroy page.
        Even if the app crashes after mark but before send, the page
        is safely wasted rather than risking reuse.
        """
        pages = self._load_pages(cid)
        used = self._load_used(cid)
        parity = self._send_parity(cid)

        for i in range(len(pages)):
            if i % 2 != parity:
                continue
            if i in used:
                continue
            line = pages[i]
            if len(line.strip()) <= PAGE_ID_LENGTH:
                continue
            # 1. Durably mark as used BEFORE reading content
            self._mark_used(cid, i)
            page_id = line[:PAGE_ID_LENGTH]
            page_content = line[PAGE_ID_LENGTH:]
            # 2. Destroy key material on disk (backup-restoration defence)
            self._destroy_page_content(cid, i)
            return (i, page_id, page_content)
        return None

    def find_page_by_index(self, index: int, cid: str) -> Optional[str]:
        """
        Look up a page by its numeric index (for decrypting incoming mail).
        Returns page_content (without page_id prefix) or None.
        """
        pages = self._load_pages(cid)
        used = self._load_used(cid)

        if index < 0 or index >= len(pages):
            return None
        if index in used:
            return None
        line = pages[index]
        if len(line.strip()) <= PAGE_ID_LENGTH:
            return None
        # 1. Durably mark as used
        self._mark_used(cid, index)
        page_content = line[PAGE_ID_LENGTH:]
        # 2. Destroy key material on disk
        self._destroy_page_content(cid, index)
        return page_content

    def generate_pad(self, cid: str, num_pages: int,
                     page_length: int = DEFAULT_PAGE_LENGTH) -> int:
        """Generate a new pad, REPLACING any existing pad for this contact."""
        self.delete_pad(cid)
        pf = self._pad_file(cid)
        with open(pf, 'w', encoding='utf-8') as out:
            for _ in range(num_pages):
                out.write(self._generate_page(page_length) + '\n')
        self._set_role(cid, "generator")
        return num_pages

    def delete_pad(self, cid: str):
        """Delete all pad data for a contact."""
        d = self._contact_dir(cid)
        for fname in ("pad.txt", "role.txt", "used.txt", "cipher.txt"):
            fp = d / fname
            if fp.exists():
                fp.unlink()

    def get_shareable_data(self, cid: str) -> str:
        """Return raw pad content for E2E sharing with the contact."""
        pf = self._pad_file(cid)
        if not pf.exists():
            return ""
        return pf.read_text(encoding='utf-8').strip()

    def import_shared_pad(self, cid: str, pad_data: str) -> int:
        """Import pad received from contact, REPLACING any existing pad."""
        pages = [l for l in pad_data.split('\n') if len(l.strip()) > PAGE_ID_LENGTH]
        if not pages:
            return 0
        self.delete_pad(cid)
        pf = self._pad_file(cid)
        pf.parent.mkdir(parents=True, exist_ok=True)
        with open(pf, 'w', encoding='utf-8') as f:
            for page in pages:
                f.write(page.rstrip('\n') + '\n')
        self._set_role(cid, "recipient")
        return len(pages)

    def _generate_page(self, length: int) -> str:
        result = []
        needed = length + PAGE_ID_LENGTH
        while len(result) < needed:
            chunk = os.urandom((needed - len(result)) * 4)
            for b in chunk:
                if b < OTP_REJECTION_LIMIT:
                    result.append(OTP_CHARSET[b % OTP_CHARSET_LEN])
                    if len(result) >= needed:
                        break
        return ''.join(result)

    def get_all_contacts(self) -> List[str]:
        if not self.pads_dir.exists():
            return []
        return sorted(d.name for d in self.pads_dir.iterdir()
                      if d.is_dir() and (d / "pad.txt").exists())


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
        """Toggle favourite flag. Returns the new state."""
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
                    # Never purge favourited messages
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
