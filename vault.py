"""
vault.py — Encrypted local storage for OTPMail.

All sensitive material (identity keys, OTP pages, messages) is stored in a
single AES-256-GCM encrypted file.  The encryption key is derived from the
user's password via scrypt.

On-disk format:
  [16 B scrypt salt] [12 B AES-GCM nonce] [ciphertext + 16 B GCM tag]

The plaintext is a UTF-8 JSON document.  All binary values are base64-encoded.

Security notes:
  • While the vault is open, the decrypted data lives in a Python dict in RAM.
    It is never written to disk in plaintext.
  • Saves are atomic: a .tmp file is written and renamed into place.
  • Message deletion overwrites the internal record before removing it
    (best-effort on Python dicts; full-disk encryption is recommended as a
     complementary control for SSD wear-levelling / journalling FS concerns).
"""

import os
import json
import uuid
import base64
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Tuple

from crypto_utils import (
    derive_vault_key,
    aes_gcm_encrypt,
    aes_gcm_decrypt,
    SCRYPT_SALT_LEN,
    OTP_PAGE_SIZE,
    OTP_DEFAULT_PAGES,
)

MSG_RETENTION_HOURS = 48


# ─── Base64 helpers ──────────────────────────────────────────────────────────

def _e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def _d(s: str) -> bytes:
    return base64.b64decode(s)


# ─────────────────────────────────────────────────────────────────────────────

class VaultError(Exception):
    pass


class Vault:
    """
    Manages the encrypted local vault.

    Usage:
        v = Vault("/path/to/vault.enc")
        v.create("my_password")   # first run
        # — or —
        v.open("my_password")     # subsequent runs
        ...
        v.save()                  # explicit save (also called by close())
        v.close()                 # clears key material from memory
    """

    def __init__(self, vault_path: str) -> None:
        self.vault_path = vault_path
        self._key:   Optional[bytes]  = None
        self._salt:  Optional[bytes]  = None
        self._data:  Optional[Dict]   = None
        self._dirty: bool             = False

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    @property
    def is_open(self) -> bool:
        return self._data is not None

    def create(self, password: str) -> None:
        """Create a brand-new, empty vault encrypted with `password`."""
        self._salt  = os.urandom(SCRYPT_SALT_LEN)
        self._key   = derive_vault_key(password, self._salt)
        self._data  = self._empty_data()
        self._dirty = True
        self.save()

    def open(self, password: str) -> None:
        """Open and decrypt an existing vault file."""
        if not os.path.exists(self.vault_path):
            raise VaultError("Vault file not found — run with --register to create one")

        raw = open(self.vault_path, "rb").read()
        min_len = SCRYPT_SALT_LEN + 12 + 16   # salt + nonce + GCM tag
        if len(raw) < min_len:
            raise VaultError("Vault file is truncated or corrupted")

        self._salt    = raw[:SCRYPT_SALT_LEN]
        nonce         = raw[SCRYPT_SALT_LEN : SCRYPT_SALT_LEN + 12]
        ciphertext    = raw[SCRYPT_SALT_LEN + 12 :]
        self._key     = derive_vault_key(password, self._salt)

        try:
            plaintext = aes_gcm_decrypt(self._key, nonce, ciphertext)
        except Exception:
            self._key = None
            raise VaultError("Wrong password or corrupted vault file")

        self._data = json.loads(plaintext.decode("utf-8"))

    def save(self) -> None:
        """Encrypt current data and write atomically to disk."""
        if self._data is None or self._key is None:
            raise VaultError("Vault is not open")

        plaintext        = json.dumps(self._data).encode("utf-8")
        nonce, ciphertext = aes_gcm_encrypt(self._key, plaintext)

        tmp = self.vault_path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(self._salt)
            f.write(nonce)
            f.write(ciphertext)
        os.replace(tmp, self.vault_path)
        self._dirty = False

    def close(self) -> None:
        """Save (if dirty) and wipe key material from memory."""
        if self._dirty:
            self.save()
        # Overwrite sensitive fields before releasing
        self._key  = None
        self._salt = None
        self._data = None

    # ── Identity ──────────────────────────────────────────────────────────────

    def has_identity(self) -> bool:
        return bool(self._data.get("identity"))

    def set_identity(
        self,
        username: str,
        ed25519_priv: bytes,
        ed25519_pub: bytes,
        kem_priv: bytes,
        kem_pub: bytes,
    ) -> None:
        self._data["identity"] = {
            "username":       username,
            "ed25519_priv":   _e(ed25519_priv),
            "ed25519_pub":    _e(ed25519_pub),
            "kem_priv":       _e(kem_priv),
            "kem_pub":        _e(kem_pub),
        }
        self._dirty = True

    def get_identity(self) -> Optional[Dict]:
        return self._data.get("identity")

    def get_username(self) -> Optional[str]:
        ident = self._data.get("identity")
        return ident["username"] if ident else None

    def get_ed25519_priv(self) -> Optional[bytes]:
        ident = self._data.get("identity")
        return _d(ident["ed25519_priv"]) if ident else None

    def get_ed25519_pub(self) -> Optional[bytes]:
        ident = self._data.get("identity")
        return _d(ident["ed25519_pub"]) if ident else None

    def get_kem_priv(self) -> Optional[bytes]:
        ident = self._data.get("identity")
        return _d(ident["kem_priv"]) if ident else None

    def get_kem_pub(self) -> Optional[bytes]:
        ident = self._data.get("identity")
        return _d(ident["kem_pub"]) if ident else None

    # ── Contacts ──────────────────────────────────────────────────────────────

    def get_contacts(self) -> List[str]:
        return sorted(self._data["contacts"].keys())

    def has_contact(self, username: str) -> bool:
        return username in self._data["contacts"]

    def add_contact(
        self,
        username: str,
        ed25519_pub: bytes,
        kem_pub: bytes,
        outgoing_pages: List[bytes],
        incoming_pages: List[bytes],
    ) -> None:
        """
        Store a contact with their public keys and their OTP pages.

        outgoing_pages — pages we use to *encrypt* messages we send to them.
        incoming_pages — pages we use to *decrypt* messages we receive from them.
        """
        self._data["contacts"][username] = {
            "ed25519_pub":   _e(ed25519_pub),
            "kem_pub":       _e(kem_pub),
            "otp_outgoing":  [
                {"index": i, "data": _e(p), "consumed": False}
                for i, p in enumerate(outgoing_pages)
            ],
            "otp_incoming":  [
                {"index": i, "data": _e(p), "consumed": False}
                for i, p in enumerate(incoming_pages)
            ],
            "next_out_index": 0,
            "next_in_index":  0,
        }
        if username not in self._data["messages"]:
            self._data["messages"][username] = []
        self._dirty = True

    def update_contact_incoming_pages(self, username: str, pages: List[bytes]) -> None:
        """Replace all incoming OTP pages for an existing contact."""
        if username not in self._data["contacts"]:
            raise VaultError(f"Contact '{username}' not found")
        c = self._data["contacts"][username]
        c["otp_incoming"]  = [
            {"index": i, "data": _e(p), "consumed": False}
            for i, p in enumerate(pages)
        ]
        c["next_in_index"] = 0
        self._dirty = True

    def get_contact_ed25519_pub(self, username: str) -> Optional[bytes]:
        c = self._data["contacts"].get(username)
        return _d(c["ed25519_pub"]) if c else None

    def get_contact_kem_pub(self, username: str) -> Optional[bytes]:
        c = self._data["contacts"].get(username)
        return _d(c["kem_pub"]) if c else None

    def consume_outgoing_page(self, contact: str) -> Optional[Tuple[int, bytes]]:
        """
        Locate the next unconsumed outgoing OTP page, mark it consumed, and
        return (page_index, page_bytes).  Returns None if all pages consumed.
        """
        c = self._data["contacts"].get(contact)
        if not c:
            return None
        pages = c["otp_outgoing"]
        idx   = c["next_out_index"]
        # Advance past any already-consumed entries
        while idx < len(pages) and pages[idx]["consumed"]:
            idx += 1
        if idx >= len(pages):
            return None
        page_data         = _d(pages[idx]["data"])
        pages[idx]["consumed"] = True
        c["next_out_index"]    = idx + 1
        self._dirty            = True
        return (pages[idx]["index"], page_data)

    def consume_incoming_page(self, contact: str, index: int) -> Optional[bytes]:
        """
        Locate the incoming OTP page at `index`, mark it consumed, and return
        its bytes.  Returns None if not found or already consumed.
        """
        c = self._data["contacts"].get(contact)
        if not c:
            return None
        for p in c["otp_incoming"]:
            if p["index"] == index:
                if p["consumed"]:
                    return None
                data        = _d(p["data"])
                p["consumed"] = True
                self._dirty   = True
                return data
        return None

    def get_pages_remaining(self, contact: str) -> Dict[str, int]:
        c = self._data["contacts"].get(contact)
        if not c:
            return {"outgoing": 0, "incoming": 0}
        return {
            "outgoing": sum(1 for p in c["otp_outgoing"] if not p["consumed"]),
            "incoming": sum(1 for p in c["otp_incoming"] if not p["consumed"]),
        }

    def remove_contact(self, username: str) -> None:
        self._data["contacts"].pop(username, None)
        self._dirty = True

    # ── Messages ──────────────────────────────────────────────────────────────

    def add_message(
        self,
        contact: str,
        direction: str,           # "sent" | "received"
        content: str,
        page_index: int = -1,
        saved: bool = False,
    ) -> str:
        """Record a message. Returns its UUID."""
        if contact not in self._data["messages"]:
            self._data["messages"][contact] = []
        msg_id = str(uuid.uuid4())
        self._data["messages"][contact].append({
            "id":         msg_id,
            "direction":  direction,
            "content":    content,
            "timestamp":  datetime.now(timezone.utc).isoformat(),
            "page_index": page_index,
            "saved":      saved,
        })
        self._dirty = True
        return msg_id

    def get_messages(self, contact: str) -> List[Dict]:
        return list(self._data["messages"].get(contact, []))

    def toggle_save_message(self, contact: str, msg_id: str) -> bool:
        """Toggle the saved flag on a message. Returns the new saved state."""
        for msg in self._data["messages"].get(contact, []):
            if msg["id"] == msg_id:
                msg["saved"] = not msg["saved"]
                self._dirty  = True
                return msg["saved"]
        return False

    def get_message_saved(self, contact: str, msg_id: str) -> bool:
        for msg in self._data["messages"].get(contact, []):
            if msg["id"] == msg_id:
                return msg.get("saved", False)
        return False

    def cleanup_expired_messages(self) -> int:
        """
        Securely remove messages older than MSG_RETENTION_HOURS that are not
        flagged as saved.  Returns the count of deleted messages.

        Note: Python's garbage collector will eventually release the memory.
        Full-disk encryption is the recommended complement for complete
        confidentiality on modern SSDs.
        """
        cutoff  = datetime.now(timezone.utc) - timedelta(hours=MSG_RETENTION_HOURS)
        deleted = 0
        for contact in list(self._data["messages"].keys()):
            before = self._data["messages"][contact]
            kept   = []
            for m in before:
                ts = datetime.fromisoformat(m["timestamp"])
                if m.get("saved") or ts > cutoff:
                    kept.append(m)
                else:
                    # Overwrite content before dropping (best-effort)
                    m["content"] = "\x00" * len(m.get("content", ""))
                    deleted += 1
            self._data["messages"][contact] = kept
        if deleted:
            self._dirty = True
        return deleted

    # ── Internal ──────────────────────────────────────────────────────────────

    @staticmethod
    def _empty_data() -> Dict:
        return {
            "identity": None,
            "contacts": {},
            "messages": {},
        }
