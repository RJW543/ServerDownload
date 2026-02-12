#!/usr/bin/env python3
import threading
import socket
import struct
import json
import uuid
import secrets
import sys
from datetime import datetime
from pathlib import Path

# Ensure your custom crypto module is in the same directory
try:
    from otpmail_crypto import (
        derive_master_key, generate_session_salt, derive_session_key,
        aes_transit_encrypt, aes_transit_decrypt, KeyManager, ServerIdentity,
    )
except ImportError:
    print("Error: 'otpmail_crypto.py' not found. Ensure it is in the same directory.")
    sys.exit(1)

# ============================================================
#  CONFIGURATION
# ============================================================

HOST = "0.0.0.0"
DEFAULT_PORT = 65432
# Change this via environment variable or hardcode for your VPS
TRANSIT_PASSPHRASE = "12345"

MAILBOX_DIR = Path("server_mailboxes")
KEYSTORE_FILE = Path("server_keystore.json")
MAX_MSG_SIZE = 10_485_760  # 10 MB
CHALLENGE_SIZE = 32

# ============================================================
#  LOGGING REPLACEMENT
# ============================================================

def log(message: str):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] {message}")

# ============================================================
#  FRAMED SOCKET I/O
# ============================================================

def send_frame(sock, data: bytes):
    sock.sendall(struct.pack('!I', len(data)) + data)

def recv_frame(sock) -> bytes:
    raw_len = _recv_exact(sock, 4)
    if not raw_len:
        raise ConnectionError("Connection closed")
    msg_len = struct.unpack('!I', raw_len)[0]
    if msg_len > MAX_MSG_SIZE:
        raise ValueError(f"Message too large: {msg_len}")
    return _recv_exact(sock, msg_len)

def _recv_exact(sock, n: int) -> bytes:
    data = b''
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Connection closed mid-frame")
        data += chunk
    return data

# ============================================================
#  STORAGE & REGISTRY (Log-only, No GUI updates)
# ============================================================

class KeyRegistry:
    def __init__(self, filepath: Path):
        self.filepath = filepath
        self._lock = threading.Lock()
        self.keys = {}
        self._load()

    def _load(self):
        if self.filepath.exists():
            with open(self.filepath, 'r') as f:
                self.keys = json.load(f)

    def _save(self):
        with open(self.filepath, 'w') as f:
            json.dump(self.keys, f, indent=2)

    def is_registered(self, username: str) -> bool:
        with self._lock:
            return username in self.keys

    def register(self, username: str, ed25519_pub: str, x25519_pub: str):
        with self._lock:
            self.keys[username] = {
                "ed25519": ed25519_pub,
                "x25519": x25519_pub,
                "registered": datetime.now().isoformat(),
            }
            self._save()

    def get_x25519_pub(self, username: str) -> str:
        with self._lock:
            return self.keys.get(username, {}).get("x25519", "")

    def verify_keys_match(self, username: str, ed25519_pub: str) -> bool:
        with self._lock:
            return self.keys.get(username, {}).get("ed25519", "") == ed25519_pub

class ServerMailbox:
    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def _user_dir(self, uid: str) -> Path:
        d = self.base_dir / uid
        d.mkdir(exist_ok=True)
        return d

    def store(self, recipient, sender, payload, msg_type="mail") -> str:
        msg_id = uuid.uuid4().hex[:12]
        msg = {
            "id": msg_id, "type": msg_type, "from": sender,
            "payload": payload, "timestamp": datetime.now().isoformat(),
        }
        fp = self._user_dir(recipient) / f"{msg_id}.json"
        with open(fp, 'w', encoding='utf-8') as f:
            json.dump(msg, f)
        return msg_id

    def fetch_all(self, uid: str) -> list:
        msgs = []
        for fp in sorted(self._user_dir(uid).glob("*.json")):
            try:
                with open(fp, 'r', encoding='utf-8') as f:
                    m = json.load(f)
                    if 'type' not in m: m['type'] = 'mail'
                    msgs.append(m)
            except Exception: pass
        return msgs

    def delete(self, uid: str, msg_id: str) -> bool:
        fp = self._user_dir(uid) / f"{msg_id}.json"
        if fp.exists():
            fp.unlink()
            return True
        return False

    def count(self, uid: str) -> int:
        d = self._user_dir(uid)
        return len(list(d.glob("*.json"))) if d.exists() else 0

# ============================================================
#  CLIENT HANDLER (Headless)
# ============================================================

class ClientHandler(threading.Thread):
    def __init__(self, sock, addr, master_key, mailbox, key_registry, clients, clients_lock, server_identity):
        super().__init__(daemon=True)
        self.sock = sock
        self.addr = addr
        self.master_key = master_key
        self.mailbox = mailbox
        self.key_registry = key_registry
        self.clients = clients
        self.clients_lock = clients_lock
        self.server_identity = server_identity
        self.user_id = None
        self.session_key = None

    def run(self):
        try:
            self._handle_session()
        except Exception as e:
            log(f"Error with {self.user_id or self.addr}: {e}")
        finally:
            self._cleanup()

    def _send_encrypted(self, text: str):
        ct = aes_transit_encrypt(text.encode('utf-8'), self.session_key)
        send_frame(self.sock, ct)

    def _recv_encrypted(self) -> str:
        raw = recv_frame(self.sock)
        pt = aes_transit_decrypt(raw, self.session_key)
        return pt.decode('utf-8')

    def _handle_session(self):
        # 1. Authenticated Salt Exchange
        # Send: salt (16B) || server_pub (32B) || signature(salt) (64B) = 112 bytes
        session_salt = generate_session_salt()
        server_pub = self.server_identity.get_public_bytes()
        signature = self.server_identity.sign_salt(session_salt)
        self.sock.sendall(session_salt + server_pub + signature)
        self.session_key = derive_session_key(self.master_key, session_salt)

        # 2. Auth
        msg = self._recv_encrypted()
        if not msg.startswith("AUTH|"): return
        
        parts = msg.split("|")
        if len(parts) != 4: return
        _, username, ed25519_pub, x25519_pub = parts

        # 3. TOFU
        if self.key_registry.is_registered(username):
            if not self.key_registry.verify_keys_match(username, ed25519_pub):
                self._send_encrypted("ERROR|Key mismatch")
                log(f"SECURITY ALERT: Key mismatch for {username}")
                return
        else:
            self.key_registry.register(username, ed25519_pub, x25519_pub)
            log(f"Registered new user: {username}")

        # 4. Challenge
        challenge = secrets.token_bytes(CHALLENGE_SIZE)
        self._send_encrypted(f"CHALLENGE|{challenge.hex()}")
        resp = self._recv_encrypted()
        
        signature = bytes.fromhex(resp.split("|", 1)[1])
        if not KeyManager.verify_signature(ed25519_pub, signature, challenge):
            log(f"Auth Failed: {username}")
            return

        # 5. Connected
        self.user_id = username
        with self.clients_lock:
            if self.user_id in self.clients:
                self._send_encrypted("ERROR|Already connected")
                return
            self.clients[self.user_id] = self

        log(f"User '{self.user_id}' authenticated from {self.addr[0]}")
        pending = self.mailbox.count(self.user_id)
        self._send_encrypted(f"OK|Welcome {self.user_id}. {pending} messages.")

        # Command Loop
        while True:
            msg = self._recv_encrypted()
            cmd = msg.split("|", 1)[0]
            if cmd == "SEND": self._handle_send(msg)
            elif cmd == "PADSHARE": self._handle_padshare(msg)
            elif cmd == "FETCH": self._handle_fetch()
            elif cmd == "ACK": self._handle_ack(msg)
            elif cmd == "GETKEY": self._handle_getkey(msg)
            elif cmd == "PING": self._send_encrypted("PONG")

    def _handle_send(self, msg):
        _, recipient, payload = msg.split("|", 2)
        mid = self.mailbox.store(recipient, self.user_id, payload, "mail")
        log(f"Mail: {self.user_id} -> {recipient} [{mid}]")
        self._notify(recipient, f"NOTIFY|New mail from {self.user_id}")
        self._send_encrypted(f"OK|Delivered [{mid}]")

    def _handle_padshare(self, msg):
        _, recipient, payload = msg.split("|", 2)
        mid = self.mailbox.store(recipient, self.user_id, payload, "pad")
        log(f"Pad: {self.user_id} -> {recipient} [{mid}]")
        self._notify(recipient, f"NOTIFY|Pad from {self.user_id}")
        self._send_encrypted(f"OK|Pad shared [{mid}]")

    def _handle_fetch(self):
        msgs = self.mailbox.fetch_all(self.user_id)
        for m in msgs:
            if m['type'] == 'pad':
                self._send_encrypted(f"PAD|{m['id']}|{m['from']}|{m['payload']}")
            else:
                self._send_encrypted(f"MAIL|{m['id']}|{m['from']}|{m['timestamp']}|{m['payload']}")
        self._send_encrypted("DONE")

    def _handle_ack(self, msg):
        mid = msg.split("|")[1]
        self.mailbox.delete(self.user_id, mid)
        self._send_encrypted(f"OK|Deleted {mid}")

    def _handle_getkey(self, msg):
        target = msg.split("|")[1]
        pub = self.key_registry.get_x25519_pub(target)
        if pub: self._send_encrypted(f"KEY|{target}|{pub}")
        else: self._send_encrypted(f"ERROR|Unknown user")

    def _notify(self, recipient, packet):
        with self.clients_lock:
            if recipient in self.clients:
                try: self.clients[recipient]._send_encrypted(packet)
                except: pass

    def _cleanup(self):
        if self.user_id:
            with self.clients_lock:
                if self.clients.get(self.user_id) == self:
                    del self.clients[self.user_id]
            log(f"User '{self.user_id}' disconnected")
        self.sock.close()

# ============================================================
#  MAIN ENTRY POINT
# ============================================================

def main():
    # Setup data structures
    mailbox = ServerMailbox(MAILBOX_DIR)
    key_registry = KeyRegistry(KEYSTORE_FILE)
    master_key = derive_master_key(TRANSIT_PASSPHRASE)
    server_identity = ServerIdentity(Path("."))
    clients = {}
    clients_lock = threading.Lock()

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_sock.bind((HOST, DEFAULT_PORT))
        server_sock.listen(50)
        log(f"OTPMail Relay Server started on {HOST}:{DEFAULT_PORT}")
        log(f"Transit key protection active. {len(key_registry.keys)} users registered.")
        log(f"Server public key: {server_identity.get_public_hex()}")
        log(f"Server fingerprint: {server_identity.get_fingerprint()}")
    except Exception as e:
        log(f"CRITICAL: Failed to bind: {e}")
        return

    try:
        while True:
            client_sock, addr = server_sock.accept()
            handler = ClientHandler(
                client_sock, addr, master_key, mailbox, 
                key_registry, clients, clients_lock, server_identity
            )
            handler.start()
    except KeyboardInterrupt:
        log("Server shutting down (KeyboardInterrupt)")
    finally:
        server_sock.close()

if __name__ == "__main__":
    main()