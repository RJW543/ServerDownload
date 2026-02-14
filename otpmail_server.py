#!/usr/bin/env python3
import os
import threading
import socket
import struct
import json
import uuid
import secrets
import sys
from datetime import datetime
from pathlib import Path

try:
    from otpmail_crypto import (
        derive_master_key, generate_session_salt, derive_session_key,
        aes_transit_encrypt, aes_transit_decrypt, KeyManager, ServerIdentity,
        load_transit_key_from_file, generate_transit_key_file,
        generate_ephemeral_x25519, compute_ecdh_secret, validate_username,
    )
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
except ImportError:
    print("Error: 'otpmail_crypto.py' not found. Ensure it is in the same directory.")
    sys.exit(1)

# ============================================================
#  CONFIGURATION
# ============================================================

HOST = "0.0.0.0"
DEFAULT_PORT = 65432

TRANSIT_KEY_FILE = Path("transit_key.txt")
MAILBOX_DIR = Path("server_mailboxes")
KEYSTORE_FILE = Path("server_keystore.json")
BANLIST_FILE = Path("banned_ips.txt")
MAX_MSG_SIZE = 10_485_760  # 10 MB
CHALLENGE_SIZE = 32

# Connection limits (DoS protection)
MAX_CONNECTIONS = 50       # Total concurrent connections
MAX_PER_IP = 3             # Max concurrent connections per IP

# Timeouts (slow-loris protection)
HANDSHAKE_TIMEOUT = 15     # Seconds to complete handshake + auth
SESSION_TIMEOUT = 300      # Seconds of inactivity before disconnect

# Mailbox limits (disk exhaustion protection)
MAX_MESSAGES_PER_USER = 500   # Max pending messages per mailbox
MAX_MESSAGE_PAYLOAD = 1_048_576  # 1 MB max payload per message

# Regex for valid message IDs (hex-only, exactly 12 chars from uuid4)
import re
_MSG_ID_RE = re.compile(r'^[0-9a-f]{12}$')

def _is_valid_msg_id(msg_id: str) -> bool:
    """Validate message ID: hex-only, fixed length. Prevents path traversal."""
    return bool(_MSG_ID_RE.match(msg_id))

def _validate_public_keys(ed25519_pub_hex: str, x25519_pub_hex: str) -> str:
    """
    Validate that public key hex strings are well-formed and decode to valid
    curve points. Returns empty string on success, or error description.
    """
    # Check Ed25519 — must be exactly 64 hex chars (32 bytes)
    if len(ed25519_pub_hex) != 64:
        return f"Ed25519 key wrong length: {len(ed25519_pub_hex)} (expected 64 hex chars)"
    try:
        ed_bytes = bytes.fromhex(ed25519_pub_hex)
    except ValueError:
        return "Ed25519 key is not valid hex"
    try:
        Ed25519PublicKey.from_public_bytes(ed_bytes)
    except Exception as e:
        return f"Ed25519 key is not a valid curve point: {e}"

    # Check X25519 — must be exactly 64 hex chars (32 bytes)
    if len(x25519_pub_hex) != 64:
        return f"X25519 key wrong length: {len(x25519_pub_hex)} (expected 64 hex chars)"
    try:
        x_bytes = bytes.fromhex(x25519_pub_hex)
    except ValueError:
        return "X25519 key is not valid hex"
    try:
        X25519PublicKey.from_public_bytes(x_bytes)
    except Exception as e:
        return f"X25519 key is not a valid curve point: {e}"

    return ""  # Valid

# ============================================================
#  LOGGING
# ============================================================

# Log levels: 0 = minimal (errors + lifecycle only)
#              1 = normal  (+ connection events, command types)
#              2 = verbose (+ sender/recipient metadata, IPs, message IDs)
# Set via OTPMAIL_LOG_LEVEL env var. Default: 0 (minimal)
LOG_LEVEL = int(os.environ.get("OTPMAIL_LOG_LEVEL", "0"))

def log(message: str, level: int = 0):
    """Log a message if the current log level is >= the message's level."""
    if level > LOG_LEVEL:
        return
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
#  STORAGE & REGISTRY
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
        """Atomic save: write to temp file, then rename."""
        tmp = self.filepath.with_suffix('.tmp')
        with open(tmp, 'w') as f:
            json.dump(self.keys, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.rename(str(tmp), str(self.filepath))

    def is_registered(self, username: str) -> bool:
        with self._lock:
            return username in self.keys

    def register_or_verify(self, username: str, ed25519_pub: str,
                           x25519_pub: str) -> tuple:
        """
        Atomic check-then-act for user registration (TOFU).

        Holds the lock for the entire operation to prevent two concurrent
        connections from both seeing is_registered=False and racing to
        register with different keys.

        Returns (success: bool, error_message: str).
        On success for new user: registers the keys.
        On success for existing user: verifies BOTH Ed25519 and X25519 keys match.
        """
        with self._lock:
            if username in self.keys:
                # Existing user — verify TOFU key match for BOTH keys
                if self.keys[username].get("ed25519", "") != ed25519_pub:
                    return (False, "Key mismatch — Ed25519 public key does not match registration")
                if self.keys[username].get("x25519", "") != x25519_pub:
                    return (False, "Key mismatch — X25519 public key does not match registration")
                return (True, "")
            else:
                # New user — validate key format before storing
                key_error = _validate_public_keys(ed25519_pub, x25519_pub)
                if key_error:
                    return (False, f"Invalid public key: {key_error}")
                self.keys[username] = {
                    "ed25519": ed25519_pub,
                    "x25519": x25519_pub,
                    "registered": datetime.now().isoformat(),
                }
                self._save()
                return (True, "registered")

    def get_x25519_pub(self, username: str) -> str:
        with self._lock:
            return self.keys.get(username, {}).get("x25519", "")

class ServerMailbox:
    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def _user_dir(self, uid: str) -> Path:
        # Validate before using as path component
        if not validate_username(uid):
            raise ValueError(f"Invalid mailbox username: {repr(uid)}")
        d = self.base_dir / uid
        d.mkdir(exist_ok=True)
        return d

    def store(self, recipient, sender, payload, msg_type="mail") -> str:
        # Enforce payload size limit
        if len(payload) > MAX_MESSAGE_PAYLOAD:
            raise ValueError(f"Payload too large: {len(payload)} bytes")
        # Enforce per-user message count limit
        current = self.count(recipient)
        if current >= MAX_MESSAGES_PER_USER:
            raise ValueError(f"Mailbox full ({MAX_MESSAGES_PER_USER} messages)")
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
        try:
            for fp in sorted(self._user_dir(uid).glob("*.json")):
                try:
                    with open(fp, 'r', encoding='utf-8') as f:
                        m = json.load(f)
                        if 'type' not in m:
                            m['type'] = 'mail'
                        msgs.append(m)
                except Exception as e:
                    log(f"Error reading mailbox file {fp}: {e}", level=1)
        except ValueError:
            pass
        return msgs

    def delete(self, uid: str, msg_id: str) -> bool:
        # Defense-in-depth: reject traversal attempts at storage layer too
        if not _is_valid_msg_id(msg_id):
            return False
        try:
            fp = self._user_dir(uid) / f"{msg_id}.json"
            if fp.exists():
                fp.unlink()
                return True
        except ValueError:
            pass
        return False

    def count(self, uid: str) -> int:
        try:
            d = self._user_dir(uid)
            return len(list(d.glob("*.json"))) if d.exists() else 0
        except ValueError:
            return 0

# ============================================================
#  BAN LIST (cached with mtime check)
# ============================================================

class BanList:
    """
    Cached ban list that re-reads from disk only when the file changes.
    Eliminates per-connection disk I/O and the TOCTOU race from reading
    a file that might be mid-write.
    """
    def __init__(self, filepath: Path):
        self.filepath = filepath
        self._lock = threading.Lock()
        self._banned: set = set()
        self._mtime: float = 0.0
        self._reload()

    def _reload(self):
        """Reload ban list if the file has been modified."""
        try:
            if not self.filepath.exists():
                self._banned = set()
                self._mtime = 0.0
                return
            current_mtime = self.filepath.stat().st_mtime
            if current_mtime != self._mtime:
                text = self.filepath.read_text(encoding='utf-8')
                self._banned = set(
                    line.strip() for line in text.splitlines() if line.strip())
                self._mtime = current_mtime
        except Exception:
            pass  # Keep existing set on read error

    def is_banned(self, ip: str) -> bool:
        with self._lock:
            self._reload()
            return ip in self._banned


# Module-level singleton — initialised in main() after startup
_ban_list: BanList = None


def is_banned(ip: str) -> bool:
    """Check if an IP is banned (cached, thread-safe)."""
    if _ban_list is None:
        return False
    return _ban_list.is_banned(ip)

# ============================================================
#  CLIENT HANDLER
# ============================================================

class ClientHandler(threading.Thread):
    def __init__(self, sock, addr, master_key, mailbox, key_registry,
                 clients, clients_lock, server_identity,
                 conn_semaphore, ip_counts, ip_lock):
        super().__init__(daemon=True)
        self.sock = sock
        self.addr = addr
        self.master_key = master_key
        self.mailbox = mailbox
        self.key_registry = key_registry
        self.clients = clients
        self.clients_lock = clients_lock
        self.server_identity = server_identity
        self.conn_semaphore = conn_semaphore
        self.ip_counts = ip_counts
        self.ip_lock = ip_lock
        self.user_id = None
        self.session_key = None
        self._send_seq = 0    # Outbound sequence counter (replay protection)
        self._recv_seq = 0    # Inbound sequence counter (replay protection)
        self._send_lock = threading.Lock()  # Protects _send_seq + socket writes

    def run(self):
        try:
            self._handle_session()
        except (ConnectionError, socket.timeout) as e:
            if self.user_id:
                log(f"Connection lost for {self.user_id}", level=1)
        except Exception as e:
            log(f"Error with client session: {e}", level=1)
        finally:
            self._cleanup()

    def _send_encrypted(self, text: str):
        with self._send_lock:
            aad = struct.pack('!Q', self._send_seq)
            ct = aes_transit_encrypt(text.encode('utf-8'), self.session_key, aad)
            send_frame(self.sock, ct)
            self._send_seq += 1

    def _recv_encrypted(self) -> str:
        raw = recv_frame(self.sock)
        aad = struct.pack('!Q', self._recv_seq)
        pt = aes_transit_decrypt(raw, self.session_key, aad)
        self._recv_seq += 1
        return pt.decode('utf-8')

    def _handle_session(self):
        # Set handshake timeout — prevents slow-loris during auth
        self.sock.settimeout(HANDSHAKE_TIMEOUT)

        # 1. Ephemeral ECDHE + Authenticated Handshake
        server_eph_priv, server_eph_pub = generate_ephemeral_x25519()

        session_salt = generate_session_salt()
        server_id_pub = self.server_identity.get_public_bytes()
        signature = self.server_identity.sign_data(session_salt + server_eph_pub)
        self.sock.sendall(session_salt + server_id_pub + server_eph_pub + signature)

        # Receive client's ephemeral public key (32 bytes)
        client_eph_pub = _recv_exact(self.sock, 32)

        # Compute ECDH shared secret and derive session key
        ecdh_secret = compute_ecdh_secret(server_eph_priv, client_eph_pub)
        self.session_key = derive_session_key(self.master_key, session_salt, ecdh_secret)
        del server_eph_priv

        # 2. Auth
        msg = self._recv_encrypted()
        if not msg.startswith("AUTH|"):
            return

        parts = msg.split("|")
        if len(parts) != 4:
            return
        _, username, ed25519_pub, x25519_pub = parts

        # 2b. Username validation (prevents directory traversal)
        if not validate_username(username):
            self._send_encrypted("ERROR|Invalid username. Use letters, digits, _ or - only (1-32 chars).")
            log(f"REJECTED invalid username from client", level=2)
            return

        # 3. TOFU — atomic register-or-verify (prevents TOCTOU race)
        success, reg_msg = self.key_registry.register_or_verify(
            username, ed25519_pub, x25519_pub)
        if not success:
            self._send_encrypted(f"ERROR|{reg_msg}")
            log(f"SECURITY ALERT: key mismatch for user")
            return
        if reg_msg == "registered":
            log(f"New user registered", level=1)

        # 4. Challenge
        challenge = secrets.token_bytes(CHALLENGE_SIZE)
        self._send_encrypted(f"CHALLENGE|{challenge.hex()}")
        resp = self._recv_encrypted()

        if not resp.startswith("RESPONSE|"):
            self._send_encrypted("ERROR|Invalid challenge response format")
            log("Auth failed: bad response format", level=1)
            return

        try:
            sig_bytes = bytes.fromhex(resp.split("|", 1)[1])
        except ValueError:
            self._send_encrypted("ERROR|Invalid signature encoding")
            log("Auth failed: bad hex encoding", level=1)
            return

        if not KeyManager.verify_signature(ed25519_pub, sig_bytes, challenge):
            self._send_encrypted("ERROR|Challenge signature verification failed")
            log("Auth failed: bad signature", level=1)
            return

        # 5. Connected — switch to session timeout
        self.sock.settimeout(SESSION_TIMEOUT)
        self.user_id = username

        with self.clients_lock:
            if self.user_id in self.clients:
                self._send_encrypted("ERROR|Already connected")
                return
            self.clients[self.user_id] = self

        log(f"User authenticated", level=1)
        log(f"User '{self.user_id}' from {self.addr[0]}", level=2)
        pending = self.mailbox.count(self.user_id)
        self._send_encrypted(f"OK|Welcome {self.user_id}. {pending} messages.")

        # Command Loop
        while True:
            msg = self._recv_encrypted()
            cmd = msg.split("|", 1)[0]
            if cmd == "SEND":
                self._handle_send(msg)
            elif cmd == "PADSHARE":
                self._handle_padshare(msg)
            elif cmd == "FETCH":
                self._handle_fetch()
            elif cmd == "ACK":
                self._handle_ack(msg)
            elif cmd == "GETKEY":
                self._handle_getkey(msg)
            elif cmd == "PING":
                self._send_encrypted("PONG")
            else:
                self._send_encrypted("ERROR|Unknown command")

    def _handle_send(self, msg):
        parts = msg.split("|", 2)
        if len(parts) != 3:
            self._send_encrypted("ERROR|Invalid SEND format")
            return
        _, recipient, payload = parts

        # Validate recipient (prevents directory traversal)
        if not validate_username(recipient):
            self._send_encrypted("ERROR|Invalid recipient username")
            log("BLOCKED invalid recipient in SEND", level=2)
            return

        # Verify recipient exists
        if not self.key_registry.is_registered(recipient):
            self._send_encrypted("ERROR|Unknown recipient")
            return

        try:
            mid = self.mailbox.store(recipient, self.user_id, payload, "mail")
        except ValueError as e:
            self._send_encrypted(f"ERROR|{e}")
            return

        log(f"Mail delivered", level=1)
        log(f"Mail: {self.user_id} -> {recipient} [{mid}]", level=2)
        self._notify(recipient, f"NOTIFY|New mail from {self.user_id}")
        self._send_encrypted(f"OK|Delivered [{mid}]")

    def _handle_padshare(self, msg):
        parts = msg.split("|", 2)
        if len(parts) != 3:
            self._send_encrypted("ERROR|Invalid PADSHARE format")
            return
        _, recipient, payload = parts

        # Validate recipient (prevents directory traversal)
        if not validate_username(recipient):
            self._send_encrypted("ERROR|Invalid recipient username")
            log("BLOCKED invalid recipient in PADSHARE", level=2)
            return

        # Verify recipient exists
        if not self.key_registry.is_registered(recipient):
            self._send_encrypted("ERROR|Unknown recipient")
            return

        try:
            mid = self.mailbox.store(recipient, self.user_id, payload, "pad")
        except ValueError as e:
            self._send_encrypted(f"ERROR|{e}")
            return

        log(f"Pad shared", level=1)
        log(f"Pad: {self.user_id} -> {recipient} [{mid}]", level=2)
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
        parts = msg.split("|")
        if len(parts) < 2:
            self._send_encrypted("ERROR|Invalid ACK format")
            return
        mid = parts[1]
        # Validate msg_id: must be hex-only, fixed length (12 chars from uuid4)
        # Prevents path traversal via crafted IDs like "../../server_keystore"
        if not _is_valid_msg_id(mid):
            self._send_encrypted("ERROR|Invalid message ID")
            log("BLOCKED invalid ACK msg_id", level=2)
            return
        self.mailbox.delete(self.user_id, mid)
        self._send_encrypted(f"OK|Deleted {mid}")

    def _handle_getkey(self, msg):
        parts = msg.split("|")
        if len(parts) < 2:
            self._send_encrypted("ERROR|Invalid GETKEY format")
            return
        target = parts[1]

        # Validate target username (prevents enumeration via crafted names)
        if not validate_username(target):
            self._send_encrypted("ERROR|Invalid username")
            return

        pub = self.key_registry.get_x25519_pub(target)
        if pub:
            self._send_encrypted(f"KEY|{target}|{pub}")
        else:
            self._send_encrypted("ERROR|Unknown user")

    def _notify(self, recipient, packet):
        with self.clients_lock:
            if recipient in self.clients:
                try:
                    self.clients[recipient]._send_encrypted(packet)
                except Exception as e:
                    log(f"Notify delivery failed", level=2)

    def _cleanup(self):
        if self.user_id:
            with self.clients_lock:
                if self.clients.get(self.user_id) == self:
                    del self.clients[self.user_id]
            log(f"User disconnected", level=1)
        try:
            self.sock.close()
        except Exception:
            pass
        # Release connection tracking
        ip = self.addr[0]
        with self.ip_lock:
            self.ip_counts[ip] = self.ip_counts.get(ip, 1) - 1
            if self.ip_counts[ip] <= 0:
                del self.ip_counts[ip]
        self.conn_semaphore.release()

# ============================================================
#  MAIN ENTRY POINT
# ============================================================

def main():
    # Require server identity passphrase
    server_passphrase = os.environ.get("OTPMAIL_SERVER_PASSPHRASE", "")
    if not server_passphrase:
        log("FATAL: OTPMAIL_SERVER_PASSPHRASE environment variable is not set.")
        log("The server identity key must be encrypted at rest.")
        log("Set it with:  export OTPMAIL_SERVER_PASSPHRASE='your-strong-passphrase'")
        sys.exit(1)

    # Load or generate transit key
    transit_key = load_transit_key_from_file(TRANSIT_KEY_FILE)
    if not transit_key:
        transit_key = generate_transit_key_file(TRANSIT_KEY_FILE)
        log(f"Generated new transit key -> {TRANSIT_KEY_FILE}")
        log("Share this key with clients securely (in-person, your website, etc.)")
    else:
        log(f"Transit key loaded from {TRANSIT_KEY_FILE}")

    # Setup data structures
    mailbox = ServerMailbox(MAILBOX_DIR)
    key_registry = KeyRegistry(KEYSTORE_FILE)
    master_key = derive_master_key(transit_key)
    server_identity = ServerIdentity(Path("."), passphrase=server_passphrase)

    # Initialise cached ban list
    global _ban_list
    _ban_list = BanList(BANLIST_FILE)

    clients = {}
    clients_lock = threading.Lock()

    # Connection limiting (DoS protection)
    conn_semaphore = threading.Semaphore(MAX_CONNECTIONS)
    ip_counts = {}
    ip_lock = threading.Lock()

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_sock.bind((HOST, DEFAULT_PORT))
        server_sock.listen(50)
        log(f"OTPMail Relay Server started on {HOST}:{DEFAULT_PORT}")
        log(f"Max connections: {MAX_CONNECTIONS} total, {MAX_PER_IP} per IP")
        log(f"Mailbox limits: {MAX_MESSAGES_PER_USER} msgs/user, {MAX_MESSAGE_PAYLOAD} bytes/msg")
        log(f"Timeouts: handshake={HANDSHAKE_TIMEOUT}s, session={SESSION_TIMEOUT}s")
        log(f"Log level: {LOG_LEVEL} (set OTPMAIL_LOG_LEVEL=0/1/2)")
        log(f"{len(key_registry.keys)} users registered.")
        log(f"Server public key: {server_identity.get_public_hex()}")
        log(f"Server fingerprint: {server_identity.get_fingerprint()}")
    except Exception as e:
        log(f"CRITICAL: Failed to bind: {e}")
        return

    try:
        while True:
            client_sock, addr = server_sock.accept()
            client_ip = addr[0]

            # Ban check
            if is_banned(client_ip):
                log("BLOCKED banned IP", level=1)
                log(f"Banned IP: {client_ip}", level=2)
                client_sock.close()
                continue

            # Per-IP limit check
            with ip_lock:
                current = ip_counts.get(client_ip, 0)
                if current >= MAX_PER_IP:
                    log("BLOCKED per-IP limit", level=1)
                    log(f"Per-IP limit for {client_ip}", level=2)
                    client_sock.close()
                    continue

            # Global limit check (non-blocking)
            if not conn_semaphore.acquire(blocking=False):
                log("BLOCKED server at max connections", level=1)
                client_sock.close()
                continue

            # Track the connection
            with ip_lock:
                ip_counts[client_ip] = ip_counts.get(client_ip, 0) + 1

            handler = ClientHandler(
                client_sock, addr, master_key, mailbox,
                key_registry, clients, clients_lock, server_identity,
                conn_semaphore, ip_counts, ip_lock,
            )
            handler.start()
    except KeyboardInterrupt:
        log("Server shutting down (KeyboardInterrupt)")
    finally:
        server_sock.close()

if __name__ == "__main__":
    main()
