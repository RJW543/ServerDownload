"""
client.py — OTPMail Client

Architecture:
  RelayClient   — blocking SSL/TLS connection to the relay server, framed JSON
  OTPMailCore   — business logic: registration, OTP exchange, send/receive
  CursesApp     — terminal UI (curses), with a background daemon thread for
                  periodic message fetching

Usage:
  python client.py                         # open existing vault
  python client.py --register              # create new account
  python client.py --vault /path/to.enc    # specify vault path
  python client.py --server 10.0.0.1:4433  # specify server
"""

import os
import sys
import ssl
import json
import socket
import struct
import base64
import uuid
import threading
import queue
import time
import curses
import curses.textpad
import textwrap
import argparse
import traceback
from datetime import datetime, timezone
from typing import Optional, List, Dict, Tuple, Any

from crypto_utils import (
    generate_identity_keypair,
    generate_kem_keypair,
    generate_otp_pages,
    otp_encrypt_message,
    otp_decrypt_message,
    kem_encapsulate,
    kem_decapsulate,
    derive_aes_key,
    aes_gcm_encrypt,
    aes_gcm_decrypt,
    sign_data,
    verify_signature,
    pubkey_fingerprint,
    OTP_DEFAULT_PAGES,
)
from vault import Vault, VaultError

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_SERVER      = "127.0.0.1:4433"
DEFAULT_VAULT       = os.path.expanduser("~/.otpmail/vault.enc")
MAX_FRAME_SIZE      = 2 * 1024 * 1024
CONNECT_TIMEOUT     = 10
READ_TIMEOUT        = 15
FETCH_INTERVAL      = 10          # seconds between background fetches
CLEANUP_INTERVAL    = 1800        # 30 minutes between expired-message cleanup

# OTP exchange payload type tags (inside the relay SEND payload)
PTYPE_OTP_EXCHANGE  = "OTP_EXCHANGE"
PTYPE_MESSAGE       = "MESSAGE"


# ═════════════════════════════════════════════════════════════════════════════
# Network layer
# ═════════════════════════════════════════════════════════════════════════════

class RelayError(Exception):
    pass


class RelayClient:
    """
    Synchronous SSL/TLS connection to the relay server.

    Framing: every message is a 4-byte big-endian length followed by UTF-8 JSON.
    All public methods are thread-safe (protected by a single lock).
    """

    def __init__(self, server: str, verify_cert: bool = False) -> None:
        host, _, port_s = server.rpartition(":")
        self.host    = host or "127.0.0.1"
        self.port    = int(port_s) if port_s else 4433
        self._lock   = threading.Lock()
        self._sock: Optional[ssl.SSLSocket] = None
        self.server_pub: Optional[bytes] = None
        self._verify_cert = verify_cert

    def connect(self) -> None:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        if not self._verify_cert:
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
        raw = socket.create_connection((self.host, self.port), timeout=CONNECT_TIMEOUT)
        self._sock = ctx.wrap_socket(raw, server_hostname=self.host)
        self._sock.settimeout(READ_TIMEOUT)

    def disconnect(self) -> None:
        with self._lock:
            if self._sock:
                try:
                    self._sock.close()
                except Exception:
                    pass
                self._sock = None

    @property
    def connected(self) -> bool:
        return self._sock is not None

    def _send(self, msg: Any) -> None:
        data  = json.dumps(msg).encode("utf-8")
        frame = len(data).to_bytes(4, "big") + data
        self._sock.sendall(frame)

    def _recv(self) -> Dict:
        hdr  = self._recvn(4)
        size = int.from_bytes(hdr, "big")
        if size == 0 or size > MAX_FRAME_SIZE:
            raise RelayError(f"Invalid frame size: {size}")
        raw = self._recvn(size)
        return json.loads(raw.decode("utf-8"))

    def _recvn(self, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = self._sock.recv(n - len(buf))
            if not chunk:
                raise RelayError("Connection closed by server")
            buf += chunk
        return buf

    # ── Public protocol methods ───────────────────────────────────────────────

    def register(self, username: str, ed25519_pub: bytes, kem_pub: bytes) -> None:
        with self._lock:
            self._send({
                "type":           "REGISTER",
                "username":       username,
                "ed25519_pubkey": base64.b64encode(ed25519_pub).decode(),
                "kem_pubkey":     base64.b64encode(kem_pub).decode(),
            })
            resp = self._recv()
            if resp.get("type") == "REGISTER_OK":
                self.server_pub = base64.b64decode(resp.get("server_pub", ""))
                return
            raise RelayError(f"Registration failed: {resp.get('reason', 'unknown error')}")

    def authenticate(self, username: str, ed25519_priv: bytes) -> List[Dict]:
        """
        Perform challenge-response auth.
        Returns any queued messages waiting for this user.
        """
        with self._lock:
            self._send({"type": "HELLO", "username": username})
            challenge = self._recv()
            if challenge.get("type") != "CHALLENGE":
                raise RelayError(f"Expected CHALLENGE, got {challenge.get('type')}")

            nonce = base64.b64decode(challenge["nonce"])
            sig   = sign_data(ed25519_priv, nonce)
            self._send({
                "type":      "AUTH",
                "username":  username,
                "signature": base64.b64encode(sig).decode(),
            })

            resp = self._recv()
            if resp.get("type") == "AUTH_OK":
                self.server_pub = base64.b64decode(resp.get("server_pub", ""))
                # May be followed immediately by QUEUED_MESSAGES
                backlog: List[Dict] = []
                self._sock.settimeout(2.0)
                try:
                    qm = self._recv()
                    if qm.get("type") == "QUEUED_MESSAGES":
                        backlog = qm.get("messages", [])
                except (socket.timeout, ssl.SSLError):
                    pass
                self._sock.settimeout(READ_TIMEOUT)
                return backlog

            raise RelayError(f"Authentication failed: {resp.get('reason', 'unknown')}")

    def lookup(self, username: str) -> Dict:
        with self._lock:
            self._send({"type": "LOOKUP", "username": username})
            resp = self._recv()
        if resp.get("type") == "LOOKUP_RESP":
            return resp
        raise RelayError(f"Lookup failed: {resp.get('reason', 'user not found')}")

    def send_message(self, to: str, payload: Dict) -> str:
        msg_id = str(uuid.uuid4())
        with self._lock:
            self._send({
                "type":    "SEND",
                "to":      to,
                "msg_id":  msg_id,
                "payload": payload,
            })
            resp = self._recv()
        if resp.get("type") == "SEND_OK":
            return msg_id
        raise RelayError(f"Send failed: {resp.get('reason', 'unknown')}")

    def fetch(self) -> List[Dict]:
        with self._lock:
            self._send({"type": "FETCH"})
            resp = self._recv()
        return resp.get("messages", [])

    def ack(self, msg_ids: List[str]) -> None:
        with self._lock:
            self._send({"type": "ACK", "msg_ids": msg_ids})

    def recv_nonblocking(self, timeout: float = 0.1) -> Optional[Dict]:
        """Try to read a pushed delivery frame. Returns None on timeout."""
        with self._lock:
            old = self._sock.gettimeout()
            self._sock.settimeout(timeout)
            try:
                return self._recv()
            except (socket.timeout, ssl.SSLError):
                return None
            finally:
                self._sock.settimeout(old)


# ═════════════════════════════════════════════════════════════════════════════
# Business logic
# ═════════════════════════════════════════════════════════════════════════════

class OTPMailCore:
    """
    High-level operations combining Vault + RelayClient.
    Thread-safe for background fetch usage.
    """

    def __init__(self, vault: Vault, relay: RelayClient) -> None:
        self.vault = vault
        self.relay = relay
        self._msg_queue: queue.Queue = queue.Queue()
        self._lock = threading.Lock()

    # ── Account setup ─────────────────────────────────────────────────────────

    def register_account(self, username: str, password: str, vault_path: str) -> None:
        """
        Generate identity + KEM keypairs, create vault, register on relay.
        """
        ed_priv, ed_pub = generate_identity_keypair()
        km_priv, km_pub = generate_kem_keypair()

        self.vault.create(password)
        self.vault.set_identity(username, ed_priv, ed_pub, km_priv, km_pub)
        self.vault.save()

        self.relay.register(username, ed_pub, km_pub)

    def login(self) -> List[Dict]:
        """
        Authenticate with the relay. Returns backlogged messages.
        Runs the 48-hour message cleanup.
        """
        ed_priv   = self.vault.get_ed25519_priv()
        username  = self.vault.get_username()
        backlog   = self.relay.authenticate(username, ed_priv)
        n_deleted = self.vault.cleanup_expired_messages()
        if n_deleted:
            self._log_event(f"Auto-deleted {n_deleted} expired messages (>48 h).")
        return backlog

    # ── OTP exchange (add contact) ────────────────────────────────────────────

    def initiate_otp_exchange(self, contact_username: str) -> str:
        """
        Add a new contact by:
          1. Looking up their public keys from the relay.
          2. Verifying the server binding signature.
          3. Generating OTP pages for both directions.
          4. Encrypting the contact's half (incoming for us = outgoing for them)
             via ECIES (ephemeral X25519 ECDH → HKDF → AES-256-GCM).
          5. Sending the encrypted bundle through the relay.
          6. Storing our half and the contact's pubkeys in the vault.

        Returns the contact's Ed25519 key fingerprint for out-of-band verification.
        """
        # 1. Key lookup
        resp = self.relay.lookup(contact_username)
        ed_pub  = base64.b64decode(resp["ed25519_pubkey"])
        kem_pub = base64.b64decode(resp["kem_pubkey"])
        srv_pub = base64.b64decode(resp.get("server_pub", ""))
        binding = base64.b64decode(resp.get("binding_sig", ""))

        # 2. Verify server binding signature
        if srv_pub and binding:
            bind_data = contact_username.encode() + ed_pub + kem_pub
            if not verify_signature(srv_pub, bind_data, binding):
                raise ValueError("Server binding signature INVALID — possible key substitution attack!")

        # 3. Generate pages
        our_pages    = generate_otp_pages(OTP_DEFAULT_PAGES)   # outgoing (we send)
        their_pages  = generate_otp_pages(OTP_DEFAULT_PAGES)   # incoming (they encrypt to us)

        # 4. Encrypt `their_pages` under contact's KEM pubkey (ECIES)
        salt          = os.urandom(32)
        eph_pub, shared = kem_encapsulate(kem_pub)
        aes_key       = derive_aes_key(shared, salt)
        bundle_plain  = json.dumps([
            base64.b64encode(p).decode() for p in their_pages
        ]).encode("utf-8")
        nonce, bundle_ct = aes_gcm_encrypt(aes_key, bundle_plain)

        # Also include our own Ed25519 pubkey and KEM pubkey so they can add us back
        my_ident = self.vault.get_identity()
        payload = {
            "type":           PTYPE_OTP_EXCHANGE,
            "eph_pub":        base64.b64encode(eph_pub).decode(),
            "salt":           base64.b64encode(salt).decode(),
            "nonce":          base64.b64encode(nonce).decode(),
            "bundle":         base64.b64encode(bundle_ct).decode(),
            "sender_ed_pub":  my_ident["ed25519_pub"],
            "sender_kem_pub": my_ident["kem_pub"],
        }

        # 5. Send
        self.relay.send_message(contact_username, payload)

        # 6. Store in vault
        self.vault.add_contact(
            contact_username,
            ed_pub,
            kem_pub,
            outgoing_pages=our_pages,
            incoming_pages=their_pages,   # their_pages[i] == what we decrypt their msg[i] with
                                          # (the contact will encrypt with their copy of these)
        )
        self.vault.save()

        return pubkey_fingerprint(ed_pub)

    def handle_otp_exchange(self, sender: str, payload: Dict) -> str:
        """
        Receive and store OTP pages sent by a contact during initial setup.
        Returns the sender's fingerprint.
        """
        kem_priv = self.vault.get_kem_priv()
        eph_pub  = base64.b64decode(payload["eph_pub"])
        salt     = base64.b64decode(payload["salt"])
        nonce    = base64.b64decode(payload["nonce"])
        bundle_ct = base64.b64decode(payload["bundle"])

        shared  = kem_decapsulate(kem_priv, eph_pub)
        aes_key = derive_aes_key(shared, salt)
        bundle_plain = aes_gcm_decrypt(aes_key, nonce, bundle_ct)
        pages = [
            base64.b64decode(p) for p in json.loads(bundle_plain.decode("utf-8"))
        ]

        sender_ed_pub  = base64.b64decode(payload.get("sender_ed_pub", ""))
        sender_kem_pub = base64.b64decode(payload.get("sender_kem_pub", ""))

        if self.vault.has_contact(sender):
            # Update incoming pages only
            self.vault.update_contact_incoming_pages(sender, pages)
        else:
            # Add contact with placeholder outgoing pages (they'll send theirs separately)
            self.vault.add_contact(
                sender,
                sender_ed_pub,
                sender_kem_pub,
                outgoing_pages=[],
                incoming_pages=pages,
            )
        self.vault.save()
        return pubkey_fingerprint(sender_ed_pub) if sender_ed_pub else "unknown"

    # ── Messaging ─────────────────────────────────────────────────────────────

    def send(self, contact: str, text: str) -> None:
        """Encrypt and send a message. Consumes one OTP page."""
        result = self.vault.consume_outgoing_page(contact)
        if result is None:
            raise ValueError(f"No outgoing OTP pages remaining for '{contact}'")
        page_index, page = result

        ciphertext, hmac_tag = otp_encrypt_message(text, page)

        payload = {
            "type":       PTYPE_MESSAGE,
            "page_index": page_index,
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "hmac":       base64.b64encode(hmac_tag).decode(),
        }
        self.relay.send_message(contact, payload)
        self.vault.add_message(contact, "sent", text, page_index=page_index)
        self.vault.save()

    def receive_envelope(self, envelope: Dict) -> Optional[Tuple[str, str]]:
        """
        Process a relay envelope.  Returns (sender, message_text) for a regular
        message, or None if the envelope was an OTP exchange (handled internally).
        """
        sender  = envelope.get("from", "")
        payload = envelope.get("payload", {})

        if not isinstance(payload, dict):
            return None

        ptype = payload.get("type")

        if ptype == PTYPE_OTP_EXCHANGE:
            try:
                fp = self.handle_otp_exchange(sender, payload)
                self._log_event(f"OTP exchange completed with {sender} (fp: {fp})")
            except Exception as e:
                self._log_event(f"OTP exchange from {sender} FAILED: {e}")
            return None

        if ptype == PTYPE_MESSAGE:
            page_index = payload.get("page_index")
            try:
                ciphertext = base64.b64decode(payload["ciphertext"])
                hmac_tag   = base64.b64decode(payload["hmac"])
            except Exception:
                self._log_event(f"Malformed message from {sender}")
                return None

            if not self.vault.has_contact(sender):
                self._log_event(f"Message from unknown contact '{sender}' — ignored")
                return None

            # Verify sender's Ed25519 signature... payload isn't signed separately here
            # because the relay already authenticated the sender's session.
            # (For maximum paranoia, sign each payload with Ed25519 — see README for TODO.)

            page = self.vault.consume_incoming_page(sender, page_index)
            if page is None:
                self._log_event(
                    f"SECURITY: page index {page_index} from {sender} "
                    "already consumed or not found — message REJECTED"
                )
                return None

            try:
                text = otp_decrypt_message(ciphertext, hmac_tag, page)
            except ValueError as e:
                self._log_event(f"SECURITY: {e} (sender: {sender}, index: {page_index})")
                return None

            self.vault.add_message(sender, "received", text, page_index=page_index)
            self.vault.save()
            return sender, text

        return None

    def process_envelopes(self, envelopes: List[Dict]) -> List[Tuple[str, str]]:
        """Process a batch of envelopes. Returns list of (sender, text) for display."""
        results = []
        ack_ids = []
        for env in envelopes:
            result = self.receive_envelope(env)
            if result:
                results.append(result)
            ack_ids.append(env.get("msg_id", ""))
        if ack_ids:
            try:
                self.relay.ack([i for i in ack_ids if i])
            except Exception:
                pass
        return results

    # ── Background fetch ──────────────────────────────────────────────────────

    def start_background_fetch(self) -> None:
        """Start a daemon thread that polls for messages every FETCH_INTERVAL seconds."""
        self._stop_fetch = threading.Event()
        self._fetch_thread = threading.Thread(
            target=self._fetch_loop, daemon=True, name="otpmail-fetch"
        )
        self._fetch_thread.start()

    def stop_background_fetch(self) -> None:
        if hasattr(self, "_stop_fetch"):
            self._stop_fetch.set()

    def _fetch_loop(self) -> None:
        last_cleanup = time.time()
        while not self._stop_fetch.is_set():
            time.sleep(FETCH_INTERVAL)
            if self._stop_fetch.is_set():
                break
            try:
                envelopes = self.relay.fetch()
                if envelopes:
                    results = self.process_envelopes(envelopes)
                    for r in results:
                        self._msg_queue.put(("message", r))
            except Exception as e:
                self._msg_queue.put(("error", str(e)))

            # Periodic cleanup
            if time.time() - last_cleanup > CLEANUP_INTERVAL:
                n = self.vault.cleanup_expired_messages()
                if n:
                    self._msg_queue.put(("event", f"Auto-deleted {n} expired message(s)"))
                last_cleanup = time.time()

    def poll_incoming(self) -> List[Tuple[str, Any]]:
        """Drain the incoming message queue (non-blocking). Returns [(kind, data)]."""
        items = []
        while True:
            try:
                items.append(self._msg_queue.get_nowait())
            except queue.Empty:
                break
        return items

    def _log_event(self, msg: str) -> None:
        self._msg_queue.put(("event", msg))


# ═════════════════════════════════════════════════════════════════════════════
# Curses TUI
# ═════════════════════════════════════════════════════════════════════════════

PANEL_CONTACTS = 0
PANEL_MESSAGES = 1

# Colour pair IDs
C_NORMAL     = 0
C_TITLE      = 1
C_HIGHLIGHT  = 2
C_STATUS_OK  = 3
C_STATUS_ERR = 4
C_SAVED      = 5
C_SENT       = 6
C_RECV       = 7
C_KEY        = 8
C_DIM        = 9
C_WARNING    = 10


def _init_colours() -> None:
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(C_TITLE,      curses.COLOR_BLACK,  curses.COLOR_CYAN)
    curses.init_pair(C_HIGHLIGHT,  curses.COLOR_BLACK,  curses.COLOR_WHITE)
    curses.init_pair(C_STATUS_OK,  curses.COLOR_BLACK,  curses.COLOR_GREEN)
    curses.init_pair(C_STATUS_ERR, curses.COLOR_WHITE,  curses.COLOR_RED)
    curses.init_pair(C_SAVED,      curses.COLOR_YELLOW, -1)
    curses.init_pair(C_SENT,       curses.COLOR_CYAN,   -1)
    curses.init_pair(C_RECV,       curses.COLOR_GREEN,  -1)
    curses.init_pair(C_KEY,        curses.COLOR_YELLOW, -1)
    curses.init_pair(C_DIM,        curses.COLOR_WHITE,  -1)
    curses.init_pair(C_WARNING,    curses.COLOR_RED,    -1)


class CursesApp:
    """
    Terminal UI for OTPMail.

    Layout (variable h × w):
      Row 0           : title bar
      Rows 1..h-4     : main area (contacts left | messages right)
      Row h-3         : divider / key hints
      Row h-2         : compose input
      Row h-1         : status bar
    """

    CONTACTS_W = 22    # width of the contacts panel (columns)

    def __init__(self, core: OTPMailCore) -> None:
        self.core      = core
        self.vault     = core.vault
        self.relay     = core.relay

        self.contacts: List[str]    = []
        self.contact_idx: int       = 0
        self.msg_scroll: int        = 0
        self.active_panel: int      = PANEL_CONTACTS
        self.input_buf: str         = ""
        self.status_msg: str        = "Ready"
        self.status_err: bool       = False
        self._running: bool         = True
        self._events: List[str]     = []   # system event log

    # ── Main entry ────────────────────────────────────────────────────────────

    def run(self, stdscr: curses.window) -> None:
        _init_colours()
        curses.curs_set(1)
        stdscr.timeout(200)   # non-blocking getch with 200 ms poll
        self.scr = stdscr

        self._refresh_contacts()
        self._redraw()

        while self._running:
            # Process incoming messages from background thread
            items = self.core.poll_incoming()
            if items:
                for kind, data in items:
                    if kind == "message":
                        sender, _ = data
                        self._set_status(f"New message from {sender}")
                        if sender not in self.contacts:
                            self._refresh_contacts()
                    elif kind in ("error", "event"):
                        self._events.append(str(data))
                        self._set_status(str(data), err=(kind == "error"))
                self._redraw()

            key = stdscr.getch()
            if key == curses.ERR:
                continue
            self._handle_key(key)
            self._redraw()

    # ── Contact & state refresh ───────────────────────────────────────────────

    def _refresh_contacts(self) -> None:
        self.contacts = self.vault.get_contacts()
        if self.contact_idx >= len(self.contacts):
            self.contact_idx = max(0, len(self.contacts) - 1)

    def _current_contact(self) -> Optional[str]:
        if self.contacts:
            return self.contacts[self.contact_idx]
        return None

    # ── Drawing ───────────────────────────────────────────────────────────────

    def _redraw(self) -> None:
        h, w = self.scr.getmaxyx()
        if h < 10 or w < 40:
            self.scr.clear()
            self.scr.addstr(0, 0, "Terminal too small — resize please")
            self.scr.refresh()
            return

        self.scr.erase()
        self._draw_title(h, w)
        self._draw_contacts(h, w)
        self._draw_messages(h, w)
        self._draw_divider(h, w)
        self._draw_compose(h, w)
        self._draw_status(h, w)
        self.scr.refresh()

    def _draw_title(self, h: int, w: int) -> None:
        username = self.vault.get_username() or "?"
        server   = f"{self.relay.host}:{self.relay.port}"
        title    = f" OTPMail  ·  {username}@{server} "
        self.scr.attron(curses.color_pair(C_TITLE) | curses.A_BOLD)
        self.scr.addstr(0, 0, title.ljust(w)[:w])
        self.scr.attroff(curses.color_pair(C_TITLE) | curses.A_BOLD)

    def _draw_contacts(self, h: int, w: int) -> None:
        cw      = self.CONTACTS_W
        panel_h = h - 4
        header  = " CONTACTS "

        # Panel border / header
        attr_hdr = (curses.color_pair(C_TITLE)
                    if self.active_panel == PANEL_CONTACTS
                    else curses.A_REVERSE)
        self.scr.attron(attr_hdr)
        self.scr.addstr(1, 0, header.ljust(cw)[:cw])
        self.scr.attroff(attr_hdr)

        for row in range(panel_h - 1):
            idx = row
            y   = row + 2
            if idx < len(self.contacts):
                name  = self.contacts[idx]
                pages = self.vault.get_pages_remaining(name)
                out   = pages["outgoing"]
                unread_mark = "●" if self._has_unread(name) else " "
                label = f" {unread_mark}{name[:12]:<12} {out:>4}"
                if idx == self.contact_idx and self.active_panel == PANEL_CONTACTS:
                    self.scr.attron(curses.color_pair(C_HIGHLIGHT) | curses.A_BOLD)
                    self.scr.addstr(y, 0, label.ljust(cw)[:cw])
                    self.scr.attroff(curses.color_pair(C_HIGHLIGHT) | curses.A_BOLD)
                elif idx == self.contact_idx:
                    self.scr.attron(curses.A_BOLD)
                    self.scr.addstr(y, 0, label.ljust(cw)[:cw])
                    self.scr.attroff(curses.A_BOLD)
                else:
                    self.scr.addstr(y, 0, label.ljust(cw)[:cw])
            else:
                self.scr.addstr(y, 0, " " * cw)

        # Bottom hints
        hints = " [A]dd [D]el"
        self.scr.attron(curses.color_pair(C_DIM))
        self.scr.addstr(h - 4, 0, hints.ljust(cw)[:cw])
        self.scr.attroff(curses.color_pair(C_DIM))

    def _has_unread(self, contact: str) -> bool:
        """Cheap heuristic: any messages in the last fetch cycle."""
        return False   # background thread sets status; full unread tracking is a TODO

    def _draw_messages(self, h: int, w: int) -> None:
        cw      = self.CONTACTS_W
        mw      = w - cw - 1
        panel_h = h - 4
        contact = self._current_contact()

        # Vertical separator
        for row in range(1, h - 3):
            try:
                self.scr.addch(row, cw, "│")
            except curses.error:
                pass

        # Header
        hdr_text = f" {contact} " if contact else " (no contact selected) "
        attr_hdr = (curses.color_pair(C_TITLE)
                    if self.active_panel == PANEL_MESSAGES
                    else curses.A_REVERSE)
        self.scr.attron(attr_hdr)
        self.scr.addstr(1, cw + 1, hdr_text.ljust(mw)[:mw])
        self.scr.attroff(attr_hdr)

        if not contact:
            return

        messages  = self.vault.get_messages(contact)
        lines     = self._render_messages(messages, mw)
        visible_h = panel_h - 1

        # Auto-scroll to bottom unless user scrolled up
        max_scroll = max(0, len(lines) - visible_h)
        if self.msg_scroll > max_scroll:
            self.msg_scroll = max_scroll
        start = max(0, len(lines) - visible_h - self.msg_scroll)

        for i in range(visible_h):
            y   = i + 2
            li  = start + i
            if li < len(lines):
                text, attr = lines[li]
                try:
                    self.scr.attron(attr)
                    self.scr.addstr(y, cw + 1, text[:mw].ljust(mw)[:mw])
                    self.scr.attroff(attr)
                except curses.error:
                    pass

    def _render_messages(self, messages: List[Dict], width: int) -> List[Tuple[str, int]]:
        """Convert messages to (line_text, curses_attr) pairs."""
        lines: List[Tuple[str, int]] = []
        wrap_w = width - 13   # leave room for timestamp + margin

        for msg in messages:
            ts       = datetime.fromisoformat(msg["timestamp"]).strftime("%H:%M:%S")
            content  = msg.get("content", "")
            saved    = msg.get("saved", False)
            is_sent  = msg["direction"] == "sent"
            prefix   = f" {ts}  {'You' if is_sent else msg.get('contact', '?'):>10}: "

            wrapped = textwrap.wrap(content, max(10, wrap_w)) or [""]
            for j, chunk in enumerate(wrapped):
                if j == 0:
                    line = prefix + chunk
                    if saved:
                        line += "  [SAVED]"
                else:
                    line = " " * len(prefix) + chunk

                if is_sent:
                    attr = curses.color_pair(C_SENT)
                else:
                    attr = curses.color_pair(C_RECV)
                if saved:
                    attr |= curses.A_BOLD
                lines.append((line, attr))

        return lines

    def _draw_divider(self, h: int, w: int) -> None:
        row = h - 4
        self.scr.attron(curses.color_pair(C_DIM))
        hints = (
            " [Tab]=Switch  [↑↓]=Scroll  [S]ave msg  "
            "[F]etch  [P]ages  [?]Help  [Q]uit"
        )
        self.scr.addstr(row, self.CONTACTS_W + 1, hints[:w - self.CONTACTS_W - 1])
        self.scr.attroff(curses.color_pair(C_DIM))
        # Horizontal rule
        try:
            self.scr.addstr(h - 3, 0, "─" * w)
        except curses.error:
            pass

    def _draw_compose(self, h: int, w: int) -> None:
        contact = self._current_contact()
        prompt  = "▶ " if contact else "  "
        line    = (prompt + self.input_buf)[:w - 1]
        self.scr.addstr(h - 2, 0, line.ljust(w - 1))

        if self.active_panel == PANEL_MESSAGES:
            cursor_x = min(len(prompt) + len(self.input_buf), w - 2)
            curses.curs_set(1)
            self.scr.move(h - 2, cursor_x)
        else:
            curses.curs_set(0)

    def _draw_status(self, h: int, w: int) -> None:
        attr = curses.color_pair(C_STATUS_ERR if self.status_err else C_STATUS_OK)
        msg  = f" {self.status_msg} "
        self.scr.attron(attr)
        self.scr.addstr(h - 1, 0, msg.ljust(w)[:w])
        self.scr.attroff(attr)

    # ── Key handling ──────────────────────────────────────────────────────────

    def _handle_key(self, key: int) -> None:
        if self.active_panel == PANEL_CONTACTS:
            self._key_contacts(key)
        else:
            self._key_messages(key)

    def _key_contacts(self, key: int) -> None:
        if key == ord("\t") or key == curses.KEY_RIGHT:
            self.active_panel = PANEL_MESSAGES
        elif key in (curses.KEY_UP, ord("k")):
            self.contact_idx = max(0, self.contact_idx - 1)
            self.msg_scroll  = 0
        elif key in (curses.KEY_DOWN, ord("j")):
            self.contact_idx = min(len(self.contacts) - 1, self.contact_idx + 1)
            self.msg_scroll  = 0
        elif key in (curses.KEY_ENTER, 10, 13):
            self.active_panel = PANEL_MESSAGES
        elif key == ord("a") or key == ord("A"):
            self._action_add_contact()
        elif key == ord("d") or key == ord("D"):
            self._action_delete_contact()
        elif key == ord("f") or key == ord("F"):
            self._action_fetch()
        elif key == ord("p") or key == ord("P"):
            self._action_show_pages()
        elif key == ord("?"):
            self._action_help()
        elif key == ord("q") or key == ord("Q"):
            self._running = False

    def _key_messages(self, key: int) -> None:
        if key == ord("\t") or key == curses.KEY_LEFT:
            self.active_panel = PANEL_CONTACTS
            self.input_buf    = ""
        elif key in (curses.KEY_UP,):
            self.msg_scroll += 1
        elif key in (curses.KEY_DOWN,):
            self.msg_scroll = max(0, self.msg_scroll - 1)
        elif key in (curses.KEY_ENTER, 10, 13):
            self._action_send()
        elif key in (curses.KEY_BACKSPACE, 127, 8):
            self.input_buf = self.input_buf[:-1]
        elif key == ord("s") or key == ord("S"):
            if not self.input_buf:
                self._action_save_last_message()
            else:
                self.input_buf += chr(key)
        elif key == ord("f") or key == ord("F"):
            if not self.input_buf:
                self._action_fetch()
            else:
                self.input_buf += chr(key)
        elif key == ord("p") or key == ord("P"):
            if not self.input_buf:
                self._action_show_pages()
            else:
                self.input_buf += chr(key)
        elif key == ord("?") and not self.input_buf:
            self._action_help()
        elif key == ord("q") or key == ord("Q"):
            if not self.input_buf:
                self._running = False
            else:
                self.input_buf += chr(key)
        elif 32 <= key < 256:
            self.input_buf += chr(key)
        elif key == 27:  # ESC
            self.input_buf = ""

    # ── Actions ───────────────────────────────────────────────────────────────

    def _action_send(self) -> None:
        text    = self.input_buf.strip()
        contact = self._current_contact()
        if not text or not contact:
            return
        self.input_buf = ""
        try:
            self.core.send(contact, text)
            self._set_status(f"Message sent to {contact}")
            self.msg_scroll = 0
        except Exception as e:
            self._set_status(f"Send error: {e}", err=True)

    def _action_fetch(self) -> None:
        self._set_status("Fetching messages…")
        self._redraw()
        try:
            envelopes = self.relay.fetch()
            results   = self.core.process_envelopes(envelopes)
            if results:
                senders = ", ".join({r[0] for r in results})
                self._set_status(f"Received {len(results)} message(s) from: {senders}")
                self._refresh_contacts()
            else:
                self._set_status("No new messages")
        except Exception as e:
            self._set_status(f"Fetch error: {e}", err=True)

    def _action_save_last_message(self) -> None:
        contact = self._current_contact()
        if not contact:
            return
        msgs = self.vault.get_messages(contact)
        if not msgs:
            self._set_status("No messages to save")
            return
        # Save the most recently received (last in list)
        last = msgs[-1]
        new_state = self.vault.toggle_save_message(contact, last["id"])
        self.vault.save()
        self._set_status(
            f"Message {'saved' if new_state else 'unsaved'} — "
            f"{'exempt from 48h deletion' if new_state else 'will expire normally'}"
        )

    def _action_add_contact(self) -> None:
        name = self._prompt("Add contact — enter their username: ")
        if not name:
            self._set_status("Cancelled")
            return
        name = name.strip()
        if not name:
            return
        if self.vault.has_contact(name):
            self._set_status(f"'{name}' is already a contact")
            return
        self._set_status(f"Looking up {name} and generating OTP pages…")
        self._redraw()
        try:
            fp = self.core.initiate_otp_exchange(name)
            self._refresh_contacts()
            self._set_status(
                f"Added {name}  |  Key fingerprint: {fp}  ← verify out-of-band!"
            )
        except Exception as e:
            self._set_status(f"Failed to add contact: {e}", err=True)

    def _action_delete_contact(self) -> None:
        contact = self._current_contact()
        if not contact:
            return
        confirm = self._prompt(f"Delete contact '{contact}'? ALL OTP pages will be lost. [yes/N]: ")
        if confirm and confirm.strip().lower() == "yes":
            self.vault.remove_contact(contact)
            self.vault.save()
            self._refresh_contacts()
            self._set_status(f"Contact '{contact}' removed")
        else:
            self._set_status("Delete cancelled")

    def _action_show_pages(self) -> None:
        contact = self._current_contact()
        if not contact:
            self._set_status("No contact selected")
            return
        pages = self.vault.get_pages_remaining(contact)
        self._set_status(
            f"{contact} — Outgoing OTP pages: {pages['outgoing']}  |  "
            f"Incoming OTP pages: {pages['incoming']}"
        )

    def _action_help(self) -> None:
        h, w = self.scr.getmaxyx()
        lines = [
            "─── OTPMail Help ───────────────────────────────────────",
            "",
            "Navigation:",
            "  Tab / ← →    Switch between Contacts and Messages panels",
            "  ↑ / ↓        Move contact selection / scroll messages",
            "  Enter        Select contact / Send composed message",
            "",
            "Actions (Contacts panel or when input is empty):",
            "  A            Add a new contact (initiates OTP exchange)",
            "  D            Delete selected contact",
            "  F            Fetch new messages from relay now",
            "  P            Show remaining OTP pages for contact",
            "  S            Toggle SAVE flag on last message (exempt from 48h)",
            "  Q            Quit OTPMail",
            "",
            "Compose (Messages panel):",
            "  Type freely  Compose message",
            "  Enter        Send",
            "  Backspace    Delete character",
            "  ESC          Clear compose buffer",
            "",
            "Security:",
            "  Verify contacts' fingerprints out-of-band (call/in-person).",
            "  Saved messages persist beyond 48 h; all others auto-delete.",
            "",
            "  Press any key to close this help screen.",
        ]
        help_h = len(lines) + 4
        help_w = max(len(l) for l in lines) + 4
        by = max(0, (h - help_h) // 2)
        bx = max(0, (w - help_w) // 2)

        win = curses.newwin(help_h, min(help_w, w - 2), by, bx)
        win.box()
        for i, line in enumerate(lines):
            try:
                win.addstr(i + 2, 2, line[:help_w - 4])
            except curses.error:
                pass
        win.refresh()
        self.scr.getch()

    # ── Input prompt ──────────────────────────────────────────────────────────

    def _prompt(self, prompt_text: str, max_len: int = 64) -> Optional[str]:
        """Show an inline input prompt at the bottom. Returns user input or None."""
        h, w = self.scr.getmaxyx()
        buf  = ""
        curses.curs_set(1)
        while True:
            display = (prompt_text + buf)[:w - 1]
            self.scr.addstr(h - 2, 0, display.ljust(w - 1))
            self.scr.move(h - 2, min(len(prompt_text) + len(buf), w - 2))
            self.scr.refresh()
            key = self.scr.getch()
            if key in (curses.KEY_ENTER, 10, 13):
                return buf
            elif key == 27:
                return None
            elif key in (curses.KEY_BACKSPACE, 127, 8):
                buf = buf[:-1]
            elif 32 <= key < 256 and len(buf) < max_len:
                buf += chr(key)

    # ── Status bar ────────────────────────────────────────────────────────────

    def _set_status(self, msg: str, err: bool = False) -> None:
        self.status_msg = msg
        self.status_err = err


# ═════════════════════════════════════════════════════════════════════════════
# Registration wizard (runs before the TUI)
# ═════════════════════════════════════════════════════════════════════════════

def registration_wizard(vault_path: str, server: str) -> None:
    """Interactive registration for first-time setup."""
    print("\n── OTPMail New Account Setup ─────────────────────────")
    username = input("Choose a username (alphanumeric, max 32 chars): ").strip()
    if not username or not username.isalnum() or len(username) > 32:
        print("Invalid username.")
        sys.exit(1)

    import getpass
    password = getpass.getpass("Set vault password: ")
    confirm  = getpass.getpass("Confirm vault password: ")
    if password != confirm:
        print("Passwords do not match.")
        sys.exit(1)

    os.makedirs(os.path.dirname(vault_path), exist_ok=True)

    print(f"\nConnecting to {server}…")
    relay = RelayClient(server, verify_cert=False)
    try:
        relay.connect()
    except Exception as e:
        print(f"Connection failed: {e}")
        sys.exit(1)

    vault = Vault(vault_path)
    core  = OTPMailCore(vault, relay)

    print("Generating identity keys and registering…")
    try:
        core.register_account(username, password, vault_path)
    except Exception as e:
        print(f"Registration failed: {e}")
        sys.exit(1)

    relay.disconnect()
    print(f"\n✓ Account '{username}' created.")
    print(f"  Vault: {vault_path}")
    fp = pubkey_fingerprint(vault.get_ed25519_pub())
    print(f"  Your key fingerprint: {fp}")
    print("\nStart OTPMail again without --register to log in.\n")


# ═════════════════════════════════════════════════════════════════════════════
# Entry point
# ═════════════════════════════════════════════════════════════════════════════

def main() -> None:
    p = argparse.ArgumentParser(description="OTPMail — Encrypted One-Time Pad Messenger")
    p.add_argument("--server",   default=DEFAULT_SERVER, help="Relay server host:port")
    p.add_argument("--vault",    default=DEFAULT_VAULT,  help="Path to vault file")
    p.add_argument("--register", action="store_true",     help="Create a new account")
    args = p.parse_args()

    if args.register:
        registration_wizard(args.vault, args.server)
        return

    if not os.path.exists(args.vault):
        print(f"Vault not found at {args.vault}.")
        print("Run with --register to create a new account.")
        sys.exit(1)

    import getpass
    password = getpass.getpass("Vault password: ")

    vault = Vault(args.vault)
    try:
        vault.open(password)
    except VaultError as e:
        print(f"Could not open vault: {e}")
        sys.exit(1)

    print(f"Connecting to {args.server}…")
    relay = RelayClient(args.server, verify_cert=False)
    try:
        relay.connect()
    except Exception as e:
        print(f"Connection failed: {e}")
        vault.close()
        sys.exit(1)

    core  = OTPMailCore(vault, relay)
    try:
        backlog = core.login()
    except RelayError as e:
        print(f"Authentication failed: {e}")
        relay.disconnect()
        vault.close()
        sys.exit(1)

    # Process any backlogged messages silently before entering UI
    if backlog:
        core.process_envelopes(backlog)

    core.start_background_fetch()

    def curses_main(stdscr: curses.window) -> None:
        app = CursesApp(core)
        app.run(stdscr)

    try:
        curses.wrapper(curses_main)
    except KeyboardInterrupt:
        pass
    except Exception:
        traceback.print_exc()
    finally:
        core.stop_background_fetch()
        relay.disconnect()
        vault.close()
        print("Session closed.")


if __name__ == "__main__":
    main()
