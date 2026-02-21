"""
server.py — OTPMail Relay Server

Responsibilities:
  • Store username → {Ed25519 pubkey, KEM pubkey} bindings (signed by server)
  • Authenticate clients via Ed25519 challenge-response
  • Route encrypted messages between clients
  • Queue messages for offline users; delete on delivery or after MSG_QUEUE_TTL
  • Never access OTP key material or message plaintext

Protocol (all messages are length-prefixed JSON over TLS):
  Client → Server:
    REGISTER   {username, ed25519_pubkey, kem_pubkey}
    HELLO      {username}
    AUTH       {username, signature}   (signs the server's challenge nonce)
    LOOKUP     {username}
    SEND       {to, msg_id, payload}
    ACK        {msg_ids: [...]}
    FETCH      {}

  Server → Client:
    REGISTER_OK  / REGISTER_ERR
    CHALLENGE    {nonce}
    AUTH_OK      {server_pubkey}  / AUTH_FAIL
    LOOKUP_RESP  {username, ed25519_pubkey, kem_pubkey, binding_sig}
    LOOKUP_ERR
    SEND_OK      {msg_id}  / SEND_ERR
    DELIVERY     {messages: [...]}
    FETCH_RESP   {messages: [...]}
    QUEUED_MESSAGES {messages: [...]}
    ERROR        {reason}

TLS note:
  This implementation uses standard TLS 1.3 (Python ssl module) with an RSA
  or ECDSA certificate.  Production deployments should use an X25519Kyber768
  hybrid cipher suite (OQS-OpenSSL or BoringSSL-OQS) for post-quantum security
  at the transport layer.
"""

import asyncio
import ssl
import json
import os
import base64
import hashlib
import time
import logging
import argparse
from typing import Dict, List, Optional, Any

from crypto_utils import generate_identity_keypair, sign_data, verify_signature

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_HOST         = "0.0.0.0"
DEFAULT_PORT         = 4433
MSG_QUEUE_TTL        = 7 * 24 * 3600    # 7 days
MAX_FRAME_SIZE       = 2 * 1024 * 1024  # 2 MB
USERNAME_MAX_LEN     = 32
CHALLENGE_TIMEOUT    = 30               # seconds
READ_TIMEOUT         = 60              # seconds per frame

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SERVER] %(levelname)s %(message)s",
)
log = logging.getLogger("otpmail.server")


# ─────────────────────────────────────────────────────────────────────────────

class RelayServer:
    def __init__(
        self,
        host: str       = DEFAULT_HOST,
        port: int       = DEFAULT_PORT,
        certfile: str   = "server.crt",
        keyfile: str    = "server.key",
    ) -> None:
        self.host     = host
        self.port     = port
        self.certfile = certfile
        self.keyfile  = keyfile

        # username → {ed25519_pubkey:b64, kem_pubkey:b64, binding_sig:b64}
        self.users: Dict[str, Dict] = {}

        # username → list of queued envelope dicts
        self.queue: Dict[str, List[Dict]] = {}

        # username → asyncio.StreamWriter (authenticated, online clients)
        self.online: Dict[str, asyncio.StreamWriter] = {}

        # Generate a fresh Ed25519 server identity each run (signs user bindings)
        self._srv_priv, self._srv_pub = generate_identity_keypair()
        log.info("Server public key: %s", self._fingerprint(self._srv_pub))

    # ── Utilities ─────────────────────────────────────────────────────────────

    @staticmethod
    def _fingerprint(key: bytes) -> str:
        h = hashlib.sha256(key).hexdigest()
        return ":".join(h[i:i+4] for i in range(0, 16, 4))

    def _sign_binding(self, username: str, ed25519_pub: bytes, kem_pub: bytes) -> str:
        data = username.encode() + ed25519_pub + kem_pub
        return base64.b64encode(sign_data(self._srv_priv, data)).decode()

    # ── Framing ───────────────────────────────────────────────────────────────

    @staticmethod
    async def _send(writer: asyncio.StreamWriter, msg: Any) -> None:
        data   = json.dumps(msg).encode("utf-8")
        frame  = len(data).to_bytes(4, "big") + data
        writer.write(frame)
        await writer.drain()

    @staticmethod
    async def _recv(reader: asyncio.StreamReader, timeout: float = READ_TIMEOUT) -> Optional[Dict]:
        try:
            hdr  = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
            size = int.from_bytes(hdr, "big")
            if size == 0 or size > MAX_FRAME_SIZE:
                return None
            raw = await asyncio.wait_for(reader.readexactly(size), timeout=timeout)
            return json.loads(raw.decode("utf-8"))
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, json.JSONDecodeError,
                UnicodeDecodeError, ConnectionResetError):
            return None

    # ── Message queue maintenance ─────────────────────────────────────────────

    def _expire_queue(self) -> None:
        now = time.time()
        for user in list(self.queue):
            self.queue[user] = [
                m for m in self.queue[user]
                if now - m.get("queued_at", 0) < MSG_QUEUE_TTL
            ]

    # ── Connection handler ────────────────────────────────────────────────────

    async def handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        peer      = writer.get_extra_info("peername")
        auth_user: Optional[str] = None
        log.info("Connection from %s", peer)

        try:
            # ── Handshake ────────────────────────────────────────────────────
            msg = await self._recv(reader, timeout=CHALLENGE_TIMEOUT)
            if not msg:
                return

            t = msg.get("type")

            if t == "REGISTER":
                await self._handle_register(reader, writer, msg)
                return

            if t == "HELLO":
                auth_user = await self._handle_auth(reader, writer, msg)
                if not auth_user:
                    return
            else:
                await self._send(writer, {"type": "ERROR", "reason": "Expected HELLO or REGISTER"})
                return

            # ── Authenticated session loop ────────────────────────────────────
            self.online[auth_user] = writer
            log.info("Session open: %s", auth_user)

            # Deliver any queued messages immediately
            self._expire_queue()
            backlog = self.queue.get(auth_user, [])
            if backlog:
                await self._send(writer, {"type": "QUEUED_MESSAGES", "messages": backlog})

            while True:
                msg = await self._recv(reader)
                if msg is None:
                    break
                await self._dispatch(writer, auth_user, msg)

        except Exception as exc:
            log.exception("Unhandled error for %s: %s", peer, exc)
        finally:
            if auth_user and auth_user in self.online:
                del self.online[auth_user]
                log.info("Session closed: %s", auth_user)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    # ── Registration ──────────────────────────────────────────────────────────

    async def _handle_register(self, reader, writer, msg: Dict) -> None:
        username    = str(msg.get("username", "")).strip()
        ed25519_b64 = str(msg.get("ed25519_pubkey", ""))
        kem_b64     = str(msg.get("kem_pubkey", ""))

        def err(reason: str):
            return self._send(writer, {"type": "REGISTER_ERR", "reason": reason})

        if not username or not ed25519_b64 or not kem_b64:
            await err("Missing required fields")
            return
        if len(username) > USERNAME_MAX_LEN or not username.isalnum():
            await err("Username must be alphanumeric, max 32 characters")
            return
        if username in self.users:
            await err("Username already registered")
            return

        try:
            ed_bytes  = base64.b64decode(ed25519_b64)
            kem_bytes = base64.b64decode(kem_b64)
            if len(ed_bytes) != 32 or len(kem_bytes) != 32:
                raise ValueError()
        except Exception:
            await err("Invalid public key format (expected 32-byte base64)")
            return

        binding_sig = self._sign_binding(username, ed_bytes, kem_bytes)
        self.users[username] = {
            "ed25519_pubkey": ed25519_b64,
            "kem_pubkey":     kem_b64,
            "binding_sig":    binding_sig,
        }
        self.queue[username] = []
        log.info("Registered: %s", username)

        await self._send(writer, {
            "type":       "REGISTER_OK",
            "server_pub": base64.b64encode(self._srv_pub).decode(),
        })

    # ── Authentication (challenge-response) ───────────────────────────────────

    async def _handle_auth(self, reader, writer, msg: Dict) -> Optional[str]:
        username = str(msg.get("username", "")).strip()
        if not username or username not in self.users:
            await self._send(writer, {"type": "ERROR", "reason": "Unknown user"})
            return None

        nonce = os.urandom(32)
        await self._send(writer, {"type": "CHALLENGE", "nonce": base64.b64encode(nonce).decode()})

        auth = await self._recv(reader, timeout=CHALLENGE_TIMEOUT)
        if not auth or auth.get("type") != "AUTH":
            return None

        try:
            sig      = base64.b64decode(auth.get("signature", ""))
            pub      = base64.b64decode(self.users[username]["ed25519_pubkey"])
            if not verify_signature(pub, nonce, sig):
                raise ValueError()
        except Exception:
            await self._send(writer, {"type": "AUTH_FAIL", "reason": "Invalid signature"})
            return None

        await self._send(writer, {
            "type":       "AUTH_OK",
            "server_pub": base64.b64encode(self._srv_pub).decode(),
        })
        return username

    # ── Dispatch ──────────────────────────────────────────────────────────────

    async def _dispatch(self, writer, username: str, msg: Dict) -> None:
        t = msg.get("type")

        if t == "LOOKUP":
            await self._handle_lookup(writer, msg)

        elif t == "SEND":
            await self._handle_send(writer, username, msg)

        elif t == "FETCH":
            self._expire_queue()
            await self._send(writer, {
                "type":     "FETCH_RESP",
                "messages": self.queue.get(username, []),
            })

        elif t == "ACK":
            ack_ids = set(msg.get("msg_ids", []))
            if username in self.queue:
                self.queue[username] = [
                    m for m in self.queue[username]
                    if m.get("msg_id") not in ack_ids
                ]

        else:
            await self._send(writer, {"type": "ERROR", "reason": f"Unknown type: {t}"})

    async def _handle_lookup(self, writer, msg: Dict) -> None:
        target = str(msg.get("username", "")).strip()
        if target not in self.users:
            await self._send(writer, {"type": "LOOKUP_ERR", "reason": "User not found"})
            return
        u = self.users[target]
        await self._send(writer, {
            "type":          "LOOKUP_RESP",
            "username":      target,
            "ed25519_pubkey": u["ed25519_pubkey"],
            "kem_pubkey":    u["kem_pubkey"],
            "binding_sig":   u["binding_sig"],
            "server_pub":    base64.b64encode(self._srv_pub).decode(),
        })

    async def _handle_send(self, writer, sender: str, msg: Dict) -> None:
        recipient = str(msg.get("to", "")).strip()
        payload   = msg.get("payload")
        msg_id    = str(msg.get("msg_id", ""))

        if not recipient or payload is None or not msg_id:
            await self._send(writer, {"type": "SEND_ERR", "reason": "Missing fields"})
            return
        if recipient not in self.users:
            await self._send(writer, {"type": "SEND_ERR", "reason": "Recipient not found"})
            return

        envelope = {
            "msg_id":    msg_id,
            "from":      sender,
            "payload":   payload,
            "queued_at": time.time(),
        }

        # Try live delivery first
        if recipient in self.online:
            try:
                await self._send(self.online[recipient], {
                    "type":     "DELIVERY",
                    "messages": [envelope],
                })
                log.info("Delivered %s → %s (online)", sender, recipient)
                await self._send(writer, {"type": "SEND_OK", "msg_id": msg_id})
                return
            except Exception:
                pass  # fall through to queue

        self.queue.setdefault(recipient, []).append(envelope)
        log.info("Queued %s → %s (offline)", sender, recipient)
        await self._send(writer, {"type": "SEND_OK", "msg_id": msg_id})

    # ── Main entry point ──────────────────────────────────────────────────────

    async def run(self) -> None:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)

        server = await asyncio.start_server(
            self.handle_client,
            self.host,
            self.port,
            ssl=ctx,
        )
        log.info("OTPMail Relay listening on %s:%d (TLS 1.3)", self.host, self.port)
        log.info(
            "NOTE: For post-quantum transport security, replace the TLS stack "
            "with OQS-OpenSSL or BoringSSL-OQS using X25519Kyber768."
        )
        async with server:
            await server.serve_forever()


# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    p = argparse.ArgumentParser(description="OTPMail Relay Server")
    p.add_argument("--host",  default=DEFAULT_HOST)
    p.add_argument("--port",  type=int, default=DEFAULT_PORT)
    p.add_argument("--cert",  default="server.crt", help="TLS certificate file")
    p.add_argument("--key",   default="server.key",  help="TLS private key file")
    args = p.parse_args()

    if not os.path.exists(args.cert) or not os.path.exists(args.key):
        print(
            f"TLS certificate not found ({args.cert} / {args.key}).\n"
            "Generate one with:  python generate_certs.py"
        )
        raise SystemExit(1)

    relay = RelayServer(args.host, args.port, args.cert, args.key)
    asyncio.run(relay.run())


if __name__ == "__main__":
    main()
