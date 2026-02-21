# OTPMail — Encrypted One-Time Pad Messenger

A Python implementation of the OTP Messaging System spec, featuring:

- **Ed25519** identity keypairs (authentication, signing)
- **X25519 ECDH** KEM for OTP delivery (see *Post-Quantum Notes* below)
- **One-time pad** encryption: `os.urandom` pages, one page per message, never reused
- **HMAC-SHA256** per-message authentication (first 32 bytes of each page = HMAC key)
- **AES-256-GCM** encrypted local vault, key derived via **scrypt**
- **TLS 1.3** transport to the relay server
- **48-hour auto-deletion** for unsaved messages (runs on open + every 30 min)
- **Curses TUI** — full terminal UI, no external GUI dependencies

---

## Quick Start

### 1. Install dependencies

```bash
pip install cryptography
```

### 2. Generate TLS certificates (relay server only)

```bash
python generate_certs.py
# Outputs: server.crt, server.key
```

### 3. Start the relay server

```bash
python server.py --cert server.crt --key server.key
# Listening on 0.0.0.0:4433 (TLS 1.3)
```

### 4. Register Alice (first terminal)

```bash
python client.py --register --server 127.0.0.1:4433
# Enter username: alice
# Set vault password: ...
```

### 5. Register Bob (second terminal)

```bash
python client.py --register --server 127.0.0.1:4433 --vault ~/.otpmail/bob.enc
# Enter username: bob
```

### 6. Start clients and exchange OTP

```bash
# Alice's terminal
python client.py --server 127.0.0.1:4433

# Bob's terminal
python client.py --server 127.0.0.1:4433 --vault ~/.otpmail/bob.enc
```

In Alice's client, press **A** to add contact → type `bob`.
Bob receives the OTP bundle automatically when he fetches (F) or the background
thread polls.

Bob then adds Alice back the same way so the outgoing pages are set up in both
directions, and messaging begins.

---

## TUI Key Reference

| Key           | Panel            | Action                                      |
|---------------|------------------|---------------------------------------------|
| `Tab` / `←→`  | Either           | Switch between Contacts and Messages panels |
| `↑` / `↓`     | Contacts         | Move contact selection                      |
| `↑` / `↓`     | Messages         | Scroll message history                      |
| `Enter`       | Messages (input) | Send typed message                          |
| `A`           | Contacts         | Add contact (initiates OTP exchange)        |
| `D`           | Contacts         | Delete contact and all their OTP pages      |
| `F`           | Either           | Fetch queued messages from relay now        |
| `S`           | Messages         | Toggle SAVED flag on last message           |
| `P`           | Either           | Show remaining OTP page count               |
| `?`           | Either           | Show help screen                            |
| `Q`           | Either           | Quit                                        |
| `ESC`         | Messages         | Clear compose buffer                        |
| `Backspace`   | Messages         | Delete character                            |

---

## Architecture

```
otpmail/
├── crypto_utils.py   Cryptographic primitives (Ed25519, X25519, OTP, AES-GCM, HMAC)
├── vault.py          AES-256-GCM encrypted local storage (identity keys, OTP, messages)
├── server.py         Async relay server (asyncio + TLS)
├── client.py         Client: RelayClient + OTPMailCore + CursesApp (TUI)
├── generate_certs.py Self-signed TLS certificate generator
└── requirements.txt
```

### OTP Page Structure

```
[ 0:32  ]  HMAC-SHA256 key   (32 bytes)
[32:4096]  Encryption pad    (4064 bytes  ≡  max message length 4060 B after length prefix)
```

### Message Encryption

1. Encode message as UTF-8, prepend 4-byte big-endian length.
2. Zero-pad payload to 4064 bytes.
3. XOR with pad portion of the page.
4. Compute HMAC-SHA256 over ciphertext using page's HMAC key.
5. Transmit `{ page_index, ciphertext, hmac }`.

### OTP Exchange (contact setup)

1. Fetch contact's public keys from relay; verify server binding signature.
2. Generate 500 outgoing + 500 incoming OTP pages (`os.urandom`).
3. Encrypt the "their copy" pages via ephemeral X25519 ECDH → HKDF-SHA256 → AES-256-GCM.
4. Send encrypted bundle to contact via relay (relay sees only ciphertext).
5. Store our pages in vault.

### Vault Format

```
[16 B scrypt salt][12 B AES-GCM nonce][ciphertext + 16 B GCM tag]
```
Plaintext is a UTF-8 JSON document. All binary values are base64-encoded inside
the JSON.  Writes are atomic (`.tmp` rename).

---

## Post-Quantum Notes

This implementation uses **X25519** at the application layer for OTP delivery
and standard **TLS 1.3** for transport.  Both are vulnerable to a sufficiently
powerful quantum computer running Shor's algorithm.

For full post-quantum security, replace:

| Component          | Current        | PQ Replacement             |
|--------------------|----------------|----------------------------|
| Application KEM    | X25519         | Kyber768 (`liboqs-python`) |
| TLS cipher suite   | TLS 1.3 / X25519 | X25519Kyber768 (OQS-OpenSSL or BoringSSL-OQS) |

The `crypto_utils.py` module is structured so that `generate_kem_keypair`,
`kem_encapsulate`, and `kem_decapsulate` can be replaced with Kyber equivalents
with minimal changes to the rest of the codebase.

**Ed25519** (Schnorr-family) and **AES-256-GCM** are both considered
quantum-resistant: Ed25519 only needs a key-size bump to Ed448 for stronger
resistance; AES-256 requires Grover's algorithm doubling the effective search
space to 128-bit, which remains impractical.

---

## Known Limitations (per spec)

- **Local machine trust**: key material in memory is accessible to root and
  processes running with the same UID. A hardware security element (HSM/TPM/SE)
  would mitigate this.
- **No remote revocation**: if a device is stolen, all OTP pages on that device
  are compromised. Share a new OTP bundle over a new channel.
- **Secure deletion is best-effort**: SSDs with wear-levelling may retain data
  in sectors inaccessible to the OS. Full-disk encryption (e.g., LUKS) is a
  recommended complement.
- **Relay trust for key lookup**: the relay's binding signature is *not*
  verified against an independent CA. Out-of-band fingerprint verification
  (compare `pubkey_fingerprint(contact_ed25519_pub)` in person or via voice)
  is the correct mitigation.
- **Message signing**: individual relay envelopes are not currently signed with
  the sender's Ed25519 key (the relay authenticates the session; per-message
  signing is a TODO for defence-in-depth).
