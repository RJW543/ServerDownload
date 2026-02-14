#!/usr/bin/env python3
"""
OTPMail Admin Tool — Requires OTPMAIL_ADMIN_PASSPHRASE to run.

Manages users, mailboxes, bans, and server status.
Passphrase is checked via PBKDF2-hashed token stored on first run.

Usage:
    export OTPMAIL_ADMIN_PASSPHRASE='your-admin-passphrase'
    python3 otpmail_admin.py <command> [args...]

Commands:
    users                 List registered users
    info    <username>    Details on a specific user
    remove  <username>    Delete registration + mailbox (requires confirmation)
    kick    <username>    Wipe keys so user must re-register (keeps mailbox)
    ban     <ip>          Ban an IP address
    unban   <ip>          Remove an IP ban
    bans                  List all banned IPs
    mailbox <username>    View pending messages (metadata only)
    purge   <username>    Delete all pending messages
    status                Overall server summary
"""

import os
import sys
import json
import hmac
import secrets
import hashlib
from pathlib import Path
from datetime import datetime

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# ============================================================
#  PATHS (must match otpmail_server.py)
# ============================================================

KEYSTORE_FILE = Path("server_keystore.json")
MAILBOX_DIR = Path("server_mailboxes")
BANLIST_FILE = Path("banned_ips.txt")
ADMIN_HASH_FILE = Path(".admin_passphrase_hash")

MIN_ADMIN_PASSPHRASE = 12

# ============================================================
#  PASSPHRASE AUTHENTICATION
# ============================================================

def _derive_admin_hash(passphrase: str, salt: bytes) -> bytes:
    """Derive a verification hash from the admin passphrase."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32,
        salt=salt, iterations=480_000,
    )
    return kdf.derive(passphrase.encode('utf-8'))


def _verify_passphrase(passphrase: str) -> bool:
    """
    Verify admin passphrase against stored hash.
    On first run, stores the hash for future verification.
    """
    if not passphrase or len(passphrase) < MIN_ADMIN_PASSPHRASE:
        return False

    if ADMIN_HASH_FILE.exists():
        # Verify against stored hash
        blob = ADMIN_HASH_FILE.read_bytes()
        if len(blob) < 16:
            return False
        salt = blob[:16]
        stored_hash = blob[16:]
        computed = _derive_admin_hash(passphrase, salt)
        return hmac.compare_digest(computed, stored_hash)
    else:
        # First run — store the hash
        salt = secrets.token_bytes(16)
        hash_val = _derive_admin_hash(passphrase, salt)
        ADMIN_HASH_FILE.write_bytes(salt + hash_val)
        os.chmod(str(ADMIN_HASH_FILE), 0o600)
        print(f"Admin passphrase hash stored in {ADMIN_HASH_FILE}")
        print("Keep OTPMAIL_ADMIN_PASSPHRASE consistent across sessions.")
        return True


def require_auth():
    """Check passphrase from environment. Exit on failure."""
    passphrase = os.environ.get("OTPMAIL_ADMIN_PASSPHRASE", "")
    if not passphrase:
        print("ERROR: OTPMAIL_ADMIN_PASSPHRASE environment variable is not set.")
        print("Set it with:  export OTPMAIL_ADMIN_PASSPHRASE='your-admin-passphrase'")
        sys.exit(1)
    if len(passphrase) < MIN_ADMIN_PASSPHRASE:
        print(f"ERROR: Passphrase must be at least {MIN_ADMIN_PASSPHRASE} characters.")
        sys.exit(1)
    if not _verify_passphrase(passphrase):
        print("ERROR: Incorrect admin passphrase.")
        sys.exit(1)


# ============================================================
#  DATA ACCESS
# ============================================================

def load_keystore() -> dict:
    if KEYSTORE_FILE.exists():
        with open(KEYSTORE_FILE, 'r') as f:
            return json.load(f)
    return {}


def save_keystore(keys: dict):
    tmp = KEYSTORE_FILE.with_suffix('.tmp')
    with open(tmp, 'w') as f:
        json.dump(keys, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.rename(str(tmp), str(KEYSTORE_FILE))


def load_bans() -> set:
    if not BANLIST_FILE.exists():
        return set()
    return set(
        line.strip() for line in BANLIST_FILE.read_text().splitlines()
        if line.strip())


def save_bans(banned: set):
    tmp = BANLIST_FILE.with_suffix('.tmp')
    with open(tmp, 'w') as f:
        f.write('\n'.join(sorted(banned)) + '\n')
        f.flush()
        os.fsync(f.fileno())
    os.rename(str(tmp), str(BANLIST_FILE))


def user_mailbox_dir(username: str) -> Path:
    return MAILBOX_DIR / username


def count_mailbox(username: str) -> int:
    d = user_mailbox_dir(username)
    if not d.exists():
        return 0
    return len(list(d.glob("*.json")))


def list_mailbox(username: str) -> list:
    d = user_mailbox_dir(username)
    if not d.exists():
        return []
    msgs = []
    for fp in sorted(d.glob("*.json")):
        try:
            with open(fp, 'r') as f:
                m = json.load(f)
                msgs.append(m)
        except Exception:
            pass
    return msgs


# ============================================================
#  COMMANDS
# ============================================================

def cmd_users():
    keys = load_keystore()
    if not keys:
        print("No registered users.")
        return
    print(f"{'Username':<20} {'Registered':<22} {'Pending':<8}")
    print("-" * 52)
    for username, data in sorted(keys.items()):
        reg = data.get('registered', '?')[:19]
        pending = count_mailbox(username)
        print(f"{username:<20} {reg:<22} {pending:<8}")
    print(f"\nTotal: {len(keys)} users")


def cmd_info(username: str):
    keys = load_keystore()
    if username not in keys:
        print(f"User '{username}' not found.")
        return
    data = keys[username]
    print(f"Username:    {username}")
    print(f"Registered:  {data.get('registered', '?')}")
    print(f"Ed25519 pub: {data.get('ed25519', '?')[:16]}...")
    print(f"X25519 pub:  {data.get('x25519', '?')[:16]}...")
    print(f"Pending:     {count_mailbox(username)} messages")


def cmd_remove(username: str):
    keys = load_keystore()
    if username not in keys:
        print(f"User '{username}' not found.")
        return
    confirm = input(f"Remove user '{username}' and all data? [y/N]: ").strip().lower()
    if confirm != 'y':
        print("Cancelled.")
        return
    del keys[username]
    save_keystore(keys)
    # Remove mailbox
    d = user_mailbox_dir(username)
    if d.exists():
        import shutil
        shutil.rmtree(d)
    print(f"Removed user '{username}'.")


def cmd_kick(username: str):
    keys = load_keystore()
    if username not in keys:
        print(f"User '{username}' not found.")
        return
    confirm = input(
        f"Kick '{username}'? This wipes their keys so they must re-register. "
        f"Mailbox is kept. [y/N]: ").strip().lower()
    if confirm != 'y':
        print("Cancelled.")
        return
    del keys[username]
    save_keystore(keys)
    print(f"Kicked '{username}'. They must re-register on next connect.")


def cmd_ban(ip: str):
    banned = load_bans()
    banned.add(ip)
    save_bans(banned)
    print(f"Banned {ip}. Takes effect on next connection attempt.")


def cmd_unban(ip: str):
    banned = load_bans()
    if ip not in banned:
        print(f"{ip} is not banned.")
        return
    banned.discard(ip)
    save_bans(banned)
    print(f"Unbanned {ip}.")


def cmd_bans():
    banned = load_bans()
    if not banned:
        print("No banned IPs.")
        return
    print(f"Banned IPs ({len(banned)}):")
    for ip in sorted(banned):
        print(f"  {ip}")


def cmd_mailbox(username: str):
    msgs = list_mailbox(username)
    if not msgs:
        print(f"No pending messages for '{username}'.")
        return
    print(f"Pending messages for '{username}' ({len(msgs)}):")
    print(f"  {'ID':<14} {'Type':<6} {'From':<20} {'Timestamp':<22}")
    print("  " + "-" * 64)
    for m in msgs:
        print(f"  {m.get('id', '?'):<14} {m.get('type', 'mail'):<6} "
              f"{m.get('from', '?'):<20} {m.get('timestamp', '?')[:19]:<22}")


def cmd_purge(username: str):
    msgs = list_mailbox(username)
    if not msgs:
        print(f"No pending messages for '{username}'.")
        return
    confirm = input(
        f"Purge {len(msgs)} messages from '{username}'s mailbox? [y/N]: "
    ).strip().lower()
    if confirm != 'y':
        print("Cancelled.")
        return
    d = user_mailbox_dir(username)
    purged = 0
    for fp in d.glob("*.json"):
        fp.unlink()
        purged += 1
    print(f"Purged {purged} messages.")


def cmd_status():
    keys = load_keystore()
    banned = load_bans()
    total_pending = 0
    if MAILBOX_DIR.exists():
        for d in MAILBOX_DIR.iterdir():
            if d.is_dir():
                total_pending += len(list(d.glob("*.json")))
    print("OTPMail Server Status")
    print("-" * 30)
    print(f"Registered users:  {len(keys)}")
    print(f"Pending messages:  {total_pending}")
    print(f"Banned IPs:        {len(banned)}")
    print(f"Keystore:          {'exists' if KEYSTORE_FILE.exists() else 'missing'}")
    print(f"Mailbox dir:       {'exists' if MAILBOX_DIR.exists() else 'missing'}")


# ============================================================
#  MAIN
# ============================================================

COMMANDS = {
    'users':   (cmd_users, 0),
    'info':    (cmd_info, 1),
    'remove':  (cmd_remove, 1),
    'kick':    (cmd_kick, 1),
    'ban':     (cmd_ban, 1),
    'unban':   (cmd_unban, 1),
    'bans':    (cmd_bans, 0),
    'mailbox': (cmd_mailbox, 1),
    'purge':   (cmd_purge, 1),
    'status':  (cmd_status, 0),
}


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        print("Usage: python3 otpmail_admin.py <command> [args...]")
        print(f"Commands: {', '.join(sorted(COMMANDS.keys()))}")
        sys.exit(1)

    # Authenticate before any operation
    require_auth()

    cmd_name = sys.argv[1]
    func, nargs = COMMANDS[cmd_name]

    if nargs > 0 and len(sys.argv) < 2 + nargs:
        print(f"'{cmd_name}' requires {nargs} argument(s).")
        sys.exit(1)

    args = sys.argv[2:2 + nargs]
    func(*args)


if __name__ == "__main__":
    main()
