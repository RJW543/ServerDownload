#!/usr/bin/env python3
"""
OTPMail Server Administration Tool

Run from the OTPMail directory on the VPS (same dir as otpmail_server.py).

Usage:
    python3 otpmail_admin.py users                  List all registered users
    python3 otpmail_admin.py info <username>         Show details for a user
    python3 otpmail_admin.py remove <username>       Unregister user + delete mailbox
    python3 otpmail_admin.py kick <username>         Unregister user (keeps mailbox)
    python3 otpmail_admin.py mailbox <username>      Show pending messages
    python3 otpmail_admin.py purge <username>        Delete all pending messages

    python3 otpmail_admin.py ban <ip>                Ban an IP address
    python3 otpmail_admin.py unban <ip>              Remove an IP ban
    python3 otpmail_admin.py bans                    List all banned IPs

    python3 otpmail_admin.py status                  Server summary
"""

import sys
import json
import shutil
from pathlib import Path

KEYSTORE_FILE = Path("server_keystore.json")
MAILBOX_DIR = Path("server_mailboxes")
BANLIST_FILE = Path("banned_ips.txt")


def load_keystore() -> dict:
    if KEYSTORE_FILE.exists():
        with open(KEYSTORE_FILE, 'r') as f:
            return json.load(f)
    return {}


def save_keystore(data: dict):
    with open(KEYSTORE_FILE, 'w') as f:
        json.dump(data, f, indent=2)


def load_bans() -> set:
    if BANLIST_FILE.exists():
        return set(line.strip() for line in BANLIST_FILE.read_text().splitlines() if line.strip())
    return set()


def save_bans(bans: set):
    BANLIST_FILE.write_text('\n'.join(sorted(bans)) + '\n')


def mailbox_count(username: str) -> int:
    d = MAILBOX_DIR / username
    if d.exists():
        return len(list(d.glob("*.json")))
    return 0


# ---- Commands ----

def cmd_users():
    ks = load_keystore()
    if not ks:
        print("No registered users.")
        return
    print(f"{'Username':<20} {'Registered':<22} {'Pending':<10} {'Ed25519 (short)'}")
    print("-" * 76)
    for name, info in sorted(ks.items()):
        reg = info.get('registered', '?')[:19]
        pending = mailbox_count(name)
        ed_short = info.get('ed25519', '?')[:16] + '...'
        print(f"{name:<20} {reg:<22} {pending:<10} {ed_short}")
    print(f"\nTotal: {len(ks)} users")


def cmd_info(username: str):
    ks = load_keystore()
    if username not in ks:
        print(f"User '{username}' not found.")
        return
    info = ks[username]
    print(f"Username:      {username}")
    print(f"Registered:    {info.get('registered', '?')}")
    print(f"Ed25519 pub:   {info.get('ed25519', '?')}")
    print(f"X25519 pub:    {info.get('x25519', '?')}")
    print(f"Pending mail:  {mailbox_count(username)}")


def cmd_remove(username: str):
    ks = load_keystore()
    if username not in ks:
        print(f"User '{username}' not found.")
        return
    confirm = input(f"Remove '{username}' and delete their mailbox? (yes/no): ").strip().lower()
    if confirm != 'yes':
        print("Cancelled.")
        return
    del ks[username]
    save_keystore(ks)
    mb = MAILBOX_DIR / username
    if mb.exists():
        shutil.rmtree(mb)
        print(f"Deleted mailbox for '{username}'.")
    print(f"User '{username}' removed. They will need to re-register with new keys.")


def cmd_kick(username: str):
    ks = load_keystore()
    if username not in ks:
        print(f"User '{username}' not found.")
        return
    del ks[username]
    save_keystore(ks)
    print(f"User '{username}' unregistered. Keys wiped — they can re-register on next connect.")


def cmd_mailbox(username: str):
    d = MAILBOX_DIR / username
    if not d.exists() or not list(d.glob("*.json")):
        print(f"No pending messages for '{username}'.")
        return
    for fp in sorted(d.glob("*.json")):
        try:
            with open(fp, 'r') as f:
                m = json.load(f)
            mtype = m.get('type', 'mail')
            sender = m.get('from', '?')
            ts = m.get('timestamp', '?')[:19]
            mid = m.get('id', '?')
            print(f"  [{mid}] {mtype:<5} from {sender:<15} at {ts}")
        except Exception:
            print(f"  [ERROR] {fp.name}")
    print(f"\nTotal: {mailbox_count(username)} pending")


def cmd_purge(username: str):
    d = MAILBOX_DIR / username
    if not d.exists():
        print(f"No mailbox for '{username}'.")
        return
    count = len(list(d.glob("*.json")))
    if count == 0:
        print("Mailbox already empty.")
        return
    confirm = input(f"Delete {count} pending messages for '{username}'? (yes/no): ").strip().lower()
    if confirm != 'yes':
        print("Cancelled.")
        return
    for fp in d.glob("*.json"):
        fp.unlink()
    print(f"Purged {count} messages.")


def cmd_ban(ip: str):
    bans = load_bans()
    if ip in bans:
        print(f"{ip} is already banned.")
        return
    bans.add(ip)
    save_bans(bans)
    print(f"Banned {ip}.")
    print("Takes effect on next connection attempt (no server restart needed).")
    print("To drop an active connection immediately: systemctl restart otpmail")


def cmd_unban(ip: str):
    bans = load_bans()
    if ip not in bans:
        print(f"{ip} is not banned.")
        return
    bans.discard(ip)
    save_bans(bans)
    print(f"Unbanned {ip}.")


def cmd_bans():
    bans = load_bans()
    if not bans:
        print("No banned IPs.")
        return
    print("Banned IPs:")
    for ip in sorted(bans):
        print(f"  {ip}")
    print(f"\nTotal: {len(bans)}")


def cmd_status():
    ks = load_keystore()
    bans = load_bans()
    total_pending = 0
    if MAILBOX_DIR.exists():
        for d in MAILBOX_DIR.iterdir():
            if d.is_dir():
                total_pending += len(list(d.glob("*.json")))

    print("=== OTPMail Server Status ===")
    print(f"Registered users:  {len(ks)}")
    print(f"Pending messages:  {total_pending}")
    print(f"Banned IPs:        {len(bans)}")
    print(f"Keystore:          {KEYSTORE_FILE} ({'exists' if KEYSTORE_FILE.exists() else 'missing'})")
    print(f"Mailbox dir:       {MAILBOX_DIR} ({'exists' if MAILBOX_DIR.exists() else 'missing'})")
    print(f"Ban list:          {BANLIST_FILE} ({'exists' if BANLIST_FILE.exists() else 'not created yet'})")

    id_file = Path("server_identity_ed25519.pem")
    print(f"Server identity:   {id_file} ({'present' if id_file.exists() else 'NOT FOUND'})")


# ---- Main ----

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return

    cmd = sys.argv[1].lower()
    arg = sys.argv[2] if len(sys.argv) >= 3 else None

    commands = {
        'users':   (False, lambda: cmd_users()),
        'status':  (False, lambda: cmd_status()),
        'bans':    (False, lambda: cmd_bans()),
        'info':    (True,  lambda: cmd_info(arg)),
        'remove':  (True,  lambda: cmd_remove(arg)),
        'kick':    (True,  lambda: cmd_kick(arg)),
        'mailbox': (True,  lambda: cmd_mailbox(arg)),
        'purge':   (True,  lambda: cmd_purge(arg)),
        'ban':     (True,  lambda: cmd_ban(arg)),
        'unban':   (True,  lambda: cmd_unban(arg)),
    }

    if cmd not in commands:
        print(f"Unknown command: {cmd}")
        print(__doc__)
        return

    needs_arg, fn = commands[cmd]
    if needs_arg and not arg:
        print(f"Usage: python3 otpmail_admin.py {cmd} <argument>")
        return

    fn()


if __name__ == "__main__":
    main()
