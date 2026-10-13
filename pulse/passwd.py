#!/usr/bin/env python3
"""Set the Homelab Pulse admin password (the one the settings page asks for).

Run as root inside the Pulse container:
    homelab-pulse-passwd              # asks for a new password
    homelab-pulse-passwd --generate   # makes one up and prints it
Signs out every settings session. Restarting the service isn't needed.
"""
import argparse
import getpass
import os
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import auth  # noqa: E402
import store  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--generate", action="store_true", help="generate a random password and print it")
    ap.add_argument("--db", default=os.environ.get("PULSE_DB", "/var/lib/homelab-pulse/pulse.db"))
    a = ap.parse_args()
    if a.generate:
        pw = secrets.token_urlsafe(15)
    else:
        pw = getpass.getpass("New admin password: ")
        if pw != getpass.getpass("Again: "):
            sys.exit("The passwords don't match.")
    s = store.Store(a.db)
    if s.error:
        sys.exit(f"Can't use the database: {s.error}")
    try:
        auth.change_password(s, auth.Sessions(s), pw)
    except ValueError as e:
        sys.exit(str(e))
    if os.geteuid() == 0:            # run as root: keep the files writable for the service user
        for f in (a.db, a.db + "-wal", a.db + "-shm"):
            try:
                os.chown(f, *_pulse_ids())
            except (KeyError, OSError):
                pass
    print(f"Admin password set{': ' + pw if a.generate else '.'}")


def _pulse_ids():
    import pwd
    p = pwd.getpwnam("pulse")
    return p.pw_uid, p.pw_gid


if __name__ == "__main__":
    main()
