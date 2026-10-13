"""Admin password and sessions for the settings page. Viewing the dashboard needs neither.

Password: PBKDF2-HMAC-SHA256 (600 000 iterations, 16-byte salt), stored in the store under "admin".
Session cookie: "<expiry>.<random id>.<HMAC-SHA256(secret, expiry.id)>"; the secret lives in the
store ("cookie_secret") and is replaced when the password changes, which signs every session out.
"""
import base64
import hashlib
import hmac
import secrets
import threading
import time
from pathlib import Path

ITERATIONS = 600_000
SESSION_MAX_AGE = 30 * 86400
MIN_PASSWORD = 10


def _b64(b):
    return base64.b64encode(b).decode()


def hash_password(pw, salt=None, iterations=ITERATIONS):
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, iterations)
    return f"pbkdf2_sha256${iterations}${_b64(salt)}${_b64(dk)}"


def verify_password(pw, stored):
    try:
        algo, iters, salt, dk = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        got = hashlib.pbkdf2_hmac("sha256", pw.encode(), base64.b64decode(salt), int(iters))
        return hmac.compare_digest(got, base64.b64decode(dk))
    except (AttributeError, ValueError, TypeError):
        return False


class Sessions:
    def __init__(self, store, clock=time.time):
        self.store, self.clock = store, clock

    def _secret(self):
        s = self.store.get("cookie_secret")
        if not s:
            s = secrets.token_hex(32)
            self.store.put("cookie_secret", s)
        return bytes.fromhex(s)

    def _sign(self, payload):
        return hmac.new(self._secret(), payload.encode(), hashlib.sha256).hexdigest()

    def issue(self):
        payload = f"{int(self.clock()) + SESSION_MAX_AGE}.{secrets.token_hex(16)}"
        return f"{payload}.{self._sign(payload)}"

    def valid(self, cookie):
        try:
            exp, sid, sig = cookie.split(".")
            return int(exp) > self.clock() and hmac.compare_digest(sig, self._sign(f"{exp}.{sid}"))
        except (AttributeError, ValueError):
            return False

    def rotate(self):
        self.store.put("cookie_secret", secrets.token_hex(32))


class RateLimiter:
    """At most `limit` failed logins per IP per `window` seconds."""

    def __init__(self, limit=5, window=60, clock=time.time):
        self.limit, self.window, self.clock = limit, window, clock
        self.fails = {}
        self.lock = threading.Lock()

    def _recent(self, ip):
        now = self.clock()
        self.fails[ip] = [t for t in self.fails.get(ip, ()) if now - t < self.window]
        return self.fails[ip]

    def blocked(self, ip):
        with self.lock:
            return len(self._recent(ip)) >= self.limit

    def fail(self, ip):
        with self.lock:
            self._recent(ip).append(self.clock())


def ensure_admin(store, password_file):
    """True when an admin password is set. The first time, the installer's password file is hashed
    into the store (the file stays so the installer can show it again)."""
    if store.get("admin"):
        return True
    try:
        pw = Path(password_file).read_text().strip()
    except OSError:
        return False
    if not pw:
        return False
    store.put("admin", hash_password(pw))
    return True


def change_password(store, sessions, new):
    if len(new) < MIN_PASSWORD:
        raise ValueError(f"the password needs at least {MIN_PASSWORD} characters")
    store.put("admin", hash_password(new))
    sessions.rotate()
