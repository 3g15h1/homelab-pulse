"""Who may see and change what.

- Admin password (settings page): PBKDF2-HMAC-SHA256 (600 000 iterations, 16-byte salt), store key "admin".
- Optional viewer password (view-only, when the dashboard needs a login): same hashing, key "viewer".
- Session cookie: "<expiry>.<role>.<random id>.<HMAC-SHA256(secret, expiry.role.id)>"; the secret lives in
  the store ("cookie_secret") and is replaced when the admin password changes, which signs everyone out.
  Cookies from before roles existed ("<expiry>.<id>.<sig>") are admin sessions.
- View links: random tokens for kiosks and iframes (where cookies don't work), stored as SHA-256
  hashes under "view_links"; each can be revoked.
- A trusted reverse proxy may vouch for a user with a header (Authelia, Authentik, oauth2-proxy), but
  only from the proxy addresses the admin listed.
"""
import base64
import hashlib
import hmac
import ipaddress
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

    def issue(self, role="admin"):
        payload = f"{int(self.clock()) + SESSION_MAX_AGE}.{role}.{secrets.token_hex(16)}"
        return f"{payload}.{self._sign(payload)}"

    def role(self, cookie):
        """'admin', 'viewer' or None."""
        try:
            parts = cookie.split(".")
            if len(parts) == 3:                      # pre-1.6 cookie: admin
                exp, sid, sig = parts
                role, payload = "admin", f"{exp}.{sid}"
            else:
                exp, role, sid, sig = parts
                payload = f"{exp}.{role}.{sid}"
            if role not in ("admin", "viewer") or int(exp) <= self.clock():
                return None
            return role if hmac.compare_digest(sig, self._sign(payload)) else None
        except (AttributeError, ValueError):
            return None

    def valid(self, cookie):
        return self.role(cookie) == "admin"

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


# -- viewer password and view links --

def set_viewer_password(store, pw):
    """None or "" removes it."""
    if not pw:
        store.put("viewer", None)
        return
    if len(pw) < MIN_PASSWORD:
        raise ValueError(f"the password needs at least {MIN_PASSWORD} characters")
    store.put("viewer", hash_password(pw))


def _token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def create_view_link(store, name, now):
    """-> (link without its secret, token). The token is shown once and only its hash is kept."""
    links = store.get("view_links") or []
    if len(links) >= 20:
        raise ValueError("at most 20 view links; revoke one first")
    token = secrets.token_urlsafe(24)
    link = {"id": secrets.token_hex(4), "name": name, "created": now, "hash": _token_hash(token), "last_used": None}
    store.put("view_links", links + [link])
    return {k: v for k, v in link.items() if k != "hash"}, token


def list_view_links(store):
    return [{k: v for k, v in x.items() if k != "hash"} for x in store.get("view_links") or []]


def revoke_view_link(store, link_id):
    links = store.get("view_links") or []
    keep = [x for x in links if x["id"] != link_id]
    store.put("view_links", keep)
    return len(keep) != len(links)


def check_view_token(store, token, now=None):
    if not token or len(token) > 100:
        return False
    h = _token_hash(token)
    links = store.get("view_links") or []
    for x in links:
        if hmac.compare_digest(x["hash"], h):
            if now is not None and (x.get("last_used") or 0) < now - 300:     # don't write on every poll
                x["last_used"] = now
                store.put("view_links", links)
            return True
    return False


# -- trusted reverse proxy --

def parse_networks(text):
    """"192.168.1.10, 10.0.0.0/24" -> [ip_network]. Raises ValueError on a bad entry."""
    return [ipaddress.ip_network(part.strip(), strict=False) for part in (text or "").split(",") if part.strip()]


def proxy_user(cfg, client_ip, headers):
    """(user, role) when a trusted proxy vouches for a user, else (None, None). `cfg`: settings
    access.proxy. The header is ignored unless the request comes from one of the listed proxies."""
    if not cfg.get("enabled") or not cfg.get("header"):
        return None, None
    try:
        ip = ipaddress.ip_address(client_ip)
        if not any(ip in net for net in parse_networks(cfg.get("from"))):
            return None, None
    except ValueError:
        return None, None
    user = (headers.get(cfg["header"]) or "").strip()
    if not user or len(user) > 128:
        return None, None
    admins = {a.strip().lower() for a in (cfg.get("admins") or "").split(",") if a.strip()}
    return user, "admin" if user.lower() in admins else "viewer"
