import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import auth
import store

ROOT = Path(__file__).resolve().parent.parent


class Clock:
    def __init__(self, t=1_800_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


FAST = 1000   # iterations for speed in tests; the real default is checked separately


class PasswordTests(unittest.TestCase):
    def test_hash_verify(self):
        h = auth.hash_password("correct horse battery", iterations=FAST)
        self.assertTrue(auth.verify_password("correct horse battery", h))

    def test_hash_format(self):
        h = auth.hash_password("x" * 12)
        self.assertTrue(h.startswith("pbkdf2_sha256$600000$"))
        self.assertEqual(len(h.split("$")), 4)
        self.assertNotEqual(h, auth.hash_password("x" * 12))          # salted

    def test_wrong_password(self):
        h = auth.hash_password("right-password", iterations=FAST)
        self.assertFalse(auth.verify_password("wrong-password", h))
        self.assertFalse(auth.verify_password("x", "garbage"))
        self.assertFalse(auth.verify_password("x", None))


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.store = store.Store(":memory:")
        self.sessions = auth.Sessions(self.store, self.clock)

    def test_cookie_valid_expired_tampered(self):
        c = self.sessions.issue()
        self.assertTrue(self.sessions.valid(c))
        exp, role, sid, sig = c.split(".")
        self.assertEqual(role, "admin")
        self.assertFalse(self.sessions.valid(f"{int(exp) + 10}.{role}.{sid}.{sig}"))
        self.assertFalse(self.sessions.valid(f"{exp}.{role}.{sid}.{sig[:-2]}aa"))
        self.assertIsNone(self.sessions.role(f"{exp}.viewer.{sid}.{sig}"))      # can't promote/demote by editing
        self.assertFalse(self.sessions.valid(None))
        self.assertFalse(self.sessions.valid("nonsense"))
        self.clock.t += auth.SESSION_MAX_AGE + 1
        self.assertFalse(self.sessions.valid(c))

    def test_roles(self):
        v = self.sessions.issue("viewer")
        self.assertEqual(self.sessions.role(v), "viewer")
        self.assertFalse(self.sessions.valid(v))                          # valid() means admin
        self.assertEqual(self.sessions.role(self.sessions.issue()), "admin")

    def test_pre_roles_cookie_is_admin(self):
        exp = int(self.clock()) + 100
        payload = f"{exp}.abcdef"
        old = f"{payload}.{self.sessions._sign(payload)}"
        self.assertEqual(self.sessions.role(old), "admin")

    def test_secret_persists_in_store(self):
        c = self.sessions.issue()
        self.assertTrue(auth.Sessions(self.store, self.clock).valid(c))

    def test_rotate_invalidates(self):
        c = self.sessions.issue()
        self.sessions.rotate()
        self.assertFalse(self.sessions.valid(c))
        self.assertTrue(self.sessions.valid(self.sessions.issue()))


class RateLimitTests(unittest.TestCase):
    def test_rate_limit_sixth_blocked_then_recovers(self):
        clock = Clock()
        rl = auth.RateLimiter(limit=5, window=60, clock=clock)
        for _ in range(5):
            self.assertFalse(rl.blocked("10.0.0.9"))
            rl.fail("10.0.0.9")
        self.assertTrue(rl.blocked("10.0.0.9"))
        self.assertFalse(rl.blocked("10.0.0.10"))
        clock.t += 61
        self.assertFalse(rl.blocked("10.0.0.9"))


class AdminTests(unittest.TestCase):
    def test_ensure_admin_from_file_and_missing(self):
        s = store.Store(":memory:")
        self.assertFalse(auth.ensure_admin(s, "/nonexistent/admin-password"))
        f = Path(tempfile.mkdtemp()) / "admin-password"
        f.write_text("initial-pass-123\n")
        self.assertTrue(auth.ensure_admin(s, str(f)))
        self.assertTrue(auth.verify_password("initial-pass-123", s.get("admin")))
        f.write_text("changed-in-file-999\n")                          # file is only read once
        self.assertTrue(auth.ensure_admin(s, str(f)))
        self.assertTrue(auth.verify_password("initial-pass-123", s.get("admin")))

    def test_change_password_min_length(self):
        s = store.Store(":memory:")
        sessions = auth.Sessions(s, Clock())
        old_cookie = sessions.issue()
        with self.assertRaises(ValueError):
            auth.change_password(s, sessions, "short")
        auth.change_password(s, sessions, "a-much-longer-one")
        self.assertTrue(auth.verify_password("a-much-longer-one", s.get("admin")))
        self.assertFalse(sessions.valid(old_cookie))


class PasswdCliTests(unittest.TestCase):
    def test_passwd_cli_generate(self):
        db = str(Path(tempfile.mkdtemp()) / "pulse.db")
        r = subprocess.run([sys.executable, str(ROOT / "pulse" / "passwd.py"), "--generate", "--db", db],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        pw = r.stdout.strip().split()[-1]
        self.assertGreaterEqual(len(pw), 16)
        self.assertTrue(auth.verify_password(pw, store.Store(db).get("admin")))


class AccessTests(unittest.TestCase):
    def setUp(self):
        self.store = store.Store(":memory:")

    def test_viewer_password(self):
        with self.assertRaises(ValueError):
            auth.set_viewer_password(self.store, "short")
        auth.set_viewer_password(self.store, "family-tablet-1")
        self.assertTrue(auth.verify_password("family-tablet-1", self.store.get("viewer")))
        auth.set_viewer_password(self.store, "")
        self.assertIsNone(self.store.get("viewer"))

    def test_view_links(self):
        link, token = auth.create_view_link(self.store, "Kitchen tablet", 100.0)
        self.assertNotIn("hash", link)
        self.assertNotIn(token, str(self.store.get("view_links")))         # only the hash is stored
        self.assertTrue(auth.check_view_token(self.store, token, 1000.0))
        self.assertEqual(auth.list_view_links(self.store)[0]["last_used"], 1000.0)
        self.assertFalse(auth.check_view_token(self.store, token + "x"))
        self.assertFalse(auth.check_view_token(self.store, ""))
        self.assertTrue(auth.revoke_view_link(self.store, link["id"]))
        self.assertFalse(auth.check_view_token(self.store, token))

    def test_proxy_user(self):
        cfg = {"enabled": True, "header": "Remote-User", "from": "192.168.1.5, 10.0.0.0/24", "admins": "Alice"}
        self.assertEqual(auth.proxy_user(cfg, "192.168.1.5", {"Remote-User": "alice"}), ("alice", "admin"))
        self.assertEqual(auth.proxy_user(cfg, "10.0.0.9", {"Remote-User": "bob"}), ("bob", "viewer"))
        self.assertEqual(auth.proxy_user(cfg, "192.168.1.6", {"Remote-User": "alice"}), (None, None))   # not the proxy
        self.assertEqual(auth.proxy_user(cfg, "192.168.1.5", {}), (None, None))
        self.assertEqual(auth.proxy_user(dict(cfg, enabled=False), "192.168.1.5", {"Remote-User": "alice"}), (None, None))
        with self.assertRaises(ValueError):
            auth.parse_networks("192.168.1.0/24, nope")
