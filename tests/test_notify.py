import json
import ssl
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import notify
import store
from alerts import Notification

FIX = Path(__file__).parent / "fixtures"


class Capture:
    """Local HTTP(S) server recording requests; answers with the queued status codes (default 200)."""

    def __init__(self, codes=(), tls=False):
        self.requests, self.codes = [], list(codes)
        cap = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                cap.requests.append({"path": self.path, "headers": dict(self.headers), "body": body})
                code = cap.codes.pop(0) if cap.codes else 200
                self.send_response(code)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *a):
                pass

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        if tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(FIX / "selfsigned.crt", FIX / "selfsigned.key")
            self.srv.socket = ctx.wrap_socket(self.srv.socket, server_side=True)
        self.url = f"{'https' if tls else 'http'}://127.0.0.1:{self.srv.server_address[1]}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


def note(title="AdGuard Home on adguard is down", severity="critical", state="fire"):
    return Notification(title, title, severity, state, [{"key": "check:101:80", "title": title, "severity": severity,
                                                         "state": state, "since": 1.0}], 1_800_000_000.0)


def cfg(webhook=None, ntfy=None):
    return {"webhook": dict({"enabled": False, "url": "", "headers": {}, "insecure": False}, **(webhook or {})),
            "ntfy": dict({"enabled": False, "server": "https://ntfy.sh", "topic": "", "token": "", "insecure": False},
                         **(ntfy or {}))}


class NotifyTests(unittest.TestCase):
    def setUp(self):
        self.store = store.Store(":memory:")
        self.sleeps = []
        self.n = notify.Notifier(self.store, "http://192.168.1.16/", sleep=self.sleeps.append)

    def cap(self, *a, **kw):
        c = Capture(*a, **kw)
        self.addCleanup(c.close)
        return c

    def test_webhook_json_and_headers(self):
        c = self.cap()
        res = self.n.send_now(note(), cfg(webhook={"enabled": True, "url": c.url + "/api/webhook/pulse",
                                                   "headers": {"Authorization": "Bearer abc"}}))
        self.assertEqual(res, [{"channel": "webhook", "ok": True, "status": "200", "error": None}])
        r = c.requests[0]
        self.assertEqual(r["path"], "/api/webhook/pulse")
        self.assertEqual(r["headers"]["Authorization"], "Bearer abc")
        self.assertEqual(r["headers"]["Content-Type"], "application/json")
        body = json.loads(r["body"])
        self.assertEqual((body["title"], body["severity"], body["state"], body["url"]),
                         ("AdGuard Home on adguard is down", "critical", "fire", "http://192.168.1.16/"))
        self.assertEqual(body["items"][0]["key"], "check:101:80")
        self.assertEqual(self.store.deliveries()[0]["channel"], "webhook")

    def test_ntfy_headers(self):
        c = self.cap()
        conf = cfg(ntfy={"enabled": True, "server": c.url + "/", "topic": "lab-alerts", "token": "tk_123"})
        for sev, state, prio, tag in (("critical", "fire", "5", "rotating_light"), ("warning", "fire", "4", "warning"),
                                      ("info", "resolve", "3", "white_check_mark")):
            self.n.send_now(note(severity=sev, state=state), conf)
            r = c.requests[-1]
            self.assertEqual(r["path"], "/lab-alerts")
            self.assertEqual((r["headers"]["Priority"], r["headers"]["Tags"]), (prio, tag))
        r = c.requests[0]
        self.assertEqual(r["headers"]["Title"], "AdGuard Home on adguard is down")
        self.assertEqual(r["headers"]["Click"], "http://192.168.1.16/")
        self.assertEqual(r["headers"]["Authorization"], "Bearer tk_123")
        self.assertEqual(r["body"].decode(), "AdGuard Home on adguard is down")

    def test_ntfy_non_ascii_title(self):
        c = self.cap()
        self.n.send_now(note(title="Wärme 🔥 local-lvm full in ~5 days"),
                        cfg(ntfy={"enabled": True, "server": c.url, "topic": "t"}))
        r = c.requests[0]
        self.assertNotIn("Title", r["headers"])
        self.assertTrue(r["body"].decode().startswith("Wärme 🔥 local-lvm"))

    def test_retry_then_success(self):
        c = self.cap(codes=[500, 502])
        res = self.n.send_now(note(), cfg(webhook={"enabled": True, "url": c.url}))
        self.assertTrue(res[0]["ok"])
        self.assertEqual(len(c.requests), 3)
        self.assertEqual(self.sleeps, [5, 30])

    def test_failure_recorded(self):
        res = self.n.send_now(note(), cfg(webhook={"enabled": True, "url": "http://127.0.0.1:9/"}))
        self.assertFalse(res[0]["ok"])
        self.assertIn("refused", res[0]["error"])
        d = self.store.deliveries()[0]
        self.assertEqual((d["ok"], d["channel"]), (False, "webhook"))
        self.assertFalse(self.n.last["ok"])

    def test_http_error_status_recorded(self):
        c = self.cap(codes=[404, 404, 404])
        res = self.n.send_now(note(), cfg(webhook={"enabled": True, "url": c.url}))
        self.assertEqual((res[0]["ok"], res[0]["status"]), (False, "404"))

    def test_disabled_channels_skipped(self):
        self.assertEqual(self.n.send_now(note(), cfg()), [])
        self.assertEqual(self.store.deliveries(), [])

    def test_explicit_channel_for_test_button(self):
        c = self.cap()
        res = self.n.send_now(note(state="test"), cfg(ntfy={"server": c.url, "topic": "t"}), channel="ntfy")
        self.assertTrue(res[0]["ok"])                      # works before the channel is switched on
        self.assertEqual(self.n.send_now(note(), cfg(), channel="ntfy")[0]["error"], "no topic set")

    def test_insecure_flag_allows_self_signed(self):
        c = self.cap(tls=True)
        bad = self.n.send_now(note(), cfg(webhook={"enabled": True, "url": c.url}))
        self.assertFalse(bad[0]["ok"])
        self.assertIn("certificate", bad[0]["error"])
        good = self.n.send_now(note(), cfg(webhook={"enabled": True, "url": c.url, "insecure": True}))
        self.assertTrue(good[0]["ok"])

    def test_background_queue(self):
        c = self.cap()
        self.n.start()
        self.n.enqueue(note(), cfg(webhook={"enabled": True, "url": c.url}))
        self.n.queue.join()
        self.assertEqual(len(c.requests), 1)


if __name__ == "__main__":
    unittest.main()


class ActionTests(unittest.TestCase):
    def setUp(self):
        self.store = store.Store(":memory:")
        self.n = notify.Notifier(self.store, "http://pulse.local/", sleep=lambda s: None)

    def noted(self):
        n = note()
        n.items[0]["actions"] = [{"id": "tok", "title": "Run fix: Restart the service behind the check",
                                  "url": "http://pulse.local/api/heal/run/tok"}]
        return n

    def test_webhook_items_carry_actions(self):
        c = Capture()
        self.addCleanup(c.close)
        self.n.send_now(self.noted(), cfg(webhook={"enabled": True, "url": c.url}))
        body = json.loads(c.requests[0]["body"])
        self.assertEqual(body["items"][0]["actions"][0]["url"], "http://pulse.local/api/heal/run/tok")

    def test_ntfy_actions_header(self):
        c = Capture()
        self.addCleanup(c.close)
        self.n.send_now(self.noted(), cfg(ntfy={"enabled": True, "server": c.url, "topic": "t"}))
        self.assertEqual(c.requests[0]["headers"]["Actions"],
                         "http, Run fix, http://pulse.local/api/heal/run/tok, method=POST, clear=true")
