"""Settings API: sign-in, CSRF header, masking, mutes, password change, test notifications."""
import json
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import server

H = {"X-Pulse-Request": "1", "Content-Type": "application/json"}


class Capture:
    def __init__(self):
        self.requests = []
        cap = self

        class Hd(BaseHTTPRequestHandler):
            def do_POST(self):
                cap.requests.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *a):
                pass

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), Hd)
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}/hook"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()


class Client:
    def __init__(self, base):
        self.base, self.cookie = base, None

    def req(self, method, path, body=None, headers=None, raw=None):
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        hdrs = dict(headers if headers is not None else H)
        if self.cookie:
            hdrs["Cookie"] = self.cookie
        r = urllib.request.Request(self.base + path, data=data, method=method, headers=hdrs)
        try:
            with urllib.request.urlopen(r, timeout=10) as resp:
                code, h, out = resp.status, resp.headers, resp.read()
        except urllib.error.HTTPError as e:
            code, h, out = e.code, e.headers, e.read()
        set_cookie = h.get("Set-Cookie")
        if set_cookie:
            self.cookie = set_cookie.split(";")[0] if "Max-Age=0" not in set_cookie else None
        try:
            return code, json.loads(out) if out else None, h
        except json.JSONDecodeError:
            return code, out, h

    def login(self, pw="demo"):
        return self.req("POST", "/api/login", {"password": pw})


class AuthApiTests(unittest.TestCase):
    def setUp(self):
        self.c = server.build_collector({"PULSE_PVE": "demo"})
        self.c.poll_fast()
        self.c.poll_slow()
        self.c.poll_discovery()
        self.c.poll_probes()
        self.c.poll_alerts()
        self.srv = server.serve(self.c, "127.0.0.1", 0)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.srv.server_address[1]}"
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)
        self.cl = Client(self.base)

    def test_login_logout_flow(self):
        self.assertEqual(self.cl.req("GET", "/api/session")[1], {"signed_in": False, "role": None, "via": None, "admin_set": True,
                                                                  "login_required": False, "demo": True})
        code, body, h = self.cl.login()
        self.assertEqual(code, 200)
        cookie = h["Set-Cookie"]
        for part in ("pulse_session=", "HttpOnly", "SameSite=Strict", "Path=/", "Max-Age=2592000"):
            self.assertIn(part, cookie)
        self.assertNotIn("Secure", cookie)
        self.assertTrue(self.cl.req("GET", "/api/session")[1]["signed_in"])
        self.assertEqual(self.cl.req("POST", "/api/logout")[0], 200)
        self.assertIsNone(self.cl.cookie)
        self.assertFalse(self.cl.req("GET", "/api/session")[1]["signed_in"])

    def test_secure_cookie_behind_https_proxy(self):
        code, _, h = self.cl.req("POST", "/api/login", {"password": "demo"}, headers=dict(H, **{"X-Forwarded-Proto": "https"}))
        self.assertIn("Secure", h["Set-Cookie"])

    def test_wrong_password_and_rate_limit(self):
        for _ in range(5):
            self.assertEqual(self.cl.login("nope")[0], 401)
        self.assertEqual(self.cl.login("demo")[0], 429)

    def test_settings_requires_session(self):
        self.assertEqual(self.cl.req("GET", "/api/settings")[0], 401)
        self.assertEqual(self.cl.req("PUT", "/api/settings", {"alerts": {}})[0], 401)
        self.assertEqual(self.cl.req("GET", "/api/deliveries")[0], 401)
        self.assertEqual(self.cl.req("GET", "/api/mutes")[0], 401)

    def test_put_requires_header(self):
        self.cl.login()
        code, body, _ = self.cl.req("PUT", "/api/settings", {"alerts": {"down_after_s": 60}},
                                    headers={"Content-Type": "application/json"})
        self.assertEqual(code, 403)
        self.assertEqual(self.cl.req("POST", "/api/logout", headers={})[0], 403)
        self.assertEqual(self.cl.req("POST", "/api/login", {"password": "demo"}, headers={})[0], 403)

    def test_settings_roundtrip_and_validation(self):
        self.cl.login()
        code, body, _ = self.cl.req("GET", "/api/settings")
        self.assertEqual(code, 200)
        doc = body["settings"]
        doc["alerts"]["down_after_s"] = 60
        code, body, _ = self.cl.req("PUT", "/api/settings", doc)
        self.assertEqual((code, body["settings"]["alerts"]["down_after_s"]), (200, 60))
        doc["alerts"]["quiet"]["start"] = "25:61"
        code, body, _ = self.cl.req("PUT", "/api/settings", doc)
        self.assertEqual((code, body["path"]), (400, "alerts.quiet.start"))

    def test_settings_never_leaks_secrets(self):
        self.cl.login()
        doc = self.cl.req("GET", "/api/settings")[1]["settings"]
        doc["notify"]["ntfy"].update(topic="lab", token="tk_supersecret_9876")
        doc["notify"]["webhook"].update(url="http://x.invalid/h", headers={"Authorization": "Bearer hush-5555"})
        body = self.cl.req("PUT", "/api/settings", doc)[1]
        self.assertEqual(body["settings"]["notify"]["ntfy"]["token"], "••••9876")
        self.assertEqual(body["settings"]["notify"]["webhook"]["headers"]["Authorization"], "••••5555")
        state = json.dumps(self.cl.req("GET", "/api/state")[1])
        self.assertNotIn("supersecret", state)
        self.assertNotIn("hush", state)
        self.assertNotIn("supersecret", json.dumps(self.cl.req("GET", "/api/settings")[1]))

    def test_put_masked_keeps_secret(self):
        self.cl.login()
        doc = self.cl.req("GET", "/api/settings")[1]["settings"]
        doc["notify"]["ntfy"].update(topic="lab", token="tk_supersecret_9876")
        masked = self.cl.req("PUT", "/api/settings", doc)[1]["settings"]
        masked["alerts"]["down_after_s"] = 120
        self.cl.req("PUT", "/api/settings", masked)
        self.assertEqual(self.c.settings_loader()["notify"]["ntfy"]["token"], "tk_supersecret_9876")

    def test_test_notify_hits_capture_server(self):
        cap = Capture()
        self.addCleanup(cap.srv.shutdown)
        self.cl.login()
        doc = self.cl.req("GET", "/api/settings")[1]["settings"]
        doc["notify"]["webhook"]["url"] = cap.url
        self.cl.req("PUT", "/api/settings", doc)
        code, body, _ = self.cl.req("POST", "/api/test-notify", {"channel": "webhook"})
        self.assertEqual(code, 200)
        self.assertEqual(body["results"][0]["ok"], True)
        self.assertEqual((cap.requests[0]["state"], cap.requests[0]["title"]), ("test", "Test from Homelab Pulse"))
        self.assertEqual(self.cl.req("GET", "/api/deliveries")[1]["deliveries"][0]["channel"], "webhook")
        self.assertEqual(self.cl.req("POST", "/api/test-notify", {"channel": "pigeon"})[0], 400)

    def test_mutes_crud(self):
        self.cl.login()
        self.assertEqual(self.cl.req("POST", "/api/mutes", {"target": "guest:202", "minutes": 60})[0], 200)
        self.assertEqual(self.cl.req("POST", "/api/mutes", {"target": "node:pve2", "until_recovered": True})[0], 200)
        mutes = self.cl.req("GET", "/api/mutes")[1]["mutes"]
        self.assertEqual(sorted(m["target"] for m in mutes), ["guest:202", "node:pve2"])
        self.assertEqual(self.cl.req("DELETE", "/api/mutes/guest%3A202")[0], 200)
        self.assertEqual([m["target"] for m in self.cl.req("GET", "/api/mutes")[1]["mutes"]], ["node:pve2"])
        self.assertEqual(self.cl.req("POST", "/api/mutes", {"target": "<script>"})[0], 400)

    def test_clear_alert(self):
        self.cl.login()
        self.c.stopped[203] = self.c.clock() - 200
        self.c.poll_alerts()
        self.assertIn("guest:203:stopped", self.c.engine.states)
        self.assertEqual(self.cl.req("POST", "/api/alerts/guest%3A203%3Astopped/clear")[0], 200)
        self.assertNotIn("guest:203:stopped", self.c.engine.states)

    def test_password_change_logs_out(self):
        self.cl.login()
        self.assertEqual(self.cl.req("POST", "/api/password", {"current": "wrong", "new": "x" * 12})[0], 403)
        self.assertEqual(self.cl.req("POST", "/api/password", {"current": "demo", "new": "short"})[0], 400)
        self.assertEqual(self.cl.req("POST", "/api/password", {"current": "demo", "new": "a-new-password"})[0], 200)
        self.assertIsNone(self.cl.cookie)
        self.assertEqual(self.cl.login("demo")[0], 401)
        self.assertEqual(self.cl.login("a-new-password")[0], 200)

    def test_body_too_large_413(self):
        self.cl.login()
        code = self.cl.req("PUT", "/api/settings", raw=b"{" + b" " * 70000 + b"}")[0]
        self.assertEqual(code, 413)

    def test_bad_json_400(self):
        self.cl.login()
        self.assertEqual(self.cl.req("PUT", "/api/settings", raw=b"{nope")[0], 400)


class ReadRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.c = server.build_collector({"PULSE_PVE": "demo"})
        cls.c.poll_fast()
        cls.c.poll_slow()
        cls.c.poll_discovery()
        cls.c.poll_probes()
        cls.c.poll_alerts()
        cls.srv = server.serve(cls.c, "127.0.0.1", 0)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.cl = Client(f"http://127.0.0.1:{cls.srv.server_address[1]}")

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def test_rrd_and_uptime_routes(self):
        code, body, _ = self.cl.req("GET", "/api/rrd/200?range=week")
        self.assertEqual(code, 200)
        self.assertEqual(set(body), {"t", "cpu", "mem", "net_in", "net_out"})
        self.assertEqual(self.cl.req("GET", "/api/rrd/pve1?range=day")[0], 200)
        self.assertEqual(self.cl.req("GET", "/api/rrd/200?range=decade")[0], 404)
        self.assertEqual(self.cl.req("GET", "/api/rrd/nosuch?range=day")[0], 404)
        code, body, _ = self.cl.req("GET", "/api/uptime")
        self.assertEqual(code, 200)
        self.assertIn("200:11434", body)

    def test_state_has_attention(self):
        state = self.cl.req("GET", "/api/state")[1]
        self.assertTrue(any(a["key"] == "warn:storage_full:pve2/local-lvm" for a in state["attention"]))
        self.assertNotIn("settings", state)

    def test_settings_page_served(self):
        code, body, h = self.cl.req("GET", "/settings")
        self.assertEqual(code, 200)
        self.assertIn(b"<title>", body)
        self.assertIn("text/html", h["Content-Type"])

    def test_healthz_ignores_alert_delivery(self):
        self.c.sources["alerts"]["ok"] = False
        try:
            self.assertEqual(self.cl.req("GET", "/healthz")[0], 200)
        finally:
            self.c.sources["alerts"]["ok"] = None


if __name__ == "__main__":
    unittest.main()
