"""Self-healing API: status, settings, dry-run test, manual run, overrides, phone 'Run fix' tokens."""
import threading
import unittest

import server
from tests.test_server_auth import Client

H = {"X-Pulse-Request": "1", "Content-Type": "application/json"}


class HealApiTests(unittest.TestCase):
    def setUp(self):
        self.c = server.build_collector({"PULSE_PVE": "demo"})
        self.c.heal.submit = lambda fn: fn()
        for step in (self.c.poll_fast, self.c.poll_slow, self.c.poll_discovery, self.c.poll_probes, self.c.poll_alerts):
            step()
        self.srv = server.serve(self.c, "127.0.0.1", 0)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)
        self.cl = Client(f"http://127.0.0.1:{self.srv.server_address[1]}")

    def signed_in(self):
        self.assertEqual(self.cl.login()[0], 200)
        return self.cl

    def test_heal_status_requires_session(self):
        self.assertEqual(self.cl.req("GET", "/api/heal")[0], 401)
        code, body, _ = self.signed_in().req("GET", "/api/heal")
        self.assertEqual(code, 200)
        self.assertEqual(body["mode"], "auto")                       # demo showcases healing
        self.assertTrue(body["gate"]["ok"])
        rec = {r["id"]: r for r in body["recipes"]}["restart-port-owner"]
        self.assertIn("202:443", rec["matches"])
        self.assertEqual(rec["mode"], "default")
        self.assertIn("history", body)

    def test_heal_settings_put_validates(self):
        cl = self.signed_in()
        self.assertEqual(cl.req("PUT", "/api/heal/settings", {"mode": "ask", "recipes": {"restart-port-owner": "off"}})[0], 200)
        self.assertEqual(self.c.settings_loader()["heal"], {"mode": "ask", "recipes": {"restart-port-owner": "off"}})
        self.assertEqual(cl.req("PUT", "/api/heal/settings", {"mode": "yolo"})[0], 400)
        self.assertEqual(self.c.settings_loader()["alerts"]["down_after_s"], 180)        # rest untouched

    def test_test_endpoint_dry_runs(self):
        code, body, _ = self.signed_in().req("POST", "/api/heal/test", {"recipe_id": "restart-port-owner", "check_id": "202:443"})
        self.assertEqual(code, 200)
        self.assertEqual(body["steps"][0]["argv"], ["systemctl", "restart", "truenas.service"])
        self.assertEqual(self.c.heal.gate.calls, [])

    def test_manual_run(self):
        code, body, _ = self.signed_in().req("POST", "/api/heal/run", {"recipe_id": "restart-port-owner", "check_id": "202:443"})
        self.assertEqual(code, 200)
        self.assertTrue(body["ok"])
        self.assertEqual(len(self.c.heal.gate.calls), 1)
        self.assertEqual(self.c.store.heal_runs()[0]["mode"], "manual")

    def test_override_put(self):
        cl = self.signed_in()
        self.assertEqual(cl.req("PUT", "/api/heal/override/202:443", {"unit": "nas-ui.service"})[0], 200)
        self.assertEqual(self.c.store.get_target("202:443")["override"], {"unit": "nas-ui.service"})
        self.assertEqual(cl.req("PUT", "/api/heal/override/202:443", {"unit": "$(id).service"})[0], 400)
        self.assertEqual(cl.req("PUT", "/api/heal/override/202:443", {"skip": True})[0], 200)
        self.assertEqual(cl.req("PUT", "/api/heal/override/202:443", None)[0], 200)
        self.assertIsNone(self.c.store.get_target("202:443")["override"])
        self.assertEqual(cl.req("PUT", "/api/heal/override/../../x", {"skip": True})[0], 400)

    def ask_token(self):
        import heal
        rec = next(r for r in self.c.heal.recipes() if r["id"] == "restart-port-owner")
        d = heal.Decision(rec, "ask", "202:443", "check:202:443", 202, 443, {"init": "systemd", "unit": "truenas.service"})
        self.c.heal.start(d, self.c.clock())
        return self.c.heal.pending_token("202:443")

    def test_token_single_use_and_bound(self):
        tok = self.ask_token()
        anon = Client(self.cl.base)
        code, body, _ = anon.req("POST", f"/api/heal/run/{tok}", headers={})
        self.assertEqual(code, 200, body)
        self.assertEqual(len(self.c.heal.gate.calls), 1)
        self.assertEqual(anon.req("POST", f"/api/heal/run/{tok}", headers={})[0], 403)        # used
        tok2 = self.ask_token()
        bad = tok2.rsplit(".", 1)[0] + ".0123456789abcdef0123456789abcdef"
        self.assertEqual(anon.req("POST", f"/api/heal/run/{bad}", headers={})[0], 403)        # tampered

    def test_token_rate_limited(self):
        anon = Client(self.cl.base)
        for _ in range(5):
            self.assertEqual(anon.req("POST", "/api/heal/run/nope.1.abc", headers={})[0], 403)
        self.assertEqual(anon.req("POST", "/api/heal/run/nope.1.abc", headers={})[0], 429)


if __name__ == "__main__":
    unittest.main()
