"""Who may view the dashboard (1.6): open by default; login, viewer password, view links, trusted proxy."""
import http.client
import threading
import unittest

import server
from tests.test_server_auth import H, Client


class AccessTests(unittest.TestCase):
    def setUp(self):
        self.c = server.build_collector({"PULSE_PVE": "demo"})
        self.c.poll_fast()
        self.c.poll_slow()
        self.srv = server.serve(self.c, "127.0.0.1", 0)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.port = self.srv.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)
        self.admin = Client(self.base)
        self.admin.login()
        self.anon = Client(self.base)

    def raw_get(self, path, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", path, headers=headers or {})
        r = conn.getresponse()
        r.read()
        conn.close()
        return r.status, r.getheader("Location")

    def set_access(self, **access):
        code, body, _ = self.admin.req("GET", "/api/settings")
        doc = body["settings"]
        for k, v in access.items():
            doc["access"][k] = v if not isinstance(v, dict) else dict(doc["access"][k], **v)
        return self.admin.req("PUT", "/api/settings", doc)

    def test_open_by_default(self):
        self.assertEqual(self.anon.req("GET", "/api/state", headers={})[0], 200)
        self.assertEqual(self.raw_get("/")[0], 200)
        self.assertFalse(self.anon.req("GET", "/api/session", headers={})[1]["login_required"])

    def test_login_required_locks_the_dashboard(self):
        self.assertEqual(self.set_access(dashboard="login")[0], 200)
        for path in ("/api/state", "/api/uptime", "/api/history/pve1", "/api/rrd/pve1?range=day", "/api/stream"):
            self.assertEqual(self.anon.req("GET", path, headers={})[0], 401, path)
        self.assertEqual(self.raw_get("/"), (302, "login"))
        self.assertEqual(self.raw_get("/?embed"), (302, "login?next=embed"))
        self.assertEqual(self.raw_get("/index.html")[0], 302)
        for path in ("/login", "/settings", "/icon.svg", "/manifest.webmanifest"):
            self.assertEqual(self.raw_get(path)[0], 200, path)
        code, body, _ = self.anon.req("GET", "/healthz", headers={})
        self.assertEqual(code, 200)
        self.assertEqual(set(body["sources"]["pve"]), {"ok"})               # no error texts for strangers
        self.assertEqual(self.admin.req("GET", "/api/state")[0], 200)       # the admin session still works

    def test_viewer_password_is_view_only(self):
        self.set_access(dashboard="login")
        self.assertEqual(self.admin.req("PUT", "/api/access/viewer", {"password": "short"})[0], 400)
        code, body, _ = self.admin.req("PUT", "/api/access/viewer", {"password": "family-tablet-1"})
        self.assertEqual((code, body["viewer_set"]), (200, True))
        viewer = Client(self.base)
        self.assertEqual(viewer.login("family-tablet-1")[1]["role"], "viewer")
        self.assertEqual(viewer.req("GET", "/api/state")[0], 200)
        self.assertEqual(viewer.req("GET", "/api/settings")[0], 401)
        self.assertEqual(viewer.req("PUT", "/api/settings", {})[0], 401)
        self.assertEqual(viewer.req("GET", "/api/session")[1]["role"], "viewer")
        self.assertEqual(viewer.req("POST", "/api/logout", {})[0], 200)
        self.assertEqual(viewer.req("GET", "/api/state")[0], 401)
        viewer.login("family-tablet-1")
        self.admin.req("PUT", "/api/access/viewer", {"password": ""})
        self.assertEqual(Client(self.base).login("family-tablet-1")[0], 401)
        self.assertEqual(viewer.req("GET", "/api/state")[0], 401)          # removing it signs viewers out
        self.assertEqual(self.admin.req("GET", "/api/settings")[0], 200)   # the admin got a fresh cookie

    def test_view_links(self):
        self.set_access(dashboard="login")
        code, body, _ = self.admin.req("POST", "/api/access/links", {"name": "Kitchen tablet"})
        self.assertEqual(code, 200)
        token, link = body["token"], body["link"]
        self.assertEqual(self.anon.req("GET", f"/api/state?token={token}", headers={})[0], 200)
        self.assertEqual(self.anon.req("GET", "/api/state", headers={"X-Pulse-Token": token})[0], 200)
        self.assertEqual(self.raw_get(f"/?embed&token={token}")[0], 200)
        self.assertEqual(self.anon.req("GET", f"/api/settings?token={token}", headers={})[0], 401)   # never admin
        links = self.admin.req("GET", "/api/access")[1]["links"]
        self.assertEqual([x["name"] for x in links], ["Kitchen tablet"])
        self.assertNotIn("hash", links[0])
        self.assertEqual(self.admin.req("DELETE", f"/api/access/links/{link['id']}")[0], 200)
        self.assertEqual(self.anon.req("GET", f"/api/state?token={token}", headers={})[0], 401)
        self.assertEqual(self.anon.req("POST", "/api/access/links", {"name": "x"})[0], 401)

    def test_revoked_link_ends_an_open_stream(self):
        self.set_access(dashboard="login")
        body = self.admin.req("POST", "/api/access/links", {"name": "tablet"})[1]
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        conn.request("GET", f"/api/stream?token={body['token']}")
        r = conn.getresponse()
        self.assertEqual(r.status, 200)
        self.assertTrue(r.fp.readline().startswith(b"data: "))
        self.admin.req("DELETE", f"/api/access/links/{body['link']['id']}")
        with self.c.cond:                                                  # wake the stream with a change
            self.c.version += 1
            self.c.cond.notify_all()
        r.read()                    # returns only because the server closed the stream (else: timeout error)
        conn.close()

    def test_trusted_proxy_header(self):
        self.set_access(dashboard="login")
        code, body, _ = self.set_access(proxy={"enabled": True, "header": "Remote-User", "from": ""})
        self.assertEqual((code, body["path"]), (400, "access.proxy.from"))
        self.assertEqual(self.set_access(proxy={"enabled": True, "from": "10.9.9.9"})[0], 200)
        self.assertEqual(self.anon.req("GET", "/api/state", headers={"Remote-User": "alice"})[0], 401)   # not the proxy
        self.assertEqual(self.set_access(proxy={"enabled": True, "from": "127.0.0.1", "admins": "alice"})[0], 200)
        self.assertEqual(self.anon.req("GET", "/api/state", headers={"Remote-User": "bob"})[0], 200)
        self.assertEqual(self.anon.req("GET", "/api/settings", headers={"Remote-User": "bob"})[0], 401)
        code, body, _ = self.anon.req("GET", "/api/session", headers={"Remote-User": "alice"})
        self.assertEqual((body["role"], body["via"]), ("admin", "proxy:alice"))
        self.assertEqual(self.anon.req("GET", "/api/settings", headers={"Remote-User": "alice"})[0], 200)
        self.assertEqual(self.anon.req("PUT", "/api/settings", {}, headers={"Remote-User": "alice"})[0], 403)  # still needs X-Pulse-Request


if __name__ == "__main__":
    unittest.main()
