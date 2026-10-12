import json
import threading
import unittest
import urllib.error
import urllib.request

import server


class BuildTests(unittest.TestCase):
    def test_live_requires_host_and_token(self):
        with self.assertRaisesRegex(SystemExit, "PULSE_PVE_HOST"):
            server.build_collector({"PULSE_PVE": "live"})
        with self.assertRaisesRegex(SystemExit, "token"):
            server.build_collector({"PULSE_PVE": "live", "PULSE_PVE_HOST": "10.0.0.2",
                                    "PULSE_PVE_TOKEN_FILE": "/nonexistent"})

    def test_demo_is_default(self):
        c = server.build_collector({})
        self.assertEqual(c.sources["pve"]["mode"], "demo")


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.c = server.build_collector({"PULSE_PVE": "demo"})
        cls.c.poll_fast()
        cls.c.poll_slow()
        cls.c.poll_discovery()
        cls.c.poll_probes()
        cls.srv = server.serve(cls.c, "127.0.0.1", 0)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.srv.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def get(self, path):
        try:
            with urllib.request.urlopen(self.base + path, timeout=5) as r:
                return r.status, r.headers, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.headers, e.read()

    def test_index_and_state(self):
        code, _, body = self.get("/?embed")
        self.assertEqual(code, 200)
        self.assertIn(b"<title>", body)
        state = json.loads(self.get("/api/state")[2])
        self.assertEqual([n["name"] for n in state["nodes"]], ["pve1", "pve2"])
        self.assertIn("discovery", state["sources"])

    def test_healthz_and_history(self):
        self.assertEqual(self.get("/healthz")[0], 200)
        code, _, body = self.get("/api/history/200")
        self.assertEqual((code, len(json.loads(body)["cpu"])), (200, 1))
        self.assertEqual(self.get("/api/history/pve2")[0], 200)
        self.assertEqual(self.get("/api/history/../etc")[0], 404)

    def test_history_unknown_node_404(self):
        self.assertEqual(self.get("/api/history/nosuchnode")[0], 404)
        self.assertEqual(self.get("/api/history/999")[0], 404)

    def test_healthz_fails_when_discovery_fails(self):
        self.c.sources["discovery"]["ok"] = False
        try:
            self.assertEqual(self.get("/healthz")[0], 503)
        finally:
            self.c.sources["discovery"]["ok"] = True

    def test_static_cannot_escape(self):
        self.assertEqual(self.get("/../server.py")[0], 404)
        self.assertEqual(self.get("/%2e%2e/server.py")[0], 404)

    def test_sse_sends_a_snapshot(self):
        with urllib.request.urlopen(self.base + "/api/stream", timeout=5) as r:
            self.assertEqual(r.headers["Content-Type"], "text/event-stream")
            line = r.readline()
        self.assertTrue(line.startswith(b"data: {"))
