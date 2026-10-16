"""Adding and removing separate Proxmox hosts from the settings page (1.7)."""
import base64
import json
import ssl
import tempfile
import threading
import unittest
from pathlib import Path

import demo
import server
import sources
from tests.test_server_auth import Client

CA = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
TOKEN = "pulse@pve!pulse-remote=0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"


class FakeClient:
    """Stands in for PveClient: answers like a standalone host called `gpu`, or fails as told."""
    fail = None

    def __init__(self, host, port, token, cafile, tls_name=None):
        self.host, self.port, self.token, self.cafile, self.tls_name = host, port, token, cafile, tls_name
        self.ca_text = Path(cafile).read_text() if Path(cafile).exists() else None

    def cluster_status(self):
        if FakeClient.fail:
            raise FakeClient.fail
        return [{"type": "node", "name": "GPU", "ip": self.host, "local": 1}]


class AddHostTests(unittest.TestCase):
    def setUp(self):
        FakeClient.fail = None
        self.dir = Path(tempfile.mkdtemp())
        self.multi = sources.MultiPve(demo.DemoPve(), [])

    def add(self, **kw):
        d = dict({"host": "192.168.1.70", "token": TOKEN, "ca": CA}, **kw.pop("d", {}))
        return sources.add_host(self.multi, self.dir, d, client_factory=FakeClient, **kw)

    def test_add_saves_and_watches(self):
        h = self.add()
        self.assertEqual((h.label, h.slot, h.source), ("gpu", 1, "ui"))
        self.assertEqual(self.multi.slots, {"gpu": 1})
        saved = json.loads((self.dir / "gpu.json").read_text())
        self.assertEqual((saved["host"], saved["tls_name"], saved["token"]), ("192.168.1.70", "GPU", TOKEN))
        self.assertEqual((self.dir / "gpu.json").stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.dir / "gpu-ca.pem").read_text(), CA)
        self.assertEqual([p.name for p in self.dir.iterdir() if p.name.startswith(".test")], [])   # temp CA gone
        hosts, errors = sources.load_hosts(self.dir, source="ui")              # survives a restart
        self.assertEqual(([(x.label, x.slot, x.source) for x in hosts], errors), ([("gpu", 1, "ui")], []))

    def test_slots_are_never_reused(self):
        self.assertEqual(self.add(used_slots=[1, 2]).slot, 3)

    def test_label_and_duplicates(self):
        self.assertEqual(self.add(label="big-box").label, "big-box")
        with self.assertRaises(sources.HostSetupError) as e:
            self.add()
        self.assertIn("already connected", str(e.exception))
        with self.assertRaises(sources.HostSetupError) as e:
            self.add(d={"host": "192.168.1.71"}, label="big-box")
        self.assertIn("already a host called", str(e.exception))
        with self.assertRaises(sources.HostSetupError):
            self.add(d={"host": "192.168.1.72"}, label="Bad Name")

    def test_refuses_the_primary_cluster(self):
        with self.assertRaises(sources.HostSetupError) as e:
            self.add(d={"host": "192.168.1.2"})                                # demo pve1
        self.assertIn("already watches", str(e.exception))

    def test_readable_errors(self):
        for exc, words in ((sources.SourceError("PVE /cluster/status: HTTP 401 authentication failure"), "token was refused"),
                           (ssl.SSLCertVerificationError("certificate verify failed"), "CA certificate doesn't match"),
                           (ConnectionRefusedError(111, "Connection refused"), "can't reach")):
            FakeClient.fail = exc
            with self.assertRaises(sources.HostSetupError) as e:
                self.add()
            self.assertIn(words, str(e.exception))
        self.assertEqual(list(self.dir.glob("*.json")), [])                    # nothing saved on failure
        FakeClient.fail = None
        for d, words in (({"token": "nope"}, "token should look like"), ({"ca": "hello"}, "CA certificate should be"),
                         ({"host": "bad host!"}, "address")):
            with self.assertRaises(sources.HostSetupError) as e:
                self.add(d=d)
            self.assertIn(words, str(e.exception))

    def test_remove(self):
        self.add()
        sources.remove_host(self.multi, self.dir, "gpu")
        self.assertEqual((self.multi.slots, list(self.dir.iterdir())), ({}, []))
        installer = sources.ExtraHost("nas", 5, FakeClient("192.168.1.80", 8006, TOKEN, "/x"))
        self.multi.add(installer)
        with self.assertRaises(sources.HostSetupError) as e:
            sources.remove_host(self.multi, self.dir, "nas")
        self.assertIn("install.sh --remove-host nas", str(e.exception))

    def test_decode_line(self):
        line = "pulse-host:" + base64.urlsafe_b64encode(json.dumps(
            {"host": "192.168.1.70", "port": 8006, "node": "gpu", "token": TOKEN, "ca": CA}).encode()).decode().rstrip("=")
        self.assertEqual(sources.decode_host_line(line)["host"], "192.168.1.70")
        with self.assertRaises(sources.HostSetupError):
            sources.decode_host_line("pulse-host:bm9wZQ")


class HostsApiTests(unittest.TestCase):
    def setUp(self):
        self.c = server.build_collector({"PULSE_PVE": "demo"})
        self.c.poll_fast()
        self.srv = server.serve(self.c, "127.0.0.1", 0)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)
        self.cl = Client(f"http://127.0.0.1:{self.srv.server_address[1]}")

    def test_needs_admin(self):
        self.assertEqual(self.cl.req("GET", "/api/hosts")[0], 401)
        self.assertEqual(self.cl.req("POST", "/api/hosts", {"line": "x"})[0], 401)

    def test_list_add_errors_and_remove(self):
        self.cl.login()
        code, body, _ = self.cl.req("GET", "/api/hosts")
        self.assertEqual((code, body["can_add"], [h["label"] for h in body["hosts"]]), (200, True, ["mini"]))
        code, body, _ = self.cl.req("POST", "/api/hosts", {"line": "pulse-host:garbage"})
        self.assertEqual((code, "damaged" in body["error"]), (400, True))
        code, body, _ = self.cl.req("POST", "/api/hosts", {"host": "127.0.0.1", "port": 1, "token": TOKEN, "ca": CA})
        self.assertEqual(code, 400)
        self.assertIn("can't reach", body["error"])
        self.assertEqual(self.cl.req("POST", "/api/hosts", {"host": "127.0.0.1"})[0], 400)
        self.assertEqual(self.cl.req("DELETE", "/api/hosts/mini")[0], 200)     # the demo host counts as added here
        self.assertEqual(self.cl.req("GET", "/api/hosts")[1]["hosts"], [])
        self.assertEqual(self.cl.req("DELETE", "/api/hosts/mini")[0], 400)


if __name__ == "__main__":
    unittest.main()
