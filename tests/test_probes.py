"""Unverified TLS / HTTPS probes used for discovered services (self-signed certs are normal there)."""
import calendar
import socket
import ssl
import threading
import time
import unittest
import unittest.mock
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import probes

FIX = Path(__file__).parent / "fixtures"


def der_of(name):
    return ssl.PEM_cert_to_DER_cert((FIX / f"{name}.crt").read_text())


class TlsServer:
    """Local HTTPS server presenting a fixture certificate."""

    def __init__(self, name):
        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                body = b"<title>Fixture</title>"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(FIX / f"{name}.crt", FIX / f"{name}.key")
        self.srv.socket = ctx.wrap_socket(self.srv.socket, server_side=True)
        self.port = self.srv.server_address[1]

    def __enter__(self):
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *a):
        self.srv.shutdown()
        self.srv.server_close()


class CertInfoTests(unittest.TestCase):
    def test_cert_info_reads_cn_and_expiry(self):
        info = probes.cert_info(der_of("selfsigned"))
        self.assertEqual(info["cn"], "pulse-test")
        want = ssl.cert_time_to_seconds("Oct  7 21:35:47 2046 GMT")
        self.assertEqual(info["not_after"], want)

    def test_cert_info_expired_fixture(self):
        info = probes.cert_info(der_of("expired"))
        self.assertEqual(info["cn"], "pulse-expired")
        self.assertEqual(info["not_after"], calendar.timegm((2020, 1, 2, 0, 0, 0)))

    def test_cert_info_garbage_raises_value_error(self):
        with self.assertRaises(ValueError):
            probes.cert_info(b"\x30\x03\x02\x01")


class InsecureProbeTests(unittest.TestCase):
    def test_tls_insecure_reads_expiry_from_self_signed(self):
        with TlsServer("selfsigned") as s:
            r = probes.probe_tls("127.0.0.1", s.port, verify=False)
            verified = probes.probe_tls("127.0.0.1", s.port, sni="pulse-test")
        self.assertTrue(r.ok, r.detail)
        self.assertTrue(r.detail.startswith("cert ") and r.detail.endswith(" days left"), r.detail)
        self.assertFalse(verified.ok)            # the default (verified) path still rejects it

    def test_tls_insecure_expired_is_down(self):
        with TlsServer("expired") as s:
            r = probes.probe_tls("127.0.0.1", s.port, verify=False, now=time.time())
        self.assertFalse(r.ok)
        self.assertRegex(r.detail, r"^cert -\d+ days left$")

    def test_http_insecure_accepts_self_signed(self):
        with TlsServer("selfsigned") as s:
            url = f"https://127.0.0.1:{s.port}/"
            self.assertTrue(probes.probe_http(url, insecure=True).ok)
            self.assertFalse(probes.probe_http(url).ok)

    def test_run_passes_verify_and_insecure(self):
        with TlsServer("selfsigned") as s:
            self.assertTrue(probes.run({"kind": "tls", "host": "127.0.0.1", "port": s.port, "verify": False}).ok)
            self.assertTrue(probes.run({"kind": "http", "url": f"https://127.0.0.1:{s.port}/", "insecure": True}).ok)




class PingProbeTests(unittest.TestCase):
    def test_ping_localhost_ok(self):
        r = probes.probe_ping("127.0.0.1")
        self.assertTrue(r.ok, r.detail)
        self.assertIsNotNone(r.latency_ms)

    def test_ping_unroutable_fails(self):
        r = probes.probe_ping("192.0.2.1", timeout=1.0)  # TEST-NET-1, unroutable
        self.assertFalse(r.ok)
        self.assertTrue(r.detail)

    def test_ping_missing_binary_fails_cleanly(self):
        with unittest.mock.patch("probes.subprocess.run", side_effect=FileNotFoundError("ping")):
            r = probes.probe_ping("127.0.0.1")
        self.assertFalse(r.ok)
        self.assertIn("ping", r.detail)

    def test_run_dispatches_ping(self):
        r = probes.run({"kind": "ping", "host": "127.0.0.1"})
        self.assertTrue(r.ok, r.detail)


def _canned_dns_reply(qname, ip, qid=0x1234):
    import struct
    _, query = probes.build_query(qname, qid=qid)
    question = query[12:]
    header = struct.pack(">HHHHHH", qid, 0x8180, 1, 1, 0, 0)
    answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + socket.inet_aton(ip)
    return header + question + answer


def _fixed_qid():
    real = probes.build_query
    return unittest.mock.patch("probes.build_query",
                               lambda qname, qid=0x1234, qtype=1: real(qname, qid=qid, qtype=qtype))


class ResolveProbeTests(unittest.TestCase):
    def _mock_socket(self, reply):
        ms = unittest.mock.MagicMock()
        ms.__enter__.return_value.recvfrom.return_value = (reply, ("127.0.0.1", 53))
        return unittest.mock.patch("socket.socket", return_value=ms)

    def test_resolve_answers(self):
        reply = _canned_dns_reply("example.com", "93.184.216.34")
        with _fixed_qid(), self._mock_socket(reply):
            r = probes.probe_resolve("127.0.0.1", "example.com")
        self.assertTrue(r.ok, r.detail)
        self.assertIn("93.184.216.34", r.detail)

    def test_resolve_garbage_reply_fails(self):
        with self._mock_socket(b"\x00\x01garbage"):
            r = probes.probe_resolve("127.0.0.1", "example.com")
        self.assertFalse(r.ok)

    def test_resolve_no_server_fails(self):
        r = probes.probe_resolve("127.0.0.1", "example.com", timeout=1.0)  # nothing on :53
        self.assertFalse(r.ok)

    def test_run_dispatches_resolve(self):
        reply = _canned_dns_reply("example.com", "93.184.216.34")
        with _fixed_qid(), self._mock_socket(reply):
            r = probes.run({"kind": "resolve", "server": "127.0.0.1", "qname": "example.com"})
        self.assertTrue(r.ok, r.detail)




class _FakeResp:
    def __init__(self, status, body):
        self.status, self._body = status, body
    def read(self, n=-1):
        return self._body[:n] if n and n > 0 else self._body
    def __enter__(self):
        return self
    def __exit__(self, *a):
        return False


class _FakeOpener:
    def __init__(self, resp):
        self.resp = resp
    def open(self, req, timeout=None):
        return self.resp


class HttpContainsTests(unittest.TestCase):
    def _probe(self, body, contains, status=200):
        with unittest.mock.patch.object(probes, "_opener", _FakeOpener(_FakeResp(status, body))):
            return probes.probe_http("http://x/", contains=contains)

    def test_contains_match(self):
        r = self._probe(b"<html><title>Dashboard</title></html>", "Dashboard")
        self.assertTrue(r.ok, r.detail)

    def test_contains_mismatch(self):
        r = self._probe(b"<html><title>Other</title></html>", "Dashboard")
        self.assertFalse(r.ok)
        self.assertIn("Dashboard", r.detail)

    def test_contains_ignores_binary_junk(self):
        r = self._probe(b"\xff\xfe\x00binary", "Dashboard")
        self.assertFalse(r.ok)  # must not raise on undecodable bytes

    def test_no_contains_unchanged(self):
        r = self._probe(b"anything", None)
        self.assertTrue(r.ok)

    def test_run_passes_contains(self):
        with unittest.mock.patch.object(probes, "_opener",
                                        _FakeOpener(_FakeResp(200, b"hello world"))):
            r = probes.run({"kind": "http", "url": "http://x/", "contains": "world"})
        self.assertTrue(r.ok, r.detail)
        with unittest.mock.patch.object(probes, "_opener",
                                        _FakeOpener(_FakeResp(200, b"hello world"))):
            r = probes.run({"kind": "http", "url": "http://x/", "contains": "nope"})
        self.assertFalse(r.ok)

if __name__ == "__main__":
    unittest.main()
