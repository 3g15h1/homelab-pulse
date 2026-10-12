"""Unverified TLS / HTTPS probes used for discovered services (self-signed certs are normal there)."""
import calendar
import ssl
import threading
import time
import unittest
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


if __name__ == "__main__":
    unittest.main()
