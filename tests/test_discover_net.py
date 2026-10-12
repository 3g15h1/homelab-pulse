"""Real Net.fingerprint against listeners started here (HTTP, HTTPS, UDP DNS, SSH-style banner)."""
import socket
import ssl
import struct
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import discover

FIX = Path(__file__).parent / "fixtures"


def http_server(pages, tls=False):
    """pages: {path: (status, headers, body)}"""
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            status, headers, body = pages.get(self.path, (404, {}, b"nope"))
            self.send_response(status)
            for k, v in headers.items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    if tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(FIX / "selfsigned.crt", FIX / "selfsigned.key")
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


class NetTests(unittest.TestCase):
    def setUp(self):
        self.net = discover.Net(timeout=1.0, fp_timeout=2.0)

    def serve(self, *a, **kw):
        srv = http_server(*a, **kw)
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        return srv.server_address[1]

    def test_http_title_identifies_app(self):
        port = self.serve({"/": (200, {"Server": "nginx"}, b"<html><head><title>\n Paperless-ngx sign in </title>")})
        self.assertTrue(self.net.connect("127.0.0.1", port))
        f = self.net.fingerprint("127.0.0.1", port)
        self.assertEqual((f.kind, f.scheme, f.product, f.icon), ("http", "http", "Paperless-ngx", "doc"))
        self.assertEqual((f.title, f.server), ("Paperless-ngx sign in", "nginx"))

    def test_follows_one_same_host_redirect(self):
        port = self.serve({"/": (302, {"Location": "/login.html"}, b""),
                           "/login.html": (200, {}, b"<title>AdGuard Home</title>")})
        self.assertEqual(self.net.fingerprint("127.0.0.1", port).product, "AdGuard Home")

    def test_does_not_follow_offsite_redirect(self):
        port = self.serve({"/": (302, {"Location": "http://example.com/x"}, b"")})
        f = self.net.fingerprint("127.0.0.1", port)
        self.assertEqual(f.kind, "http")
        self.assertEqual(f.product, "Web app")

    def test_generic_title_is_not_a_product(self):
        for title in (b"Login", b"Sign In", b"Welcome", b"Index of /"):
            port = self.serve({"/": (200, {}, b"<title>" + title + b"</title>")})
            self.assertEqual(self.net.fingerprint("127.0.0.1", port).product, "Web app", title)

    def test_unknown_title_becomes_product(self):
        port = self.serve({"/": (200, {}, b"<title>My Thing &amp; Co</title>")})
        f = self.net.fingerprint("127.0.0.1", port)
        self.assertEqual((f.product, f.icon), ("My Thing & Co", "globe"))
        self.assertGreaterEqual(f.rank, 100)

    def test_https_self_signed(self):
        port = self.serve({"/": (200, {}, b"<title>Grafana</title>")}, tls=True)
        f = self.net.fingerprint("127.0.0.1", port)
        self.assertEqual((f.kind, f.scheme, f.product, f.cert_cn), ("tls", "https", "Grafana", "pulse-test"))
        self.assertGreater(f.cert_days, 3000)

    def test_dns_responder(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        self.addCleanup(sock.close)

        def answer():
            msg, addr = sock.recvfrom(512)
            qend = 12 + msg[12:].index(b"\0") + 5
            ans = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + bytes(4)
            sock.sendto(msg[:2] + struct.pack(">HHHHH", 0x8180, 1, 1, 0, 0) + msg[12:qend] + ans, addr)

        threading.Thread(target=answer, daemon=True).start()
        f = self.net.fingerprint("127.0.0.1", 53, dns_port=sock.getsockname()[1])
        self.assertEqual((f.kind, f.product, f.icon), ("dns", "DNS + ad blocking", "shield"))

    def test_banner_service(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen()
        self.addCleanup(srv.close)

        def greet():
            c, _ = srv.accept()
            c.sendall(b"SSH-2.0-OpenSSH_9.2p1 Debian\r\n")
            c.close()

        threading.Thread(target=greet, daemon=True).start()
        f = self.net.fingerprint("127.0.0.1", srv.getsockname()[1])
        self.assertEqual(f.kind, "tcp")
        self.assertEqual(f.banner, "SSH-2.0-OpenSSH_9.2p1 Debian")

    def test_non_http_ports_get_no_http_request(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen()
        self.addCleanup(srv.close)
        port, got = srv.getsockname()[1], []

        def silent():                                   # like Redis or Mosquitto: waits for the client
            c, _ = srv.accept()
            c.settimeout(2)
            try:
                got.append(c.recv(100))
            except OSError:
                got.append(b"")
            c.close()

        t = threading.Thread(target=silent, daemon=True)
        t.start()
        f = discover.Net(timeout=1.0, fp_timeout=1.0, no_http={port}).fingerprint("127.0.0.1", port)
        t.join(3)
        self.assertEqual(got, [b""])                    # nothing was sent to it
        self.assertEqual(f.kind, "tcp")

    def test_closed_port(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        self.assertFalse(self.net.connect("127.0.0.1", port))


if __name__ == "__main__":
    unittest.main()
