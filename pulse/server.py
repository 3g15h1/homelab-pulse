#!/usr/bin/env python3
"""Homelab Pulse: a live, self-discovering map of a Proxmox homelab. Python stdlib only.

Routes:  /  (UI, ?embed hides header/footer)   /api/state   /api/stream (SSE)
         /api/history/<vmid|node name>   /healthz
Config comes from the environment (see env.example) and the optional overrides file.
"""
import json
import logging
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import collect
import demo
import discover
import probes
import sources

HERE = Path(__file__).resolve().parent
STATIC = HERE / "static"
CONTENT_TYPES = {".html": "text/html; charset=utf-8", ".svg": "image/svg+xml",
                 ".webmanifest": "application/manifest+json", ".js": "text/javascript"}
log = logging.getLogger("pulse")


def _read_secret(path):
    try:
        return Path(path).read_text().strip() or None
    except OSError:
        return None


def build_collector(env=os.environ):
    pve_mode = env.get("PULSE_PVE", "demo")
    ca = env.get("PULSE_PVE_CA", "/etc/homelab-pulse/pve-ca.pem")
    ov = env.get("PULSE_OVERRIDES", "/etc/homelab-pulse/overrides.json")
    if pve_mode != "live":
        net = demo.DemoNet()
        return collect.Collector(demo.DemoPve(), "demo", net, probe_fn=net.probe, overrides_path=ov, ca_path=ca)
    host = env.get("PULSE_PVE_HOST")
    if not host:
        sys.exit("PULSE_PVE=live needs PULSE_PVE_HOST (the IP of a Proxmox node)")
    token = _read_secret(env.get("PULSE_PVE_TOKEN_FILE", "/etc/homelab-pulse/pve-token"))
    if not token:
        sys.exit("PULSE_PVE=live but the token file is missing or empty")
    pve = sources.PveClient(host, int(env.get("PULSE_PVE_PORT", 8006)), token, ca, env.get("PULSE_PVE_TLS_NAME") or None)
    return collect.Collector(pve, "live", discover.Net(), probe_fn=probes.run, overrides_path=ov, ca_path=ca)


def make_handler(collector):
    class Handler(BaseHTTPRequestHandler):
        server_version = "pulse"
        sys_version = ""

        def log_message(self, fmt, *args):
            log.debug("%s " + fmt, self.client_address[0], *args)

        def _send(self, code, body, ctype="application/json", cache="no-store"):
            if isinstance(body, (dict, list)):
                body = json.dumps(body, separators=(",", ":")).encode()
            elif isinstance(body, str):
                body = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", cache)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def do_HEAD(self):
            self.do_GET()

        def do_GET(self):
            path = self.path.split("?", 1)[0]
            if path == "/":
                path = "/index.html"
            if path == "/api/state":
                return self._send(200, collector.snapshot())
            if path == "/api/stream":
                return self._stream()
            if path == "/healthz":
                src = collector.snapshot()["sources"]
                ok = all(s["ok"] is not False for s in src.values())
                return self._send(200 if ok else 503, {"ok": ok, "sources": src})
            if path.startswith("/api/history/"):
                key = path[len("/api/history/"):]
                hist = collector.history_for(int(key) if key.isdigit() else key) if "/" not in key else None
                return self._send(200, hist) if hist else self._send(404, {"error": "unknown"})
            f = (STATIC / path.lstrip("/")).resolve()
            if f.parent == STATIC and f.is_file() and f.suffix in CONTENT_TYPES:
                return self._send(200, f.read_bytes(), CONTENT_TYPES[f.suffix], "no-cache")
            return self._send(404, {"error": "not found"})

        def _stream(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()
            seen = -1
            try:
                while True:
                    with collector.cond:
                        collector.cond.wait_for(lambda: collector.version != seen, timeout=15)
                        changed = collector.version != seen
                    if changed:
                        snap = collector.snapshot()
                        seen = snap["version"]
                        self.wfile.write(b"data: " + json.dumps(snap, separators=(",", ":")).encode() + b"\n\n")
                    else:
                        self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, TimeoutError):
                pass

    return Handler


def serve(collector, host="0.0.0.0", port=80):
    server = ThreadingHTTPServer((host, port), make_handler(collector))
    server.daemon_threads = True
    return server


def main():
    logging.basicConfig(level=os.environ.get("PULSE_LOG", "INFO"), format="%(levelname)s %(message)s")
    collector = build_collector()
    collector.start()
    port = int(os.environ.get("PULSE_PORT", 80))
    server = serve(collector, os.environ.get("PULSE_BIND", "0.0.0.0"), port)
    log.info("homelab-pulse on :%d (proxmox=%s)", port, collector.sources["pve"]["mode"])
    server.serve_forever()


if __name__ == "__main__":
    main()
