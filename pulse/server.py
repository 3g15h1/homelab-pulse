#!/usr/bin/env python3
"""Homelab Pulse: a live, self-discovering map of a Proxmox homelab. Python stdlib only.

Routes (viewers):  /  (UI, ?embed hides header/footer)  /api/state  /api/stream (SSE)
                   /api/history/<vmid|node>  /api/rrd/<vmid|node>?range=  /api/uptime
                   Open to everyone unless the dashboard needs a login (settings: access.dashboard); then
                   a session cookie, a view link (?token=) or a trusted proxy's user header is needed.
Routes (open):     /settings  /login  /api/session  /api/login  /api/logout  /healthz (just ok/not ok behind a login)
Routes (admin):    /api/settings /api/test-notify /api/deliveries /api/mutes /api/password /api/access/…
                   /api/alerts/<key>/clear  (writes also need the X-Pulse-Request header)
Config comes from the environment (see env.example) and the optional overrides file.
"""
import json
import logging
import os
import re
import socket
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import alerts
import auth
import collect
import demo
import discover
import gate_client
import heal as heal_mod
import recipes as recipes_mod
import notify
import probes
import settings as settings_mod
import sources
import store as store_mod

HERE = Path(__file__).resolve().parent
STATIC = HERE / "static"
CONTENT_TYPES = {".html": "text/html; charset=utf-8", ".svg": "image/svg+xml",
                 ".webmanifest": "application/manifest+json", ".js": "text/javascript",
                 ".png": "image/png"}
log = logging.getLogger("pulse")
MAX_BODY = 64 * 1024
HEALTH_SOURCES = ("pve", "probes", "discovery")
COOKIE = "pulse_session"
MUTE_TARGET = re.compile(r"(check|guest|node|warn|backup|source):[\w.:/@-]{1,120}")


def _read_secret(path):
    try:
        return Path(path).read_text().strip() or None
    except OSError:
        return None


def _guess_url(port):
    """http://<this container's LAN address>/ for links in notifications (no packet is sent)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sk:
            sk.connect(("1.1.1.1", 80))
            ip = sk.getsockname()[0]
    except OSError:
        ip = "localhost"
    return f"http://{ip}{'' if port == 80 else f':{port}'}/"


def build_collector(env=os.environ):
    pve_mode = env.get("PULSE_PVE", "demo")
    ca = env.get("PULSE_PVE_CA", "/etc/homelab-pulse/pve-ca.pem")
    ov = env.get("PULSE_OVERRIDES", "/etc/homelab-pulse/overrides.json")
    public_url = env.get("PULSE_PUBLIC_URL") or _guess_url(int(env.get("PULSE_PORT", 80)))
    if pve_mode != "live":
        st = store_mod.Store(":memory:")
        st.put("admin", auth.hash_password("demo", iterations=1000))
        net = demo.DemoNet()
        st.put("config", {"heal": {"mode": "auto", "recipes": {}}})      # the demo shows healing in action
        mini = demo.DemoPve(seed=11, nodes=demo.MINI_NODES, guests=demo.MINI_GUESTS, cluster=None)
        pve = sources.MultiPve(demo.DemoPve(), [sources.ExtraHost("mini", 1, mini)])
        c = collect.Collector(pve, "demo", net, probe_fn=net.probe, overrides_path=ov, ca_path=ca,
                              store=st, notifier=notify.Notifier(st, public_url),
                              heal=heal_mod.HealEngine(demo.DemoGate(net), st))
        c.demo, c.admin_ready = True, True
        return c
    host = env.get("PULSE_PVE_HOST")
    if not host:
        sys.exit("PULSE_PVE=live needs PULSE_PVE_HOST (the IP of a Proxmox node)")
    token = _read_secret(env.get("PULSE_PVE_TOKEN_FILE", "/etc/homelab-pulse/pve-token"))
    if not token:
        sys.exit("PULSE_PVE=live but the token file is missing or empty")
    db = env.get("PULSE_DB") or str(Path(env.get("STATE_DIRECTORY", "/var/lib/homelab-pulse").split(":")[0]) / "pulse.db")
    st = store_mod.Store(db)
    primary = sources.PveClient(host, int(env.get("PULSE_PVE_PORT", 8006)), token, ca, env.get("PULSE_PVE_TLS_NAME") or None)
    extras, errors = sources.load_hosts(env.get("PULSE_PVE_HOSTS_DIR", "/etc/homelab-pulse/hosts"))
    for name, err in errors:
        log.error("extra Proxmox host %s: %s", name, err)
    pve = sources.MultiPve(primary, extras, errors)
    healer = None
    if env.get("PULSE_HEAL_GATE"):              # set by install.sh --enable-heal
        gate = gate_client.GateClient(env["PULSE_HEAL_GATE"], env.get("PULSE_HEAL_KEY", "/etc/homelab-pulse/heal_key"),
                                      known_hosts=str(Path(db).parent / "heal_known_hosts"))
        healer = heal_mod.HealEngine(gate, st)
    c = collect.Collector(pve, "live", discover.Net(), probe_fn=probes.run, overrides_path=ov, ca_path=ca,
                          store=st, notifier=notify.Notifier(st, public_url), heal=healer)
    c.demo = False
    c.admin_ready = auth.ensure_admin(st, env.get("PULSE_ADMIN_PASSWORD_FILE", "/etc/homelab-pulse/admin-password"))
    return c


def make_handler(collector):
    st = collector.store
    sessions = auth.Sessions(st, collector.clock)
    limiter = auth.RateLimiter(clock=collector.clock)
    token_limiter = auth.RateLimiter(clock=collector.clock)
    demo_mode = getattr(collector, "demo", False)

    class Handler(BaseHTTPRequestHandler):
        server_version = "pulse"
        sys_version = ""

        def log_message(self, fmt, *args):
            log.debug("%s " + fmt, self.client_address[0], *args)

        def _send(self, code, body, ctype="application/json", cache="no-store", cookie=None):
            if isinstance(body, (dict, list)):
                body = json.dumps(body, separators=(",", ":")).encode()
            elif isinstance(body, str):
                body = body.encode()
            self.send_response(code)
            if cookie is not None:
                self.send_header("Set-Cookie", cookie)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", cache)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def do_HEAD(self):
            self.do_GET()

        # -- auth helpers --

        def _cookie_value(self):
            for part in (self.headers.get("Cookie") or "").split(";"):
                k, _, v = part.strip().partition("=")
                if k == COOKIE:
                    return v
            return None

        def _who(self):
            """(role, how): role is 'admin', 'viewer' or None; how is 'session', 'proxy:<user>' or 'link'."""
            role = sessions.role(self._cookie_value())
            if role:
                return role, "session"
            user, role = auth.proxy_user(settings_mod.load(st)["access"]["proxy"], self.client_address[0], self.headers)
            if role:
                return role, f"proxy:{user}"
            token = urllib.parse.parse_qs(self.path.partition("?")[2]).get("token", [None])[0] or self.headers.get("X-Pulse-Token")
            if token and auth.check_view_token(st, token, collector.clock()):
                return "viewer", "link"
            return None, None

        def _signed_in(self):
            return self._who()[0] == "admin"

        def _login_required(self):
            return settings_mod.load(st)["access"]["dashboard"] == "login"

        def _need_view(self):
            if self._login_required() and not self._who()[0]:
                raise _HttpError(401, "sign in to view this dashboard")

        def _cookie(self, value, max_age):
            secure = "; Secure" if self.headers.get("X-Forwarded-Proto", "").lower() == "https" else ""
            return f"{COOKIE}={value}; HttpOnly; SameSite=Strict; Path=/; Max-Age={max_age}{secure}"

        def _body(self):
            n = int(self.headers.get("Content-Length") or 0)
            if n > MAX_BODY:
                raise _HttpError(413, "request too large")
            try:
                return json.loads(self.rfile.read(n) or b"{}")
            except (json.JSONDecodeError, UnicodeDecodeError):
                raise _HttpError(400, "invalid JSON") from None

        def _guard(self, need_session=True):
            """Every write needs the X-Pulse-Request header (blocks cross-site forms) and, except
            for login, a valid session."""
            if self.headers.get("X-Pulse-Request") != "1":
                raise _HttpError(403, "missing X-Pulse-Request header")
            if need_session and not self._signed_in():
                raise _HttpError(401, "sign in first")

        def _need_session(self):
            if not self._signed_in():
                raise _HttpError(401, "sign in first")

        def _dispatch(self, fn):
            try:
                fn()
            except _HttpError as e:
                self._send(e.code, {"error": e.message, **e.extra})

        def do_POST(self):
            self._dispatch(self._post)

        def do_PUT(self):
            self._dispatch(self._put)

        def do_DELETE(self):
            self._dispatch(self._delete)

        # -- admin API --

        def _post(self):
            path = urllib.parse.unquote(self.path.split("?", 1)[0])
            m = re.fullmatch(r"/api/heal/run/([A-Za-z0-9_.-]{1,120})", path)
            if m:                                 # "Run fix" from a phone notification: the token is the auth
                ip = self.client_address[0]
                if token_limiter.blocked(ip):
                    raise _HttpError(429, "too many attempts; wait a minute")
                d = collector.heal.redeem(m.group(1), collector.clock()) if collector.heal else None
                if not d:
                    token_limiter.fail(ip)
                    raise _HttpError(403, "this fix link is not valid (used, expired or wrong)")
                collector.heal.start(d, collector.clock())
                return self._send(200, {"ok": True, "text": f"Running: {d.recipe['name']}"})
            if path == "/api/login":
                self._guard(need_session=False)
                ip = self.client_address[0]
                if limiter.blocked(ip):
                    raise _HttpError(429, "too many attempts; wait a minute")
                pw = str(self._body().get("password", ""))
                if not st.get("admin"):
                    raise _HttpError(503, "no admin password set; run homelab-pulse-passwd in the container")
                if auth.verify_password(pw, st.get("admin")):
                    role = "admin"
                elif st.get("viewer") and auth.verify_password(pw, st.get("viewer")):
                    role = "viewer"                # view-only: the dashboard, never the settings
                else:
                    limiter.fail(ip)
                    log.warning("failed sign-in from %s", ip)
                    raise _HttpError(401, "wrong password")
                return self._send(200, {"ok": True, "role": role},
                                  cookie=self._cookie(sessions.issue(role), auth.SESSION_MAX_AGE))
            if path == "/api/logout":
                self._guard(need_session=False)
                return self._send(200, {"ok": True}, cookie=self._cookie("", 0))
            self._guard()
            if path == "/api/access/links":
                name = str(self._body().get("name", "")).strip()[:60] or "View link"
                try:
                    link, token = auth.create_view_link(st, name, collector.clock())
                except ValueError as e:
                    raise _HttpError(400, str(e)) from None
                return self._send(200, {"link": link, "token": token})
            if path == "/api/test-notify":
                channel = self._body().get("channel")
                if channel not in notify.CHANNELS:
                    raise _HttpError(400, f"channel must be one of {', '.join(notify.CHANNELS)}")
                n = alerts.Notification("Test from Homelab Pulse", "If you can read this, alerts will reach you.",
                                        "info", "test", [], collector.clock())
                results = collector.notifier.send_now(n, collector.settings_loader()["notify"], channel=channel)
                return self._send(200, {"results": results})
            if path == "/api/mutes":
                b = self._body()
                target = str(b.get("target", ""))
                if not MUTE_TARGET.fullmatch(target):
                    raise _HttpError(400, "invalid mute target")
                minutes = b.get("minutes")
                if minutes is not None and (not isinstance(minutes, int) or not 1 <= minutes <= 60 * 24 * 30):
                    raise _HttpError(400, "minutes must be 1 to 43200")
                st.add_mute(target, collector.clock() + minutes * 60 if minutes else None, bool(b.get("until_recovered")))
                return self._send(200, {"ok": True})
            if path == "/api/password":
                b = self._body()
                if not auth.verify_password(str(b.get("current", "")), st.get("admin")):
                    raise _HttpError(403, "the current password is wrong")
                try:
                    auth.change_password(st, sessions, str(b.get("new", "")))
                except ValueError as e:
                    raise _HttpError(400, str(e)) from None
                return self._send(200, {"ok": True}, cookie=self._cookie("", 0))
            if path in ("/api/heal/test", "/api/heal/run"):
                if not collector.heal:
                    raise _HttpError(409, "no heal gate installed")
                b = self._body()
                d = collector.heal_decision(str(b.get("recipe_id", "")), str(b.get("check_id", "")),
                                            "manual" if path.endswith("run") else "dry_run")
                if not d:
                    raise _HttpError(400, "unknown recipe or check")
                if path.endswith("test"):
                    try:
                        res = collector.heal.gate.run(d.recipe["id"], d.vmid, d.port or 0, target=d.target, dry_run=True)
                    except gate_client.GateError as e:
                        res = {"ok": False, "error": str(e)}
                    return self._send(200, res)
                return self._send(200, collector.heal.run_now(d))
            m = re.fullmatch(r"/api/alerts/(.{1,200})/clear", path)
            if m:
                collector.clear_alert(m.group(1))
                return self._send(200, {"ok": True})
            raise _HttpError(404, "not found")

        def _put(self):
            path = urllib.parse.unquote(self.path.split("?", 1)[0])
            if path == "/api/access/viewer":
                self._guard()
                try:
                    auth.set_viewer_password(st, str(self._body().get("password") or ""))
                except ValueError as e:
                    raise _HttpError(400, str(e)) from None
                via_session = self._who()[1] == "session"
                sessions.rotate()                  # whoever signed in with the old viewer password is out
                cookie = self._cookie(sessions.issue("admin"), auth.SESSION_MAX_AGE) if via_session else None
                return self._send(200, {"ok": True, "viewer_set": bool(st.get("viewer"))}, cookie=cookie)
            if path == "/api/heal/settings":
                self._guard()
                b = self._body()
                current = settings_mod.load(st)
                try:
                    doc = settings_mod.validate(dict(current, heal={"mode": b.get("mode"), "recipes": b.get("recipes", {})}))
                except settings_mod.SettingsError as e:
                    raise _HttpError(400, e.message, path=e.path) from None
                st.put("config", doc)
                return self._send(200, {"heal": doc["heal"]})
            m = re.fullmatch(r"/api/heal/override/(\d{3,9}:\d{1,5})", path)
            if path.startswith("/api/heal/override/"):
                self._guard()
                if not m:
                    raise _HttpError(400, "invalid check id")
                n = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(n) if n <= MAX_BODY else b""
                b = json.loads(raw) if raw.strip() else None
                if b is None:
                    st.set_override(m.group(1), None)
                elif b == {"skip": True}:
                    st.set_override(m.group(1), b)
                elif set(b) == {"unit"} and (recipes_mod.UNIT_RE.fullmatch(str(b["unit"])) or recipes_mod.SERVICE_RE.fullmatch(str(b["unit"]))):
                    st.set_override(m.group(1), {"unit": b["unit"]})
                elif set(b) == {"container"} and recipes_mod.CONTAINER_RE.fullmatch(str(b["container"])):
                    st.set_override(m.group(1), {"container": b["container"]})
                else:
                    raise _HttpError(400, "override must be {unit}, {container}, {skip: true} or null")
                return self._send(200, {"ok": True})
            if path != "/api/settings":
                raise _HttpError(404, "not found")
            self._guard()
            current = settings_mod.load(st)
            try:
                doc = settings_mod.validate(settings_mod.merge_masked(self._body(), current))
            except settings_mod.SettingsError as e:
                raise _HttpError(400, e.message, path=e.path) from None
            st.put("config", doc)
            self._send(200, {"settings": settings_mod.mask(doc)})

        def _delete(self):
            path = urllib.parse.unquote(self.path.split("?", 1)[0])
            m = re.fullmatch(r"/api/access/links/([0-9a-f]{8})", path)
            if m:
                self._guard()
                if not auth.revoke_view_link(st, m.group(1)):
                    raise _HttpError(404, "no such link")
                return self._send(200, {"ok": True})
            if not path.startswith("/api/mutes/"):
                raise _HttpError(404, "not found")
            self._guard()
            st.remove_mute(path[len("/api/mutes/"):])
            self._send(200, {"ok": True})

        def _get_admin(self, path):
            self._need_session()
            if path == "/api/settings":
                return self._send(200, {"settings": settings_mod.mask(settings_mod.load(st)), "demo": demo_mode})
            if path == "/api/deliveries":
                return self._send(200, {"deliveries": st.deliveries()})
            if path == "/api/access":
                return self._send(200, {"viewer_set": bool(st.get("viewer")), "links": auth.list_view_links(st)})
            return self._send(200, {"mutes": st.list_mutes(collector.clock())})

        def do_GET(self):
            self._dispatch(self._get)

        def _get(self):
            path, _, query = self.path.partition("?")
            if path in ("/api/settings", "/api/deliveries", "/api/mutes", "/api/access"):
                return self._get_admin(path)
            if path == "/api/heal":
                self._need_session()
                return self._send(200, collector.heal_overview())
            if path == "/api/session":
                role, how = self._who()
                return self._send(200, {"signed_in": role == "admin", "role": role, "via": how,
                                        "admin_set": bool(st.get("admin")), "login_required": self._login_required(),
                                        "demo": demo_mode})
            if path in ("/", "/index.html") and self._login_required() and not self._who()[0]:
                return self._redirect("login" + (f"?next={urllib.parse.quote(query)}" if query else ""))
            if path in ("/api/uptime", "/api/state", "/api/stream") or path.startswith(("/api/rrd/", "/api/history/")):
                self._need_view()
            if path == "/api/uptime":
                return self._send(200, collector.uptime())
            if path.startswith("/api/rrd/"):
                key = urllib.parse.unquote(path[len("/api/rrd/"):])
                rng = urllib.parse.parse_qs(query).get("range", ["day"])[0]
                series = collector.rrd_series(int(key) if key.isdigit() else key, rng) if "/" not in key else None
                return self._send(200, series) if series else self._send(404, {"error": "unknown"})
            if path in ("/settings", "/login"):
                path += ".html"
            if path == "/":
                path = "/index.html"
            if path == "/api/state":
                return self._send(200, collector.snapshot())
            if path == "/api/stream":
                return self._stream()
            if path == "/healthz":
                src = collector.snapshot()["sources"]
                ok = all(src[k]["ok"] is not False for k in HEALTH_SOURCES if k in src)
                if self._login_required() and not self._who()[0]:      # error texts name hosts: viewers only
                    src = {k: {"ok": v.get("ok")} for k, v in src.items()}
                return self._send(200 if ok else 503, {"ok": ok, "sources": src})
            if path.startswith("/api/history/"):
                key = urllib.parse.unquote(path[len("/api/history/"):])
                hist = collector.history_for(int(key) if key.isdigit() else key) if "/" not in key else None
                return self._send(200, hist) if hist else self._send(404, {"error": "unknown"})
            f = (STATIC / path.lstrip("/")).resolve()
            if f.parent == STATIC and f.is_file() and f.suffix in CONTENT_TYPES:
                return self._send(200, f.read_bytes(), CONTENT_TYPES[f.suffix], "no-cache")
            return self._send(404, {"error": "not found"})

        def _redirect(self, location):
            self.send_response(302)
            self.send_header("Location", location)         # relative: works under a proxy's sub-path
            self.send_header("Content-Length", "0")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()

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
                    if self._login_required() and not self._who()[0]:
                        break                      # signed out, link revoked or sign-in just turned on
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


class _HttpError(Exception):
    def __init__(self, code, message, **extra):
        super().__init__(message)
        self.code, self.message, self.extra = code, message, extra


def serve(collector, host="0.0.0.0", port=80):
    server = ThreadingHTTPServer((host, port), make_handler(collector))
    server.daemon_threads = True
    return server


def main():
    logging.basicConfig(level=os.environ.get("PULSE_LOG", "INFO"), format="%(levelname)s %(message)s")
    collector = build_collector()
    if not collector.admin_ready:
        log.warning("no admin password: settings are locked until homelab-pulse-passwd is run")
    collector.notifier.start()
    collector.start()
    port = int(os.environ.get("PULSE_PORT", 80))
    server = serve(collector, os.environ.get("PULSE_BIND", "0.0.0.0"), port)
    log.info("homelab-pulse on :%d (proxmox=%s)", port, collector.sources["pve"]["mode"])
    server.serve_forever()


if __name__ == "__main__":
    main()
