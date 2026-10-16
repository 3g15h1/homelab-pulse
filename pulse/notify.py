"""Deliver notifications: a generic webhook (JSON POST), ntfy, Discord, Telegram, Gotify, Pushover
and email (SMTP).

Runs on its own thread so the collector never waits on the network. Each delivery is tried 3 times
(5 s and 30 s apart), and the outcome goes into the store's delivery log. While the internet is down,
channels that need it are skipped (a self-hosted ntfy/Gotify/mail server on the LAN is still tried).
"""
import ipaddress
import json
import logging
import queue
import smtplib
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from email.message import EmailMessage

import probes

log = logging.getLogger("pulse")

TIMEOUT = 10
BACKOFF = (5, 30)
PRIORITY = {"critical": "5", "warning": "4"}
TAGS = {"critical": "rotating_light", "warning": "warning"}
STATE_TAGS = {"resolve": "white_check_mark", "summary": "bell", "test": "test_tube"}


def _payload(n, url):
    return {"title": n.title, "message": n.message, "severity": n.severity, "state": n.state,
            "items": n.items, "url": url, "ts": n.ts}


def webhook_request(n, cfg, url):
    headers = {"Content-Type": "application/json", "User-Agent": "homelab-pulse", **cfg.get("headers", {})}
    return cfg["url"], headers, json.dumps(_payload(n, url)).encode()


def ntfy_request(n, cfg, url):
    headers = {"User-Agent": "homelab-pulse", "Click": url,
               "Priority": "3" if n.state in ("resolve", "test") else PRIORITY.get(n.severity, "3"),
               "Tags": STATE_TAGS.get(n.state) or TAGS.get(n.severity, "information_source")}
    body = n.message
    try:
        n.title.encode("latin-1")             # HTTP header values must be latin-1
        headers["Title"] = n.title
    except UnicodeEncodeError:
        if not body.startswith(n.title):
            body = f"{n.title}\n{body}"
    if cfg.get("token"):
        headers["Authorization"] = f"Bearer {cfg['token']}"
    action = next((a for it in n.items for a in it.get("actions", ())), None)
    if action:                                  # "Run fix" button (self-healing, ask-first mode)
        headers["Actions"] = f"http, Run fix, {action['url']}, method=POST, clear=true"
    return f"{cfg['server'].rstrip('/')}/{cfg['topic']}", headers, body.encode()


TELEGRAM_API = "https://api.telegram.org"
PUSHOVER_API = "https://api.pushover.net/1/messages.json"
COLOR = {"critical": 0xF87171, "warning": 0xFCD34D, "resolve": 0x4ADE80, "info": 0xA5B4FC}


def _split(n):
    """(title, body without a repeated title line). Single alerts have the title as their first line."""
    body = n.message[len(n.title):].lstrip("\n") if n.message.startswith(n.title) else n.message
    return n.title, body


def _needs_approval(n, url):
    """For channels that can't POST back: where to approve a waiting fix ("" if none)."""
    if any(it.get("actions") for it in n.items):
        return f"A fix is waiting for your approval: {url.rstrip('/')}/settings"
    return ""


def _rest(n, url):
    """Everything after the title: the alert's details and, if any, where to approve a fix."""
    return "\n".join(p for p in (_split(n)[1], _needs_approval(n, url)) if p)


def _level(n):
    return "resolve" if n.state == "resolve" else n.severity if n.severity in COLOR else "info"


def discord_request(n, cfg, url):
    title, _ = _split(n)
    embed = {"title": title[:256], "description": _rest(n, url)[:4000], "color": COLOR[_level(n)], "url": url}
    return cfg["url"], {"Content-Type": "application/json", "User-Agent": "homelab-pulse"}, \
        json.dumps({"username": "Homelab Pulse", "embeds": [embed], "allowed_mentions": {"parse": []}}).encode()


def telegram_request(n, cfg, url):
    text = "\n".join(p for p in (n.title, _rest(n, url), url) if p)
    body = {"chat_id": cfg["chat_id"], "text": text[:4000], "disable_web_page_preview": True,
            "disable_notification": n.state in ("resolve", "test")}
    return f"{TELEGRAM_API}/bot{cfg['token']}/sendMessage", \
        {"Content-Type": "application/json", "User-Agent": "homelab-pulse"}, json.dumps(body).encode()


def gotify_request(n, cfg, url):
    title, _ = _split(n)
    prio = 2 if n.state in ("resolve", "test") else {"critical": 8, "warning": 5}.get(n.severity, 4)
    body = {"title": title, "message": _rest(n, url) or title, "priority": prio,
            "extras": {"client::notification": {"click": {"url": url}}}}
    return f"{cfg['server'].rstrip('/')}/message", \
        {"Content-Type": "application/json", "User-Agent": "homelab-pulse", "X-Gotify-Key": cfg["token"]}, \
        json.dumps(body).encode()


def pushover_request(n, cfg, url):
    title, _ = _split(n)
    prio = -1 if n.state in ("resolve", "test") else {"critical": 1}.get(n.severity, 0)
    form = {"token": cfg["token"], "user": cfg["user"], "title": title[:250], "message": (_rest(n, url) or title)[:1024],
            "priority": str(prio), "url": url, "url_title": "Open Pulse"}
    return PUSHOVER_API, {"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "homelab-pulse"}, \
        urllib.parse.urlencode(form).encode()


def email_message(n, cfg, url):
    title, _ = _split(n)
    m = EmailMessage()
    m["Subject"] = f"[Pulse] {title}"
    m["From"] = cfg["from"]
    m["To"] = ", ".join(a.strip() for a in cfg["to"].split(",") if a.strip())
    m.set_content((_rest(n, url) or title) + f"\n\n{url}\n")
    return m


HTTP = {"webhook": webhook_request, "ntfy": ntfy_request, "discord": discord_request, "telegram": telegram_request,
        "gotify": gotify_request, "pushover": pushover_request}
CHANNELS = ("webhook", "ntfy", "discord", "telegram", "gotify", "pushover", "email")
LABELS = {"webhook": "webhook", "ntfy": "ntfy", "discord": "Discord", "telegram": "Telegram", "gotify": "Gotify",
          "pushover": "Pushover", "email": "email"}
REQUIRED = {"webhook": (("url", "no URL set"),), "ntfy": (("topic", "no topic set"),),
            "discord": (("url", "no webhook URL set"),),
            "telegram": (("token", "no bot token set"), ("chat_id", "no chat ID set")),
            "gotify": (("server", "no server set"), ("token", "no app token set")),
            "pushover": (("user", "no user key set"), ("token", "no app token set")),
            "email": (("host", "no SMTP server set"), ("from", "no sender set"), ("to", "no recipient set"))}


def _missing(channel, cfg):
    return next((msg for key, msg in REQUIRED.get(channel, ()) if not cfg.get(key)), None)


def _is_local(host):
    """True when `host` is a LAN/loopback address (or a name resolving to one)."""
    try:
        addrs = [ipaddress.ip_address(host)]
    except ValueError:
        try:
            addrs = [ipaddress.ip_address(a[4][0]) for a in socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)]
        except (OSError, UnicodeError, ValueError):
            return False
    return bool(addrs) and all(a.is_private or a.is_loopback or a.is_link_local for a in addrs)


def needs_internet(channel, cfg):
    if channel == "webhook":
        return False                 # usually Home Assistant on the LAN; never skipped
    if channel in ("ntfy", "gotify"):
        host = urllib.parse.urlsplit(cfg.get("server") or "").hostname or ""
        return not _is_local(host)
    if channel == "email":
        return not _is_local(cfg.get("host") or "")
    return True                      # Discord, Telegram, Pushover are cloud services


class Notifier:
    def __init__(self, store, public_url, clock=time.time, sleep=time.sleep):
        self.store, self.public_url, self.clock, self.sleep = store, public_url, clock, sleep
        self.queue = queue.Queue()
        self.last = None

    def _post(self, url, headers, body, insecure):
        ctx = probes.insecure_context() if insecure else ssl.create_default_context()
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        last = None
        for attempt in range(len(BACKOFF) + 1):
            if attempt:
                self.sleep(BACKOFF[attempt - 1])
            try:
                with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as r:
                    return True, str(r.status), None
            except urllib.error.HTTPError as e:
                last = (False, str(e.code), f"HTTP {e.code} {e.reason}"[:200])
            except (urllib.error.URLError, OSError, ValueError) as e:
                reason = getattr(e, "reason", e)
                last = (False, "", (str(reason) or type(reason).__name__)[:200])
        return last

    def _smtp(self, msg, cfg):
        last = None
        for attempt in range(len(BACKOFF) + 1):
            if attempt:
                self.sleep(BACKOFF[attempt - 1])
            try:
                ctx = ssl.create_default_context()
                if cfg.get("security") == "ssl":
                    conn = smtplib.SMTP_SSL(cfg["host"], cfg.get("port") or 465, timeout=TIMEOUT, context=ctx)
                else:
                    conn = smtplib.SMTP(cfg["host"], cfg.get("port") or 587, timeout=TIMEOUT)
                with conn:
                    if cfg.get("security", "starttls") == "starttls":
                        conn.starttls(context=ctx)
                    if cfg.get("username"):
                        conn.login(cfg["username"], cfg.get("password", ""))
                    conn.send_message(msg)
                return True, "250", None
            except smtplib.SMTPAuthenticationError as e:
                return False, str(e.smtp_code), "the mail server rejected the username or password"
            except (smtplib.SMTPException, OSError, ssl.SSLError) as e:
                last = (False, str(getattr(e, "smtp_code", "") or ""), (str(e) or type(e).__name__)[:200])
        return last

    def _deliver(self, name, n, c):
        if name == "email":
            return self._smtp(email_message(n, c, self.public_url), c)
        return self._post(*HTTP[name](n, c, self.public_url), c.get("insecure", False))

    def send_now(self, n, cfg_notify, channel=None):
        """Send to every enabled channel, or just `channel` (the test button, enabled or not)."""
        results = []
        for name in CHANNELS:
            c = cfg_notify.get(name) or {}
            if (channel and channel != name) or (not channel and not c.get("enabled")):
                continue
            if n.net_down and needs_internet(name, c):
                res = {"channel": name, "ok": False, "status": "skipped",
                       "error": f"internet is down \u2014 {LABELS[name]} cannot deliver"}
                results.append(res)
                self.last = dict(res, ts=self.clock())
                log.info("%s skipped for %r: internet is down", name, n.title)
                continue
            problem = _missing(name, c)
            if problem:
                ok, status, err = False, "", problem
            else:
                ok, status, err = self._deliver(name, n, c)
            res = {"channel": name, "ok": ok, "status": status, "error": err}
            results.append(res)
            self.last = dict(res, ts=self.clock())
            self.store.add_delivery(self.clock(), name, ok, status, err, n.title)
            if not ok:
                log.warning("notification via %s failed: %s", name, err)
        return results

    def enqueue(self, n, cfg_notify):
        self.queue.put((n, cfg_notify))

    def _worker(self):
        while True:
            n, cfg_notify = self.queue.get()
            try:
                self.send_now(n, cfg_notify)
            except Exception:  # noqa: BLE001 - never let one bad message kill the sender
                log.exception("notification failed")
            finally:
                self.queue.task_done()

    def start(self):
        threading.Thread(target=self._worker, daemon=True, name="notifier").start()
