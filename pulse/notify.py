"""Deliver notifications to a generic webhook (JSON POST) and/or an ntfy topic.

Runs on its own thread so the collector never waits on the network. Each delivery is tried 3 times
(5 s and 30 s apart), and the outcome goes into the store's delivery log.
"""
import json
import logging
import queue
import ssl
import threading
import time
import urllib.error
import urllib.request

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
    return f"{cfg['server'].rstrip('/')}/{cfg['topic']}", headers, body.encode()


def _missing(channel, cfg):
    if channel == "webhook" and not cfg.get("url"):
        return "no URL set"
    if channel == "ntfy" and not cfg.get("topic"):
        return "no topic set"
    return None


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

    def send_now(self, n, cfg_notify, channel=None):
        """Send to every enabled channel, or just `channel` (the test button, enabled or not)."""
        results = []
        for name, build in (("webhook", webhook_request), ("ntfy", ntfy_request)):
            c = cfg_notify[name]
            if (channel and channel != name) or (not channel and not c.get("enabled")):
                continue
            problem = _missing(name, c)
            if problem:
                ok, status, err = False, "", problem
            else:
                ok, status, err = self._post(*build(n, c, self.public_url), c.get("insecure", False))
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
