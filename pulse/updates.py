"""New-release check and the in-place upgrade request.

The check asks GitHub for the latest release of the configured repository (twice a day, can be turned
off on the settings page). Upgrading is done by root, not by Pulse: Pulse writes the wanted release tag
to `update-request` in its state directory, a systemd path unit notices, and `homelab-pulse-update`
(root, installed by install.sh) runs update.sh for exactly that tag, checks that Pulse comes back, rolls
back if it doesn't, and writes the outcome to `update-status.json`.
"""
import json
import logging
import re
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

from version import VERSION

log = logging.getLogger("pulse")
CHECK_EVERY = 12 * 3600
RETRY_AFTER = 3600
TAG = re.compile(r"v(\d{1,4})\.(\d{1,4})\.(\d{1,4})")
UPDATER = "/usr/local/sbin/homelab-pulse-update"


def parse(v):
    """'v1.7.0' or '1.7.0' -> (1, 7, 0); anything else -> None."""
    m = TAG.fullmatch(v if str(v).startswith("v") else f"v{v}")
    return tuple(int(x) for x in m.groups()) if m else None


def newer(latest, current=VERSION):
    a, b = parse(latest or ""), parse(current)
    return bool(a and b and a > b)


def fetch_latest(repo, timeout=10):
    req = urllib.request.Request(f"https://api.github.com/repos/{repo}/releases/latest",
                                 headers={"Accept": "application/vnd.github+json", "User-Agent": f"homelab-pulse/{VERSION}"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        d = json.load(r)
    notes = re.sub(r"\s+", " ", re.sub(r"[*`#]", "", d.get("body") or "")).strip()
    return {"tag": d.get("tag_name"), "name": d.get("name") or d.get("tag_name"), "url": d.get("html_url"),
            "notes": notes[:600], "published": d.get("published_at")}


class Updates:
    def __init__(self, store, repo, state_dir, clock=time.time, fetch=fetch_latest, updater=UPDATER):
        self.store, self.repo, self.clock, self.fetch = store, repo, clock, fetch
        self.state_dir, self.updater = Path(state_dir) if state_dir else None, updater
        self.lock = threading.Lock()

    @property
    def last(self):
        return self.store.get("update_check") or {}

    def due(self, now):
        last = self.last
        wait = RETRY_AFTER if last.get("error") else CHECK_EVERY
        return not last.get("checked") or now - last["checked"] >= wait

    def check(self, force=False):
        """Ask GitHub if due (or forced). Never raises; errors are kept for the settings page."""
        now = self.clock()
        if not self.repo or (not force and not self.due(now)):
            return self.last
        with self.lock:
            try:
                res = dict(self.fetch(self.repo), checked=now, error=None)
            except (urllib.error.URLError, OSError, ValueError) as e:
                res = dict(self.last, checked=now, error=str(getattr(e, "reason", e))[:160])
                log.info("update check failed: %s", res["error"])
            self.store.put("update_check", res)
            return res

    def can_upgrade(self):
        return bool(self.state_dir) and Path(self.updater).exists()

    def status(self):
        try:
            return json.loads((self.state_dir / "update-status.json").read_text()) if self.state_dir else None
        except (OSError, ValueError):
            return None

    def request(self, tag):
        """Ask root to upgrade to `tag` (must be the newer release the check found)."""
        last = self.last
        if not self.can_upgrade():
            raise ValueError("one-click upgrades aren't set up here; run the installer again on the Proxmox host")
        if tag != last.get("tag") or not newer(tag):
            raise ValueError("that isn't the newer release Pulse found; check again first")
        st = self.status()
        if st and st.get("state") == "running" and self.clock() - (st.get("ts") or 0) < 900:
            raise ValueError("an upgrade is already running")
        (self.state_dir / "update-request").write_text(tag + "\n")
        return {"requested": tag}

    def view(self):
        last = self.last
        return {"current": VERSION, "latest": last.get("tag"), "name": last.get("name"), "url": last.get("url"),
                "notes": last.get("notes"), "checked": last.get("checked"), "error": last.get("error"),
                "available": newer(last.get("tag")), "enabled": bool(self.repo), "can_upgrade": self.can_upgrade(),
                "status": self.status()}

    def run(self, enabled, stop):
        """Background loop: check when due while checks are enabled (`enabled()` reads the settings)."""
        while not stop.wait(300):
            try:
                if enabled():
                    self.check()
            except Exception as e:  # noqa: BLE001 - never kill the loop
                log.warning("update check: %s", e)
