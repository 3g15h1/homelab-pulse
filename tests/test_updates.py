"""Release check and one-click upgrades (1.7)."""
import json
import os
import re
import stat
import subprocess
import tempfile
import threading
import unittest
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import server
import store
import updates
from tests.test_server_auth import Client
from version import VERSION

ROOT = Path(__file__).resolve().parent.parent


def bump(v, i=2):
    parts = list(updates.parse(v))
    parts[i] += 1
    return "v" + ".".join(map(str, parts))


class VersionTests(unittest.TestCase):
    def test_version_matches_changelog(self):
        top = re.search(r"^## (\d+\.\d+\.\d+)", (ROOT / "CHANGELOG.md").read_text(), re.M).group(1)
        self.assertEqual(top, VERSION)

    def test_parse_and_newer(self):
        self.assertEqual(updates.parse("v1.10.2"), (1, 10, 2))
        self.assertEqual(updates.parse("1.7.0"), (1, 7, 0))
        self.assertIsNone(updates.parse("v1.7"))
        self.assertIsNone(updates.parse("latest"))
        self.assertTrue(updates.newer("v1.10.0", "1.9.9"))                 # numeric, not text order
        self.assertFalse(updates.newer("v1.7.0", "1.7.0"))
        self.assertFalse(updates.newer(None))


class CheckTests(unittest.TestCase):
    def setUp(self):
        self.st = store.Store(":memory:")
        self.t = [1000.0]
        self.calls = []
        self.dir = Path(tempfile.mkdtemp())
        self.updater = self.dir / "updater"
        self.updater.write_text("#!/bin/sh\n")

    def make(self, answer=None, error=None):
        def fetch(repo):
            self.calls.append(repo)
            if error:
                raise error
            return answer or {"tag": bump(VERSION), "name": "next", "url": "https://example/rel", "notes": "n"}
        return updates.Updates(self.st, "me/pulse", self.dir, clock=lambda: self.t[0], fetch=fetch, updater=str(self.updater))

    def test_checks_twice_a_day_and_retries_errors_sooner(self):
        u = self.make()
        u.check()
        u.check()
        self.assertEqual(len(self.calls), 1)
        self.t[0] += updates.CHECK_EVERY
        u.check()
        self.assertEqual(len(self.calls), 2)
        bad = self.make(error=urllib.error.URLError("no route"))
        self.t[0] += updates.CHECK_EVERY
        res = bad.check()
        self.assertEqual(res["error"], "no route")
        self.assertEqual(res["tag"], bump(VERSION))                         # the last good answer is kept
        self.t[0] += updates.RETRY_AFTER
        bad.check()
        self.assertEqual(len(self.calls), 4)

    def test_view_and_request(self):
        u = self.make()
        u.check()
        v = u.view()
        self.assertEqual((v["current"], v["latest"], v["available"], v["can_upgrade"]), (VERSION, bump(VERSION), True, True))
        with self.assertRaises(ValueError):
            u.request("v0.0.1")                                             # only the release it found
        self.assertEqual(u.request(bump(VERSION)), {"requested": bump(VERSION)})
        self.assertEqual((self.dir / "update-request").read_text().strip(), bump(VERSION))
        (self.dir / "update-status.json").write_text(json.dumps({"state": "running", "ts": self.t[0]}))
        with self.assertRaises(ValueError) as e:
            u.request(bump(VERSION))
        self.assertIn("already running", str(e.exception))

    def test_no_upgrade_without_the_updater(self):
        self.updater.unlink()
        u = self.make()
        u.check()
        self.assertFalse(u.view()["can_upgrade"])
        with self.assertRaises(ValueError) as e:
            u.request(bump(VERSION))
        self.assertIn("installer", str(e.exception))

    def test_not_newer_is_not_available(self):
        u = self.make(answer={"tag": "v" + VERSION, "name": "", "url": "", "notes": ""})
        u.check()
        self.assertFalse(u.view()["available"])

    def test_disabled_repo_never_fetches(self):
        u = updates.Updates(self.st, None, None, fetch=lambda r: self.fail("fetched"))
        u.check(force=True)
        self.assertFalse(u.view()["enabled"])


class Up(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(503)          # up but unhealthy still counts as "answering"
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


class UpdaterScriptTests(unittest.TestCase):
    """homelab-pulse-update with update.sh and systemctl stubbed."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.state, self.app, self.bin = self.d / "state", self.d / "app", self.d / "bin"
        for p in (self.state, self.app / "pulse", self.bin):
            p.mkdir(parents=True)
        (self.app / "pulse" / "version.py").write_text('VERSION = "1.7.0"\n')
        (self.app / "pulse" / "server.py").write_text("")
        for name, body in (("systemctl", 'echo "systemctl $*" >> "$LOGF"'), ("chown", "true")):
            f = self.bin / name
            f.write_text(f"#!/bin/sh\n{body}\n")
            f.chmod(f.stat().st_mode | stat.S_IEXEC)
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), Up)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)

    def run_updater(self, update_sh, port=None, tag="v1.7.1"):
        (self.app / "update.sh").write_text(update_sh)
        (self.d / "env").write_text(f"PULSE_PORT={port or self.srv.server_address[1]}\n")
        (self.state / "update-request").write_text(tag + "\n")
        env = dict(os.environ, PATH=f"{self.bin}:{os.environ['PATH']}", PULSE_STATE=str(self.state), PULSE_APP=str(self.app),
                   PULSE_ENV=str(self.d / "env"), PULSE_UPDATE_TRIES="2", LOGF=str(self.d / "log"))
        r = subprocess.run(["bash", str(ROOT / "homelab-pulse-update")], env=env, capture_output=True, text=True, timeout=60)
        status = json.loads((self.state / "update-status.json").read_text())
        self.assertFalse((self.state / "update-request").exists())
        return r.returncode, status

    SWAP = """set -e
APP={app}
cp -a "$APP" "$APP.prev.tmp"; rm -rf "$APP.prev"; mv "$APP.prev.tmp" "$APP.prev"
echo 'VERSION = "1.7.1"' > "$APP/pulse/version.py"
"""

    def test_success(self):
        code, st = self.run_updater(self.SWAP.format(app=self.app))
        self.assertEqual((code, st["state"], st["tag"]), (0, "ok", "v1.7.1"))
        self.assertIn("1.7.1", (self.app / "pulse" / "version.py").read_text())

    def test_download_failure_changes_nothing(self):
        (self.app.parent / "app.prev" / "pulse").mkdir(parents=True)        # an old leftover copy
        (self.app.parent / "app.prev" / "pulse" / "server.py").write_text("old")
        code, st = self.run_updater("echo 'curl: (6) Could not resolve host' >&2; exit 1\n")
        self.assertEqual((code, st["state"]), (1, "failed"))
        self.assertIn("before anything changed", st["message"])
        self.assertIn("Could not resolve host", st["log"])
        self.assertIn("1.7.0", (self.app / "pulse" / "version.py").read_text())   # not "rolled back" to the leftover

    def test_new_version_not_answering_rolls_back(self):
        code, st = self.run_updater(self.SWAP.format(app=self.app), port=1)
        self.assertEqual((code, st["state"]), (1, "failed"))
        self.assertIn("went back to 1.7.0", st["message"])
        self.assertIn("1.7.0", (self.app / "pulse" / "version.py").read_text())
        self.assertIn("1.7.1", (self.d / "app.failed" / "pulse" / "version.py").read_text())
        self.assertIn("systemctl restart homelab-pulse", (self.d / "log").read_text())

    def test_refuses_anything_but_a_release_tag(self):
        code, st = self.run_updater("echo should-not-run > /dev/null; exit 0\n", tag="main; rm -rf /")
        self.assertEqual((code, st["state"]), (1, "failed"))
        self.assertIn("not a release tag", st["message"])


class UpdateApiTests(unittest.TestCase):
    def test_demo_api(self):
        c = server.build_collector({"PULSE_PVE": "demo"})
        srv = server.serve(c, "127.0.0.1", 0)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        cl = Client(f"http://127.0.0.1:{srv.server_address[1]}")
        self.assertEqual(cl.req("GET", "/api/update")[0], 401)
        cl.login()
        code, body, _ = cl.req("GET", "/api/update")
        self.assertEqual((code, body["current"], body["enabled"]), (200, VERSION, False))
        self.assertEqual(cl.req("POST", "/api/update", {"tag": "v99.0.0"})[0], 400)
        self.assertEqual(cl.req("GET", "/api/state")[1]["app"], {"version": VERSION, "update": None})


if __name__ == "__main__":
    unittest.main()
