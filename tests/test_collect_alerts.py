"""Collector + alerts: conditions, unexpected stops, demo outage end to end, persistence, RRD."""
import tempfile
import unittest
from pathlib import Path

import collect
import demo
import store as store_mod

NOW = 1_790_900_000.0          # NOW % 1200 == 800: the demo outage window (100–340 s of each 20 min) is ahead


class Clock:
    def __init__(self, t=NOW):
        self.t = t

    def __call__(self):
        return self.t


class FakeNotifier:
    def __init__(self):
        self.sent = []
        self.last = None

    def enqueue(self, n, cfg):
        self.sent.append(n)


def make(store=None, notifier=None, settings_doc=None):
    clock = Clock()
    net = demo.DemoNet(clock=clock)
    st = store or store_mod.Store(":memory:", clock=clock)
    c = collect.Collector(demo.DemoPve(clock=clock), "demo", net, probe_fn=net.probe, ca_path=None,
                          clock=clock, store=st, notifier=notifier or FakeNotifier(),
                          settings_loader=(lambda: settings_doc) if settings_doc else None)
    return c, clock


def boot(c):
    c.poll_fast()
    c.poll_slow()
    c.poll_discovery()
    c.poll_probes()
    c.poll_alerts()


def snap(**kw):
    s = {"nodes": [{"name": "home", "online": True}], "guests": [], "probes": [], "backups": None,
         "sources": {"pve": {"ok": True, "error": None}}}
    s.update(kw)
    return s


class BuildConditionsTests(unittest.TestCase):
    def test_build_conditions_kinds(self):
        s = snap(
            nodes=[{"name": "home", "online": True}, {"name": "pve2", "online": False}],
            guests=[{"vmid": 101, "name": "adguard", "node": "home", "running": True}],
            probes=[{"id": "101:80", "name": "AdGuard Home", "up": False, "paused": False, "target": 101,
                     "guest": "adguard"},
                    {"id": "101:53", "name": "DNS", "up": True, "paused": False, "target": 101, "guest": "adguard"},
                    {"id": "102:80", "name": "Gone", "up": False, "paused": True, "target": 102},
                    {"id": "node:home", "name": "Proxmox UI", "up": False, "paused": False, "target": "home"},
                    {"id": "internet", "name": "Internet", "up": False, "paused": False, "target": "internet"}],
            backups={"runs": [{"node": "home", "ok": False, "status": "job errors"},
                              {"node": "pve2", "ok": True, "status": "OK"}]},
            sources={"pve": {"ok": False, "error": "PVE /cluster/resources: HTTP 401"}})
        c = {x["key"]: x for x in collect.build_conditions(s, {}, [], NOW)}
        self.assertEqual(set(c), {"check:101:80", "check:node:home", "check:internet", "node:pve2", "source:pve",
                                  "backup:home"})
        self.assertEqual(c["check:101:80"]["title"], "AdGuard Home on adguard is down")
        self.assertEqual((c["check:101:80"]["node"], c["check:101:80"]["target"]), ("home", 101))
        self.assertEqual(c["check:node:home"]["node"], "home")
        self.assertIsNone(c["check:internet"]["node"])
        self.assertEqual(c["node:pve2"]["title"], "pve2 is offline")
        self.assertEqual(c["backup:home"]["title"], "Backup on home failed: job errors")
        self.assertEqual(c["source:pve"]["kind"], "api_down")
        self.assertIn("HTTP 401", c["source:pve"]["title"])

    def test_guest_stopped_explained_by_task(self):
        s = snap(guests=[{"vmid": 105, "name": "docker", "node": "home", "running": False}])
        tasks = [{"type": "qmshutdown", "id": "105", "starttime": NOW - 200, "endtime": NOW - 150, "status": "OK"}]
        self.assertEqual(collect.build_conditions(s, {105: NOW - 160}, tasks, NOW), [])

    def test_guest_stopped_unexplained(self):
        s = snap(guests=[{"vmid": 105, "name": "docker", "node": "home", "running": False}])
        tasks = [{"type": "qmshutdown", "id": "105", "starttime": NOW - 5000, "endtime": NOW - 4990, "status": "OK"}]
        self.assertEqual(collect.build_conditions(s, {105: NOW - 60}, tasks, NOW), [])      # wait for task list
        c = collect.build_conditions(s, {105: NOW - 100}, tasks, NOW)
        self.assertEqual([(x["key"], x["kind"], x["title"]) for x in c],
                         [("guest:105:stopped", "guest_stopped", "docker stopped unexpectedly")])

    def test_guest_running_again_or_deleted_clears(self):
        s = snap(guests=[{"vmid": 105, "name": "docker", "node": "home", "running": True}])
        self.assertEqual(collect.build_conditions(s, {105: NOW - 500, 106: NOW - 500}, [], NOW), [])


class PipelineTests(unittest.TestCase):
    def test_demo_flap_fires_and_resolves(self):
        n = FakeNotifier()
        c, clock = make(notifier=n)
        boot(c)
        self.assertEqual(n.sent, [])
        for _ in range(int(900 / 15)):                  # through one demo outage of the nas TLS check
            clock.t += 15
            c.poll_fast()
            c.poll_probes()
            c.poll_alerts()
        states = [x.state for x in n.sent if any(i["key"] == "check:202:443" for i in x.items)]
        self.assertEqual(states, ["fire", "resolve"])
        fire = next(x for x in n.sent if x.state == "fire" and x.items[0]["key"] == "check:202:443")
        self.assertEqual(fire.title, "TrueNAS on nas is down")
        self.assertTrue(any(e["kind"] == "alert" for e in c.snapshot()["events"]))

    def test_attention_in_snapshot(self):
        c, clock = make()
        boot(c)
        att = {a["key"]: a for a in c.snapshot()["attention"]}
        w = att["warn:storage_full:pve2/local-lvm"]
        self.assertRegex(w["title"], r"^local-lvm on pve2 full in ~(19|20|21) days$")
        self.assertEqual((w["severity"], w["muted"], w["target"]), ("warning", False, "pve2"))
        self.assertEqual(w["state"], "firing")

    def test_attention_marks_muted(self):
        c, clock = make()
        c.store.add_mute("node:pve2", None, False)
        boot(c)
        att = {a["key"]: a for a in c.snapshot()["attention"]}
        self.assertTrue(att["warn:storage_full:pve2/local-lvm"]["muted"])

    def test_events_persist_across_collectors(self):
        path = str(Path(tempfile.mkdtemp()) / "pulse.db")
        c, clock = make(store=store_mod.Store(path, clock=Clock()))
        boot(c)
        texts = [e["text"] for e in c.snapshot()["events"] if e["kind"] == "alert"]
        self.assertTrue(texts)
        c2, _ = make(store=store_mod.Store(path, clock=Clock()))
        self.assertLessEqual(set(texts), {e["text"] for e in c2.snapshot()["events"]})
        self.assertIn("warn:storage_full:pve2/local-lvm", c2.engine.states)     # alert state reloaded too

    def test_check_results_feed_uptime(self):
        c, clock = make()
        boot(c)
        clock.t += 15
        c.poll_probes()
        up = c.uptime()
        self.assertEqual(up["200:11434"]["24h"], 100.0)

    def test_rrd_series_cached(self):
        c, clock = make()
        boot(c)
        calls = []
        orig = c.pve.rrd
        c.pve.rrd = lambda *a: calls.append(a) or orig(*a)
        s = c.rrd_series(200, "day")
        self.assertEqual(set(s), {"t", "cpu", "mem", "net_in", "net_out"})
        self.assertTrue(len(s["t"]) > 10 and 0 <= max(s["mem"]) <= 1)
        c.rrd_series(200, "day")
        self.assertEqual(len(calls), 1)
        clock.t += 61
        c.rrd_series(200, "day")
        self.assertEqual(len(calls), 2)
        self.assertEqual(len(c.rrd_series("pve1", "week")["t"]) > 10, True)
        self.assertIsNone(c.rrd_series(999, "day"))
        self.assertIsNone(c.rrd_series(200, "decade"))

    def test_storage_history_feeds_forecast(self):
        c, clock = make()
        boot(c)
        self.assertIn(("pve2", "local-lvm"), c.storage_hist)
        self.assertIn(("*", "nas-backup"), c.storage_hist)

    def test_guest_stop_without_task_alerts(self):
        n = FakeNotifier()
        c, clock = make(notifier=n)
        boot(c)
        guests = dict(demo.GUESTS)
        g = list(guests[201])
        g[9] = False                                   # grafana stops, nobody asked it to
        import unittest.mock as m
        with m.patch.dict(demo.GUESTS, {201: tuple(g)}):
            for _ in range(20):                         # 90 s settle time + 60 s grouping window
                clock.t += 15
                c.poll_fast()
                c.poll_alerts()
        self.assertIn("grafana stopped unexpectedly", [x.title for x in n.sent])

    def test_clear_guest_stopped(self):
        c, clock = make()
        boot(c)
        c.stopped[203] = clock.t - 200                 # the demo sandbox is stopped
        c.poll_alerts()
        self.assertIn("guest:203:stopped", c.engine.states)
        c.clear_alert("guest:203:stopped")
        self.assertNotIn(203, c.stopped)
        self.assertNotIn("guest:203:stopped", c.engine.states)

    def test_sources_include_store_and_alerts(self):
        c, clock = make()
        boot(c)
        src = c.snapshot()["sources"]
        self.assertEqual(src["store"]["ok"], True)
        self.assertIn("alerts", src)


if __name__ == "__main__":
    unittest.main()


class LockTests(unittest.TestCase):
    def test_clear_waits_for_running_alert_evaluation(self):
        import threading
        import time as _t
        c, clock = make()
        boot(c)
        with c._alert_lock:                           # as if poll_alerts were mid-evaluation
            t = threading.Thread(target=c.clear_alert, args=("guest:203:stopped",))
            t.start()
            _t.sleep(0.2)
            self.assertTrue(t.is_alive())
        t.join(2)
        self.assertFalse(t.is_alive())
