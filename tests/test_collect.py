"""Collector: multi-node polling, discovery-driven checks, snapshot shape. Runs on the demo cluster."""
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

import collect
import demo
import probes
import sources

NOW = 1_790_900_000.0


class FakeClock:
    def __init__(self, t=NOW):
        self.t = t

    def __call__(self):
        return self.t


def make(overrides_path="/nonexistent/overrides.json", pve=None):
    clock = FakeClock()
    net = demo.DemoNet()
    c = collect.Collector(pve or demo.DemoPve(clock=clock), "demo", net, probe_fn=net.probe,
                          overrides_path=overrides_path, ca_path="/etc/homelab-pulse/pve-ca.pem", clock=clock)
    return c, clock


def boot(c):
    c.poll_fast()
    c.poll_slow()
    c.poll_discovery()     # (no second poll_fast: node IPs must show straight after the slow poll)
    c.poll_probes()


class PipelineTests(unittest.TestCase):
    def test_demo_pipeline_end_to_end(self):
        c, clock = make()
        boot(c)
        clock.t += 5
        c.poll_fast()
        s = c.snapshot()
        self.assertEqual([n["name"] for n in s["nodes"]], ["pve1", "pve2"])
        self.assertEqual([n["ip"] for n in s["nodes"]], ["192.168.1.2", "192.168.1.3"])
        self.assertTrue(all(n["online"] and n["cpus"] for n in s["nodes"]))
        self.assertEqual(len(s["guests"]), 11)
        by = {g["vmid"]: g for g in s["guests"]}
        self.assertEqual((by[200]["node"], by[200]["ip"], by[200]["role"], by[200]["icon"]),
                         ("pve2", "192.168.1.20", "Ollama", "brain"))
        self.assertEqual(by[105]["ip"], "192.168.1.15")                      # agentless VM via cloud-init config
        self.assertEqual(by[104]["tags"], ["media"])
        running = [g for g in s["guests"] if g["running"]]
        self.assertTrue(all(g["services"] for g in running), [g["name"] for g in running if not g["services"]])
        self.assertTrue(all(g["net_in"] > 0 for g in running))
        ids = {p["id"] for p in s["probes"]}
        self.assertLessEqual({"internet", "router:80", "node:pve1", "node:pve2", "100:53", "200:11434"}, ids)
        self.assertTrue(all(p["up"] for p in s["probes"] if not p["paused"]))
        self.assertEqual(s["router"], {"name": "Router", "ip": "192.168.1.1"})
        self.assertEqual(s["backups"]["fresh"], 10)                          # all but the brand-new pulse guest
        self.assertEqual({r["node"] for r in s["backups"]["runs"]}, {"pve1", "pve2"})
        self.assertEqual([x["id"] for x in s["shared_storage"]], ["nas-backup"])
        self.assertEqual([x["id"] for x in s["nodes"][0]["storage"]], ["local", "local-lvm"])
        self.assertEqual(s["nodes"][0]["disks"][0]["wear_used"], 4)
        self.assertEqual((s["nodes"][0]["pve"], s["nodes"][0]["kernel"]), ("9.2.20", "7.0.14-19-pve"))
        self.assertEqual({k: v["ok"] for k, v in s["sources"].items()}, {"pve": True, "probes": True, "discovery": True})
        self.assertEqual(len(c.history_for("pve2")["cpu"]), 2)
        self.assertEqual(len(c.history_for(200)["cpu"]), 2)
        self.assertIsNone(c.history_for("nope"))
        json.dumps(s)

    def test_node_ip_known_after_first_slow_poll(self):
        c, _ = make()
        boot(c)
        self.assertEqual([n["ip"] for n in c.snapshot()["nodes"]], ["192.168.1.2", "192.168.1.3"])

    def test_stopped_guest_checks_are_paused(self):
        c, _ = make()
        boot(c)
        s = c.snapshot()
        self.assertEqual([g["services"] for g in s["guests"] if g["vmid"] == 203], [[]])
        self.assertFalse(any(p["paused"] for p in s["probes"]))

    def test_check_state_survives_rediscovery(self):
        c, clock = make()
        boot(c)
        clock.t += 15
        c.poll_probes()
        clock.t += 300
        c.poll_discovery()
        c.poll_probes()
        p = next(p for p in c.snapshot()["probes"] if p["id"] == "200:11434")
        self.assertEqual(len(p["history"]), 3)

    def test_new_checks_wake_the_prober(self):
        c, _ = make()
        c.poll_fast()
        c.poll_slow()
        c._probe_wake.clear()
        c.poll_discovery()
        self.assertTrue(c._probe_wake.is_set())           # discovered checks get probed right away
        c._probe_wake.clear()
        c._replan()
        self.assertFalse(c._probe_wake.is_set())          # same set again: no early run

    def test_paused_when_guest_stops(self):
        c, _ = make()
        boot(c)
        c.guests = [dict(g, running=False) if g["vmid"] == 200 else g for g in c.guests]
        c.poll_probes()
        p = next(p for p in c.snapshot()["probes"] if p["id"] == "200:11434")
        self.assertTrue(p["paused"])
        self.assertEqual(len(p["history"]), 1)                   # not probed while stopped


class LifecycleTests(unittest.TestCase):
    def test_new_vmid_schedules_early_discovery(self):
        guests = dict(demo.GUESTS)
        services = dict(demo.SERVICES)
        with mock.patch.object(demo, "GUESTS", guests), mock.patch.object(demo, "SERVICES", services):
            c, clock = make()
            boot(c)
            guests[107] = ("pve1", "lxc", "immich", 2, 4096, 32, 0.02, 0.4, "192.168.1.17", True, None)
            services["192.168.1.17"] = [demo._f(2283, "http", "Immich", "photo", 9)]
            c.ports = c.ports + (2283,)
            clock.t += 5
            c.poll_fast()
            clock.t += 10
            c.poll_discovery()
            self.assertNotIn(107, c.discoverer.known)            # too early: guest still booting
            clock.t += 40
            c.poll_discovery()
            s = c.snapshot()
        g = next(g for g in s["guests"] if g["vmid"] == 107)
        self.assertEqual((g["role"], g["ip"]), ("Immich", "192.168.1.17"))
        self.assertIn("107:2283", {p["id"] for p in s["probes"]})
        self.assertIn("Found Immich on immich", [e["text"] for e in s["events"]])

    def test_discovery_waits_for_guests(self):
        c, clock = make()
        c.poll_discovery()                       # Proxmox not polled yet: nothing to discover
        boot(c)
        clock.t += 15
        c.poll_fast()
        self.assertIn(200, c.discoverer.known)
        self.assertTrue(c.snapshot()["guests"][0]["services"])

    def test_offline_node_is_skipped(self):
        pve = demo.DemoPve()
        real = pve.resources
        pve.resources = lambda: [dict(r, status="offline") if r["type"] == "node" and r["node"] == "pve2"
                                 else dict(r, status="unknown") if r.get("node") == "pve2" and r["type"] in ("lxc", "qemu")
                                 else r for r in real()]
        called = []
        for name in ("node_status", "disks", "backup_runs"):
            orig = getattr(pve, name)
            setattr(pve, name, lambda node, *a, _o=orig, _n=name: called.append((_n, node)) or _o(node, *a))
        c, _ = make(pve=pve)
        boot(c)
        s = c.snapshot()
        self.assertFalse(any(node == "pve2" for _n, node in called))
        n2 = next(n for n in s["nodes"] if n["name"] == "pve2")
        self.assertEqual((n2["online"], n2["cpu"]), (False, 0))
        self.assertTrue(next(n for n in s["nodes"] if n["name"] == "pve1")["online"])
        self.assertTrue(s["sources"]["pve"]["ok"])

    def test_ignored_guest_hidden(self):
        pve = demo.DemoPve()
        real = pve.resources
        pve.resources = lambda: [dict(r, tags="pulse-ignore") if r.get("vmid") == 201 else r for r in real()]
        c, _ = make(pve=pve)
        boot(c)
        s = c.snapshot()
        self.assertNotIn(201, [g["vmid"] for g in s["guests"]])
        self.assertFalse(any(p.get("target") == 201 for p in s["probes"]))

    def test_tag_role_beats_discovery(self):
        pve = demo.DemoPve()
        real = pve.resources
        pve.resources = lambda: [dict(r, tags="pulse-role-family-photos;pulse-icon-photo") if r.get("vmid") == 202
                                 else r for r in real()]
        c, _ = make(pve=pve)
        boot(c)
        g = next(g for g in c.snapshot()["guests"] if g["vmid"] == 202)
        self.assertEqual((g["role"], g["icon"]), ("family photos", "photo"))


class OverrideTests(unittest.TestCase):
    def write(self, text):
        d = tempfile.mkdtemp()
        p = Path(d) / "overrides.json"
        p.write_text(text)
        return str(p)

    def test_overrides_file_applies(self):
        path = self.write(json.dumps({
            "internet": False, "router": {"name": "Gateway"}, "guests": {"100": {"role": "DNS"}},
            "checks": [{"id": "proxy-cert", "name": "Public cert", "kind": "tls", "host": "192.168.1.11", "port": 443,
                        "sni": "example.org", "target": 101}],
            "hide_checks": ["100:80"]}))
        c, _ = make(path)
        boot(c)
        s = c.snapshot()
        ids = {p["id"] for p in s["probes"]}
        self.assertNotIn("internet", ids)
        self.assertNotIn("100:80", ids)
        self.assertNotIn("101:443", ids)
        self.assertIn("proxy-cert", ids)
        self.assertEqual(s["router"]["name"], "Gateway")
        self.assertEqual(next(g for g in s["guests"] if g["vmid"] == 100)["role"], "DNS")

    def test_bad_overrides_marks_source_but_discovery_runs(self):
        c, _ = make(self.write("{oops"))
        boot(c)
        s = c.snapshot()
        self.assertFalse(s["sources"]["discovery"]["ok"])
        self.assertIn("invalid JSON", s["sources"]["discovery"]["error"])
        self.assertTrue(any(p["id"] == "200:11434" for p in s["probes"]))


class FailureTests(unittest.TestCase):
    def test_failing_source_is_reported_not_fatal(self):
        c, _ = make()

        def boom():
            raise sources.SourceError("PVE /cluster/resources: HTTP 401")
        c.pve.resources = boom
        t = threading.Thread(target=c._loop, args=("pve", c.poll_fast, 0.01))
        t.start()
        time.sleep(0.05)
        c.stop()
        t.join()
        s = c.snapshot()["sources"]["pve"]
        self.assertEqual((s["ok"], s["error"]), (False, "PVE /cluster/resources: HTTP 401"))


class BuilderTests(unittest.TestCase):
    def test_build_storage_splits_shared(self):
        res = [{"type": "storage", "storage": "local", "node": "a", "disk": 1, "maxdisk": 2, "status": "available"},
               {"type": "storage", "storage": "nfs", "node": "a", "shared": 1, "disk": 5, "maxdisk": 9, "status": "available"},
               {"type": "storage", "storage": "nfs", "node": "b", "shared": 1, "disk": 5, "maxdisk": 9, "status": "available"}]
        per_node, shared = collect.build_storage(res)
        self.assertEqual([s["id"] for s in per_node["a"]], ["local"])
        self.assertEqual([s["id"] for s in shared], ["nfs"])

    def test_backup_summary_multi_node(self):
        guests = [{"vmid": 100, "name": "a"}, {"vmid": 200, "name": "b"}, {"vmid": 300, "name": "new"}]
        runs = [{"node": "n1", "starttime": NOW - 7200, "endtime": NOW - 7000, "status": "OK"},
                {"node": "n2", "starttime": NOW - 7100, "endtime": NOW - 3000, "status": "job errors"}]
        per_vm = {100: {"ts": NOW - 7000, "size": 7, "ok": True, "error": None},
                  200: {"ts": None, "size": 0, "ok": False, "error": "boom"}}
        s = collect.backup_summary(runs, per_vm, guests, NOW)
        self.assertEqual((s["last_run"]["node"], s["last_run"]["ok"]), ("n2", False))
        self.assertEqual([r["node"] for r in s["runs"]], ["n1", "n2"])
        self.assertEqual(s["fresh"], 1)
        self.assertEqual(s["guests"][1]["error"], "boom")
        self.assertIsNone(collect.backup_summary([], {}, guests, NOW)["last_run"])


if __name__ == "__main__":
    unittest.main()
