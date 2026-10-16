"""More than one Proxmox: a standalone second host next to the primary cluster (sources.MultiPve)."""
import json
import tempfile
import unittest
from pathlib import Path

import collect
import demo
import overrides
import sources
from sources import UID_SPAN

NOW = 1_790_900_000.0


class Flaky:
    """Wraps a demo host; `down = True` makes every call fail like an unreachable API."""

    def __init__(self, inner):
        self.inner, self.down, self.calls = inner, False, []

    def __getattr__(self, name):
        fn = getattr(self.inner, name)

        def call(*a, **kw):
            self.calls.append((name, a))
            if self.down:
                raise sources.SourceError("connect timed out")
            return fn(*a, **kw)
        return call


def mini(nodes=None):
    return demo.DemoPve(seed=11, nodes=nodes or demo.MINI_NODES, guests=demo.MINI_GUESTS, cluster=None)


def multi(extra=None, label="mini", slot=1):
    extra = extra or Flaky(mini())
    return sources.MultiPve(demo.DemoPve(), [sources.ExtraHost(label, slot, extra)]), extra


class MergeTests(unittest.TestCase):
    def test_guests_get_their_own_keys_and_keep_the_real_vmid(self):
        m, _ = multi()
        guests = {r["vmid"]: r for r in m.resources() if r["type"] in ("lxc", "qemu")}
        self.assertEqual(len(guests), 13)
        self.assertEqual(guests[100]["name"], "adguard")                   # the primary keeps plain VMIDs
        self.assertNotIn("host", guests[100])
        g = guests[UID_SPAN + 100]
        self.assertEqual((g["name"], g["pve_vmid"], g["host"], g["node"]), ("frigate", 100, "mini", "mini"))
        self.assertEqual(sources.split_uid(g["vmid"]), (1, 100))

    def test_node_calls_reach_the_right_host_with_real_ids(self):
        m, extra = multi()
        m.resources()
        m.lxc_interfaces("mini", UID_SPAN + 101)
        m.guest_config("mini", "lxc", UID_SPAN + 101)
        m.node_status("mini")
        m.node_status("pve1")                                              # primary: not the extra host
        self.assertEqual([c for c in extra.calls if c[0] != "resources"],
                         [("lxc_interfaces", ("mini", 101)), ("guest_config", ("mini", "lxc", 101)),
                          ("node_status", ("mini",))])
        self.assertEqual(m.uid("mini", 101), UID_SPAN + 101)
        self.assertEqual(m.uid("pve1", 101), 101)

    def test_taken_node_name_gets_the_host_label(self):
        # both hosts are called "pve1": the second one shows as pve1@mini, but is asked as "pve1"
        clash = {"pve1": dict(demo.MINI_NODES["mini"])}
        guests = {v: ("pve1",) + g[1:] for v, g in demo.MINI_GUESTS.items()}
        extra = Flaky(demo.DemoPve(seed=11, nodes=clash, guests=guests, cluster=None))
        m, _ = multi(extra)
        nodes = [r["node"] for r in m.resources() if r["type"] == "node"]
        self.assertEqual(sorted(nodes), ["pve1", "pve1@mini", "pve2"])
        extra.calls.clear()
        m.node_status("pve1@mini")
        self.assertEqual(extra.calls, [("node_status", ("pve1",))])
        names = {e["name"] for e in m.cluster_status() if e["type"] == "node"}
        self.assertEqual(names, {"pve1", "pve2", "pve1@mini"})
        self.assertEqual(m.node_meta("pve1@mini")["tls_name"], "pve1")    # the certificate has the real name
        self.assertEqual(m.node_meta("pve1"), {})

    def test_extra_host_down_shows_offline_not_gone(self):
        m, extra = multi()
        m.resources()
        extra.down = True
        res = m.resources()                                                # doesn't raise
        node = next(r for r in res if r["type"] == "node" and r["node"] == "mini")
        self.assertEqual(node["status"], "offline")
        g = next(r for r in res if r.get("vmid") == UID_SPAN + 100)
        self.assertEqual(g["status"], "unknown")
        st = {e["name"]: e for e in m.cluster_status() if e["type"] == "node"}
        self.assertEqual(st["mini"]["online"], 0)
        self.assertEqual(m.host_status()[0]["ok"], False)
        self.assertEqual(m.host_status()[0]["nodes"], ["mini"])
        self.assertEqual(len(m.tasks()), len(m.primary.tasks()))         # its tasks are skipped

    def test_extra_host_never_reached(self):
        extra = Flaky(mini())
        extra.down = True
        m, _ = multi(extra)
        res = m.resources()
        self.assertFalse(any(r.get("host") for r in res))
        self.assertEqual(m.host_status(), [{"label": "mini", "ok": False, "error": "connect timed out", "nodes": [],
                                            "source": "installer", "host": None}])
        snap = {"sources": {"pve": {"ok": True, "hosts": m.host_status()}}}
        conds = collect.build_conditions(snap, {}, [], NOW)
        self.assertEqual([(c["key"], c["kind"]) for c in conds], [("source:pve:mini", "api_down")])

    def test_primary_failure_still_raises(self):
        primary = Flaky(demo.DemoPve())
        primary.down = True
        m = sources.MultiPve(primary, [sources.ExtraHost("mini", 1, mini())])
        with self.assertRaises(sources.SourceError):
            m.resources()

    def test_extra_storage_stays_under_its_node(self):
        m, _ = multi()
        res = m.resources()
        st = [r for r in res if r["type"] == "storage" and r.get("host") == "mini"]
        self.assertTrue(st)
        self.assertTrue(all(r["shared"] == 0 and r["node"] == "mini" for r in st))
        per_node, shared = collect.build_storage(res)
        self.assertEqual([s["id"] for s in shared], ["nas-backup"])        # only the primary's shared one
        self.assertIn("nas-backup", [s["id"] for s in per_node["mini"]])

    def test_tasks_and_backups_are_remapped(self):
        m, _ = multi()
        m.resources()
        runs = m.backup_runs("mini")
        self.assertEqual({r["node"] for r in runs}, {"mini"})
        extra_task = {"upid": "UPID:mini:1", "type": "vzstop", "id": "101", "node": "mini", "starttime": 1}
        t = m._remap_task(m.extras[0], extra_task)
        self.assertEqual((t["id"], t["host"]), (str(UID_SPAN + 101), "mini"))


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.m, self.extra = multi()
        self.net = demo.DemoNet(clock=lambda: NOW)
        self.c = collect.Collector(self.m, "demo", self.net, probe_fn=self.net.probe, clock=lambda: NOW)
        self.c.poll_fast()
        self.c.poll_slow()
        self.c.poll_discovery(force_full=True)

    def test_snapshot_has_both_hosts(self):
        snap = self.c.snapshot()
        g = next(g for g in snap["guests"] if g["vmid"] == UID_SPAN + 100)
        self.assertEqual((g["pve_vmid"], g["host"], g["ip"], g["role"]), (100, "mini", "192.168.1.30", "Frigate"))
        self.assertEqual(next(g for g in snap["guests"] if g["vmid"] == 100)["host"], None)
        self.assertEqual([n["name"] for n in snap["nodes"]], ["pve1", "pve2", "mini"])
        self.assertEqual(snap["sources"]["pve"]["hosts"][0]["label"], "mini")
        ids = {p["id"] for p in snap["probes"]}
        self.assertIn(f"{UID_SPAN + 100}:5000", ids)
        self.assertIn("100:80", ids)                                      # the primary's CT 100 too

    def test_backups_of_the_extra_host_land_on_its_guests(self):
        b = {x["vmid"]: x for x in self.c.snapshot()["backups"]["guests"]}
        self.assertTrue(b[UID_SPAN + 100]["fresh"])
        self.assertTrue(b[100]["fresh"])

    def test_node_check_uses_the_extra_hosts_ca_and_name(self):
        self.extra.cafile = "/etc/homelab-pulse/hosts/mini-ca.pem"
        self.c._replan()
        spec = self.c.checks["node:mini"].spec
        self.assertEqual((spec["sni"], spec["cafile"]), ("mini", "/etc/homelab-pulse/hosts/mini-ca.pem"))

    def test_extra_host_offline_alerts_as_a_node(self):
        self.extra.down = True
        self.c.poll_fast()
        conds = collect.build_conditions(self.c.snapshot(), {}, [], NOW)
        keys = {c["key"] for c in conds}
        self.assertIn("node:mini", keys)
        self.assertNotIn("source:pve", keys)
        self.assertNotIn("source:pve:mini", keys)                          # it has nodes: "offline" says it

    def test_host_outage_is_not_counted_as_guest_stops(self):
        # three blips of the extra host within an hour mustn't look like its guests flapping
        for _ in range(3):
            self.extra.down = True
            self.c.poll_fast()
            self.extra.down = False
            self.c.poll_fast()
        self.assertEqual(self.c.stopped, {})
        self.assertEqual(self.c.flap_hist, {})

    def test_bad_host_file_is_reported_by_name(self):
        m = sources.MultiPve(demo.DemoPve(), [], [("gpu", "Expecting value")])
        self.assertEqual(m.host_status(), [{"label": "gpu", "ok": False, "error": "bad host file: Expecting value",
                                            "nodes": []}])

    def test_self_healing_leaves_extra_hosts_alone(self):
        class Gate:
            inspected = []
        heal = type("H", (), {"learn": lambda _s, svc: Gate.inspected.extend(s["vmid"] for s in svc),
                              "asks": {}})()
        self.c.heal = heal
        self.c.poll_discovery(force_full=True)
        self.assertTrue(Gate.inspected)
        self.assertTrue(all(v < UID_SPAN for v in Gate.inspected))
        cond = {"kind": "service_down", "target": UID_SPAN + 100}
        self.assertIsNone(self.c._on_fire(f"check:{UID_SPAN + 100}:5000", cond, NOW))

    def test_overrides_name_extra_guests_by_label(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "overrides.json"
            p.write_text(json.dumps({"guests": {"mini/100": {"role": "NVR"}}, "hide_checks": ["mini/101:22"]}))
            self.c.overrides_path = str(p)
            self.c.poll_slow()
            self.c.poll_discovery(force_full=True)
        snap = self.c.snapshot()
        self.assertEqual(next(g for g in snap["guests"] if g["vmid"] == UID_SPAN + 100)["role"], "NVR")
        self.assertNotIn(f"{UID_SPAN + 101}:22", {p["id"] for p in snap["probes"]})
        self.assertIsNone(self.c.ov_error)


class RefTests(unittest.TestCase):
    def test_resolve_refs(self):
        ov = {"guests": {"103": {"role": "HA"}, "gpu/105": {"icon": "brain"}},
              "hide_checks": ["101:22", "gpu/105:22"], "http_contains": {"gpu/105:80": "Ollama"},
              "checks": [{"id": "x", "name": "X", "kind": "tcp", "host": "h", "port": 1, "target": "gpu/105"}]}
        out = overrides.resolve_refs(ov, {"gpu": 2}, UID_SPAN)
        self.assertEqual(set(out["guests"]), {"103", str(2 * UID_SPAN + 105)})
        self.assertEqual(out["hide_checks"], ["101:22", f"{2 * UID_SPAN + 105}:22"])
        self.assertEqual(out["http_contains"], {f"{2 * UID_SPAN + 105}:80": "Ollama"})
        self.assertEqual(out["checks"][0]["target"], str(2 * UID_SPAN + 105))
        self.assertEqual(ov["guests"].keys(), {"103", "gpu/105"})          # input untouched

    def test_unknown_label_is_an_error(self):
        with self.assertRaises(overrides.OverrideError) as e:
            overrides.resolve_refs({"guests": {"gpu/105": {}}}, {}, UID_SPAN)
        self.assertIn("gpu", str(e.exception))

    def test_http_contains_is_a_valid_key(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "o.json"
            p.write_text(json.dumps({"http_contains": {"101:80": "AdGuard"}}))
            self.assertEqual(overrides.load(p)["http_contains"], {"101:80": "AdGuard"})
            p.write_text(json.dumps({"http_contains": {"101:80": 5}}))
            with self.assertRaises(overrides.OverrideError):
                overrides.load(p)


class MuteTargetTests(unittest.TestCase):
    def test_renamed_nodes_and_host_sources_can_be_muted(self):
        import server
        for t in ("node:pve1@mini", "source:pve:gpu", f"guest:{UID_SPAN + 100}", f"check:{UID_SPAN + 100}:5000"):
            self.assertTrue(server.MUTE_TARGET.fullmatch(t), t)


class LoadHostsTests(unittest.TestCase):
    def test_load_hosts(self):
        with tempfile.TemporaryDirectory() as d:
            good = {"label": "gpu", "slot": 1, "host": "192.168.1.70", "token": "pulse@pve!x=y"}
            (Path(d) / "gpu.json").write_text(json.dumps(good))
            (Path(d) / "zdup.json").write_text(json.dumps(dict(good, label="dup")))    # same slot: first file wins
            (Path(d) / "bad.json").write_text("{")
            (Path(d) / "BIG.json").write_text(json.dumps(dict(good, label="Bad Label", slot=3)))
            hosts, errors = sources.load_hosts(d)
        self.assertEqual([(h.label, h.slot) for h in hosts], [("gpu", 1)])
        self.assertEqual(hosts[0].client.cafile, str(Path(d) / "gpu-ca.pem"))
        self.assertEqual(hosts[0].client.port, 8006)
        self.assertEqual(len(errors), 3)

    def test_missing_dir_is_fine(self):
        self.assertEqual(sources.load_hosts("/nonexistent/hosts"), ([], []))

    def test_multi_implements_every_client_call(self):
        public = {m for m in dir(sources.PveClient) if not m.startswith("_")}
        self.assertLessEqual(public, set(dir(sources.MultiPve)))


if __name__ == "__main__":
    unittest.main()
