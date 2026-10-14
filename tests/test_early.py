import copy
import random
import unittest

import early
import settings

D, GB = 86400, 1024 ** 3
NOW = 1_800_000_000.0


def cfg(**patch):
    c = copy.deepcopy(settings.DEFAULTS["warnings"])
    for k, v in patch.items():
        rule, field = k.split("__")
        c[rule][field] = v
    return c


def hourly(days, start_used, per_day, noise=0.0, seed=1):
    rng = random.Random(seed)
    pts = []
    for h in range(int(days * 24)):
        t = NOW - days * D + h * 3600
        pts.append((t, start_used + per_day * (t - (NOW - days * D)) / D + rng.gauss(0, noise)))
    return pts


def snap(**kw):
    s = {"nodes": [{"name": "pve1", "online": True, "mem": 8 * GB, "maxmem": 32 * GB,
                    "storage": [{"id": "local-lvm", "used": 90 * GB, "total": 100 * GB, "ok": True}],
                    "disks": [{"dev": "/dev/sda", "model": "Samsung SSD", "wear_used": 19, "health": "PASSED"}]}],
         "shared_storage": [], "guests": [], "probes": [], "backups": None}
    s.update(kw)
    return s


def keys(conds):
    return {c["key"]: c["severity"] for c in conds}


class ForecastTests(unittest.TestCase):
    def test_forecast_linear(self):
        pts = hourly(14, 80 * GB, 0.5 * GB)            # ends at 87 GB of 100 → 13 GB / 0.5 = 26 days
        self.assertAlmostEqual(early.forecast_days(pts, 100 * GB, NOW), 26, delta=0.5)

    def test_forecast_flat_noisy_short_none(self):
        self.assertIsNone(early.forecast_days(hourly(14, 50 * GB, 0), 100 * GB, NOW))              # flat
        self.assertIsNone(early.forecast_days(hourly(14, 50 * GB, -1 * GB), 100 * GB, NOW))        # shrinking
        self.assertIsNone(early.forecast_days(hourly(14, 50 * GB, 0.01 * GB, noise=3 * GB), 100 * GB, NOW))
        self.assertIsNone(early.forecast_days(hourly(1.5, 50 * GB, 5 * GB), 100 * GB, NOW))        # < 48 points
        self.assertIsNone(early.forecast_days([], 100 * GB, NOW))

    def test_forecast_uses_last_14_days_only(self):
        old = [(NOW - 30 * D + h * 3600, 10 * GB) for h in range(24 * 10)]     # flat month-old data ignored
        pts = old + hourly(14, 80 * GB, 0.5 * GB)
        self.assertAlmostEqual(early.forecast_days(pts, 100 * GB, NOW), 26, delta=0.5)


class RuleTests(unittest.TestCase):
    def ev(self, s, hist=None, c=None, state=None, now=NOW):
        return early.evaluate(s, hist or {}, c or cfg(), state if state is not None else {}, now)

    def test_storage_rules(self):
        s = snap()
        self.assertEqual(keys(self.ev(s)), {"warn:storage_full:pve1/local-lvm": "warning"})       # 90 % > 85
        s["nodes"][0]["storage"][0]["used"] = 96 * GB
        self.assertEqual(keys(self.ev(s))["warn:storage_full:pve1/local-lvm"], "critical")
        s["nodes"][0]["storage"][0]["used"] = 50 * GB
        self.assertEqual(self.ev(s), [])
        hist = {("pve1", "local-lvm"): hourly(14, 40 * GB, 2 * GB)}     # ends ~68 GB, 32 GB free / 2 = ~16 d
        c = self.ev(s, hist)
        self.assertEqual(keys(c), {"warn:storage_full:pve1/local-lvm": "warning"})
        self.assertRegex(c[0]["title"], r"^local-lvm full in ~1[56] days$")                       # one node: no node name
        self.assertEqual((c[0]["target"], c[0]["node"]), ("pve1", "pve1"))
        hist = {("pve1", "local-lvm"): hourly(14, 40 * GB, 7 * GB)}
        self.assertEqual(keys(self.ev(s, hist))["warn:storage_full:pve1/local-lvm"], "critical")

    def test_shared_storage_once(self):
        s = snap(shared_storage=[{"id": "nas", "used": 97 * GB, "total": 100 * GB, "ok": True}])
        s["nodes"][0]["storage"][0]["used"] = 10 * GB
        s["nodes"].append(dict(s["nodes"][0], name="pve2", storage=[]))
        c = self.ev(s)
        self.assertEqual(keys(c), {"warn:storage_full:nas": "critical"})
        self.assertEqual(c[0]["title"], "nas 97 % full")

    def test_cert_expiry_from_detail(self):
        s = snap(probes=[
            {"id": "104:443", "name": "nginx", "kind": "tls", "detail": "cert 19 days left", "target": 104, "guest": "proxy"},
            {"id": "ha-proxy", "name": "Remote access", "kind": "tls", "detail": "cert 5 days left", "target": 104},
            {"id": "x", "name": "Gone", "kind": "tls", "detail": "cert -2 days left", "target": 105},
            {"id": "y", "name": "Fine", "kind": "tls", "detail": "cert 200 days left", "target": 106},
            {"id": "z", "name": "Down", "kind": "tls", "detail": "timed out", "target": 107},
        ])
        s["nodes"][0]["storage"] = []
        c = {x["key"]: x for x in self.ev(s)}
        self.assertEqual(c["warn:cert_expiry:104:443"]["severity"], "warning")
        self.assertEqual(c["warn:cert_expiry:104:443"]["title"], "Certificate for nginx (proxy) expires in 19 days")
        self.assertEqual(c["warn:cert_expiry:ha-proxy"]["severity"], "critical")
        self.assertEqual(c["warn:cert_expiry:x"]["title"], "Certificate for Gone has expired")
        self.assertEqual(len(c), 3)

    def test_ssd_and_smart(self):
        s = snap()
        s["nodes"][0]["storage"] = []
        s["nodes"][0]["disks"] = [{"dev": "/dev/sda", "model": "Old SSD", "wear_used": 85, "health": "PASSED"},
                                  {"dev": "/dev/sdb", "model": "Tired SSD", "wear_used": 93, "health": "OK"},
                                  {"dev": "/dev/sdc", "model": "Bad HDD", "wear_used": None, "health": "FAILED"}]
        self.assertEqual(keys(self.ev(s)), {"warn:ssd_wear:pve1/sda": "warning", "warn:ssd_wear:pve1/sdb": "critical",
                                            "warn:smart:pve1/sdc": "critical"})

    def test_backup_stale_only_for_guests_in_job(self):
        s = snap(backups={"guests": [
            {"vmid": 100, "name": "a", "ts": NOW - 3 * D, "error": None},       # in job, too old
            {"vmid": 101, "name": "b", "ts": NOW - 3600, "error": None},        # fine
            {"vmid": 102, "name": "c", "ts": None, "error": "boom"},            # failed in the job
            {"vmid": 103, "name": "new", "ts": None, "error": None},            # never in a job: not our business
        ]})
        s["nodes"][0]["storage"] = []
        c = {x["key"]: x for x in self.ev(s)}
        self.assertEqual(set(c), {"warn:backup_stale:100", "warn:backup_stale:102"})
        self.assertEqual(c["warn:backup_stale:100"]["title"], "a has no backup for 3 days")
        self.assertEqual(c["warn:backup_stale:102"]["title"], "c: last backup failed (boom)")
        self.assertEqual(c["warn:backup_stale:100"]["target"], 100)

    def test_node_memory_needs_duration(self):
        s = snap()
        s["nodes"][0]["storage"] = []
        s["nodes"][0]["mem"] = 30 * GB                 # 93.75 %
        state = {}
        self.assertEqual(self.ev(s, state=state, now=NOW), [])
        self.assertEqual(self.ev(s, state=state, now=NOW + 14 * 60), [])
        self.assertEqual(keys(self.ev(s, state=state, now=NOW + 16 * 60)), {"warn:node_memory:pve1": "warning"})
        s["nodes"][0]["mem"] = 10 * GB
        self.assertEqual(self.ev(s, state=state, now=NOW + 17 * 60), [])
        s["nodes"][0]["mem"] = 30 * GB
        self.assertEqual(self.ev(s, state=state, now=NOW + 18 * 60), [])           # timer restarted

    def test_ct_disk(self):
        s = snap(guests=[{"vmid": 101, "name": "a", "type": "lxc", "running": True, "disk": 95, "maxdisk": 100},
                         {"vmid": 102, "name": "b", "type": "lxc", "running": True, "disk": 98, "maxdisk": 100},
                         {"vmid": 103, "name": "vm", "type": "qemu", "running": True, "disk": 0, "maxdisk": 100},
                         {"vmid": 104, "name": "off", "type": "lxc", "running": False, "disk": 99, "maxdisk": 100}])
        s["nodes"][0]["storage"] = []
        c = {x["key"]: x for x in self.ev(s)}
        self.assertEqual({k: v["severity"] for k, v in c.items()},
                         {"warn:ct_disk:101": "warning", "warn:ct_disk:102": "critical"})
        self.assertEqual(c["warn:ct_disk:101"]["title"], "a disk 95 % full")

    def test_disabled_rule_silent(self):
        self.assertEqual(self.ev(snap(), c=cfg(storage_full__enabled=False)), [])

    def test_offline_node_skipped(self):
        s = snap()
        s["nodes"][0]["online"] = False
        self.assertEqual(self.ev(s), [])

    def test_every_condition_has_kind_warning(self):
        for c in self.ev(snap()):
            self.assertEqual(c["kind"], "warning")


class DataSafetyTests(unittest.TestCase):
    def ev(self, s, **kw):
        return early.evaluate(s, {}, cfg(**kw), {}, NOW)

    def clean_snap(self):
        s = snap()
        s["nodes"][0]["storage"] = [{"id": "local-lvm", "used": 50 * GB, "total": 100 * GB,
                                     "ok": True}]
        return s

    def test_zfs_degraded_is_critical(self):
        s = self.clean_snap()
        s["nodes"][0]["zfs"] = [{"name": "tank", "health": "DEGRADED"}]
        out = self.ev(s)
        self.assertEqual([(c["key"], c["severity"]) for c in out],
                         [("warn:zfs_health:pve1/tank", "critical")])
        self.assertIn("DEGRADED", out[0]["title"])

    def test_zfs_online_silent(self):
        s = self.clean_snap()
        s["nodes"][0]["zfs"] = [{"name": "tank", "health": "ONLINE"}]
        self.assertEqual(self.ev(s), [])

    def test_zfs_no_pools_silent(self):
        self.assertEqual(self.ev(self.clean_snap()), [])

    def test_backup_storage_full(self):
        s = self.clean_snap()
        s["nodes"][0]["storage"] = [{"id": "backup", "used": 96 * GB, "total": 100 * GB,
                                     "ok": True, "for_backup": True}]
        out = self.ev(s)
        self.assertEqual([(c["key"], c["severity"]) for c in out],
                         [("warn:backup_storage_full:pve1/backup", "critical")])

    def test_backup_storage_ignored_by_storage_full(self):
        s = snap()
        s["nodes"][0]["storage"] = [{"id": "backup", "used": 96 * GB, "total": 100 * GB,
                                     "ok": True, "for_backup": True}]
        out = early.evaluate(s, {}, cfg(backup_storage_full__enabled=False), {}, NOW)
        self.assertEqual(out, [])

    def test_pve_updates_disabled_by_default(self):
        self.assertFalse(settings.DEFAULTS["warnings"]["pve_updates"]["enabled"])

    def test_pve_updates_reports_count(self):
        s = self.clean_snap()
        s["nodes"][0]["updates"] = [{"package": "pve-manager", "version": "9.2.21",
                                     "old": "9.2.20", "origin": "Proxmox"}]
        out = early.evaluate(s, {}, cfg(pve_updates__enabled=True), {}, NOW)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["key"], "warn:pve_updates:pve1")
        self.assertEqual(out[0]["severity"], "warning")

    def test_pve_updates_none_silent(self):
        s = self.clean_snap()
        s["nodes"][0]["updates"] = []
        out = early.evaluate(s, {}, cfg(pve_updates__enabled=True), {}, NOW)
        self.assertEqual(out, [])

    def test_pve_updates_unknown_silent(self):
        s = self.clean_snap()
        s["nodes"][0]["updates"] = None
        out = early.evaluate(s, {}, cfg(pve_updates__enabled=True), {}, NOW)
        self.assertEqual(out, [])
