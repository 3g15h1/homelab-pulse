import copy
import json
import time
import unittest

import alerts
import settings

T0 = time.mktime((2026, 10, 13, 12, 0, 0, 0, 0, -1))        # local noon


def cfg(**kw):
    c = copy.deepcopy(settings.DEFAULTS["alerts"])
    for k, v in kw.items():
        if "__" in k:
            a, b = k.split("__")
            c[a][b] = v
        else:
            c[k] = v
    return c


def down(cid, node="home", title=None):
    return {"key": f"check:{cid}", "kind": "service_down", "severity": "critical",
            "title": title or f"{cid} is down", "target": int(cid.split(":")[0]) if cid[0].isdigit() else cid,
            "node": node}


def warn(subject, sev="warning", title=None):
    return {"key": f"warn:storage_full:{subject}", "kind": "warning", "severity": sev,
            "title": title or f"{subject} filling up", "target": "home", "node": "home"}


class Harness:
    """Runs the engine every 15 s like the collector does and collects what it sends."""

    def __init__(self, c=None, saved=None, started=T0, warmup=0):
        self.cfg = c or cfg(group_window_s=0)
        self.engine = alerts.AlertEngine(saved or {}, started=started, warmup_s=warmup)
        self.now = started
        self.sent = []
        self.events = []
        self.mutes = []

    def step(self, conds, seconds=15):
        out = self.engine.process(conds, self.now, self.cfg, self.mutes, "home")
        self.sent += out
        self.events += self.engine.events
        self.now += seconds
        return out

    def run(self, conds, seconds):
        for _ in range(int(seconds // 15)):
            self.step(conds)

    def titles(self):
        return [n.title for n in self.sent]


class FireResolveTests(unittest.TestCase):
    def test_pending_discarded_when_clearing_early(self):
        h = Harness()
        h.run([down("101:80")], 120)
        h.run([], 300)
        self.assertEqual(h.sent, [])
        self.assertEqual(h.events, [])
        self.assertEqual([k for k in h.engine.states if not k.startswith("_")], [])

    def test_fire_after_delay_then_resolve_with_duration(self):
        h = Harness()
        h.run([down("101:80", title="AdGuard Home on adguard is down")], 180)       # checked at 0…165 s
        self.assertEqual(h.sent, [])
        h.step([down("101:80", title="AdGuard Home on adguard is down")])        # 180 s reached
        self.assertEqual(len(h.sent), 1)
        n = h.sent[0]
        self.assertEqual((n.title, n.severity, n.state), ("AdGuard Home on adguard is down", "critical", "fire"))
        self.assertEqual(n.items[0]["key"], "check:101:80")
        h.run([down("101:80", title="AdGuard Home on adguard is down")], 540)       # 12 min since it went down
        h.step([])
        self.assertEqual(len(h.sent), 2)
        self.assertEqual((h.sent[1].state, h.sent[1].severity), ("resolve", "info"))
        self.assertEqual(h.sent[1].title, "AdGuard Home on adguard is back after 12 min")
        self.assertEqual([e["level"] for e in h.events], ["bad", "ok"])
        json.dumps(h.engine.states)

    def test_immediate_kinds_have_no_delay(self):
        h = Harness()
        h.step([{"key": "node:pve2", "kind": "node_offline", "severity": "critical", "title": "pve2 is offline",
                 "target": "pve2", "node": "pve2"}])
        self.assertEqual(h.titles(), ["pve2 is offline"])

    def test_api_down_waits_two_minutes(self):
        h = Harness()
        c = {"key": "source:pve", "kind": "api_down", "severity": "critical", "title": "Can't reach Proxmox",
             "target": None}
        h.run([c], 105)
        self.assertEqual(h.sent, [])
        h.run([c], 30)
        self.assertEqual(h.titles(), ["Can't reach Proxmox"])

    def test_kind_disabled_silent(self):
        h = Harness(cfg(group_window_s=0, kinds__service_down=False))
        h.run([down("101:80")], 600)
        self.assertEqual(h.sent, [])

    def test_no_recovery_message_when_disabled(self):
        h = Harness(cfg(group_window_s=0, send_recovery=False))
        h.run([down("101:80")], 200)
        h.step([])
        self.assertEqual([n.state for n in h.sent], ["fire"])

    def test_repeat(self):
        h = Harness(cfg(group_window_s=0, repeat_every_s=3600))
        h.run([down("101:80")], 180 + 3600 + 30)
        self.assertEqual([n.state for n in h.sent], ["fire", "repeat"])
        self.assertTrue(h.sent[1].title.startswith("Still: "))

    def test_warning_escalation_refires(self):
        h = Harness()
        h.step([warn("pve1/local-lvm")])
        h.run([warn("pve1/local-lvm")], 600)
        h.step([warn("pve1/local-lvm", "critical", "local-lvm full in ~5 days")])
        h.step([warn("pve1/local-lvm", "critical", "local-lvm full in ~5 days")])
        self.assertEqual([(n.state, n.severity) for n in h.sent], [("fire", "warning"), ("fire", "critical")])


class GroupingTests(unittest.TestCase):
    def test_reboot_groups_fire_and_resolve(self):
        h = Harness(cfg())                                   # group window 60 s
        checks = [down(f"{100 + i}:80", title=f"svc{i} is down") for i in range(12)]
        h.run(checks[:7], 30)                                # they fail over a few seconds
        h.run(checks, 240)
        fires = [n for n in h.sent if n.state == "fire"]
        self.assertEqual(len(fires), 1)
        self.assertEqual(fires[0].title, "12 services down on home")
        self.assertEqual(len(fires[0].items), 12)
        self.assertIn("svc0 is down", fires[0].message)
        h.run([], 120)
        resolves = [n for n in h.sent if n.state == "resolve"]
        self.assertEqual(len(resolves), 1)
        self.assertEqual(resolves[0].title, "12 services back on home")
        self.assertIn("• svc0 is back after", resolves[0].message)
        self.assertNotIn("is down is back", resolves[0].message)
        self.assertEqual(len(h.sent), 2)

    def test_mixed_problems_title(self):
        h = Harness(cfg())
        offline = {"key": "node:pve2", "kind": "node_offline", "severity": "critical", "title": "pve2 is offline",
                   "target": "pve2", "node": "pve2"}
        h.run([offline, warn("pve1/local-lvm")], 120)
        self.assertEqual(h.titles(), ["2 problems on home"])
        self.assertEqual(h.sent[0].severity, "critical")

    def test_long_list_truncated(self):
        h = Harness(cfg(group_window_s=0))
        h.run([down(f"{100 + i}:80", node=f"n{i}") for i in range(14)], 200)
        self.assertEqual(h.titles(), ["14 problems on home"])
        self.assertIn("and 4 more", h.sent[0].message)


class QuietTests(unittest.TestCase):
    def quiet(self, **kw):
        # quiet from 11:00 to 13:00 local, so T0 (noon) is inside
        return Harness(cfg(group_window_s=0, quiet__enabled=True, quiet__start="11:00", quiet__end="13:00", **kw))

    def test_quiet_hours_hold_warning_summary_at_end(self):
        h = self.quiet()
        h.run([warn("pve1/local-lvm")], 1800)
        self.assertEqual(h.sent, [])
        h.run([warn("pve1/local-lvm")], 1800 + 15)           # past 13:00
        self.assertEqual(len(h.sent), 1)
        self.assertEqual(h.sent[0].state, "summary")
        self.assertEqual(h.sent[0].title, "While you were away: 1 alert")
        self.assertIn("pve1/local-lvm filling up", h.sent[0].message)

    def test_quiet_critical_sent_unless_critical_too(self):
        h = self.quiet()
        h.run([down("101:80")], 200)
        self.assertEqual([n.state for n in h.sent], ["fire"])
        h = self.quiet(quiet__critical_too=True)
        h.run([down("101:80")], 200)
        self.assertEqual(h.sent, [])

    def test_fired_and_resolved_in_quiet_shows_resolved(self):
        h = self.quiet()
        h.run([warn("pve1/local-lvm")], 600)
        h.run([], 600)
        self.assertEqual(h.sent, [])
        h.run([], 6000)
        self.assertEqual(len(h.sent), 1)
        self.assertIn("pve1/local-lvm filling up (resolved)", h.sent[0].message)

    def test_quiet_window_across_midnight(self):
        self.assertTrue(alerts.in_quiet({"enabled": True, "start": "23:00", "end": "07:00"},
                                        time.mktime((2026, 10, 13, 2, 30, 0, 0, 0, -1))))
        self.assertFalse(alerts.in_quiet({"enabled": True, "start": "23:00", "end": "07:00"},
                                         time.mktime((2026, 10, 13, 7, 30, 0, 0, 0, -1))))
        self.assertFalse(alerts.in_quiet({"enabled": False, "start": "00:00", "end": "23:59"}, T0))


class MuteTests(unittest.TestCase):
    def test_mute_suppresses_then_sends_on_expiry(self):
        h = Harness()
        h.mutes = [{"target": "check:101:80", "until_ts": T0 + 600, "until_recovered": False}]
        h.run([down("101:80")], 300)
        self.assertEqual(h.sent, [])
        self.assertEqual(h.engine.states["check:101:80"]["state"], "firing")
        h.mutes = []                                          # expired
        h.step([down("101:80")])
        self.assertEqual([n.state for n in h.sent], ["fire"])

    def test_guest_mute_covers_its_keys(self):
        h = Harness()
        h.mutes = [{"target": "guest:101", "until_ts": None, "until_recovered": False}]
        h.run([down("101:80"), down("101:53"), down("102:8000")], 300)
        self.assertEqual([i["key"] for n in h.sent for i in n.items], ["check:102:8000"])

    def test_node_mute(self):
        h = Harness()
        h.mutes = [{"target": "node:pve2", "until_ts": None, "until_recovered": False}]
        h.run([down("201:80", node="pve2")], 300)
        self.assertEqual(h.sent, [])

    def test_no_recovery_when_fire_never_sent(self):
        h = Harness()
        h.mutes = [{"target": "check:101:80", "until_ts": None, "until_recovered": True}]
        h.run([down("101:80")], 300)
        h.step([])
        self.assertEqual(h.sent, [])
        self.assertEqual(h.engine.recovered, {"check:101:80"})    # an until-recovered mute can go now


class RestartTests(unittest.TestCase):
    def test_restart_no_resend(self):
        h = Harness()
        h.run([down("101:80")], 200)
        saved = json.loads(json.dumps(h.engine.states))
        h2 = Harness(saved=saved, started=h.now, warmup=60)
        h2.run([down("101:80")], 600)
        self.assertEqual(h2.sent, [])

    def test_restart_resolve_after_warmup(self):
        h = Harness()
        h.run([down("101:80")], 200)
        saved = json.loads(json.dumps(h.engine.states))
        h2 = Harness(saved=saved, started=h.now, warmup=60)
        h2.run([], 45)
        self.assertEqual(h2.sent, [])                         # still warming up: maybe not rediscovered yet
        h2.run([], 30)
        self.assertEqual([n.state for n in h2.sent], ["resolve"])

    def test_outbox_survives_restart(self):
        h = Harness(cfg())                                    # 60 s window
        h.run([down("101:80")], 195)                          # fired at 180 s, still in the window
        self.assertEqual(h.sent, [])
        saved = json.loads(json.dumps(h.engine.states))
        h2 = Harness(cfg(), saved=saved, started=h.now, warmup=60)
        h2.run([down("101:80")], 60)
        self.assertEqual([n.state for n in h2.sent], ["fire"])


class ClearTests(unittest.TestCase):
    def test_clear_forgets_a_key(self):
        h = Harness()
        stopped = {"key": "guest:105:stopped", "kind": "guest_stopped", "severity": "warning",
                   "title": "docker stopped unexpectedly", "target": 105, "node": "home"}
        h.step([stopped])
        h.engine.clear("guest:105:stopped")
        self.assertNotIn("guest:105:stopped", h.engine.states)


if __name__ == "__main__":
    unittest.main()
