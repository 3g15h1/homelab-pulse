"""Collector + self-healing on the demo lab: the demo outage gets healed with one message."""
import unittest

import collect
import demo
import heal
import store as store_mod

NOW = 1_790_900_000.0          # demo outage starts 500 s later


class Clock:
    def __init__(self, t=NOW):
        self.t = t

    def __call__(self):
        return self.t


class FakeNotifier:
    def __init__(self):
        self.sent, self.last = [], None

    def enqueue(self, n, cfg):
        self.sent.append(n)


def make(mode="auto", with_heal=True):
    clock = Clock()
    net = demo.DemoNet(clock=clock)
    st = store_mod.Store(":memory:", clock=clock)
    st.put("config", {"heal": {"mode": mode, "recipes": {}}})
    h = heal.HealEngine(demo.DemoGate(net), st, clock=clock, submit=lambda fn: fn()) if with_heal else None
    n = FakeNotifier()
    c = collect.Collector(demo.DemoPve(clock=clock), "demo", net, probe_fn=net.probe, clock=clock, store=st,
                          notifier=n, heal=h)
    return c, clock, n, h, net


def boot(c):
    c.poll_fast()
    c.poll_slow()
    c.poll_discovery()
    c.poll_probes()
    c.poll_alerts()


def run(c, clock, seconds):
    for _ in range(int(seconds / 15)):
        clock.t += 15
        c.poll_fast()
        c.poll_probes()
        c.poll_alerts()


class CollectHealTests(unittest.TestCase):
    def test_learning_after_discovery(self):
        c, clock, n, h, net = make()
        boot(c)
        t = c.store.get_target("202:443")
        self.assertEqual((t["unit"], t["init"]), ("truenas.service", "systemd"))
        self.assertEqual(c.store.get_target("105:9443")["container"], "portainer")

    def test_demo_outage_healed_end_to_end(self):
        c, clock, n, h, net = make("auto")
        boot(c)
        run(c, clock, 900)
        about = [x for x in n.sent if any(i["key"] == "check:202:443" for i in x.items)]
        self.assertEqual([x.state for x in about], ["healed"])
        self.assertEqual(about[0].title, "TrueNAS on nas was down; restarted truenas.service; back after 15 s")
        self.assertEqual(len(c.heal.gate.calls), 1)
        texts = [e["text"] for e in c.snapshot()["events"]]
        self.assertTrue(any(t.startswith("Healed: TrueNAS on nas was down") for t in texts), texts)
        self.assertEqual(c.store.heal_runs()[0]["recovered"], True)

    def test_dry_run_mode_alerts_normally_and_logs(self):
        c, clock, n, h, net = make("dry_run")
        boot(c)
        run(c, clock, 900)
        about = [x.state for x in n.sent if any(i["key"] == "check:202:443" for i in x.items)]
        self.assertEqual(about, ["fire", "resolve"])
        self.assertEqual(c.heal.gate.calls, [])
        self.assertTrue(any("would run: systemctl restart truenas.service" in e["text"] for e in c.snapshot()["events"]))

    def test_ask_mode_offers_fix(self):
        c, clock, n, h, net = make("ask")
        boot(c)
        run(c, clock, 720)
        self.assertIn("202:443", c.snapshot()["heal"]["asks"])
        self.assertTrue(h.pending_token("202:443"))
        self.assertNotIn(h.pending_token("202:443"), str(c.snapshot()))          # tokens never in public state

    def test_no_gate_means_off(self):
        c, clock, n, h, net = make(with_heal=False)
        boot(c)
        self.assertEqual(c.snapshot()["sources"]["heal"]["mode"], "off")

    def test_heal_source_in_snapshot(self):
        c, clock, n, h, net = make("auto")
        boot(c)
        src = c.snapshot()["sources"]["heal"]
        self.assertEqual((src["mode"], src["ok"]), ("auto", True))


class WarningHealTests(unittest.TestCase):
    def test_warning_fix_not_healed_while_warning_persists(self):
        import recipes
        c, clock, n, h, net = make("auto")
        boot(c)
        cleanup = dict(recipes.validate({"schema": 1, "id": "test-disk-cleanup", "name": "Clean up",
                                         "when": {"alert": "warning", "rule": "ct_disk"},
                                         "do": {"exec": [["apt-get", "clean"]]}}), source="built-in", errors=[])
        h._recipes, h._recipes_at = h.recipes() + [cleanup], clock.t
        h.gate._recipes = lambda: h._recipes
        cond = {"key": "warn:ct_disk:201", "kind": "warning", "severity": "warning", "title": "grafana disk 95 % full",
                "target": 201, "node": "pve2"}
        c._heal_cfg = {"mode": "auto", "recipes": {"ct-disk-cleanup": "off"}}   # use the test recipe
        hold = c._on_fire(cond["key"], cond, clock.t)
        self.assertIsNotNone(hold)
        present = {cond["key"]}
        up = {}
        outs = h.poll(clock.t + 10, lambda cid: up.get(cid) is True or (cid.startswith("warn:") and cid not in present))
        self.assertEqual(outs, [])                       # still full: not healed yet
        present.clear()
        outs = h.poll(clock.t + 20, lambda cid: up.get(cid) is True or (cid.startswith("warn:") and cid not in present))
        self.assertEqual([o.kind for o in outs], ["healed"])


class OrderTests(unittest.TestCase):
    def test_checks_published_before_learning(self):
        c, clock, n, h, net = make("auto")
        seen = []
        real = h.gate.inspect
        h.gate.inspect = lambda vmid, port: seen.append(len(c.checks)) or real(vmid, port)
        c.poll_fast()
        c.poll_slow()
        c.poll_discovery()
        self.assertTrue(seen)
        self.assertGreater(seen[0], 4)                 # discovered checks were already planned when learning began
