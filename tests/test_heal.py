"""HealEngine decisions, runs, verification, tokens; and its contract with the alert engine."""
import copy
import unittest

import alerts
import gate_client
import heal
import recipes
import settings
import store as store_mod

T0 = 1_800_000_000.0


def rec(rid, when=None, do=None, **kw):
    r = recipes.validate({"schema": 1, "id": rid, "name": rid.replace("-", " ").title(),
                          "when": when or {"alert": "service_down"}, "do": do or {"restart": "unit"}, **kw})
    return dict(r, source="built-in", errors=[])


class FakeGate:
    def __init__(self, recs=None, inspect=None, fail=None, refuse=None):
        self.recs = recs if recs is not None else [rec("restart-port-owner"), rec("restart-port-container", do={"restart": "container"})]
        self.inspect_map = inspect or {(101, 80): {"init": "systemd", "unit": "AdGuardHome.service", "container": None}}
        self.fail, self.refuse, self.runs, self.inspects = fail, refuse, [], []

    def list_recipes(self):
        if self.fail:
            raise gate_client.GateError(self.fail)
        return {"ok": True, "recipes": self.recs}

    def inspect(self, vmid, port):
        self.inspects.append((vmid, port))
        if self.fail:
            raise gate_client.GateError(self.fail)
        return dict({"ok": True, "init": "systemd", "unit": None, "container": None}, **self.inspect_map.get((vmid, port), {}))

    def run(self, recipe_id, vmid, port, target=None, dry_run=False, timeout=None):
        if self.fail:
            raise gate_client.GateError(self.fail)
        if self.refuse:
            return {"ok": False, "error": self.refuse}
        self.runs.append((recipe_id, vmid, port, dict(target or {}), dry_run))
        r = next(r for r in self.recs if r["id"] == recipe_id)
        steps = recipes.resolve(r, dict(target or {}, port=port, init=(target or {}).get("init", "systemd")))
        return {"ok": True, "steps": [{"argv": s, ("dry_run" if dry_run else "exit"): True if dry_run else 0} for s in steps]}


def cfg_heal(mode="auto", **recipes_modes):
    c = copy.deepcopy(settings.DEFAULTS["heal"])
    c["mode"] = mode
    c["recipes"] = {k.replace("_", "-"): v for k, v in recipes_modes.items()}
    return c


COND = {"key": "check:101:80", "kind": "service_down", "severity": "critical", "title": "AdGuard Home on adguard is down",
        "target": 101, "node": "home"}
CHECK = {"id": "101:80", "product": "AdGuard Home", "port": 80}
GUEST = {"vmid": 101, "type": "lxc", "tags": [], "running": True}
CTX = {"running": True, "node_online": True, "api_ok": True, "muted": False}


def make(gate=None, clock_t=T0):
    st = store_mod.Store(":memory:")
    clock = [clock_t]
    h = heal.HealEngine(gate or FakeGate(), st, clock=lambda: clock[0], submit=lambda fn: fn())
    return h, st, clock


class LearnTests(unittest.TestCase):
    def test_learn_rate_limited_and_override_wins(self):
        g = FakeGate()
        h, st, clock = make(g)
        svc = [{"check_id": "101:80", "vmid": 101, "port": 80, "running": True},
               {"check_id": "102:22", "vmid": 102, "port": 22, "running": False}]
        h.learn(svc)
        self.assertEqual(g.inspects, [(101, 80)])                         # stopped guests aren't inspected
        self.assertEqual(st.get_target("101:80")["unit"], "AdGuardHome.service")
        h.learn(svc)
        self.assertEqual(len(g.inspects), 1)                              # once an hour
        clock[0] += 3601
        h.learn(svc)
        self.assertEqual(len(g.inspects), 2)
        st.set_override("101:80", {"unit": "custom.service"})
        self.assertEqual(h.target_for("101:80")["unit"], "custom.service")
        st.set_override("101:80", {"skip": True})
        self.assertIsNone(h.target_for("101:80"))

    def test_learn_stops_when_gate_down(self):
        g = FakeGate(fail="ssh to the heal gate failed")
        h, st, _ = make(g)
        h.learn([{"check_id": "101:80", "vmid": 101, "port": 80, "running": True}] * 3)
        self.assertEqual(len(g.inspects), 1)
        self.assertIn("ssh", h.gate_error)


    def test_learn_remembers_refusals_for_an_hour(self):
        # the gate refuses Pulse's own guest; asking again every discovery pass just fills its log
        g = FakeGate(inspect={(110, 80): {"ok": False, "error": "refusing to act on Pulse's own guest"}})
        h, st, clock = make(g)
        svc = [{"check_id": "110:80", "vmid": 110, "port": 80, "running": True}]
        h.learn(svc)
        clock[0] += 300
        h.learn(svc)
        self.assertEqual(g.inspects, [(110, 80)])
        self.assertIsNone(st.get_target("110:80"))
        clock[0] += 3600
        h.learn(svc)
        self.assertEqual(len(g.inspects), 2)

class DecideTests(unittest.TestCase):
    def setUp(self):
        self.h, self.st, self.clock = make()
        self.h.learn([{"check_id": "101:80", "vmid": 101, "port": 80, "running": True}])

    def decide(self, mode="auto", ctx=None, cond=COND, check=CHECK, guest=GUEST, **modes):
        return self.h.decide(cond, check, guest, cfg_heal(mode, **modes), dict(CTX, **(ctx or {})))

    def test_decide_skips(self):
        self.assertIsNone(self.decide("off"))
        for flag in ({"running": False}, {"node_online": False}, {"api_ok": False}, {"muted": True}):
            self.assertIsNone(self.decide(ctx=flag), flag)
        self.st.set_override("101:80", {"skip": True})
        self.assertIsNone(self.decide())
        self.st.set_override("101:80", None)
        self.assertIsNone(self.decide(check={"id": "101:53", "product": "DNS", "port": 53},
                                      cond=dict(COND, key="check:101:53")))      # no unit/container learned there
        d = self.decide()
        self.h.start(d, self.clock[0])
        self.assertIsNone(self.decide())                                          # already in progress

    def test_mode_caps(self):
        self.assertEqual(self.decide("auto").mode, "auto")
        self.assertEqual(self.decide("ask").mode, "ask")
        self.assertEqual(self.decide("dry_run").mode, "dry_run")
        self.assertEqual(self.decide("auto", restart_port_owner="ask").mode, "ask")
        self.assertIsNone(self.decide("auto", restart_port_owner="off"))
        h, st, _ = make(FakeGate(recs=[rec("restart-port-owner", safety={"default_mode": "ask"})]))
        h.learn([{"check_id": "101:80", "vmid": 101, "port": 80, "running": True}])
        self.assertEqual(h.decide(COND, CHECK, GUEST, cfg_heal("auto"), CTX).mode, "ask")

    def test_priority_choice(self):
        g = FakeGate(recs=[rec("restart-port-owner"), rec("adguard-special", when={"alert": "service_down", "product": ["AdGuard Home"]},
                                                            do={"exec": [["systemctl", "restart", "{unit}"]]})])
        h, st, _ = make(g)
        h.learn([{"check_id": "101:80", "vmid": 101, "port": 80, "running": True}])
        self.assertEqual(h.decide(COND, CHECK, GUEST, cfg_heal(), CTX).recipe["id"], "adguard-special")

    def test_max_per_hour_respected(self):
        for i in range(2):
            self.st.add_heal_run(self.clock[0] - 100 * (i + 1), "101:80", 101, "restart-port-owner", "auto", True, False, "x")
        self.assertIsNone(self.decide())
        self.clock[0] += 3600
        self.assertIsNotNone(self.decide())


class RunTests(unittest.TestCase):
    def setUp(self):
        self.g = FakeGate()
        self.h, self.st, self.clock = make(self.g)
        self.h.learn([{"check_id": "101:80", "vmid": 101, "port": 80, "running": True}])
        self.h.recipes()                       # recipe list cached (10 min), as in normal operation

    def start(self, mode="auto"):
        d = self.h.decide(COND, CHECK, GUEST, cfg_heal(mode), CTX)
        return d, self.h.start(d, self.clock[0])

    def test_auto_run_then_healed(self):
        d, hold = self.start()
        self.assertEqual(hold, self.clock[0] + 90)
        self.assertEqual(self.g.runs[0][:3], ("restart-port-owner", 101, 80))
        self.assertEqual(self.h.poll(self.clock[0], lambda cid: False), [])
        self.clock[0] += 40
        out = self.h.poll(self.clock[0], lambda cid: True)
        self.assertEqual([(o.check_id, o.kind) for o in out], [("101:80", "healed")])
        self.assertEqual(out[0].text, "restarted AdGuardHome.service; back after 40 s")
        run = self.st.heal_runs()[0]
        self.assertEqual((run["ok"], run["recovered"], run["mode"]), (True, True, "auto"))

    def test_heal_failed_alert_says_tried(self):
        self.start()
        self.clock[0] += 91
        out = self.h.poll(self.clock[0], lambda cid: False)
        self.assertEqual((out[0].kind, out[0].text), ("failed", "tried: restarted AdGuardHome.service (still down)"))
        self.assertFalse(self.st.heal_runs()[0]["recovered"])

    def test_gate_refusal_is_failed_at_once(self):
        self.g.refuse = "guest 101 is on the deny list"
        self.start()
        out = self.h.poll(self.clock[0], lambda cid: False)
        self.assertEqual((out[0].kind, out[0].text), ("failed", "fix refused by the gate: guest 101 is on the deny list"))

    def test_gate_down_alert_not_delayed_forever(self):
        self.g.fail = "the heal gate timed out"
        self.start()
        out = self.h.poll(self.clock[0], lambda cid: False)
        self.assertEqual((out[0].kind, out[0].text), ("failed", "fix not attempted: the heal gate timed out"))

    def test_dry_run_records_only(self):
        d, hold = self.start("dry_run")
        self.assertIsNone(hold)
        self.assertTrue(self.g.runs[0][4])                                  # called with dry_run=True
        out = self.h.poll(self.clock[0], lambda cid: False)
        self.assertEqual((out[0].kind, out[0].text), ("dry_run", "would run: systemctl restart AdGuardHome.service"))
        self.assertEqual(self.st.heal_runs()[0]["mode"], "dry_run")

    def test_ask_issues_token_and_expires_on_resolve(self):
        d, hold = self.start("ask")
        self.assertIsNone(hold)
        self.assertEqual(self.g.runs, [])
        tok = self.h.pending_token("101:80")
        self.assertTrue(tok)
        self.h.forget_check("101:80")                                       # problem went away
        self.assertIsNone(self.h.redeem(tok, self.clock[0]))

    def test_token_single_use_bound_and_expiring(self):
        self.start("ask")
        tok = self.h.pending_token("101:80")
        self.assertIsNone(self.h.redeem(tok[:-2] + "xx", self.clock[0]))     # tampered
        self.assertIsNone(self.h.redeem(tok, self.clock[0] + 3601))          # expired
        d = self.h.redeem(tok, self.clock[0] + 10)
        self.assertEqual((d.check_id, d.recipe["id"], d.mode), ("101:80", "restart-port-owner", "manual"))
        self.assertIsNone(self.h.redeem(tok, self.clock[0] + 11))            # used

    def test_history_written(self):
        self.start()
        self.clock[0] += 5
        self.h.poll(self.clock[0], lambda cid: True)
        self.assertEqual(self.st.heal_runs()[0]["detail"], "restarted AdGuardHome.service; back after 5 s")


class AlertIntegrationTests(unittest.TestCase):
    def cfg(self):
        c = copy.deepcopy(settings.DEFAULTS["alerts"])
        c["group_window_s"] = 0
        return c

    def test_auto_heal_single_message(self):
        g = FakeGate()
        h, st, clock = make(g)
        h.learn([{"check_id": "101:80", "vmid": 101, "port": 80, "running": True}])

        def on_fire(key, cond, now):
            d = h.decide(cond, CHECK, GUEST, cfg_heal("auto"), CTX)
            return h.start(d, now) if d else None

        eng = alerts.AlertEngine({}, started=T0, warmup_s=0, on_fire=on_fire)
        sent = []
        t = T0
        for _ in range(13):                                                 # 180 s down -> fires (held)
            sent += eng.process([COND], t, self.cfg(), [], "home")
            t += 15
        self.assertEqual(sent, [])
        self.assertEqual(len(g.runs), 1)
        clock[0] = t + 30
        for o in h.poll(clock[0], lambda cid: True):
            eng.healed(f"check:{o.check_id}", o.text)
        sent += eng.process([], clock[0], self.cfg(), [], "home")
        sent += eng.process([], clock[0] + 15, self.cfg(), [], "home")
        self.assertEqual(len(sent), 1)
        self.assertEqual(sent[0].state, "healed")
        self.assertEqual(sent[0].title, "AdGuard Home on adguard was down; restarted AdGuardHome.service; back after 45 s")
        self.assertEqual(sent[0].severity, "info")

    def test_failed_heal_releases_alert_with_note(self):
        eng = alerts.AlertEngine({}, started=T0, warmup_s=0, on_fire=lambda k, c, now: now + 90)
        t, sent = T0, []
        for _ in range(13):
            sent += eng.process([COND], t, self.cfg(), [], "home")
            t += 15
        eng.annotate("check:101:80", "tried: restarted AdGuardHome.service (still down)")
        sent += eng.process([COND], t, self.cfg(), [], "home")
        self.assertEqual(len(sent), 1)
        self.assertEqual(sent[0].state, "fire")
        self.assertIn("tried: restarted AdGuardHome.service (still down)", sent[0].message)

    def test_hold_expires_on_its_own(self):
        eng = alerts.AlertEngine({}, started=T0, warmup_s=0, on_fire=lambda k, c, now: now + 90)
        t, sent = T0, []
        for _ in range(13 + 7):                                             # 90 s more than the delay
            sent += eng.process([COND], t, self.cfg(), [], "home")
            t += 15
        self.assertEqual([n.state for n in sent], ["fire"])


if __name__ == "__main__":
    unittest.main()
