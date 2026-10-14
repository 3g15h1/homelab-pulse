"""Self-healing on the Pulse side: learn what owns each check's port, pick a recipe when an alert
fires, run it through the host gate (or just simulate it, or ask first), and tell the alert engine
whether it worked. Pulse itself never runs anything; the gate validates and executes.
"""
import hashlib
import hmac
import logging
import secrets
import threading
import time
from dataclasses import dataclass, field

import gate_client
import recipes as recipes_mod

log = logging.getLogger("pulse")
LEARN_EVERY = 3600
RECIPES_EVERY = 600
TOKEN_TTL = 3600


@dataclass
class Decision:
    recipe: dict
    mode: str                     # auto | ask | dry_run | manual
    check_id: str
    cond_key: str
    vmid: int
    port: int | None
    target: dict = field(default_factory=dict)


@dataclass
class Outcome:
    check_id: str
    cond_key: str
    kind: str                     # healed | failed | dry_run
    text: str


def action_text(recipe, target):
    do = recipe["do"]
    if do.get("restart") == "unit":
        return f"restarted {target.get('unit')}"
    if do.get("restart") == "container":
        return f"restarted container {target.get('container')}"
    return f"ran \"{recipe['name']}\""


class HealEngine:
    def __init__(self, gate, store, clock=time.time, submit=None):
        self.gate, self.store, self.clock = gate, store, clock
        self.submit = submit or (lambda fn: threading.Thread(target=fn, daemon=True, name="heal").start())
        self.gate_error = None
        self._recipes, self._recipes_at = [], None
        self.inflight = {}        # check_id -> {"d": Decision, "started", "until", "result"}
        self.dry = {}             # check_id -> finished dry-run results waiting for poll()
        self.asks = {}            # check_id -> token
        self.tokens = {}          # token id -> binding
        self.lock = threading.Lock()

    # -- recipes and targets --

    def recipes(self):
        now = self.clock()
        if self._recipes_at is None or now - self._recipes_at >= RECIPES_EVERY:
            try:
                self._recipes = self.gate.list_recipes().get("recipes", [])
                self.gate_error = None
            except gate_client.GateError as e:
                self.gate_error = str(e)
            self._recipes_at = now
        return self._recipes

    def learn(self, services):
        """services: [{check_id, vmid, port, running}]. Asks the gate who owns each port (hourly)."""
        now = self.clock()
        for s in services:
            if not s.get("running") or not s.get("port"):
                continue
            t = self.store.get_target(s["check_id"])
            if t and t.get("learned_ts") and now - t["learned_ts"] < LEARN_EVERY:
                continue
            try:
                r = self.gate.inspect(s["vmid"], s["port"])
            except gate_client.GateError as e:
                self.gate_error = str(e)
                return                       # gate down: try again next time
            if r.get("ok"):
                self.store.put_target(s["check_id"], s["vmid"], s["port"], r.get("init"), r.get("unit"),
                                      r.get("container"), now)

    def target_for(self, check_id):
        t = self.store.get_target(check_id) or {}
        ov = t.get("override") or {}
        if ov.get("skip"):
            return None
        out = {"init": t.get("init") or "systemd", "unit": t.get("unit"), "container": t.get("container")}
        if ov.get("unit"):
            out.update(unit=ov["unit"], container=None)
        if ov.get("container"):
            out.update(container=ov["container"], unit=None)
        return out

    # -- deciding --

    def decide(self, cond, check, guest, cfg, ctx):
        mode = cfg.get("mode", "off")
        if mode == "off" or not ctx.get("running") or not ctx.get("node_online") or not ctx.get("api_ok") or ctx.get("muted"):
            return None
        check_id = check["id"] if check else cond["key"]          # warnings are tracked by their own key
        if check_id in self.inflight:
            return None
        target = self.target_for(check_id) if check else {"init": "systemd", "unit": None, "container": None}
        if target is None:
            return None
        now = self.clock()
        recent = [r for r in self.store.heal_runs(200) if now - r["ts"] < 3600 and r["check_id"] == check_id
                  and r["mode"] in ("auto", "manual")]
        candidates = []
        for r in self.recipes():
            if not recipes_mod.matches(r, cond, check, guest):
                continue
            override = cfg.get("recipes", {}).get(r["id"], "default")
            if override == "off":
                continue
            kind = r["do"].get("restart")
            if (kind == "unit" and not target.get("unit")) or (kind == "container" and not target.get("container")):
                continue
            if sum(1 for x in recent if x["recipe_id"] == r["id"]) >= r["safety"]["max_per_hour"]:
                continue
            candidates.append((recipes_mod.priority(r), r, override))
        if not candidates:
            return None
        _p, r, override = max(candidates, key=lambda c: c[0])
        m = r["safety"]["default_mode"] if override == "default" else override
        if mode == "dry_run":
            m = "dry_run"
        elif mode == "ask" and m == "auto":
            m = "ask"
        return Decision(r, m, check_id, cond["key"], guest["vmid"], check.get("port") if check else None, target)

    # -- running --

    def start(self, d, now):
        """Begin acting on a decision. Returns hold-until for the alert (auto/manual runs) or None."""
        if d.mode == "ask":
            self.asks[d.check_id] = self.issue_token(d, now)
            return None
        if d.mode == "dry_run":
            def dry():
                try:
                    res = self.gate.run(d.recipe["id"], d.vmid, d.port or 0, target=d.target, dry_run=True)
                except gate_client.GateError as e:
                    res = {"ok": False, "error": str(e)}
                with self.lock:
                    self.dry[d.check_id] = (d, res)
            self.submit(dry)
            return None
        until = now + d.recipe["safety"]["verify_s"]
        entry = {"d": d, "started": now, "until": until, "result": None}
        with self.lock:
            self.inflight[d.check_id] = entry

        def go():
            try:
                res = self.gate.run(d.recipe["id"], d.vmid, d.port or 0, target=d.target)
            except gate_client.GateError as e:
                res = {"ok": False, "error": str(e), "gate_down": True}
            with self.lock:
                entry["result"] = res
        self.submit(go)
        return until

    def poll(self, now, is_up):
        """Outcomes for runs that finished: healed (check back), failed (fix error / still down), dry_run."""
        out = []
        with self.lock:
            dry, self.dry = self.dry, {}
            inflight = list(self.inflight.items())
        for check_id, (d, res) in dry.items():
            if res.get("ok"):
                text = "would run: " + "; ".join(" ".join(s["argv"]) for s in res.get("steps", []))
            else:
                text = f"dry run refused: {res.get('error')}"
            self.store.add_heal_run(now, check_id, d.vmid, d.recipe["id"], "dry_run", res.get("ok"), None, text)
            out.append(Outcome(check_id, d.cond_key, "dry_run", text))
        for check_id, e in inflight:
            d, res = e["d"], e["result"]
            done_text = None
            if res is None:
                if now >= e["until"] + 60:
                    done_text, kind, ok, recovered = "tried: the fix didn't finish in time", "failed", None, False
                else:
                    continue
            elif not res.get("ok"):
                why = res.get("error") or "the command failed"
                if res.get("gate_down"):
                    done_text = f"fix not attempted: {why}"
                elif "steps" in res:
                    done_text = f"tried: {action_text(d.recipe, d.target)} (failed: {why})"
                else:
                    done_text = f"fix refused by the gate: {why}"
                kind, ok, recovered = "failed", False, False
            elif is_up(check_id):
                secs = max(1, round(now - e["started"]))
                done_text, kind, ok, recovered = f"{action_text(d.recipe, d.target)}; back after {secs} s", "healed", True, True
            elif now >= e["until"]:
                done_text, kind, ok, recovered = f"tried: {action_text(d.recipe, d.target)} (still down)", "failed", True, False
            else:
                continue
            with self.lock:
                self.inflight.pop(check_id, None)
            self.store.add_heal_run(now, check_id, d.vmid, d.recipe["id"], d.mode, ok, recovered, done_text)
            out.append(Outcome(check_id, d.cond_key, kind, done_text))
        return out

    # -- ask first: single-use tokens --

    def _secret(self):
        s = self.store.get("heal_secret")
        if not s:
            s = secrets.token_hex(32)
            self.store.put("heal_secret", s)
        return bytes.fromhex(s)

    def _sign(self, tid, exp, b):
        msg = f"{tid}|{exp}|{b['check_id']}|{b['recipe_id']}|{b['vmid']}".encode()
        return hmac.new(self._secret(), msg, hashlib.sha256).hexdigest()[:32]

    def issue_token(self, d, now):
        tid, exp = secrets.token_urlsafe(12), int(now + TOKEN_TTL)
        b = {"check_id": d.check_id, "recipe_id": d.recipe["id"], "vmid": d.vmid, "decision": d, "exp": exp, "used": False}
        self.tokens[tid] = b
        return f"{tid}.{exp}.{self._sign(tid, exp, b)}"

    def pending_token(self, check_id):
        return self.asks.get(check_id)

    def asked_recipe_id(self, check_id):
        tok = self.asks.get(check_id)
        b = self.tokens.get(tok.split(".")[0]) if tok else None
        return b["recipe_id"] if b else None

    def asked_recipe_name(self, check_id):
        tok = self.asks.get(check_id)
        b = self.tokens.get(tok.split(".")[0]) if tok else None
        return b["decision"].recipe["name"] if b else None

    def run_now(self, d):
        """Manual run from the settings page: synchronous, recorded in the history."""
        try:
            res = self.gate.run(d.recipe["id"], d.vmid, d.port or 0, target=d.target)
        except gate_client.GateError as e:
            res = {"ok": False, "error": str(e)}
        text = (f"{action_text(d.recipe, d.target)} (manual)" if res.get("ok")
                else f"manual run failed: {res.get('error') or 'the command failed'}")
        self.store.add_heal_run(self.clock(), d.check_id, d.vmid, d.recipe["id"], "manual", res.get("ok"), None, text)
        return res

    def redeem(self, token, now):
        try:
            tid, exp_s, sig = token.split(".")
            exp = int(exp_s)
        except (AttributeError, ValueError):
            return None
        b = self.tokens.get(tid)
        if not b or b["used"] or exp != b["exp"] or now > exp or not hmac.compare_digest(sig, self._sign(tid, exp, b)):
            return None
        b["used"] = True
        self.asks.pop(b["check_id"], None)
        d = b["decision"]
        return Decision(d.recipe, "manual", d.check_id, d.cond_key, d.vmid, d.port, d.target)

    def forget_check(self, check_id):
        """The problem resolved: pending 'Run fix' offers for it expire."""
        tok = self.asks.pop(check_id, None)
        if tok:
            self.tokens.pop(tok.split(".")[0], None)
