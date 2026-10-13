"""The alert state machine: conditions in, notifications out. Pure; no I/O, no clock of its own.

A condition is {key, kind, severity, title, target, node?} that is true *right now*. Per key the
engine moves pending -> firing -> (gone). It debounces, groups what happens close together into one
message, holds non-critical messages during quiet hours, respects mutes, and keeps all of that in a
JSON-serialisable `states` dict so a restart doesn't re-send anything.
"""
import re
import time
from dataclasses import dataclass, field

IMMEDIATE = {"node_offline", "guest_stopped", "backup_failed", "warning"}
API_DELAY_S = 120
MAX_LINES = 10
RANK = {"critical": 3, "warning": 2, "info": 1}


@dataclass
class Notification:
    title: str
    message: str
    severity: str
    state: str                     # fire | resolve | repeat | update | summary | test
    items: list = field(default_factory=list)
    ts: float = 0.0


def _minutes(hhmm):
    h, m = hhmm.split(":")
    return int(h) * 60 + int(m)


def in_quiet(quiet, now):
    if not quiet.get("enabled"):
        return False
    lt = time.localtime(now)
    cur, start, end = lt.tm_hour * 60 + lt.tm_min, _minutes(quiet["start"]), _minutes(quiet["end"])
    return start <= cur < end if start <= end else (cur >= start or cur < end)


def duration(seconds):
    m = int(seconds // 60)
    if m < 60:
        return f"{max(m, 1)} min"
    if m < 48 * 60:
        return f"{m // 60} h {m % 60} min" if m % 60 else f"{m // 60} h"
    return f"{m // 1440} days"


class AlertEngine:
    def __init__(self, saved, started, warmup_s=60):
        self.states = dict(saved or {})
        self.states.setdefault("_outbox", {"opened": None, "items": []})
        self.states.setdefault("_quiet", [])
        self.started, self.warmup_s = started, warmup_s
        self.events = []           # activity events from the latest process() call
        self.recovered = set()     # keys that resolved in the latest call (for until-recovered mutes)

    def clear(self, key):
        self.states.pop(key, None)

    @staticmethod
    def _muted(key, c, mutes):
        names = {key}
        if isinstance(c.get("target"), int):
            names.add(f"guest:{c['target']}")
        if c.get("node"):
            names.add(f"node:{c['node']}")
        return any(m["target"] in names for m in mutes)

    def _delay(self, kind, cfg):
        if kind in IMMEDIATE:
            return 0
        return API_DELAY_S if kind == "api_down" else cfg["down_after_s"]

    def _item(self, st, key, state, now):
        return {"key": key, "title": st["title"], "severity": "info" if state == "resolve" else st["severity"],
                "state": state, "since": st["since"], "kind": st["kind"], "node": st.get("node"),
                "duration": now - st["since"] if state == "resolve" else None}

    def _event(self, st, key, state, now):
        if state == "fire":
            level, text = ("bad" if st["severity"] == "critical" else "warn"), st["title"]
        else:
            level, text = "ok", f"Resolved: {st['title']} (after {duration(now - st['since'])})"
        self.events.append({"ts": now, "kind": "alert", "level": level, "text": text, "key": key})

    def process(self, conditions, now, cfg, mutes, lab):
        self.events, self.recovered = [], set()
        items = []
        present = {c["key"]: c for c in conditions if cfg["kinds"].get(c["kind"], True)}
        for key, c in present.items():
            st = self.states.get(key)
            muted = self._muted(key, c, mutes)
            if st is None:
                st = self.states[key] = {"state": "pending", "kind": c["kind"], "severity": c["severity"],
                                         "title": c["title"], "target": c.get("target"), "node": c.get("node"),
                                         "since": now, "sent": False, "last_sent": None}
            escalated = st["state"] == "firing" and RANK[c["severity"]] > RANK[st["severity"]]
            st.update(severity=c["severity"], title=c["title"], target=c.get("target"), node=c.get("node"))
            if st["state"] == "pending" and now - st["since"] >= self._delay(c["kind"], cfg):
                st["state"] = "firing"
                self._event(st, key, "fire", now)
                if not muted:
                    items.append(self._item(st, key, "fire", now))
                    st.update(sent=True, last_sent=now)
            elif st["state"] == "firing" and not muted:
                if not st["sent"] or escalated:          # mute ended, or got worse
                    items.append(self._item(st, key, "fire", now))
                    st.update(sent=True, last_sent=now)
                elif cfg["repeat_every_s"] and now - st["last_sent"] >= cfg["repeat_every_s"]:
                    items.append(self._item(st, key, "repeat", now))
                    st["last_sent"] = now
        warming = now < self.started + self.warmup_s
        for key in [k for k in self.states if not k.startswith("_") and k not in present]:
            st = self.states[key]
            if st["state"] == "pending":
                del self.states[key]
                continue
            if warming:
                continue                                  # checks may not be rediscovered yet
            del self.states[key]
            self.recovered.add(key)
            self._event(st, key, "resolve", now)
            if st["sent"] and cfg["send_recovery"] and not self._muted(key, st, mutes):
                items.append(self._item(st, key, "resolve", now))
        return self._deliver(items, now, cfg, lab)

    # -- grouping and quiet hours --

    def _deliver(self, items, now, cfg, lab):
        box = self.states["_outbox"]
        if items:
            if box["opened"] is None:
                box["opened"] = now
            box["items"] += items
        out = []
        if box["items"] and now - box["opened"] >= cfg["group_window_s"]:
            batch, box["items"], box["opened"] = box["items"], [], None
            quiet = in_quiet(cfg["quiet"], now)
            send = []
            for it in batch:
                held = quiet and (it["severity"] != "critical" or cfg["quiet"]["critical_too"])
                if not held:
                    send.append(it)
                elif it["state"] == "resolve":
                    queued = [q for q in self.states["_quiet"] if q["key"] == it["key"] and q["state"] == "fire"]
                    if queued:
                        queued[-1]["resolved"] = True
                    else:
                        self.states["_quiet"].append(it)
                else:
                    self.states["_quiet"].append(it)
            if send:
                out.append(self._build(send, now, lab))
        if self.states["_quiet"] and not in_quiet(cfg["quiet"], now):
            held, self.states["_quiet"] = self.states["_quiet"], []
            n = len(held)
            lines = [f"• {it['title']}" + (" (resolved)" if it.get("resolved") or it["state"] == "resolve" else "")
                     for it in held]
            out.append(Notification(f"While you were away: {n} alert{'s' if n != 1 else ''}", self._lines(lines),
                                    max((it["severity"] for it in held), key=RANK.get), "summary", held, now))
        return out

    @staticmethod
    def _lines(lines):
        extra = len(lines) - MAX_LINES
        return "\n".join(lines[:MAX_LINES] + ([f"…and {extra} more"] if extra > 0 else []))

    def _build(self, items, now, lab):
        states = {it["state"] for it in items}
        severity = max((it["severity"] for it in items), key=RANK.get)

        def line(it):
            if it["state"] == "resolve":
                subject = re.sub(r" (is down|is offline|stopped unexpectedly)$", "", it["title"])
                return f"{subject} is back after {duration(it['duration'])}"
            return f"Still: {it['title']}" if it["state"] == "repeat" else it["title"]

        if len(items) == 1:
            it = items[0]
            return Notification(line(it), line(it), severity, it["state"], items, now)
        state = states.pop() if len(states) == 1 else "update"
        nodes = {it.get("node") for it in items}
        all_down = all(it["kind"] == "service_down" for it in items) and len(nodes) == 1 and None not in nodes
        n = len(items)
        if all_down and state == "fire":
            title = f"{n} services down on {nodes.pop()}"
        elif all_down and state == "resolve":
            title = f"{n} services back on {nodes.pop()}"
        elif state == "resolve":
            title = f"{n} problems resolved on {lab}"
        else:
            title = f"{n} problems on {lab}"
        return Notification(title, self._lines([f"• {line(it)}" for it in items]), severity, state, items, now)
