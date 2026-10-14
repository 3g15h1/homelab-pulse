"""Turns raw source data into one JSON-ready snapshot of the lab, and keeps short history.

Pure helpers at the top (easy to test against fixtures); the threaded Collector at the bottom.
"""
import logging
import re
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor

import alerts as alerts_mod
import catalog
import discover
import early
import overrides as overrides_mod
import probes as probes_mod
import recipes as recipes_mod
import settings as settings_mod
import store as store_mod

log = logging.getLogger("pulse")

HISTORY_POINTS = 360          # 30 min at the 5 s fast-poll interval
PROBE_HISTORY = 40
DOWN_AFTER_FAILS = 2          # one dropped packet shouldn't paint a service red
BACKUP_STALE_H = 30


# ---------------------------------------------------------------- pure helpers

class RateTracker:
    """Cumulative byte counters -> bytes/second. A counter that goes backwards (guest restart)
    yields 0 for that interval instead of a negative spike. Proxmox refreshes these counters only
    every ~10 s (pvestatd) while we poll every 5 s, so an unchanged counter keeps the last rate and
    the rate is measured over the real refresh interval (otherwise it alternates 0 / double)."""

    STALE_S = 30  # unchanged for longer than this means genuinely idle

    def __init__(self):
        self.prev = {}   # key -> (counter, time of last change, last rate)

    def rate(self, key, value, now):
        last = self.prev.get(key)
        if last is None or value < last[0] or now <= last[1]:
            self.prev[key] = (value, now, 0.0)
            return 0.0
        if value == last[0]:
            if now - last[1] < self.STALE_S:
                return last[2]
            self.prev[key] = (value, now, 0.0)
            return 0.0
        r = (value - last[0]) / (now - last[1])
        self.prev[key] = (value, now, r)
        return r


def split_tags(raw):
    return [t for t in re.split(r"[;, ]+", raw or "") if t]


def build_guests(resources, meta, rates, now):
    """Guests from /cluster/resources, enriched with what discovery knows (meta[vmid]).
    Templates and guests tagged pulse-ignore are left out."""
    guests = []
    for r in resources:
        if r.get("type") not in ("lxc", "qemu") or r.get("template"):
            continue
        tags = split_tags(r.get("tags"))
        if "pulse-ignore" in (t.lower() for t in tags):
            continue
        vmid = int(r["vmid"])
        m = meta.get(vmid, {})
        running = r.get("status") == "running"
        name = r.get("name") or str(vmid)
        role, icon = m.get("role"), m.get("icon")
        if not role:
            role, icon = catalog.guess_from_name(name, None, r["type"])
        guests.append({
            "vmid": vmid, "type": r["type"], "name": name, "node": r.get("node"),
            "status": r.get("status", "unknown"), "running": running, "tags": tags,
            "role": role, "icon": icon or "box", "ip": m.get("ip"), "ips": list(m.get("ips", ())),
            "services": [f.view() for f in m.get("services", ())],
            "cpu": round(float(r.get("cpu") or 0), 4), "cores": r.get("maxcpu") or 0,
            "mem": r.get("mem") or 0, "maxmem": r.get("maxmem") or 0,
            "disk": r.get("disk") or 0, "maxdisk": r.get("maxdisk") or 0,
            "uptime": r.get("uptime") or 0,
            "net_in": round(rates.rate((vmid, "in"), r.get("netin") or 0, now)) if running else 0,
            "net_out": round(rates.rate((vmid, "out"), r.get("netout") or 0, now)) if running else 0,
        })
    guests.sort(key=lambda g: g["vmid"])
    return guests


def build_storage(resources, content_map=None):
    """-> ({node: [storage]}, [shared storage, listed once]). `content_map` is
    {storage id: content string} from /storage; marks backup storages."""
    content_map = content_map or {}
    per_node, shared = {}, {}
    for r in resources:
        if r.get("type") != "storage":
            continue
        contents = [c.strip() for c in content_map.get(r["storage"], "").split(",")]
        s = {"id": r["storage"], "used": r.get("disk") or 0, "total": r.get("maxdisk") or 0,
             "type": r.get("plugintype", ""), "ok": r.get("status") == "available",
             "for_backup": "backup" in contents}
        if r.get("shared"):
            shared.setdefault(s["id"], s)
        else:
            per_node.setdefault(r.get("node"), []).append(s)
    for v in per_node.values():
        v.sort(key=lambda s: s["id"])
    return per_node, sorted(shared.values(), key=lambda s: s["id"])


def build_disks(disks):
    out = []
    for d in disks:
        wear = d.get("wearout")
        out.append({"dev": d.get("devpath"), "model": d.get("model", "").replace("_", " ").strip(),
                    "type": d.get("type", ""), "size": d.get("size") or 0, "health": d.get("health", "UNKNOWN"),
                    # PVE's "wearout" is life *remaining* (the GUI's "Wearout" column shows 100 minus it)
                    "wear_used": 100 - wear if isinstance(wear, int | float) else None})
    return out


TASK_TEXT = {
    "vzstart": "Started", "qmstart": "Started", "vzshutdown": "Shut down", "qmshutdown": "Shut down",
    "vzstop": "Stopped", "qmstop": "Stopped", "vzreboot": "Rebooted", "qmreboot": "Rebooted",
    "vzcreate": "Created", "qmcreate": "Created", "vzdestroy": "Destroyed", "qmdestroy": "Destroyed",
}


def task_events(tasks, names):
    events = []
    for t in tasks:
        typ, ok = t.get("type", ""), t.get("status") == "OK"
        running = "endtime" not in t or not t.get("status")
        ts = t.get("endtime") or t.get("starttime") or 0
        if typ == "vzdump":
            if running:
                text, level = "Backup running", "info"
            elif ok:
                text, level = f"Backup finished ({_dur(t)})", "ok"
            else:
                text, level = f"Backup problem: {t.get('status', '')[:60]}", "bad"
        elif typ in TASK_TEXT:
            vmid = t.get("id", "")
            label = names.get(int(vmid), f"#{vmid}") if str(vmid).isdigit() else vmid
            text = f"{TASK_TEXT[typ]} {label}" + ("" if ok or running else f" — {t.get('status', '')[:50]}")
            level = "info" if ok or running else "bad"
        else:
            continue
        events.append({"ts": ts, "kind": "proxmox", "text": text, "level": level})
    return events


def _dur(t):
    s = max(0, (t.get("endtime") or 0) - (t.get("starttime") or 0))
    return f"{s // 60} min" if s >= 60 else f"{s} s"


_SIZE = {"B": 1, "KB": 1024, "MB": 1024 ** 2, "GB": 1024 ** 3, "TB": 1024 ** 4}


def parse_vzdump_log(lines):
    """vzdump job log -> {vmid: {ts, size, ok, error}}. Times come from the archive file name,
    which vzdump writes in the host's local time (same zone as this container)."""
    out, cur = {}, None
    for line in lines:
        if m := re.search(r"Starting Backup of VM (\d+)", line):
            cur = out.setdefault(int(m.group(1)), {"ts": None, "size": 0, "ok": False, "error": None})
        # only the archive being created: prune lines name older archives too
        elif m := re.search(r"creating vzdump archive .*vzdump-\w+-(\d+)-(\d{4})_(\d\d)_(\d\d)-(\d\d)_(\d\d)_(\d\d)", line):
            y, mo, d, h, mi, se = (int(x) for x in m.groups()[1:])
            entry = out.setdefault(int(m.group(1)), {"ts": None, "size": 0, "ok": False, "error": None})
            entry["ts"] = time.mktime((y, mo, d, h, mi, se, 0, 0, -1))
        elif (m := re.search(r"archive file size: ([\d.]+)\s*([KMGT]?B)", line)) and cur is not None:
            cur["size"] = int(float(m.group(1)) * _SIZE[m.group(2)])
        elif m := re.search(r"Finished Backup of VM (\d+)", line):
            out.setdefault(int(m.group(1)), {"ts": None, "size": 0, "error": None})["ok"] = True
        elif m := re.search(r"Backup of VM (\d+) failed - (.*)", line):
            out.setdefault(int(m.group(1)), {"ts": None, "size": 0})
            out[int(m.group(1))].update(ok=False, error=m.group(2)[:120])
    return out


def backup_summary(runs, per_vm, guests, now):
    """`runs` are the latest finished vzdump task per node, `per_vm` their parsed logs merged."""
    per_guest = []
    for g in guests:
        b = per_vm.get(g["vmid"])
        age_h = (now - b["ts"]) / 3600 if b and b.get("ts") else None
        per_guest.append({"vmid": g["vmid"], "name": g["name"], "ts": b.get("ts") if b else None,
                          "size": b.get("size", 0) if b else 0, "error": b.get("error") if b else None,
                          "fresh": bool(b and b.get("ok") and age_h is not None and age_h < BACKUP_STALE_H)})
    views = [{"node": r.get("node"), "start": r.get("starttime"), "end": r.get("endtime"),
              "status": r.get("status") or "running", "ok": r.get("status") == "OK"}
             for r in sorted(runs, key=lambda r: r.get("starttime") or 0)]
    return {
        "last_run": views[-1] if views else None,
        "runs": views,
        "guests": per_guest,
        "fresh": sum(1 for g in per_guest if g["fresh"]),
        "total_bytes": sum(b.get("size", 0) for b in per_vm.values()),
    }


# ---------------------------------------------------------------- probe state

class ProbeState:
    def __init__(self, spec):
        self.spec = spec
        self.fails = 0
        self.up = None            # None until the first result
        self.since = None
        self.latency = None
        self.detail = "waiting…"
        self.history = deque(maxlen=PROBE_HISTORY)

    def update(self, res, now):
        """Returns an event dict when the debounced up/down state flips, else None."""
        self.history.append(res.latency_ms if res.ok else None)
        self.fails = 0 if res.ok else self.fails + 1
        self.latency, self.detail = res.latency_ms, res.detail
        new_up = True if res.ok else (False if self.fails >= DOWN_AFTER_FAILS or self.up is None else self.up)
        if new_up == self.up:
            return None
        was = self.up
        self.up, self.since = new_up, now
        if was is None and new_up:
            return None  # first successful check isn't news
        name = self.spec["name"]
        return {"ts": now, "kind": "probe", "level": "ok" if new_up else "bad",
                "text": f"{name} is back" if new_up else f"{name} is down ({res.detail})"}

    def view(self, paused=False):
        s = self.spec
        return {"id": s["id"], "name": s["name"], "kind": s["kind"], "target": s.get("target"),
                "port": s.get("port"), "product": s.get("product"), "guest": s.get("guest"),
                "source": s.get("source", "override"), "paused": paused,
                "up": None if paused else self.up, "since": self.since,
                "latency_ms": self.latency, "detail": "guest stopped" if paused else self.detail,
                "history": list(self.history)}


# ---------------------------------------------------------------- alert conditions

STOP_TASKS = {"vzstop", "vzshutdown", "qmstop", "qmshutdown", "vzdestroy", "qmdestroy", "vzmigrate", "qmigrate",
              "vzsuspend", "qmsuspend", "qmpause"}
STOP_GRACE_S = 120      # a stop task this close to the stop explains it
STOP_SETTLE_S = 90      # wait this long so the task list (polled every 60 s) has caught up
FLAP_WINDOW_S = 3600    # count unexplained stops inside this window
FLAP_COUNT = 3          # ... this many -> the guest is flapping


def _stop_explained(tasks, vmid, ts):
    """True when a stop/shutdown/migrate task explains the stop at `ts`."""
    return any(t.get("type") in STOP_TASKS and str(t.get("id")) == str(vmid)
               and (t.get("starttime") or 0) - STOP_GRACE_S <= ts <= (t.get("endtime") or ts) + STOP_GRACE_S
               for t in tasks)


def build_conditions(snap, stopped, tasks, now, flap_hist=None):
    """What is wrong right now, as alert conditions (see alerts.py). `stopped` maps VMIDs that went
    from running to stopped to when that was seen; `tasks` is Proxmox's recent task list."""
    out = []
    guests = {g["vmid"]: g for g in snap.get("guests", [])}
    nodes = {n["name"] for n in snap.get("nodes", [])}
    for p in snap.get("probes", []):
        if p.get("up") is not False or p.get("paused"):
            continue
        if p.get("id") == "internet":
            out.append({"key": "net:internet", "kind": "net_down", "severity": "critical",
                        "title": "Internet is unreachable", "target": "internet", "node": None})
            continue
        if p.get("id") == "gateway":
            ip = (snap.get("router") or {}).get("ip") or "gateway"
            out.append({"key": "net:gateway", "kind": "gateway_down", "severity": "critical",
                        "title": f"Gateway {ip} is not answering", "target": "gateway", "node": None})
            continue
        if p.get("id") == "dns-lab":
            out.append({"key": "net:dns", "kind": "dns_broken", "severity": "warning",
                        "title": "Lab DNS is not resolving names", "target": "dns-lab", "node": None})
            continue
        tgt = p.get("target")
        g = guests.get(tgt) if isinstance(tgt, int) else None
        node = g["node"] if g else (tgt if tgt in nodes else None)
        name = f"{p['name']} on {p['guest'] or g['name']}" if (p.get("guest") or g) else p["name"]
        out.append({"key": f"check:{p['id']}", "kind": "service_down", "severity": "critical",
                    "title": f"{name} is down", "target": tgt, "node": node})
    for n in snap.get("nodes", []):
        if not n.get("online"):
            out.append({"key": f"node:{n['name']}", "kind": "node_offline", "severity": "critical",
                        "title": f"{n['name']} is offline", "target": n["name"], "node": n["name"]})
    pve = snap.get("sources", {}).get("pve", {})
    if pve.get("ok") is False:
        out.append({"key": "source:pve", "kind": "api_down", "severity": "critical",
                    "title": f"Pulse can't reach Proxmox ({(pve.get('error') or 'no answer')[:80]})",
                    "target": None, "node": None})
    for r in (snap.get("backups") or {}).get("runs", []):
        if not r.get("ok"):
            out.append({"key": f"backup:{r['node']}", "kind": "backup_failed", "severity": "critical",
                        "title": f"Backup on {r['node']} failed: {(r.get('status') or '')[:60]}",
                        "target": r["node"], "node": r["node"]})
    for vmid, ts in stopped.items():
        g = guests.get(vmid)
        if not g or g.get("running") or now - ts < STOP_SETTLE_S:
            continue
        if not _stop_explained(tasks, vmid, ts):
            out.append({"key": f"guest:{vmid}:stopped", "kind": "guest_stopped", "severity": "warning",
                        "title": f"{g['name']} stopped unexpectedly", "target": vmid, "node": g.get("node")})
    for vmid, times in (flap_hist or {}).items():
        recent = [t for t in times if t >= now - FLAP_WINDOW_S]
        if len([t for t in recent if not _stop_explained(tasks, vmid, t)]) < FLAP_COUNT:
            continue
        g = guests.get(vmid)
        if g and g.get("running"):      # a stopped guest gets guest_stopped instead: no doubles
            out.append({"key": f"guest:{vmid}:flapping", "kind": "guest_flapping", "severity": "warning",
                        "title": f"{g['name']} restarted {FLAP_COUNT} times in the last hour",
                        "target": vmid, "node": g.get("node")})
    return out


def diff_services(store, current, names, now):
    """Newly-appeared services -> conditions. `current`: {vmid: [(port, product)]} for running
    guests with fresh scans; `names`: {vmid: (name, node)} for all guests. Persists the baseline
    in the store; the very first run seeds silently. Stopped guests keep their baseline."""
    seen = store.get("seen_services")
    conds, new_seen = [], {}
    for vmid in sorted(names):
        key = str(vmid)
        if vmid in current:
            cur = sorted([port, product or ""] for port, product in current[vmid])
            new_seen[key] = cur
            if seen is not None:
                old_ports = {p for p, _ in seen.get(key, [])}
                name, node = names[vmid]
                for port, product in cur:
                    if port not in old_ports:
                        label = f"port {port}" + (f" ({product})" if product else "")
                        conds.append({"key": f"svc:{vmid}:{port}:new", "kind": "service_appeared",
                                      "severity": "warning", "title": f"New service on {name}: {label}",
                                      "target": vmid, "node": node})
        elif seen and key in seen:
            new_seen[key] = seen[key]
    store.put("seen_services", new_seen)
    return conds


def diff_ips(store, current, names, now):
    """Guest IP changes -> conditions. `current`: {vmid: ip or None}; `names`: {vmid: (name, node)}.
    Persists the baseline; first sight seeds silently; stopped guests keep their last IP."""
    last = store.get("last_ips") or {}
    conds, new_last = [], {}
    for vmid in sorted(names):
        key = str(vmid)
        ip = current.get(vmid)
        name, node = names[vmid]
        if ip:
            new_last[key] = ip
            old = last.get(key)
            if old and old != ip:
                conds.append({"key": f"guest:{vmid}:ip", "kind": "ip_changed", "severity": "warning",
                              "title": f"{name} changed IP from {old} to {ip}",
                              "target": vmid, "node": node})
        elif key in last:
            new_last[key] = last[key]
    store.put("last_ips", new_last)
    return conds


# ---------------------------------------------------------------- collector

class Collector:
    FAST, SLOW, PROBE = 5, 60, 15
    DISCOVERY_TICK, FULL_DISCOVERY, EARLY_DELAY = 15, 300, 45

    ALERTS = 15
    RRD_TTL = {"day": 60, "week": 300, "month": 1800, "year": 7200}
    STORAGE_HIST_EVERY = 1800

    def __init__(self, pve, pve_mode, net, probe_fn=probes_mod.run, overrides_path=None, ca_path=None,
                 clock=time.time, store=None, notifier=None, settings_loader=None, heal=None):
        self.pve, self.clock, self.probe_fn = pve, clock, probe_fn
        self.overrides_path, self.ca_path = overrides_path, ca_path
        self.ports = catalog.SCAN_PORTS
        self.cond = threading.Condition()
        self.version = 0
        self.rates = RateTracker()
        self.sources = {
            "pve": {"mode": pve_mode, "ok": None, "error": None, "updated": None},
            "probes": {"mode": "live" if pve_mode == "live" else "demo", "ok": None, "error": None, "updated": None},
            "discovery": {"mode": "auto", "ok": None, "error": None, "updated": None},
        }
        self.discoverer = discover.Discoverer(net)
        self.nodes, self.guests, self.resources = [], [], []
        self.node_ips, self.router = {}, None
        self.storage, self.shared_storage, self.disks = {}, [], {}
        self.zfs, self.node_updates, self.storage_content = {}, {}, {}
        self._updates_unsupported = False  # token lacks Sys.Modify; stop asking
        self.meta = {}              # vmid -> {ips, ip, tags, role, icon, services}
        self.agent_cache = {}
        self.pending = {}           # vmid -> time its early discovery is due
        self.prev_running = None    # vmid -> running, from the previous fast poll
        self.last_full = None
        self.ov, self.ov_error = {}, None
        self.backups, self.task_ev = None, []
        self.vzdump_logs = {}       # upid -> parsed log (finished logs never change)
        self.history = {}
        self.checks = {}            # id -> ProbeState, in plan order
        self._stop = threading.Event()
        self._probe_wake = threading.Event()   # set when new checks appear, so they're probed at once
        # 1.1: alerts, lasting history, early warnings
        self.store = store or store_mod.Store(":memory:", clock=clock)
        self.notifier = notifier
        self.settings_loader = settings_loader or (lambda: settings_mod.load(self.store))
        self.heal = heal            # HealEngine, or None when no heal gate is set up
        self.engine = alerts_mod.AlertEngine(self.store.load_alerts(), started=clock(), on_fire=self._on_fire)
        self._alert_lock = threading.Lock()     # engine state is touched by the alert loop and "Clear" requests
        self.events_log = deque(reversed(self.store.recent_events(50)), maxlen=50)   # oldest first
        self.stopped = {}           # vmid -> when it was seen going from running to stopped
        self.pending_conds = []     # discovery diffs waiting for the next alert poll
        self.flap_hist = {}         # vmid -> deque of unexplained stop timestamps
        self.tasks_raw = []
        self.storage_hist, self.storage_hist_at = {}, None
        self.early_state, self.attention = {}, []
        self.lab_name = "homelab"
        self.last_compact = None
        self.rrd_cache, self.uptime_cache = {}, (None, {})
        self.sources["store"] = {"mode": "memory" if self.store.path == ":memory:" else "sqlite",
                                 "ok": self.store.error is None, "error": self.store.error, "updated": None}
        self.sources["alerts"] = {"mode": "off", "ok": None, "error": None, "updated": None}
        self.sources["heal"] = {"mode": "off", "ok": None, "error": None, "updated": None}

    # -- polling steps (each callable directly from tests) --

    def poll_fast(self):
        now = self.clock()
        res = self.pve.resources()
        guests = build_guests(res, self.meta, self.rates, now)
        nodes = []
        for r in sorted((r for r in res if r.get("type") == "node"), key=lambda r: r["node"]):
            nodes.append(self._node_view(r, [g for g in guests if g["node"] == r["node"]]))
        per_node, shared = build_storage(res, self.storage_content)
        running = {g["vmid"]: g["running"] for g in guests}
        with self.cond:
            if self.prev_running is not None:      # a new guest, or one that just started: look soon
                for vmid, up in running.items():
                    if up and not self.prev_running.get(vmid):
                        self.pending[vmid] = now + self.EARLY_DELAY
                    if not up and self.prev_running.get(vmid):
                        self.stopped[vmid] = now
                        if not _stop_explained(self.tasks_raw, vmid, now):
                            hist = self.flap_hist.setdefault(vmid, deque())
                            hist.append(now)
                            while hist and hist[0] < now - FLAP_WINDOW_S:
                                hist.popleft()
            for vmid in [v for v in self.stopped if running.get(v, False) or v not in running]:
                del self.stopped[vmid]
            for vmid in [v for v in self.flap_hist if v not in running]:
                del self.flap_hist[vmid]
            self.prev_running = running
            self.resources, self.guests, self.nodes = res, guests, nodes
            self.storage, self.shared_storage = per_node, shared
            for n in nodes:
                self._push_history(n["name"], now, n["cpu"], n["mem"] / (n["maxmem"] or 1), n["net_in"], n["net_out"])
            for g in guests:
                self._push_history(g["vmid"], now, g["cpu"], g["mem"] / (g["maxmem"] or 1), g["net_in"], g["net_out"])
            self._ok("pve", now)

    def _node_view(self, r, guests):
        name, online = r["node"], r.get("status") == "online"
        view = {"name": name, "online": online, "ip": self.node_ips.get(name), "cpu": 0, "cpus": r.get("maxcpu") or 0,
                "model": "", "mem": 0, "maxmem": r.get("maxmem") or 0, "load": [], "uptime": 0, "pve": "",
                "kernel": "", "net_in": sum(g["net_in"] for g in guests), "net_out": sum(g["net_out"] for g in guests),
                "error": None}
        if not online:
            return view
        try:
            st = self.pve.node_status(name)
        except Exception as e:  # noqa: BLE001 - one node failing mustn't blank the others
            view["error"] = str(e)[:160]
            return view
        mem = st.get("memory", {})
        view.update(
            cpu=round(float(st.get("cpu") or 0), 4), cpus=st.get("cpuinfo", {}).get("cpus") or view["cpus"],
            model=st.get("cpuinfo", {}).get("model", ""), mem=mem.get("used", 0), maxmem=mem.get("total", 0),
            load=[float(x) for x in st.get("loadavg", [])[:3]], uptime=st.get("uptime") or r.get("uptime", 0),
            pve="".join(st.get("pveversion", "").split("/")[1:2]),      # pve-manager/9.2.20/<hash>
            kernel=(st.get("kversion", "").split() + ["", ""])[1])      # Linux 7.0.14-19-pve #1 SMP …
        return view

    def poll_slow(self):
        now = self.clock()
        self._load_overrides()
        try:
            status = self.pve.cluster_status()
            self.node_ips = {e["name"]: e.get("ip") for e in status if e.get("type") == "node"}
            cluster = next((e.get("name") for e in status if e.get("type") == "cluster"), None)
            self.lab_name = cluster or (next(iter(self.node_ips)) if len(self.node_ips) == 1 else "homelab")
        except Exception as e:  # noqa: BLE001
            log.warning("cluster status: %s", e)
        online = [n["name"] for n in self.nodes if n["online"]]
        for g in self.guests:
            self._refresh_ips(g, now)
        router = self._find_router(online)
        disks, runs, per_vm, zfs = {}, [], {}, {}
        try:
            self.storage_content = self.pve.storage_config()
        except Exception as e:  # noqa: BLE001 - older PVE or limited token; backup flag just stays off
            log.warning("storage config: %s", e)
        if not self._updates_unsupported:
            for node in online:
                try:
                    self.node_updates[node] = [
                        {"package": u.get("Package"), "version": u.get("Version"),
                         "old": u.get("OldVersion"), "origin": u.get("Origin") or ""}
                        for u in self.pve.node_updates(node)]
                except Exception as e:  # noqa: BLE001
                    if "403" in str(e) or "401" in str(e):
                        self._updates_unsupported = True
                        self.node_updates = {}
                        log.warning("PVE updates need Sys.Modify; not retrying")
                        break
                    log.warning("node %s updates: %s", node, e)
        for node in online:
            try:
                disks[node] = build_disks(self.pve.disks(node))
                zfs[node] = [{"name": z.get("name"), "health": (z.get("health") or "UNKNOWN").upper()}
                             for z in self.pve.zfs_pools(node)]
                done = sorted((r for r in self.pve.backup_runs(node) if r.get("endtime") and r.get("status")),
                              key=lambda r: r["starttime"])
            except Exception as e:  # noqa: BLE001 - keep the other nodes
                log.warning("node %s: %s", node, e)
                continue
            if done:
                last = dict(done[-1], node=node)
                if last["upid"] not in self.vzdump_logs:
                    self.vzdump_logs[last["upid"]] = parse_vzdump_log(x["t"] for x in self.pve.task_log(node, last["upid"]))
                runs.append(last)
                per_vm.update(self.vzdump_logs[last["upid"]])
        keep = {r["upid"] for r in runs}
        self.vzdump_logs = {k: v for k, v in self.vzdump_logs.items() if k in keep}
        tasks = {t["upid"]: t for t in self.pve.tasks() + runs if t.get("upid")}   # de-duplicate
        with self.cond:
            self.router, self.disks, self.zfs = router, disks, zfs
            self._apply_meta()
            names = {g["vmid"]: g["name"] for g in self.guests}
            self.backups = backup_summary(runs, per_vm, self.guests, now)
            self.task_ev = task_events(list(tasks.values()), names)
            self.tasks_raw = list(tasks.values())
            self._replan()
            self._ok("pve", now)

    def poll_discovery(self, force_full=False):
        now = self.clock()
        full = force_full or self.last_full is None or now - self.last_full >= self.FULL_DISCOVERY
        guests = list(self.guests)
        if full and not guests:
            return                               # Proxmox hasn't answered yet; try again next tick
        if full:
            chosen = guests
        else:
            due = {v for v, t in self.pending.items() if t <= now}
            chosen = [g for g in guests if g["vmid"] in due]
            if not chosen:
                return
            for g in chosen:
                self._refresh_ips(g, now)
        targets = [{"key": g["vmid"], "ip": self.meta.get(g["vmid"], {}).get("ip"), "name": g["name"],
                    "running": g["running"], "scan": not self.meta.get(g["vmid"], {}).get("tags", {}).get("noscan")}
                   for g in chosen]
        if full and self.router and self.router.get("ip"):
            targets.append({"key": "router", "ip": self.router["ip"], "name": self.router.get("name") or "Router",
                            "running": True, "scan": True, "ports": (80, 443)})
        scan = self.ov.get("scan", {})
        ports = tuple(p for p in dict.fromkeys(self.ports + tuple(scan.get("ports_add", ())))
                      if p not in scan.get("ports_remove", ()))
        events = self.discoverer.run(targets, ports)
        if full:
            self.discoverer.forget(keep={g["vmid"] for g in guests} | {"router"})
            self.last_full = now
        with self.cond:
            for t in targets:
                self.pending.pop(t["key"], None)
            for ev in events:
                self._add_event(ev)
            self._apply_meta()
            self._replan()
            self._ok("discovery", now)
            if self.ov_error:
                self.sources["discovery"].update(ok=False, error=self.ov_error)
        if full:
            names = {g["vmid"]: (g["name"], g.get("node")) for g in guests}
            svc = {g["vmid"]: [(f.port, f.product) for f in self.discoverer.services(g["vmid"])]
                   for g in guests if g["running"]}
            ips = {g["vmid"]: self.meta.get(g["vmid"], {}).get("ip") for g in guests if g["running"]}
            new_conds = diff_services(self.store, svc, names, now) + diff_ips(self.store, ips, names, now)
            with self.cond:
                self.pending_conds.extend(new_conds)
        if full and self.heal:                  # after the checks are published: this takes a while over SSH
            self.heal.learn([{"check_id": f"{g['vmid']}:{f.port}", "vmid": g["vmid"], "port": f.port,
                              "running": g["running"]}
                             for g in guests for f in self.discoverer.services(g["vmid"])])

    def poll_probes(self, pool=None):
        with self.cond:
            running = {g["vmid"]: g["running"] for g in self.guests}
            states = list(self.checks.values())
        active = [s for s in states if running.get(s.spec.get("target"), True)]
        own = pool is None
        pool = pool or ThreadPoolExecutor(max_workers=8)
        try:
            results = list(pool.map(lambda s: self.probe_fn(s.spec), active))
        finally:
            if own:
                pool.shutdown()
        now = self.clock()
        with self.cond:
            for st, r in zip(active, results):
                ev = st.update(r, now)
                if ev:
                    self._add_event(ev)
            self._ok("probes", now)
        self.store.record_checks([(st.spec["id"], st.up, st.latency) for st in active], now)

    def poll_alerts(self):
        """Conditions + early warnings -> alert engine -> notifier. Persists state and events."""
        now = self.clock()
        cfg = self.settings_loader()
        snap = self.snapshot()
        if self.storage_hist_at is None or now - self.storage_hist_at >= self.STORAGE_HIST_EVERY:
            self._refresh_storage_history(snap)
            self.storage_hist_at = now
        with self.cond:
            flap = {v: deque(t) for v, t in self.flap_hist.items()}
        conds = build_conditions(snap, dict(self.stopped), self.tasks_raw, now, flap)
        conds += early.evaluate(snap, self.storage_hist, cfg["warnings"], self.early_state, now)
        with self.cond:
            if self.pending_conds:
                conds += self.pending_conds
                self.pending_conds = []
        mutes = self.store.list_mutes(now)
        self._heal_cfg = cfg.get("heal", {"mode": "off"})
        heal_events = []
        with self._alert_lock:
            if self.heal:
                up = {sid: st.up for sid, st in self.checks.items()}
                present = {c["key"] for c in conds}
                for o in self.heal.poll(now, lambda cid: up.get(cid) is True or (cid.startswith("warn:") and cid not in present)):
                    if o.kind == "healed":
                        self.engine.healed(o.cond_key, o.text)
                    elif o.kind == "failed":
                        self.engine.annotate(o.cond_key, o.text)
                        heal_events.append({"ts": now, "kind": "heal", "level": "warn", "text": f"Fix didn't help: {o.text}"})
                    else:
                        heal_events.append({"ts": now, "kind": "heal", "level": "info", "text": f"Dry run: {o.text}"})
            notes = self.engine.process(conds, now, cfg["alerts"], mutes, self.lab_name)
            if self.heal:
                for key in self.engine.recovered:
                    self.heal.forget_check(key[len("check:"):] if key.startswith("check:") else key)
            engine_events = list(self.engine.events)
            states = {k: dict(v) if isinstance(v, dict) else v for k, v in self.engine.states.items()}
            self.store.save_alerts(self.engine.states)
        for m in mutes:                             # "until it recovers" mutes end with their problem
            if m["until_recovered"] and not any(alerts_mod.AlertEngine._muted(c["key"], c, [m]) for c in conds):
                self.store.remove_mute(m["target"])
        if self.heal and self.notifier:         # offer "Run fix" on alerts waiting for approval
            base = getattr(self.notifier, "public_url", "/")
            for n in notes:
                for it in n.items:
                    cid = it["key"][len("check:"):] if it["key"].startswith("check:") else it["key"]
                    tok = self.heal.pending_token(cid)
                    if tok and it["state"] in ("fire", "repeat"):
                        name = self.heal.asked_recipe_name(cid)
                        it["actions"] = [{"id": tok, "title": f"Run fix: {name}", "url": f"{base.rstrip('/')}/api/heal/run/{tok}"}]
        if self.notifier:
            for n in notes:
                self.notifier.enqueue(n, cfg["notify"])
        if self.last_compact is None or now - self.last_compact >= 3600:
            self.store.compact(now)
            self.last_compact = now
        channels = [k for k in ("webhook", "ntfy") if cfg["notify"][k]["enabled"]]
        last = getattr(self.notifier, "last", None)
        attention = []
        for c in conds:
            st = states.get(c["key"], {})
            attention.append({"key": c["key"], "kind": c["kind"], "title": c["title"], "severity": c["severity"],
                              "state": st.get("state", "pending"), "target": c.get("target"),
                              "muted": alerts_mod.AlertEngine._muted(c["key"], c, mutes)})
        attention.sort(key=lambda a: (-alerts_mod.RANK[a["severity"]], a["muted"], a["title"]))
        with self.cond:
            for ev in engine_events + heal_events:
                self._add_event(ev)
            hc = getattr(self, "_heal_cfg", {"mode": "off"})
            self.sources["heal"].update(mode=hc.get("mode", "off") if self.heal else "off", updated=now,
                                        ok=None if not self.heal else self.heal.gate_error is None,
                                        error=self.heal.gate_error if self.heal else None)
            self.attention = attention
            self.sources["alerts"].update(mode="+".join(channels) or "off", updated=now,
                                          ok=None if not last else last["ok"],
                                          error=None if not last or last["ok"] else f"{last['channel']}: {last['error']}")
            self.sources["store"].update(ok=self.store.error is None, error=self.store.error, updated=now)
            self.version += 1
            self.cond.notify_all()

    def _on_fire(self, key, cond, now):
        """Alert engine hook: a condition just started firing. Try a first-response fix; return how
        long to hold the notification while it runs (None = send now)."""
        if not self.heal:
            return None
        cfg = getattr(self, "_heal_cfg", None) or self.settings_loader().get("heal", {"mode": "off"})
        tgt = cond.get("target")
        guest = next((g for g in self.guests if g["vmid"] == tgt), None) if isinstance(tgt, int) else None
        if not guest:
            return None
        check = None
        if cond["kind"] == "service_down":
            st = self.checks.get(key[len("check:"):])
            if not st:
                return None
            check = {"id": st.spec["id"], "product": st.spec.get("product"), "port": st.spec.get("port")}
        node = next((n for n in self.nodes if n["name"] == guest["node"]), {})
        ctx = {"running": guest["running"], "node_online": node.get("online", False),
               "api_ok": self.sources["pve"]["ok"] is not False, "muted": False}
        g = {"vmid": guest["vmid"], "type": guest["type"], "tags": guest.get("tags", []), "running": guest["running"]}
        try:
            d = self.heal.decide(cond, check, g, cfg, ctx)
            return self.heal.start(d, now) if d else None
        except Exception as e:  # noqa: BLE001 - a healing bug must never swallow an alert
            log.warning("self-healing: %s", e)
            return None

    def heal_overview(self):
        """For the settings page: mode, gate state, recipes (with the checks each would handle now)
        and recent runs. Admin-only."""
        cfg = self.settings_loader().get("heal", {"mode": "off", "recipes": {}})
        if not self.heal:
            return {"mode": "off", "gate": {"ok": False, "error": "no heal gate installed (install.sh --enable-heal)"},
                    "recipes": [], "history": [], "asks": []}
        try:
            version = self.heal.gate.version()
        except Exception as e:  # noqa: BLE001
            version = {"ok": False, "error": str(e)}
        guests = {g["vmid"]: g for g in self.guests}
        targets = []
        for st in list(self.checks.values()):
            if isinstance(st.spec.get("target"), int) and st.spec.get("port"):
                t = self.store.get_target(st.spec["id"]) or {}
                targets.append({"check_id": st.spec["id"], "name": st.spec["name"], "guest": st.spec.get("guest"),
                                "unit": t.get("unit"), "container": t.get("container"), "override": t.get("override")})
        recs = []
        for r in self.heal.recipes():
            matches = []
            for st in list(self.checks.values()):
                g = guests.get(st.spec.get("target")) if isinstance(st.spec.get("target"), int) else None
                if not g or r.get("errors"):
                    continue
                cond = {"key": f"check:{st.spec['id']}", "kind": "service_down"}
                check = {"id": st.spec["id"], "product": st.spec.get("product"), "port": st.spec.get("port")}
                guest = {"vmid": g["vmid"], "type": g["type"], "tags": g.get("tags", [])}
                if recipes_mod.matches(r, cond, check, guest):
                    tgt = self.heal.target_for(st.spec["id"]) or {}
                    kind = r.get("do", {}).get("restart")
                    if (kind == "unit" and not tgt.get("unit")) or (kind == "container" and not tgt.get("container")):
                        continue
                    matches.append(st.spec["id"])
            recs.append(dict(r, matches=matches, mode=cfg.get("recipes", {}).get(r["id"], "default")))
        return {"mode": cfg.get("mode", "off"),
                "gate": {"ok": bool(version.get("ok")) and self.heal.gate_error is None,
                         "error": version.get("error") or self.heal.gate_error,
                         "version": version.get("version"), "enabled": version.get("enabled"),
                         "budget_per_hour": version.get("budget_per_hour")},
                "recipes": recs, "history": self.store.heal_runs(50),
                "asks": [{"check_id": cid, "recipe": self.heal.asked_recipe_name(cid),
                          "recipe_id": self.heal.asked_recipe_id(cid)} for cid in sorted(self.heal.asks)],
                "targets": targets}

    def heal_decision(self, recipe_id, check_id, mode):
        """A Decision for a manual run or dry-run test from the settings page."""
        import heal as heal_mod
        r = next((r for r in self.heal.recipes() if r["id"] == recipe_id), None)
        st = self.checks.get(check_id)
        if not r or not st or not isinstance(st.spec.get("target"), int):
            return None
        target = self.heal.target_for(check_id) or {}
        return heal_mod.Decision(r, mode, check_id, f"check:{check_id}", st.spec["target"], st.spec.get("port"), target)

    def clear_alert(self, key):
        m = re.fullmatch(r"guest:(\d+):stopped", key)
        if m:
            self.stopped.pop(int(m.group(1)), None)
        with self._alert_lock:
            self.engine.clear(key)
            self.store.save_alerts(self.engine.states)

    def _refresh_storage_history(self, snap):
        hist = dict(self.storage_hist)
        targets = [(n["name"], s["id"], n["name"]) for n in snap["nodes"] if n["online"] for s in n["storage"]]
        first = next((n["name"] for n in snap["nodes"] if n["online"]), None)
        if first:
            targets += [("*", s["id"], first) for s in snap.get("shared_storage", [])]
        for key_node, sid, node in targets:
            try:
                hist[(key_node, sid)] = [(p["time"], p.get("used")) for p in self.pve.storage_rrd(node, sid, "month")
                                         if p.get("used") is not None]
            except Exception as e:  # noqa: BLE001 - no forecast for this one; % rules still work
                log.debug("storage history %s/%s: %s", node, sid, e)
        self.storage_hist = hist

    def rrd_series(self, key, rng):
        """Long-range history for the drawer, from Proxmox's RRD. key: VMID or node name."""
        if rng not in self.RRD_TTL:
            return None
        now = self.clock()
        hit = self.rrd_cache.get((key, rng))
        if hit and now - hit[0] < self.RRD_TTL[rng]:
            return hit[1]
        g = next((g for g in self.guests if g["vmid"] == key), None) if isinstance(key, int) else None
        try:
            if g:
                pts = self.pve.rrd(g["node"], g["type"], g["vmid"], rng)
                mem = [(p.get("mem") or 0) / (p.get("maxmem") or 1) for p in pts]
            elif any(n["name"] == key for n in self.nodes):
                pts = self.pve.node_rrd(key, rng)
                mem = [(p.get("memused") or 0) / (p.get("memtotal") or 1) for p in pts]
            else:
                return None
        except Exception as e:  # noqa: BLE001
            log.debug("rrd %s %s: %s", key, rng, e)
            return None
        series = {"t": [p.get("time") for p in pts], "cpu": [round(p.get("cpu") or 0, 4) for p in pts],
                  "mem": [round(m, 4) for m in mem], "net_in": [round(p.get("netin") or 0) for p in pts],
                  "net_out": [round(p.get("netout") or 0) for p in pts]}
        self.rrd_cache[(key, rng)] = (now, series)
        return series

    def uptime(self):
        now = self.clock()
        at, data = self.uptime_cache
        if at is None or now - at >= 60:
            data = self.store.uptime(now)
            self.uptime_cache = (now, data)
        return data

    def _add_event(self, ev):
        self.events_log.append(ev)
        try:
            self.store.add_event(ev)
        except Exception as e:  # noqa: BLE001 - the feed still works from memory
            log.warning("event not stored: %s", e)

    # -- discovery plumbing (call with or without the lock; they only touch their own fields) --

    def _load_overrides(self):
        try:
            self.ov, self.ov_error = overrides_mod.load(self.overrides_path) if self.overrides_path else {}, None
        except overrides_mod.OverrideError as e:
            if str(e) != self.ov_error:
                log.error("overrides: %s", e)
            self.ov, self.ov_error = {}, str(e)

    def _tags_for(self, vmid):
        r = next((r for r in self.resources if r.get("vmid") == vmid), {})
        tags = overrides_mod.parse_tags(split_tags(r.get("tags")))
        file_ip = self.ov.get("guests", {}).get(str(vmid), {}).get("ip")
        if file_ip and "ip" not in tags:
            tags["ip"] = file_ip
        return tags

    def _refresh_ips(self, g, now):
        tags = self._tags_for(g["vmid"])
        ips = discover.guest_ips(self.pve, g, tags, self.agent_cache, now)
        m = self.meta.setdefault(g["vmid"], {})
        m.update(tags=tags, ips=ips, ip=discover.pick_primary(ips, self.node_ips.get(g["node"])))

    def _find_router(self, online):
        ov = self.ov.get("router", {})
        ip = ov.get("ip")
        for node in online if not ip else ():
            try:
                ip = next((i["gateway"] for i in self.pve.node_network(node) if i.get("gateway")), None)
            except Exception:  # noqa: BLE001
                ip = None
            if ip:
                break
        return {"name": ov.get("name", "Router"), "ip": ip} if ip else None

    def _apply_meta(self):
        """Role/icon/services per guest. Precedence: tag, overrides.json, discovery, name guess."""
        file_guests = self.ov.get("guests", {})
        for g in self.guests:
            m = self.meta.setdefault(g["vmid"], {})
            found = self.discoverer.services(g["vmid"])
            role, icon = discover.classify(found, g["name"], None, g["type"])
            fg, tags = file_guests.get(str(g["vmid"]), {}), m.get("tags", {})
            m.update(services=found, role=tags.get("role") or fg.get("role") or role,
                     icon=tags.get("icon") or fg.get("icon") or icon)
            g.update(role=m["role"], icon=m["icon"], ip=m.get("ip"), ips=list(m.get("ips", ())),
                     services=[f.view() for f in found])

    def _replan(self):
        guests = [{"vmid": g["vmid"], "name": g["name"], "ip": self.meta.get(g["vmid"], {}).get("ip")}
                  for g in self.guests]
        services = {k: self.discoverer.services(k) for k in list(self.discoverer.known)}
        nodes = [{"name": n["name"], "ip": self.node_ips.get(n["name"])} for n in self.nodes]
        specs = discover.plan_checks(services, guests, self.router, nodes, self.ov, self.ca_path)
        new = {}
        for spec in specs:
            st = self.checks.get(spec["id"]) or ProbeState(spec)
            st.spec = spec
            new[spec["id"]] = st
        if set(new) - set(self.checks):
            self._probe_wake.set()
        self.checks = new

    # -- plumbing --

    def _push_history(self, key, now, cpu, memf, nin, nout):
        h = self.history.setdefault(key, deque(maxlen=HISTORY_POINTS))
        h.append((round(now), round(cpu, 4), round(memf, 4), round(nin), round(nout)))

    def _ok(self, src, now):
        s = self.sources[src]
        s.update(ok=True, error=None, updated=now)
        self.version += 1
        self.cond.notify_all()

    def _fail(self, src, err):
        with self.cond:
            self.sources[src].update(ok=False, error=str(err)[:160])
            self.version += 1
            self.cond.notify_all()

    def _loop(self, src, step, every):
        while not self._stop.is_set():
            try:
                step()
            except Exception as e:  # noqa: BLE001 - shown on the dashboard, loop keeps going
                log.warning("%s: %s", step.__name__, e)
                self._fail(src, e)
            self._stop.wait(every)

    def start(self):
        for src, step in (("pve", self.poll_fast), ("pve", self.poll_slow)):
            try:
                step()   # so discovery and the first checks already know the guests
            except Exception as e:  # noqa: BLE001
                self._fail(src, e)
        jobs = [("pve", self.poll_fast, self.FAST, self.FAST), ("pve", self.poll_slow, self.SLOW, self.SLOW),
                ("discovery", self.poll_discovery, self.DISCOVERY_TICK, 0)]    # fast/slow just ran above
        for src, step, every, delay in jobs:
            threading.Thread(target=self._delayed_loop, args=(src, step, every, delay), daemon=True,
                             name=step.__name__).start()
        threading.Thread(target=self._probe_loop, daemon=True, name="poll_probes").start()
        threading.Thread(target=self._delayed_loop, args=("alerts", self.poll_alerts, self.ALERTS, 5),
                         daemon=True, name="poll_alerts").start()

    def _delayed_loop(self, src, step, every, delay):
        if not self._stop.wait(delay):
            self._loop(src, step, every)

    def _probe_loop(self):
        while not self._stop.is_set():
            self._probe_wake.clear()
            try:
                self.poll_probes()
            except Exception as e:  # noqa: BLE001
                self._fail("probes", e)
            self._probe_wake.wait(self.PROBE)

    def stop(self):
        self._stop.set()

    def history_for(self, key):
        """key: VMID (int) or node name. None if unknown."""
        with self.cond:
            if key not in self.history:
                return None
            pts = list(self.history[key])
        return {"t": [p[0] for p in pts], "cpu": [p[1] for p in pts], "mem": [p[2] for p in pts],
                "net_in": [p[3] for p in pts], "net_out": [p[4] for p in pts]}

    def snapshot(self):
        now = self.clock()
        with self.cond:
            running = {g["vmid"]: g["running"] for g in self.guests}
            nodes = []
            for n in self.nodes:
                hist = [p[1] for p in list(self.history.get(n["name"], ()))[-120:]]
                nodes.append(dict(n, ip=self.node_ips.get(n["name"]), cpu_history=hist,
                                  storage=list(self.storage.get(n["name"], ())),
                                  disks=list(self.disks.get(n["name"], ())),
                                  zfs=list(self.zfs.get(n["name"], ())),
                                  updates=self.node_updates.get(n["name"])))
            events = sorted(self.task_ev + list(self.events_log), key=lambda e: -e["ts"])[:30]
            return {
                "version": self.version, "now": now, "router": self.router,
                "sources": {k: dict(v) for k, v in self.sources.items()},
                "nodes": nodes,
                "guests": [dict(g) for g in self.guests],
                "shared_storage": list(self.shared_storage),
                "backups": self.backups,
                "probes": [st.view(paused=not running.get(st.spec.get("target"), True)) for st in self.checks.values()],
                "events": events,
                "attention": list(self.attention),
                "heal": {"mode": self.sources["heal"]["mode"],
                         "asks": sorted(self.heal.asks) if self.heal else []},
            }
