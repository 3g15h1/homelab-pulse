"""MCP (Model Context Protocol) endpoint: lets an AI assistant read the lab through Pulse.

POST /mcp speaks JSON-RPC 2.0 the way MCP's "Streamable HTTP" transport expects, answering every request
with one JSON reply (no SSE, no sessions). The tools are read-only views of the same snapshot the dashboard
shows, so they can never change anything. Who may call them follows the dashboard's own rule (open, or a
sign-in / view link when the dashboard needs one); see server.py.
"""
import json
import time

PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
GB = 1024 ** 3

TOOLS = [
    {"name": "lab_overview",
     "description": "One-call summary of the whole homelab: each Proxmox host (online, CPU, RAM, storage), "
                    "how many guests run, failing health checks, active alerts and last night's backups. "
                    "Start here for 'is everything OK?' questions.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "list_guests",
     "description": "List the VMs and containers with status, host, IP, role, CPU and memory use.",
     "inputSchema": {"type": "object", "properties": {
         "status": {"type": "string", "enum": ["all", "running", "stopped"], "default": "all"},
         "host": {"type": "string", "description": "Only guests on this Proxmox node or host label"}}}},
    {"name": "guest_details",
     "description": "Everything Pulse knows about one guest: status, resources, IPs, services, its health "
                    "checks, its last backup and recent events about it.",
     "inputSchema": {"type": "object", "required": ["guest"], "properties": {
         "guest": {"type": "string", "description": "Guest name or VMID, e.g. 'nextcloud' or '105'"}}}},
    {"name": "health_checks",
     "description": "The service health checks Pulse runs (web apps, DNS, MQTT, ...) and whether each answers.",
     "inputSchema": {"type": "object", "properties": {
         "only_failing": {"type": "boolean", "default": False}}}},
    {"name": "alerts",
     "description": "Active alerts and early warnings (things about to break, e.g. a disk filling up), "
                    "most severe first. Muted ones are marked.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "backups",
     "description": "Proxmox backups: the last backup job runs and each guest's latest backup (age, size, "
                    "whether it's fresh).",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "recent_events",
     "description": "What happened recently: guests started/stopped/created/destroyed, backups, checks going "
                    "down or up, alerts.",
     "inputSchema": {"type": "object", "properties": {
         "hours": {"type": "number", "default": 24, "minimum": 1, "maximum": 168},
         "limit": {"type": "integer", "default": 50, "minimum": 1, "maximum": 200}}}},
    {"name": "storage_and_disks",
     "description": "Storage pools (used/total) and physical disks (SMART health, wear) on every host.",
     "inputSchema": {"type": "object", "properties": {}}},
]
for _t in TOOLS:
    _t["annotations"] = {"readOnlyHint": True, "openWorldHint": False}


class ToolError(Exception):
    pass


def _when(ts):
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts)) if ts else None


def _gb(n):
    return round(n / GB, 1) if n else 0


def _pct(used, total):
    return round(100 * used / total) if total else None


def _guest_row(g):
    return {"vmid": g.get("pve_vmid", g.get("vmid")), "name": g.get("name"), "type": g.get("type"),
            "host": g.get("host"), "node": g.get("node"), "status": g.get("status"), "ip": g.get("ip"),
            "role": g.get("role"), "cpu_pct": round(100 * (g.get("cpu") or 0)),
            "mem_gb": _gb(g.get("mem")), "maxmem_gb": _gb(g.get("maxmem")),
            "uptime_h": round((g.get("uptime") or 0) / 3600, 1)}


def _check_row(p):
    return {"name": p.get("name"), "target": p.get("target"), "port": p.get("port"), "kind": p.get("kind"),
            "up": p.get("up"), "paused": p.get("paused"), "since": _when(p.get("since")),
            "latency_ms": p.get("latency_ms"), "detail": p.get("detail") or None}


def _find_guest(snap, ref):
    ref = str(ref).strip().lower()
    for g in snap.get("guests", []):
        ids = {str(g.get("vmid")), str(g.get("pve_vmid"))}
        if ref in ids or ref == str(g.get("name", "")).lower():
            return g
    hits = [g for g in snap.get("guests", []) if ref and ref in str(g.get("name", "")).lower()]
    if len(hits) == 1:
        return hits[0]
    names = ", ".join(sorted(str(g.get("name")) for g in hits)) if hits else "none"
    raise ToolError(f"no single guest matches {ref!r} (matches: {names}); use list_guests to see them")


def _backup_rows(snap):
    out = []
    for b in snap.get("backups", {}).get("guests", []):
        out.append({"vmid": b.get("vmid"), "name": b.get("name"), "last": _when(b.get("ts")),
                    "size_gb": _gb(b.get("size")), "fresh": b.get("fresh"), "error": b.get("error")})
    return out


def lab_overview(snap, args):
    guests = snap.get("guests", [])
    probes = snap.get("probes", [])
    att = [a for a in snap.get("attention", []) if not a.get("muted")]
    b = snap.get("backups", {})
    hosts = []
    for n in snap.get("nodes", []):
        stor = [{"id": s.get("id"), "used_pct": _pct(s.get("used", 0), s.get("total", 0))}
                for s in n.get("storage", [])]
        hosts.append({"name": n.get("name"), "host": n.get("host"), "online": n.get("online"), "ip": n.get("ip"),
                      "cpu_pct": round(100 * (n.get("cpu") or 0)), "cpus": n.get("cpus"),
                      "mem_pct": _pct(n.get("mem", 0), n.get("maxmem", 0)), "maxmem_gb": _gb(n.get("maxmem")),
                      "uptime_days": round((n.get("uptime") or 0) / 86400, 1), "storage": stor,
                      "disks_failing": [d.get("dev") for d in n.get("disks", [])
                                        if d.get("health") not in (None, "PASSED", "OK")]})
    last = b.get("last_run") or {}
    return {"time": _when(snap.get("now")), "hosts": hosts,
            "guests": {"total": len(guests), "running": sum(1 for g in guests if g.get("running"))},
            "health_checks": {"total": len(probes), "failing": [p.get("name") for p in probes
                                                                if p.get("up") is False and not p.get("paused")]},
            "alerts": [{"title": a.get("title"), "severity": a.get("severity")} for a in att],
            "backups": {"last_job": {"start": _when(last.get("start")), "ok": last.get("ok"),
                                     "status": last.get("status")},
                        "fresh": b.get("fresh"), "guests": len(b.get("guests", []))},
            "pulse_sources_ok": {k: v.get("ok") for k, v in snap.get("sources", {}).items()}}


def list_guests(snap, args):
    status = args.get("status") or "all"
    host = (args.get("host") or "").strip().lower()
    rows = []
    for g in snap.get("guests", []):
        if status == "running" and not g.get("running") or status == "stopped" and g.get("running"):
            continue
        if host and host not in {str(g.get("node", "")).lower(), str(g.get("host") or "").lower()}:
            continue
        rows.append(_guest_row(g))
    return {"count": len(rows), "guests": rows}


def guest_details(snap, args):
    g = _find_guest(snap, args.get("guest", ""))
    ips = set(g.get("ips") or []) | ({g["ip"]} if g.get("ip") else set())
    ids = (g.get("vmid"), g.get("pve_vmid"))
    checks = [_check_row(p) for p in snap.get("probes", [])        # a check names its guest, targets its VMID
              if (g.get("name") and p.get("guest") == g.get("name")) or p.get("target") in ids or p.get("target") in ips]
    backup = next((b for b in _backup_rows(snap) if b["vmid"] in (g.get("vmid"), g.get("pve_vmid"))), None)
    name = str(g.get("name", "")).lower()
    events = [{"time": _when(e.get("ts")), "text": e.get("text"), "level": e.get("level")}
              for e in snap.get("events", [])
              if name and name in str(e.get("text", "")).lower()
              or f"#{g.get('pve_vmid', g.get('vmid'))}" in str(e.get("text", ""))][:20]
    row = _guest_row(g)
    row.update({"tags": g.get("tags"), "ips": sorted(ips), "cores": g.get("cores"),
                "disk_gb": _gb(g.get("disk")), "maxdisk_gb": _gb(g.get("maxdisk")),
                "services": [{"port": s.get("port"), "product": s.get("product")} for s in g.get("services", [])],
                "health_checks": checks, "last_backup": backup, "recent_events": events})
    return row


def health_checks(snap, args):
    rows = [_check_row(p) for p in snap.get("probes", [])]
    if args.get("only_failing"):
        rows = [r for r in rows if r["up"] is False and not r["paused"]]
    return {"count": len(rows), "checks": rows}


def alerts(snap, args):
    rows = [{"title": a.get("title"), "severity": a.get("severity"), "kind": a.get("kind"),
             "state": a.get("state"), "target": a.get("target"), "muted": a.get("muted")}
            for a in snap.get("attention", [])]
    return {"count": len(rows), "alerts": rows}


def backups(snap, args):
    b = snap.get("backups", {})
    runs = [{"node": r.get("node"), "start": _when(r.get("start")), "end": _when(r.get("end")),
             "ok": r.get("ok"), "status": r.get("status")} for r in b.get("runs", [])]
    return {"runs": runs, "guests": _backup_rows(snap), "fresh": b.get("fresh"),
            "total_gb": _gb(b.get("total_bytes"))}


def recent_events(snap, args):
    try:
        hours = min(max(float(args.get("hours") or 24), 1), 168)
        limit = min(max(int(args.get("limit") or 50), 1), 200)
    except (TypeError, ValueError):
        raise ToolError("hours and limit must be numbers") from None
    since = (snap.get("now") or time.time()) - hours * 3600
    rows = [{"time": _when(e.get("ts")), "kind": e.get("kind"), "text": e.get("text"), "level": e.get("level")}
            for e in snap.get("events", []) if (e.get("ts") or 0) >= since]
    return {"hours": hours, "count": len(rows[:limit]), "events": rows[:limit]}


def storage_and_disks(snap, args):
    hosts = []
    for n in snap.get("nodes", []):
        hosts.append({"node": n.get("name"), "host": n.get("host"),
                      "storage": [{"id": s.get("id"), "type": s.get("type"), "used_gb": _gb(s.get("used")),
                                   "total_gb": _gb(s.get("total")), "used_pct": _pct(s.get("used", 0),
                                                                                    s.get("total", 0)),
                                   "backups": s.get("for_backup")} for s in n.get("storage", [])],
                      "disks": [{"dev": d.get("dev"), "model": d.get("model"), "type": d.get("type"),
                                 "size_gb": _gb(d.get("size")), "smart": d.get("health"),
                                 "wear_used_pct": d.get("wear_used")} for d in n.get("disks", [])],
                      "zfs": n.get("zfs") or []})
    shared = [{"id": s.get("id"), "used_gb": _gb(s.get("used")), "total_gb": _gb(s.get("total"))}
              for s in snap.get("shared_storage", [])]
    return {"hosts": hosts, "shared_storage": shared}


HANDLERS = {"lab_overview": lab_overview, "list_guests": list_guests, "guest_details": guest_details,
            "health_checks": health_checks, "alerts": alerts, "backups": backups,
            "recent_events": recent_events, "storage_and_disks": storage_and_disks}


def _error(mid, code, message):
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}


def _result(mid, result):
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def handle(msg, snapshot, version):
    """One JSON-RPC message -> its reply, or None for notifications. ``snapshot`` is a function."""
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or not isinstance(msg.get("method"), str):
        return _error(msg.get("id") if isinstance(msg, dict) else None, -32600, "invalid request")
    mid, method, params = msg.get("id"), msg["method"], msg.get("params") or {}
    if "id" not in msg:                       # a notification (e.g. notifications/initialized): no reply
        return None
    if method == "initialize":
        asked = params.get("protocolVersion")
        return _result(mid, {"protocolVersion": asked if asked in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[0],
                             "capabilities": {"tools": {"listChanged": False}},
                             "serverInfo": {"name": "homelab-pulse", "version": version},
                             "instructions": "Read-only view of a Proxmox homelab from Homelab Pulse. Call "
                                             "lab_overview first, then the specific tool. Times are the "
                                             "Pulse server's local time."})
    if method == "ping":
        return _result(mid, {})
    if method == "tools/list":
        return _result(mid, {"tools": TOOLS})
    if method == "tools/call":
        name, args = params.get("name"), params.get("arguments")
        args = {} if args is None else args
        fn = HANDLERS.get(name)
        if not fn:
            return _error(mid, -32602, f"unknown tool: {name}")
        if not isinstance(args, dict):
            return _error(mid, -32602, "arguments must be an object")
        try:
            data = fn(snapshot(), args)
        except ToolError as e:
            return _result(mid, {"content": [{"type": "text", "text": str(e)}], "isError": True})
        return _result(mid, {"content": [{"type": "text", "text": json.dumps(data, separators=(",", ":"))}],
                             "structuredContent": data, "isError": False})
    return _error(mid, -32601, f"method not found: {method}")
