"""Demo mode: a simulated two-node cluster, a standalone second host, and the network their guests answer on.

DemoPve returns the same JSON shapes as the real API, and DemoNet stands in for the network, so
discovery, checks and the UI run through exactly the code paths a live install uses.
"""
import math
import random
import re
import time

from pathlib import Path

import probes
import recipes as recipes_mod
from discover import Finding, Net
from sources import SourceError

GIB, MIB = 1024 ** 3, 1024 ** 2
NODES = {"pve1": {"ip": "192.168.1.2", "cpus": 8, "mem": 32, "model": "Intel(R) Core(TM) i7-8700 CPU @ 3.20GHz"},
         "pve2": {"ip": "192.168.1.3", "cpus": 4, "mem": 16, "model": "Intel(R) N100"}}
ROUTER = "192.168.1.1"
STORAGE_TREND = {"used_now": 300e9, "per_day": 3e9}     # pve2 local-lvm: 60 GB free, ~20 days left

# vmid: (node, type, name, cores, maxmem MiB, maxdisk GiB, base cpu, mem fraction, ip, running, agent)
GUESTS = {
    100: ("pve1", "lxc", "adguard", 1, 512, 4, 0.02, 0.30, "192.168.1.10", True, None),
    101: ("pve1", "lxc", "proxy", 1, 512, 4, 0.01, 0.20, "192.168.1.11", True, None),
    102: ("pve1", "lxc", "paperless", 2, 4096, 32, 0.03, 0.55, "192.168.1.12", True, None),
    103: ("pve1", "qemu", "homeassistant", 2, 4096, 32, 0.06, 0.62, "192.168.1.13", True, True),
    104: ("pve1", "lxc", "jellyfin", 4, 4096, 16, 0.05, 0.40, "192.168.1.14", True, None),
    105: ("pve1", "qemu", "docker", 4, 8192, 64, 0.08, 0.50, "192.168.1.15", True, False),
    106: ("pve1", "lxc", "pulse", 1, 512, 4, 0.01, 0.12, "192.168.1.16", True, None),
    200: ("pve2", "lxc", "ollama", 4, 8192, 32, 0.01, 0.70, "192.168.1.20", True, None),
    201: ("pve2", "lxc", "grafana", 1, 1024, 8, 0.02, 0.35, "192.168.1.21", True, None),
    202: ("pve2", "qemu", "nas", 2, 8192, 32, 0.03, 0.60, "192.168.1.22", True, True),
    203: ("pve2", "lxc", "sandbox", 2, 2048, 8, 0.0, 0.0, "192.168.1.23", False, None),
}

# A standalone second host (not in the cluster), as `install.sh --add-host` would add it. Its VMIDs
# deliberately repeat the cluster's: Pulse keys them apart.
MINI_NODES = {"mini": {"ip": "192.168.1.4", "cpus": 6, "mem": 64, "model": "Intel(R) Xeon(R) W-2133 CPU @ 3.60GHz"}}
MINI_GUESTS = {
    100: ("mini", "lxc", "frigate", 4, 4096, 32, 0.12, 0.45, "192.168.1.30", True, None),
    101: ("mini", "lxc", "immich", 2, 4096, 64, 0.03, 0.50, "192.168.1.31", True, None),
}


def _f(port, kind, product, icon, rank=0, scheme=None, **kw):
    return Finding(port=port, kind=kind, product=product, icon=icon, rank=rank,
                   scheme=scheme or ("https" if kind == "tls" else "http" if kind == "http" else None), **kw)


SSH = _f(22, "tcp", "SSH", "terminal", rank=90, banner="SSH-2.0-OpenSSH_9.2p1 Debian")
SERVICES = {   # what DemoNet answers on, per IP
    "192.168.1.10": [SSH, _f(53, "dns", "DNS server", "shield", 40), _f(80, "http", "AdGuard Home", "shield", 1)],
    "192.168.1.11": [SSH, _f(80, "http", "nginx", "globe", 80), _f(81, "http", "Nginx Proxy Manager", "globe", 15),
                     _f(443, "tls", "nginx", "globe", 80, cert_days=61)],
    "192.168.1.12": [SSH, _f(8000, "http", "Paperless-ngx", "doc", 3)],
    "192.168.1.13": [_f(8123, "http", "Home Assistant", "home", 0)],
    "192.168.1.14": [SSH, _f(8096, "http", "Jellyfin", "film", 5)],
    "192.168.1.15": [SSH, _f(9443, "tls", "Portainer", "cube", 14, cert_days=300), _f(3001, "http", "Uptime Kuma", "pulse", 13)],
    "192.168.1.16": [_f(80, "http", "Pulse", "pulse", 100)],
    "192.168.1.20": [_f(11434, "http", "Ollama", "brain", 25)],
    "192.168.1.21": [SSH, _f(3000, "http", "Grafana", "chart", 11)],
    "192.168.1.22": [SSH, _f(443, "tls", "TrueNAS", "disk", 28, cert_days=200)],
    "192.168.1.30": [SSH, _f(5000, "http", "Frigate", "camera", 21)],
    "192.168.1.31": [SSH, _f(2283, "http", "Immich", "photo", 9)],
    ROUTER: [_f(80, "http", "Router", "router", 300)],
}


OUTAGE_CHECK = "202:443"          # the demo nas's web UI drops out for 5 min every 20 min
OUTAGE_CYCLE, OUTAGE_FROM, OUTAGE_TO = 1200, 100, 400


class DemoNet(Net):
    def __init__(self, seed=3, clock=time.time):
        super().__init__()
        self.rng = random.Random(seed)
        self.clock = clock
        self.healed_cycle = None      # the outage cycle a demo heal ended early

    def connect(self, ip, port):
        return any(f.port == port for f in SERVICES.get(ip, ()))

    def fingerprint(self, ip, port, dns_port=None):
        return next(f for f in SERVICES[ip] if f.port == port)

    def probe(self, spec):
        now = self.clock()
        if (spec.get("id") == OUTAGE_CHECK and OUTAGE_FROM <= now % OUTAGE_CYCLE < OUTAGE_TO
                and self.healed_cycle != now // OUTAGE_CYCLE):
            return probes.Result(False, None, "timed out")
        lat = round(self.rng.uniform(0.4, 4.0) if spec.get("target") != "internet" else self.rng.uniform(9, 16), 1)
        detail = {"dns": "blocking ads", "tls": "cert 61 days left", "tcp": f"port {spec.get('port')} open"}
        return probes.Result(True, lat, detail.get(spec["kind"], "HTTP 200"))


class DemoPve:
    """Smooth random-walk CPU, growing network counters, an AI job on the ollama guest now and then,
    and last night's 02:00 backup on each node. Deterministic per seed."""

    def __init__(self, seed=7, clock=time.time, nodes=None, guests=None, cluster="demo"):
        self.nodes, self.guests, self.cluster = nodes or NODES, guests or GUESTS, cluster
        self.rng = random.Random(seed)
        self.clock = clock
        self.t0 = clock()
        self.counters = {v: [self.rng.randint(2, 40) * GIB, self.rng.randint(1, 20) * GIB] for v in self.guests}
        self.cpu = {v: g[6] for v, g in self.guests.items()}
        self.last = clock()
        self.ai_until = 0.0

    def _tick(self):
        now = self.clock()
        dt = max(0.0, now - self.last)
        self.last = now
        if now > self.ai_until and self.rng.random() < 0.02 * max(dt, 1) / 5:
            self.ai_until = now + self.rng.uniform(25, 90)
        for vmid, g in self.guests.items():
            base, running = g[6], g[9]
            self.cpu.setdefault(vmid, base)                  # guests can appear while running
            self.counters.setdefault(vmid, [0, 0])
            if not running:
                self.cpu[vmid] = 0.0
                continue
            target = 0.93 if (vmid == 200 and now < self.ai_until) else base
            c = self.cpu[vmid] + (target - self.cpu[vmid]) * 0.35 + self.rng.gauss(0, base * 0.35 + 0.004)
            self.cpu[vmid] = min(1.0, max(0.0, c))
            rate_in = {104: 2e6, 103: 2.5e5, 101: 6e4, 100: 3e4, 200: 4e4, 202: 3e5}.get(vmid, 8e3)
            rate_out = {104: 4e6, 103: 1.4e5, 101: 9e4, 100: 3.5e4, 202: 1e5}.get(vmid, 6e3)
            wobble = 0.6 + 0.8 * (0.5 + 0.5 * math.sin(now / 37 + vmid))
            self.counters[vmid][0] += int(rate_in * wobble * dt * self.rng.uniform(0.5, 1.5))
            self.counters[vmid][1] += int(rate_out * wobble * dt * self.rng.uniform(0.5, 1.5))

    def _node_cpu(self, node):
        return sum(self.cpu[v] * self.guests[v][3] for v in self.guests if self.guests[v][0] == node) / self.nodes[node]["cpus"]

    def resources(self):
        self._tick()
        out = []
        for vmid, (node, kind, name, cores, maxmem, maxdisk, _c, memf, _ip, running, _a) in self.guests.items():
            out.append({
                "id": f"{kind}/{vmid}", "type": kind, "vmid": vmid, "name": name, "node": node,
                "status": "running" if running else "stopped", "cpu": self.cpu[vmid], "maxcpu": cores,
                "mem": int(maxmem * MIB * (memf + 0.02 * math.sin(self.clock() / 90 + vmid))) if running else 0,
                "maxmem": maxmem * MIB, "disk": int(maxdisk * GIB * 0.31) if kind == "lxc" else 0,
                "maxdisk": maxdisk * GIB, "netin": self.counters[vmid][0], "netout": self.counters[vmid][1],
                "uptime": int(self.clock() - self.t0 + 86400 * 3 + vmid * 611) if running else 0, "template": 0,
                "tags": "media" if vmid == 104 else "",
            })
        for node in self.nodes:
            lvm_used = STORAGE_TREND["used_now"] if node == "pve2" else 90e9
            for sid, total, used, kind in (("local", 100e9, 14e9, "dir"), ("local-lvm", 360e9, lvm_used, "lvmthin")):
                out.append({"id": f"storage/{node}/{sid}", "type": "storage", "storage": sid, "node": node,
                            "status": "available", "disk": int(used), "maxdisk": int(total), "plugintype": kind,
                            "shared": 0})
            out.append({"id": f"storage/{node}/nas-backup", "type": "storage", "storage": "nas-backup", "node": node,
                        "status": "available", "disk": int(820e9), "maxdisk": int(3.8e12), "plugintype": "nfs",
                        "shared": 1})
            n = self.nodes[node]
            out.append({"id": f"node/{node}", "type": "node", "node": node, "status": "online",
                        "cpu": self._node_cpu(node), "maxcpu": n["cpus"], "mem": n["mem"] * GIB * 0.4,
                        "maxmem": n["mem"] * GIB, "uptime": int(self.clock() - self.t0 + 86400 * 5)})
        return out

    def cluster_status(self):
        first = next(iter(self.nodes))
        head = [{"type": "cluster", "name": self.cluster, "nodes": len(self.nodes), "quorate": 1}] if self.cluster else []
        return head + [{"type": "node", "name": n, "ip": v["ip"], "online": 1, "local": int(n == first)}
                       for n, v in self.nodes.items()]

    def node_status(self, node):
        n, cpu = self.nodes[node], self._node_cpu(node)
        return {"cpu": cpu, "loadavg": [f"{cpu * n['cpus'] * 0.9:.2f}", "0.41", "0.33"],
                "memory": {"total": n["mem"] * GIB, "used": int(n["mem"] * GIB * (0.4 + 0.01 * math.sin(self.clock() / 120)))},
                "rootfs": {"total": 100e9, "used": 14e9}, "uptime": int(self.clock() - self.t0 + 86400 * 5),
                "cpuinfo": {"cpus": n["cpus"], "model": n["model"]},
                "pveversion": "pve-manager/9.2.20/49318c671b82f31e",
                "kversion": "Linux 7.0.14-19-pve #1 SMP PREEMPT_DYNAMIC PMX 7.0.14-19 (2026-09-18T07:31Z)"}

    def node_network(self, node):
        return [{"iface": "vmbr0", "type": "bridge", "address": self.nodes[node]["ip"], "gateway": ROUTER, "active": 1}]

    def guest_config(self, node, kind, vmid):
        g = self.guests[int(vmid)]
        if kind == "qemu":
            cfg = {"net0": "virtio=BC:24:11:00:00:01,bridge=vmbr0", "cores": g[3], "ostype": "l26"}
            if g[10] is False:
                cfg["ipconfig0"] = f"ip={g[8]}/24,gw={ROUTER}"     # cloud-init VM without the agent
            return cfg
        return {"net0": f"name=eth0,bridge=vmbr0,gw={ROUTER},ip={g[8]}/24,type=veth", "cores": g[3], "ostype": "debian"}

    def lxc_interfaces(self, node, vmid):
        g = self.guests[int(vmid)]
        return [{"name": "lo", "inet": "127.0.0.1/8"}, {"name": "eth0", "inet": f"{g[8]}/24"}]

    def agent_interfaces(self, node, vmid):
        g = self.guests[int(vmid)]
        if not g[10]:
            raise SourceError(f"PVE /nodes/{node}/qemu/{vmid}/agent/network-get-interfaces: HTTP 500 "
                              "QEMU guest agent is not running")
        return {"result": [{"name": "lo", "ip-addresses": [{"ip-address": "127.0.0.1", "ip-address-type": "ipv4"}]},
                           {"name": "ens18", "ip-addresses": [{"ip-address": g[8], "ip-address-type": "ipv4"}]}]}

    def zfs_pools(self, node):
        return [{"name": "tank", "health": "ONLINE"}] if node == "pve1" else []

    def storage_config(self):
        return {"local": "iso,backup,vztmpl", "backup": "backup"}

    def node_updates(self, node):
        return []

    def disks(self, node):
        if node == "pve1":
            return [{"devpath": "/dev/nvme0n1", "model": "Samsung SSD 980 1TB", "type": "nvme", "size": 1000204886016,
                     "health": "PASSED", "wearout": 96}]
        return [{"devpath": "/dev/sda", "model": "Crucial_CT500MX500SSD1", "type": "ssd", "size": 500107862016,
                 "health": "PASSED", "wearout": 88}]

    def _last_2am(self):
        lt = time.localtime(self.clock())
        two = time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday, 2, 0, 0, 0, 0, -1))
        return two if two <= self.clock() else two - 86400

    def backup_runs(self, node, limit=3):
        start = self._last_2am() + (0 if node == "pve1" else 300)
        return [{"upid": f"UPID:{node}:demo:vzdump", "type": "vzdump", "id": "", "user": "root@pam", "node": node,
                 "starttime": int(start), "endtime": int(start + 1260), "status": "OK"}][:limit]

    def task_log(self, node, upid):
        t, lines = self._last_2am(), []
        for vmid, g in self.guests.items():
            if g[0] != node or vmid == 106:
                continue  # 106 (pulse) was created after last night's run
            t += 40 + vmid % 7 * 30
            stamp = time.strftime("%Y_%m_%d-%H_%M_%S", time.localtime(t))
            ext = "vma.zst" if g[1] == "qemu" else "tar.zst"
            lines += [f"INFO: Starting Backup of VM {vmid} ({g[1]})",
                      f"INFO: creating vzdump archive '/mnt/pve/nas-backup/dump/vzdump-{g[1]}-{vmid}-{stamp}.{ext}'",
                      f"INFO: archive file size: {(vmid % 9 + 1) * 410}MB",
                      f"INFO: Finished Backup of VM {vmid} (00:00:{20 + vmid % 30:02d})"]
        lines.append("INFO: Backup job finished successfully")
        return [{"n": i + 1, "t": line} for i, line in enumerate(lines)]

    # -- Proxmox RRD (history) --

    _SPAN = {"hour": 3600, "day": 86400, "week": 7 * 86400, "month": 30 * 86400, "year": 365 * 86400}

    def _times(self, timeframe, n=240):
        span, now = self._SPAN[timeframe], self.clock()
        step = span / n
        return [int(now - span + i * step) for i in range(1, n + 1)]

    def rrd(self, node, kind, vmid, timeframe):
        g = self.guests[int(vmid)]
        out = []
        for t in self._times(timeframe):
            wave = 0.5 + 0.5 * math.sin(t / 5400 + int(vmid))
            out.append({"time": t, "cpu": g[6] * (0.5 + wave) if g[9] else 0, "maxcpu": g[3],
                        "mem": g[4] * MIB * (g[7] + 0.05 * wave) if g[9] else 0, "maxmem": g[4] * MIB,
                        "netin": 3e4 * (1 + 3 * wave), "netout": 2e4 * (1 + 2 * wave),
                        "disk": g[5] * GIB * 0.31, "maxdisk": g[5] * GIB})
        return out

    def node_rrd(self, node, timeframe):
        n = self.nodes[node]
        return [{"time": t, "cpu": 0.05 + 0.04 * math.sin(t / 7200), "maxcpu": n["cpus"],
                 "memused": n["mem"] * GIB * (0.4 + 0.03 * math.sin(t / 9000)), "memtotal": n["mem"] * GIB,
                 "netin": 2e5 * (1.2 + math.sin(t / 3600)), "netout": 1.5e5 * (1.2 + math.sin(t / 4000))}
                for t in self._times(timeframe)]

    def storage_rrd(self, node, storage, timeframe):
        trend = node == "pve2" and storage == "local-lvm"
        out = []
        for t in self._times(timeframe, n=720):
            if trend:       # fills ~3 GB a day: full in ~20 days
                used = STORAGE_TREND["used_now"] - STORAGE_TREND["per_day"] * (self.clock() - t) / 86400
            else:
                used = {"local": 14e9, "local-lvm": 90e9, "nas-backup": 820e9}.get(storage, 1e9)
            out.append({"time": t, "used": used, "total": 3.8e12 if storage == "nas-backup" else
                        (100e9 if storage == "local" else 360e9)})
        return out

    def tasks(self):
        if self.guests is not GUESTS:
            return []
        start = self._last_2am()
        return [
            {"upid": "UPID:pve1:demo:2", "type": "vzstart", "id": "106", "user": "root@pam", "node": "pve1",
             "starttime": int(self.t0 - 600), "endtime": int(self.t0 - 597), "status": "OK"},
            {"upid": "UPID:pve2:demo:3", "type": "vzshutdown", "id": "203", "user": "root@pam", "node": "pve2",
             "starttime": int(start - 86400 * 4), "endtime": int(start - 86400 * 4 + 6), "status": "OK"},
        ]


# ---------------------------------------------------------------- self-healing stand-in

DEMO_CONTAINERS = {(105, 9443): "portainer", (105, 3001): "uptime-kuma"}
RECIPES_DIR = Path(__file__).resolve().parent.parent / "recipes"


class DemoGate:
    """Behaves like pulse-heal-gate for the demo lab: real recipe files and validation, fake guests.
    A real (not dry) run on the demo outage check ends that outage, so healing can be watched."""

    def __init__(self, net, recipes_dir=RECIPES_DIR):
        self.net, self.dir, self.calls = net, Path(recipes_dir), []

    def _recipes(self):
        return recipes_mod.load_dir(self.dir, "built-in")

    def version(self):
        return {"ok": True, "version": "demo", "schema": recipes_mod.SCHEMA_VERSION, "enabled": True, "budget_per_hour": 10}

    def list_recipes(self):
        return {"ok": True, "recipes": self._recipes()}

    def inspect(self, vmid, port):
        g = GUESTS.get(int(vmid))
        if not g:
            return {"ok": False, "error": f"no such guest {vmid}"}
        container = DEMO_CONTAINERS.get((int(vmid), int(port)))
        f = next((f for f in SERVICES.get(g[8], ()) if f.port == int(port)), None)
        systemd = g[1] == "lxc" or g[10] is True          # containers, and VMs with the guest agent
        unit = None
        if f and systemd and not container:
            unit = re.sub(r"[^a-z0-9]+", "-", f.product.lower()).strip("-") + ".service"
        return {"ok": True, "vmid": int(vmid), "port": int(port), "init": "systemd" if systemd else "none",
                "unit": unit, "container": container, "pid": 1234}

    def run(self, recipe_id, vmid, port, target=None, dry_run=False, timeout=None):
        rec = next((r for r in self._recipes() if r["id"] == recipe_id), None)
        if not rec or rec.get("errors"):
            return {"ok": False, "error": "unknown recipe"}
        t = dict(target or {}, port=int(port) or None)          # 0 = no port (warning fixes)
        t.setdefault("init", "systemd")
        try:
            steps = recipes_mod.resolve(rec, t)
        except recipes_mod.RecipeError as e:
            return {"ok": False, "error": str(e)}
        if dry_run:
            return {"ok": True, "dry_run": True, "steps": [{"argv": s, "dry_run": True} for s in steps]}
        self.calls.append((recipe_id, int(vmid), int(port), steps))
        if f"{vmid}:{port}" == OUTAGE_CHECK:
            self.net.healed_cycle = self.net.clock() // OUTAGE_CYCLE
        return {"ok": True, "steps": [{"argv": s, "exit": 0} for s in steps], "output": "ok"}
