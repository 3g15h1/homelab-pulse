"""The Proxmox API, read-only. The demo stand-in with identical shapes lives in demo.py.

Every call returns the raw JSON `data` the API returns, so the rest of the app can't tell a demo
source from a live one. Node-scoped calls take the node name: in a cluster any node's API answers
for all of them.
"""
import http.client
import json
import re
import secrets
import socket
import ssl
import urllib.parse
from pathlib import Path

from probes import private_ca_context


class SourceError(Exception):
    pass


class PveClient:
    """TLS is verified against the cluster CA. Node certs are issued for the node *name*, not its
    IP, so we connect by IP and verify as `tls_name`, which is detected from /cluster/status on the
    first call (that one call verifies the chain only) unless given explicitly."""

    def __init__(self, host, port, token, cafile, tls_name=None, timeout=8):
        self.host, self.port, self.timeout = host, port, timeout
        self.auth = "PVEAPIToken=" + token
        self.cafile = cafile
        self.tls_name = tls_name

    def _context(self, check_name):
        ctx = private_ca_context(self.cafile)
        ctx.check_hostname = check_name
        return ctx

    def _request(self, path, check_name=True):
        sock = socket.create_connection((self.host, self.port), self.timeout)
        conn = http.client.HTTPSConnection(self.host, self.port, timeout=self.timeout)
        conn.sock = self._context(check_name).wrap_socket(sock, server_hostname=self.tls_name or self.host)
        try:
            conn.request("GET", "/api2/json" + path, headers={"Authorization": self.auth})
            r = conn.getresponse()
            body = r.read()
            if r.status != 200:
                raise SourceError(f"PVE {path.split('?')[0]}: HTTP {r.status} {r.reason}".strip())
            return json.loads(body)["data"]
        finally:
            conn.close()

    def _get(self, path):
        if self.tls_name is None:
            local = [e for e in self._request("/cluster/status", check_name=False)
                     if e.get("type") == "node" and e.get("local")]
            if not local:
                raise SourceError("PVE /cluster/status: no local node in the answer")
            self.tls_name = local[0]["name"]
        return self._request(path)

    def resources(self):
        return self._get("/cluster/resources")

    def cluster_status(self):
        return self._get("/cluster/status")

    def node_status(self, node):
        return self._get(f"/nodes/{node}/status")

    def node_network(self, node):
        return self._get(f"/nodes/{node}/network")

    def guest_config(self, node, kind, vmid):
        return self._get(f"/nodes/{node}/{kind}/{vmid}/config")

    def lxc_interfaces(self, node, vmid):
        return self._get(f"/nodes/{node}/lxc/{vmid}/interfaces")

    def agent_interfaces(self, node, vmid):
        return self._get(f"/nodes/{node}/qemu/{vmid}/agent/network-get-interfaces")

    def disks(self, node):
        return self._get(f"/nodes/{node}/disks/list")

    def backup_runs(self, node, limit=3):
        """Recent vzdump jobs. (Listing the backup storage itself needs more than PVEAuditor on
        PVE 9, but the job log is readable with Sys.Audit and says everything we need.)"""
        return self._get(f"/nodes/{node}/tasks?typefilter=vzdump&source=all&limit={limit}")

    def task_log(self, node, upid):
        return self._get(f"/nodes/{node}/tasks/{urllib.parse.quote(upid, safe='')}/log?limit=20000")

    def tasks(self):
        return self._get("/cluster/tasks")

    # Proxmox keeps these round-robin databases for a year; Pulse reads them for long graphs and
    # storage forecasts instead of recording metrics itself. timeframe: hour|day|week|month|year
    def rrd(self, node, kind, vmid, timeframe):
        return self._get(f"/nodes/{node}/{kind}/{vmid}/rrddata?timeframe={timeframe}&cf=AVERAGE")

    def node_rrd(self, node, timeframe):
        return self._get(f"/nodes/{node}/rrddata?timeframe={timeframe}&cf=AVERAGE")

    def storage_rrd(self, node, storage, timeframe):
        return self._get(f"/nodes/{node}/storage/{storage}/rrddata?timeframe={timeframe}&cf=AVERAGE")

    def zfs_pools(self, node):
        """ZFS pools on a node: [{name, health, ...}]. Empty when the node has no ZFS."""
        return self._get(f"/nodes/{node}/disks/zfs")

    def storage_config(self):
        """Cluster storage config as {storage id: content string} (e.g. 'backup,iso')."""
        return {s["storage"]: s.get("content", "") for s in self._get("/storage")}

    def node_updates(self, node):
        """Available package updates: [{Package, Version, OldVersion, ...}].
        Reading this needs Sys.Modify, which the stock read-only token lacks."""
        return self._get(f"/nodes/{node}/apt/update")


# ---------------------------------------------------------------- more than one Proxmox

UID_SPAN = 1_000_000_000      # Proxmox VMIDs stay below this, so slot * UID_SPAN + vmid never collides
_LABEL = re.compile(r"[a-z0-9][a-z0-9-]{0,30}")


def split_uid(uid):
    """Pulse's guest key -> (host slot, the VMID Proxmox uses). Slot 0 is the primary host."""
    return divmod(int(uid), UID_SPAN)


class ExtraHost:
    """A Proxmox host (or cluster) that isn't part of the primary one, e.g. a standalone second
    server. `slot` (1, 2, …) is fixed when it's added, so its guests keep their keys."""

    def __init__(self, label, slot, client, source="installer"):
        self.label, self.slot, self.client = label, int(slot), client
        self.source = source     # "installer" (/etc, read-only to Pulse) or "ui" (added on the settings page)
        self.names = {}          # its real node name -> the name Pulse shows (name@label if taken)
        self.last = None         # last good /cluster/resources (raw), kept while it's unreachable
        self.last_status = None  # last good /cluster/status
        self.ok, self.error, self.updated = None, None, None


def load_hosts(directory, timeout=8, source="installer"):
    """Extra hosts from <dir>/*.json, written by `install.sh --add-host`:
    {"label", "slot", "host", "port", "token", "ca_file"?, "tls_name"?}. -> (hosts, [(file stem, error)])."""
    hosts, errors = [], []
    try:
        files = sorted(Path(directory).glob("*.json"))
    except OSError:
        return hosts, errors
    seen = set()
    for f in files:
        try:
            d = json.loads(f.read_text())
            label, slot = str(d["label"]), int(d["slot"])
            if not _LABEL.fullmatch(label) or slot < 1 or slot in seen:
                raise ValueError("bad label or slot")
            ca = d.get("ca_file") or str(f.with_name(f"{label}-ca.pem"))
            client = PveClient(d["host"], int(d.get("port", 8006)), d["token"], ca, d.get("tls_name"), timeout)
        except (OSError, ValueError, KeyError, TypeError) as e:
            errors.append((f.stem, str(e)[:120]))
            continue
        seen.add(slot)
        hosts.append(ExtraHost(label, slot, client, source))
    return sorted(hosts, key=lambda h: h.slot), errors


class MultiPve:
    """The primary Proxmox plus extra hosts that aren't in its cluster, presented as one API with the
    same shapes, so the rest of Pulse treats an extra host like one more node.

    - Guests on an extra host get the key slot * UID_SPAN + vmid (the real VMID stays in `pve_vmid`),
      so two hosts that both have a CT 100 don't collide. The primary keeps plain VMIDs.
    - Node names stay as they are unless already taken, then they become name@label.
    - Node-scoped calls go to the host that owns the node, with the real node name and VMID.
    - The primary failing raises, as before. An extra host failing doesn't: its nodes show offline
      and its guests "unknown" (from the last good answer), like an offline node in a cluster.
    - Storage on an extra host is listed under its own node(s), never merged with the primary's.
    """

    def __init__(self, primary, extras=(), errors=()):
        self.primary = primary
        self.extras = sorted(extras, key=lambda h: h.slot)
        self.config_errors = list(errors)
        self.route = {}          # node name shown -> (client, real name, slot)
        self.slots = {h.label: h.slot for h in self.extras}

    # -- hosts added or removed at runtime (settings page); readers see either the old or the new list --

    def add(self, host):
        self.extras = sorted(self.extras + [host], key=lambda h: h.slot)
        self.slots = {h.label: h.slot for h in self.extras}

    def remove(self, label):
        self.extras = [h for h in self.extras if h.label != label]
        self.slots = {h.label: h.slot for h in self.extras}

    # -- mapping --

    def _node(self, node):
        return self.route.get(node, (self.primary, node, 0))

    def uid(self, node, vmid):
        return self._node(node)[2] * UID_SPAN + int(vmid)

    def _guest(self, node, vmid):
        client, real, slot = self._node(node)
        return client, real, int(vmid) - slot * UID_SPAN

    def _alias(self, h, raw, taken):
        h.names = {}
        for r in raw:
            if r.get("type") == "node":
                real = r["node"]
                h.names[real] = real if real not in taken else f"{real}@{h.label}"
        taken |= set(h.names.values())
        for real, shown in h.names.items():
            self.route[shown] = (h.client, real, h.slot)

    def _remap(self, h, r, offline):
        r = dict(r, host=h.label)
        if r.get("node"):
            r["node"] = h.names.get(r["node"], r["node"])
        typ = r.get("type")
        if typ in ("lxc", "qemu"):
            vmid = int(r["vmid"])
            r.update(pve_vmid=vmid, vmid=h.slot * UID_SPAN + vmid, id=f"{typ}/{h.slot * UID_SPAN + vmid}")
            if offline:
                r.update(status="unknown", cpu=0, mem=0, netin=0, netout=0, uptime=0)
        elif typ == "node":
            r["id"] = f"node/{r['node']}"
            if offline:
                r.update(status="offline", cpu=0, mem=0, uptime=0)
        elif typ == "storage":
            r.update(id=f"storage/{r.get('node')}/{r.get('storage')}", shared=0)
            if offline:
                r["status"] = "unknown"
        return r

    def _remap_task(self, h, t):
        t = dict(t, host=h.label)
        if t.get("node"):
            t["node"] = h.names.get(t["node"], t["node"])
        if str(t.get("id", "")).isdigit() and t.get("type") != "vzdump":
            t["id"] = str(h.slot * UID_SPAN + int(t["id"]))
        return t

    # -- cluster-wide calls --

    def resources(self):
        res = self.primary.resources()
        primary_nodes = {r["node"] for r in res if r.get("type") == "node"}
        self.route = {n: (self.primary, n, 0) for n in primary_nodes}
        taken, out = set(primary_nodes), list(res)
        for h in self.extras:
            try:
                raw = h.client.resources()
                h.last, h.ok, h.error = raw, True, None
            except Exception as e:  # noqa: BLE001 - one host down mustn't blank the others
                raw, h.ok, h.error = None, False, str(e)[:160]
            src = raw if raw is not None else h.last
            if src is None:
                continue         # never reached since Pulse started: host_status() says so
            self._alias(h, src, taken)
            out += [self._remap(h, r, offline=raw is None) for r in src]
        return out

    def cluster_status(self):
        out = list(self.primary.cluster_status())
        for h in self.extras:
            try:
                st = h.client.cluster_status()
                h.last_status = st
                online = None
            except Exception:  # noqa: BLE001
                st = h.last_status or [{"type": "node", "name": real} for real in h.names]
                online = 0
            for e in st:
                if e.get("type") == "node":
                    out.append(dict(e, name=h.names.get(e["name"], e["name"]), local=0, host=h.label,
                                    **({"online": online} if online is not None else {})))
        return out

    def tasks(self):
        out = list(self.primary.tasks())
        for h in self.extras:
            if h.ok:
                try:
                    out += [self._remap_task(h, t) for t in h.client.tasks()]
                except Exception:  # noqa: BLE001
                    pass
        return out

    def storage_config(self):
        merged = {}
        for h in reversed(self.extras):
            if h.ok:
                try:
                    merged.update(h.client.storage_config())
                except Exception:  # noqa: BLE001
                    pass
        merged.update(self.primary.storage_config())       # the primary wins a shared id
        return merged

    def host_status(self):
        """Extra hosts for the dashboard: [{label, ok, error, nodes}]."""
        return ([{"label": h.label, "ok": h.ok, "error": h.error, "nodes": sorted(h.names.values()),
                  "source": h.source, "host": getattr(h.client, "host", None)}
                 for h in self.extras] + [{"label": name, "ok": False, "error": f"bad host file: {err}", "nodes": []}
                                          for name, err in self.config_errors])

    def unreached(self):
        """Extra hosts never reached since Pulse started (so they have no nodes to show offline)."""
        return [h for h in self.extras if h.ok is False and h.last is None]

    def node_meta(self, node):
        """TLS details for a node's Proxmox UI check: its own CA and certificate name."""
        client, real, slot = self._node(node)
        if not slot:
            return {}
        return {"ca": getattr(client, "cafile", None), "tls_name": real}

    # -- node-scoped calls --

    def node_status(self, node):
        c, n, _ = self._node(node)
        return c.node_status(n)

    def node_network(self, node):
        c, n, _ = self._node(node)
        return c.node_network(n)

    def disks(self, node):
        c, n, _ = self._node(node)
        return c.disks(n)

    def zfs_pools(self, node):
        c, n, _ = self._node(node)
        return c.zfs_pools(n)

    def node_updates(self, node):
        c, n, _ = self._node(node)
        return c.node_updates(n)

    def node_rrd(self, node, timeframe):
        c, n, _ = self._node(node)
        return c.node_rrd(n, timeframe)

    def storage_rrd(self, node, storage, timeframe):
        c, n, _ = self._node(node)
        return c.storage_rrd(n, storage, timeframe)

    def backup_runs(self, node, limit=3):
        c, n, slot = self._node(node)
        runs = c.backup_runs(n, limit)
        return [dict(r, node=node) for r in runs] if slot else runs

    def task_log(self, node, upid):
        c, n, _ = self._node(node)
        return c.task_log(n, upid)

    def guest_config(self, node, kind, vmid):
        c, n, v = self._guest(node, vmid)
        return c.guest_config(n, kind, v)

    def lxc_interfaces(self, node, vmid):
        c, n, v = self._guest(node, vmid)
        return c.lxc_interfaces(n, v)

    def agent_interfaces(self, node, vmid):
        c, n, v = self._guest(node, vmid)
        return c.agent_interfaces(n, v)

    def rrd(self, node, kind, vmid, timeframe):
        c, n, v = self._guest(node, vmid)
        return c.rrd(n, kind, v, timeframe)


# ---------------------------------------------------------------- adding a host from the settings page

class HostSetupError(Exception):
    pass


def decode_host_line(line):
    """The "pulse-host:…" line `install.sh --extra-host` prints -> {host, port, node, token, ca}."""
    import base64
    try:
        d = json.loads(base64.urlsafe_b64decode(line.strip().removeprefix("pulse-host:") + "=="))
        if not all(isinstance(d.get(k), str) and d[k] for k in ("host", "token", "ca")):
            raise ValueError
        return d
    except (ValueError, TypeError, UnicodeDecodeError):
        raise HostSetupError("that line is damaged; copy the whole pulse-host:… line again") from None


def add_host(multi, directory, d, label=None, used_slots=(), client_factory=None):
    """Test the connection, then save the host under `directory` and start watching it.
    `d`: {host, port?, token, ca}. Returns the new ExtraHost. Raises HostSetupError with a readable reason."""
    host, port, token, ca = str(d["host"]).strip(), int(d.get("port") or 8006), str(d["token"]).strip(), str(d["ca"])
    if not re.fullmatch(r"[A-Za-z0-9.:\[\]-]{1,253}", host):
        raise HostSetupError("the address doesn't look like an IP or host name")
    if not re.fullmatch(r"[^\s!=]+@[^\s!=]+![A-Za-z][A-Za-z0-9._-]*=[0-9a-fA-F-]{20,64}", token):
        raise HostSetupError("the token should look like user@realm!tokenid=xxxxxxxx-xxxx-…")
    if "BEGIN CERTIFICATE" not in ca:
        raise HostSetupError("the CA certificate should be the text of /etc/pve/pve-root-ca.pem on that host")
    if any(getattr(h.client, "host", None) == host for h in multi.extras):
        raise HostSetupError(f"{host} is already connected")
    directory = Path(directory)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp_ca = directory / f".test-{secrets.token_hex(4)}-ca.pem"
    tmp_ca.write_text(ca)
    try:
        client = (client_factory or PveClient)(host, port, token, str(tmp_ca), None)
        try:
            status = client.cluster_status()
        except SourceError as e:
            msg = str(e)
            raise HostSetupError("the token was refused (check it, and that it has the PVEAuditor role)" if "401" in msg
                                 else f"Proxmox answered with an error: {msg}") from None
        except ssl.SSLError as e:
            why = getattr(e, "verify_message", None) or getattr(e, "reason", None) or e
            raise HostSetupError(f"the CA certificate doesn't match that host ({why})") from None
        except OSError as e:
            raise HostSetupError(f"can't reach {host}:{port} ({e.strerror or e})") from None
        node = next((e for e in status if e.get("type") == "node" and e.get("local")), None)
        if not node:
            raise HostSetupError("that host didn't say which node it is")
        mine = {e.get("ip") for e in multi.primary.cluster_status() if e.get("type") == "node"}
        if host in mine or node.get("ip") in mine:
            raise HostSetupError(f"{host} is a node of the cluster Pulse already watches")
        label = (label or re.sub(r"[^a-z0-9-]+", "-", node["name"].lower())).strip("-")[:31]
        if not _LABEL.fullmatch(label):
            raise HostSetupError("the name must be lowercase letters, digits and dashes")
        if label in multi.slots:
            raise HostSetupError(f"there is already a host called {label}; pick another name")
        slot = max([h.slot for h in multi.extras] + list(used_slots) + [0]) + 1
        (directory / f"{label}-ca.pem").write_text(ca)
        f = directory / f"{label}.json"
        f.write_text(json.dumps({"label": label, "slot": slot, "host": host, "port": port, "token": token,
                                 "tls_name": node["name"]}, indent=1))
        f.chmod(0o600)
        h = ExtraHost(label, slot, (client_factory or PveClient)(host, port, token, str(directory / f"{label}-ca.pem"),
                                                                    node["name"]), "ui")
        multi.add(h)
        return h
    finally:
        tmp_ca.unlink(missing_ok=True)


def remove_host(multi, directory, label):
    h = next((h for h in multi.extras if h.label == label), None)
    if not h:
        raise HostSetupError(f"no host called {label}")
    if h.source != "ui":
        raise HostSetupError(f"{label} was added by the installer; remove it with: install.sh --remove-host {label}")
    for name in (f"{label}.json", f"{label}-ca.pem"):
        (Path(directory) / name).unlink(missing_ok=True)
    multi.remove(label)
    return h
