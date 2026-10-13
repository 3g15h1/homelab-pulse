"""The Proxmox API, read-only. The demo stand-in with identical shapes lives in demo.py.

Every call returns the raw JSON `data` the API returns, so the rest of the app can't tell a demo
source from a live one. Node-scoped calls take the node name: in a cluster any node's API answers
for all of them.
"""
import http.client
import json
import socket
import urllib.parse

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
