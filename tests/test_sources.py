import unittest

import demo
import discover
import sources


def public(cls):
    return {m for m in dir(cls) if not m.startswith("_") and callable(getattr(cls, m))}


class ClientTests(unittest.TestCase):
    def test_demo_implements_every_client_call(self):
        self.assertLessEqual(public(sources.PveClient), public(demo.DemoPve))

    def test_tls_name_autodetect(self):
        c = sources.PveClient("192.168.0.50", 8006, "pulse@pve!dash=x", None)
        calls = []

        def fake_get(path, check_name=True):
            calls.append((path, check_name, c.tls_name))
            if path == "/cluster/status":
                return [{"type": "cluster", "name": "lab"}, {"type": "node", "name": "pve2", "local": 0},
                        {"type": "node", "name": "home", "local": 1, "ip": "192.168.0.50"}]
            return []
        c._request = fake_get
        c.resources()
        self.assertEqual(c.tls_name, "home")
        self.assertEqual(calls[0], ("/cluster/status", False, None))   # chain-only for the very first call
        self.assertEqual(calls[1], ("/cluster/resources", True, "home"))
        c.resources()
        self.assertEqual(len(calls), 3)                                  # detected once

    def test_explicit_tls_name_skips_detection(self):
        c = sources.PveClient("h", 8006, "t", None, tls_name="pve1")
        seen = []
        c._request = lambda path, check_name=True: seen.append(path) or []
        c.resources()
        self.assertEqual(seen, ["/cluster/resources"])

    def test_node_scoped_paths(self):
        c = sources.PveClient("h", 8006, "t", None, tls_name="n")
        seen = []
        c._request = lambda path, check_name=True: seen.append(path) or {}
        c.node_status("pve2")
        c.lxc_interfaces("pve2", 201)
        c.agent_interfaces("pve1", 103)
        c.task_log("pve1", "UPID:pve1:1:2:3:vzdump::root@pam:")
        self.assertEqual(seen[:3], ["/nodes/pve2/status", "/nodes/pve2/lxc/201/interfaces",
                                    "/nodes/pve1/qemu/103/agent/network-get-interfaces"])
        self.assertTrue(seen[3].startswith("/nodes/pve1/tasks/UPID%3Apve1%3A1"))


class DemoTests(unittest.TestCase):
    def test_two_node_cluster(self):
        d = demo.DemoPve()
        nodes = [r["node"] for r in d.resources() if r["type"] == "node"]
        self.assertEqual(nodes, ["pve1", "pve2"])
        self.assertEqual(sum(r["type"] in ("lxc", "qemu") for r in d.resources()), 11)
        self.assertEqual({e["name"] for e in d.cluster_status() if e["type"] == "node"}, {"pve1", "pve2"})

    def test_agentless_vm_raises(self):
        with self.assertRaises(sources.SourceError):
            demo.DemoPve().agent_interfaces("pve1", 105)

    def test_ips_found_through_discovery_paths(self):
        d = demo.DemoPve()
        guests = [r for r in d.resources() if r["type"] in ("lxc", "qemu")]
        for r in guests:
            g = {"node": r["node"], "type": r["type"], "vmid": r["vmid"], "running": r["status"] == "running"}
            self.assertTrue(discover.guest_ips(d, g, {}, {}, 0), r["name"])

    def test_demo_net_serves_services(self):
        net, d = demo.DemoNet(), demo.DemoPve()
        ip = discover.static_ips(d.guest_config("pve2", "lxc", 200))[0]
        self.assertTrue(net.connect(ip, 11434))
        self.assertFalse(net.connect(ip, 22222))
        self.assertEqual(net.fingerprint(ip, 11434).product, "Ollama")
        self.assertTrue(net.probe({"kind": "tcp", "host": ip, "port": 11434}).ok)


class RrdTests(unittest.TestCase):
    def test_rrd_paths(self):
        c = sources.PveClient("h", 8006, "t", None, tls_name="n")
        seen = []
        c._request = lambda path, check_name=True: seen.append(path) or []
        c.rrd("pve2", "lxc", 201, "week")
        c.node_rrd("pve1", "day")
        c.storage_rrd("pve1", "local-lvm", "month")
        self.assertEqual(seen, ["/nodes/pve2/lxc/201/rrddata?timeframe=week&cf=AVERAGE",
                                "/nodes/pve1/rrddata?timeframe=day&cf=AVERAGE",
                                "/nodes/pve1/storage/local-lvm/rrddata?timeframe=month&cf=AVERAGE"])

    def test_demo_rrd_shapes(self):
        d = demo.DemoPve()
        pts = d.rrd("pve2", "lxc", 200, "day")
        self.assertTrue(len(pts) > 100 and {"time", "cpu", "mem", "maxmem", "netin", "netout"} <= set(pts[-1]))
        self.assertIn("memused", d.node_rrd("pve1", "week")[-1])
        st = d.storage_rrd("pve2", "local-lvm", "month")
        self.assertTrue(st[-1]["used"] > st[0]["used"])


class NewSourceMethodsTests(unittest.TestCase):
    def test_new_source_paths(self):
        c = sources.PveClient("h", 8006, "t", None, tls_name="n")
        seen = []
        c._request = lambda path, check_name=True: seen.append(path) or []
        c.zfs_pools("pve1")
        c.storage_config()
        c.node_updates("pve1")
        self.assertEqual(seen, ["/nodes/pve1/disks/zfs", "/storage", "/nodes/pve1/apt/update"])

    def test_demo_implements_new_calls(self):
        for m in ("zfs_pools", "storage_config", "node_updates"):
            self.assertTrue(callable(getattr(demo.DemoPve, m)), m)
