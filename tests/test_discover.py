"""Discovery logic against fakes: IP selection, scan targeting, service lifecycle, check planning."""
import unittest

import discover
from discover import Finding

LXC_IFACES = [  # GET /nodes/<n>/lxc/<id>/interfaces (real shape, PVE 9)
    {"name": "lo", "inet": "127.0.0.1/8", "hwaddr": "00:00:00:00:00:00"},
    {"name": "eth0", "inet": "192.168.0.51/22", "inet6": "fe80::be24:11ff:fea7:5365/64", "hwaddr": "bc:24:11:a7:53:65"},
    {"name": "docker0", "inet": "172.17.0.1/16"},
]
AGENT_IFACES = {"result": [  # GET /nodes/<n>/qemu/<id>/agent/network-get-interfaces
    {"name": "lo", "ip-addresses": [{"ip-address": "127.0.0.1", "ip-address-type": "ipv4", "prefix": 8}]},
    {"name": "enp0s18", "ip-addresses": [{"ip-address": "fe80::1", "ip-address-type": "ipv6", "prefix": 64},
                                         {"ip-address": "192.168.0.75", "ip-address-type": "ipv4", "prefix": 22}]},
    {"name": "hassio", "ip-addresses": [{"ip-address": "172.30.32.1", "ip-address-type": "ipv4", "prefix": 23}]},
    {"name": "tailscale0", "ip-addresses": [{"ip-address": "100.64.1.2", "ip-address-type": "ipv4", "prefix": 32}]},
]}


class FakePve:
    def __init__(self, agent=True):
        self.agent, self.calls = agent, []

    def lxc_interfaces(self, node, vmid):
        self.calls.append(("lxc", vmid))
        return LXC_IFACES

    def agent_interfaces(self, node, vmid):
        self.calls.append(("agent", vmid))
        if not self.agent:
            raise discover.SourceError("PVE agent: HTTP 500")
        return AGENT_IFACES

    def guest_config(self, node, kind, vmid):
        self.calls.append(("config", vmid))
        return {"net0": "virtio=BC:24:11:00:00:01,bridge=vmbr0", "net1": "name=eth1,ip=10.0.0.9/24,gw=10.0.0.1"}


class IpTests(unittest.TestCase):
    def test_extract_ips_lxc_and_agent_shapes(self):
        self.assertEqual(discover.extract_ips(LXC_IFACES), ["192.168.0.51"])
        self.assertEqual(discover.extract_ips(AGENT_IFACES["result"]), ["192.168.0.75", "172.30.32.1"])

    def test_static_ips_and_gateway(self):
        cfg = {"net0": "name=eth0,bridge=vmbr0,gw=192.168.0.1,ip=192.168.0.58/22,type=veth", "net1": "name=e,ip=dhcp",
               "cores": 2}
        self.assertEqual(discover.static_ips(cfg), ["192.168.0.58"])
        self.assertEqual(discover.config_gateway(cfg), "192.168.0.1")
        self.assertIsNone(discover.config_gateway({"net0": "virtio=x,bridge=vmbr0"}))

    def test_static_ips_cloud_init(self):
        self.assertEqual(discover.static_ips({"ipconfig0": "ip=192.168.1.30/24,gw=192.168.1.1"}), ["192.168.1.30"])
        self.assertEqual(discover.config_gateway({"ipconfig0": "ip=192.168.1.30/24,gw=192.168.1.1"}), "192.168.1.1")

    def test_pick_primary_prefers_node_subnet(self):
        self.assertEqual(discover.pick_primary(["172.30.32.1", "192.168.0.75"], "192.168.0.50"), "192.168.0.75")
        self.assertEqual(discover.pick_primary(["172.30.32.1"], "192.168.0.50"), "172.30.32.1")
        self.assertIsNone(discover.pick_primary([], "192.168.0.50"))

    def test_guest_ips_qemu_via_agent(self):
        pve = FakePve()
        g = {"node": "n1", "type": "qemu", "vmid": 103, "running": True}
        self.assertEqual(discover.guest_ips(pve, g, {}, {}, 0), ["192.168.0.75", "172.30.32.1"])

    def test_ips_fallback_when_agent_missing(self):
        pve, cache = FakePve(agent=False), {}
        g = {"node": "n1", "type": "qemu", "vmid": 103, "running": True}
        self.assertEqual(discover.guest_ips(pve, g, {}, cache, 100), ["10.0.0.9"])
        discover.guest_ips(pve, g, {}, cache, 200)          # within 10 min: agent not asked again
        self.assertEqual([c for c in pve.calls if c[0] == "agent"], [("agent", 103)])
        discover.guest_ips(pve, g, {}, cache, 100 + 601)
        self.assertEqual(len([c for c in pve.calls if c[0] == "agent"]), 2)

    def test_explicit_ip_comes_first(self):
        g = {"node": "n1", "type": "lxc", "vmid": 101, "running": True}
        self.assertEqual(discover.guest_ips(FakePve(), g, {"ip": "192.168.0.99"}, {}, 0), ["192.168.0.99", "192.168.0.51"])

    def test_stopped_guest_uses_static_config_only(self):
        pve = FakePve()
        g = {"node": "n1", "type": "lxc", "vmid": 101, "running": False}
        self.assertEqual(discover.guest_ips(pve, g, {}, {}, 0), ["10.0.0.9"])
        self.assertNotIn(("lxc", 101), pve.calls)


class FakeNet:
    """open: {(ip, port): Finding}. Records every connect."""

    def __init__(self, open_):
        self.open, self.connects = dict(open_), []

    def connect(self, ip, port):
        self.connects.append((ip, port))
        return (ip, port) in self.open

    def fingerprint(self, ip, port):
        return self.open[(ip, port)]


def F(port, product, kind="http", rank=0, icon="box"):
    return Finding(port=port, kind=kind, product=product, icon=icon, rank=rank, scheme="http")


def T(key, ip, name="g", running=True, scan=True, ports=None):
    return {"key": key, "ip": ip, "name": name, "running": running, "scan": scan, "ports": ports}


class DiscovererTests(unittest.TestCase):
    def test_scan_uses_only_given_ports(self):
        net = FakeNet({("10.0.0.5", 80): F(80, "Web")})
        d = discover.Discoverer(net)
        d.run([T(105, "10.0.0.5"), T("router", "10.0.0.1", ports=(80, 443))], ports=(22, 80))
        self.assertEqual(sorted(p for ip, p in net.connects if ip == "10.0.0.5"), [22, 80])
        self.assertEqual(sorted(p for ip, p in net.connects if ip == "10.0.0.1"), [80, 443])
        self.assertEqual([f.product for f in d.services(105)], ["Web"])

    def test_noscan_and_missing_ip_are_not_scanned(self):
        net = FakeNet({})
        discover.Discoverer(net).run([T(1, "10.0.0.5", scan=False), T(2, None)], ports=(80,))
        self.assertEqual(net.connects, [])

    def test_service_removed_only_after_two_misses(self):
        net = FakeNet({("10.0.0.5", 80): F(80, "Web"), ("10.0.0.5", 22): F(22, "SSH")})
        d = discover.Discoverer(net)
        d.run([T(105, "10.0.0.5", "box")], ports=(22, 80))
        del net.open[("10.0.0.5", 80)]
        self.assertEqual(d.run([T(105, "10.0.0.5", "box")], ports=(22, 80)), [])
        self.assertEqual(len(d.services(105)), 2)                    # one miss: still there
        ev = d.run([T(105, "10.0.0.5", "box")], ports=(22, 80))
        self.assertEqual([e["text"] for e in ev], ["Web on box is gone"])
        self.assertEqual([f.product for f in d.services(105)], ["SSH"])

    def test_miss_counter_resets_when_service_returns(self):
        net = FakeNet({("10.0.0.5", 80): F(80, "Web")})
        d = discover.Discoverer(net)
        d.run([T(105, "10.0.0.5")], ports=(80,))
        net.open.clear()
        d.run([T(105, "10.0.0.5")], ports=(80,))
        net.open[("10.0.0.5", 80)] = F(80, "Web")
        d.run([T(105, "10.0.0.5")], ports=(80,))
        net.open.clear()
        d.run([T(105, "10.0.0.5")], ports=(80,))
        self.assertEqual(len(d.services(105)), 1)

    def test_stopped_guest_keeps_services(self):
        net = FakeNet({("10.0.0.5", 80): F(80, "Web")})
        d = discover.Discoverer(net)
        d.run([T(105, "10.0.0.5")], ports=(80,))
        for _ in range(3):
            self.assertEqual(d.run([T(105, "10.0.0.5", running=False)], ports=(80,)), [])
        self.assertEqual(len(d.services(105)), 1)

    def test_new_service_event_not_on_first_run(self):
        net = FakeNet({("10.0.0.5", 80): F(80, "Web")})
        d = discover.Discoverer(net)
        self.assertEqual(d.run([T(105, "10.0.0.5", "box")], ports=(80, 8000)), [])   # startup isn't news
        net.open[("10.0.0.5", 8000)] = F(8000, "Paperless-ngx")
        net.open[("10.0.0.9", 80)] = F(80, "Grafana")
        ev = d.run([T(105, "10.0.0.5", "box"), T(109, "10.0.0.9", "new")], ports=(80, 8000))
        self.assertEqual(sorted(e["text"] for e in ev), ["Found Grafana on new", "Found Paperless-ngx on box"])
        self.assertTrue(all(e["kind"] == "discovery" and e["level"] == "info" for e in ev))

    def test_run_never_mutates_a_published_service_map(self):
        # the slow poll reads services() from another thread; run() must swap maps, not edit them
        net = FakeNet({("10.0.0.5", 80): F(80, "Web"), ("10.0.0.5", 22): F(22, "SSH")})
        d = discover.Discoverer(net)
        d.run([T(105, "10.0.0.5")], ports=(22, 80))
        before = d.known[105]
        snapshot = dict(before)
        net.open[("10.0.0.5", 8000)] = F(8000, "New")
        del net.open[("10.0.0.5", 80)]
        d.run([T(105, "10.0.0.5")], ports=(22, 80, 8000))
        d.run([T(105, "10.0.0.5")], ports=(22, 80, 8000))
        self.assertEqual(before, snapshot)
        self.assertEqual(sorted(d.known[105]), [22, 8000])

    def test_forget_drops_deleted_guests(self):
        net = FakeNet({("10.0.0.5", 80): F(80, "Web")})
        d = discover.Discoverer(net)
        d.run([T(105, "10.0.0.5")], ports=(80,))
        d.forget(keep={"router"})
        self.assertEqual(d.services(105), [])


class PlanTests(unittest.TestCase):
    def setUp(self):
        self.services = {
            104: [F(443, "nginx", kind="tls", rank=40), F(22, "SSH", kind="tcp")],
            101: [F(53, "DNS server", kind="dns"), F(80, "AdGuard Home")],
            "router": [F(80, "Router", rank=99)],
        }
        self.guests = [{"vmid": 104, "name": "ha-proxy", "ip": "192.168.0.53"},
                       {"vmid": 101, "name": "adguard", "ip": "192.168.0.51"}]
        self.router = {"name": "Router", "ip": "192.168.0.1"}
        self.nodes = [{"name": "home", "ip": "192.168.0.50"}]

    def plan(self, ov=None):
        return {c["id"]: c for c in discover.plan_checks(self.services, self.guests, self.router, self.nodes,
                                                          ov or {}, "/etc/homelab-pulse/pve-ca.pem")}

    def test_builtin_and_discovered_checks(self):
        p = self.plan()
        self.assertEqual(p["internet"], {"id": "internet", "name": "Internet", "kind": "tcp", "host": "1.1.1.1",
                                         "port": 443, "target": "internet", "source": "builtin"})
        self.assertEqual((p["node:home"]["kind"], p["node:home"]["sni"], p["node:home"]["cafile"]),
                         ("tls", "home", "/etc/homelab-pulse/pve-ca.pem"))
        self.assertEqual(p["node:home"]["target"], "home")
        self.assertEqual(p["101:53"], {"id": "101:53", "name": "DNS server", "kind": "dns", "server": "192.168.0.51",
                                       "qname": "doubleclick.net", "target": 101, "port": 53, "product": "DNS server",
                                       "guest": "adguard", "source": "discovered"})
        self.assertEqual((p["104:443"]["kind"], p["104:443"]["verify"]), ("tls", False))
        self.assertEqual(p["101:80"]["url"], "http://192.168.0.51:80/")
        self.assertEqual((p["router:80"]["target"], p["router:80"]["kind"]), ("router", "http"))

    def test_plan_checks_precedence(self):
        ov = {"internet": False, "hide_checks": ["101:80"],
              "checks": [{"id": "ha-proxy", "name": "Remote access (HTTPS)", "kind": "tls", "host": "192.168.0.53",
                          "port": 443, "sni": "home.example.org", "target": 104}]}
        p = self.plan(ov)
        self.assertNotIn("internet", p)
        self.assertNotIn("101:80", p)
        self.assertNotIn("104:443", p)                           # replaced by the override for the same port
        self.assertEqual((p["ha-proxy"]["sni"], p["ha-proxy"]["source"]), ("home.example.org", "override"))

    def test_internet_override_target(self):
        p = self.plan({"internet": {"host": "9.9.9.9", "port": 53}})
        self.assertEqual((p["internet"]["host"], p["internet"]["port"]), ("9.9.9.9", 53))

    def test_quiet_services_get_no_periodic_check(self):
        p = self.plan()
        self.assertNotIn("104:22", p)                            # SSH: listed on the guest, not hammered every 15 s
        p = self.plan({"checks": [{"id": "ssh-proxy", "name": "SSH", "kind": "tcp", "host": "192.168.0.53",
                                   "port": 22, "target": 104}]})
        self.assertIn("ssh-proxy", p)                            # but an explicit override still works

    def test_node_without_ca_is_unverified(self):
        p = {c["id"]: c for c in discover.plan_checks({}, [], None, self.nodes, {}, None)}
        self.assertFalse(p["node:home"]["verify"])


class ClassifyTests(unittest.TestCase):
    def test_classify_prefers_specific(self):
        fs = [F(22, "SSH", rank=45, icon="terminal"), F(80, "nginx", rank=43), F(8000, "Paperless-ngx", rank=3, icon="doc")]
        self.assertEqual(discover.classify(fs, "paperless", "debian", "lxc"), ("Paperless-ngx", "doc"))

    def test_classify_ignores_generic_and_falls_back_to_name(self):
        fs = [F(22, "SSH", rank=45, icon="terminal"), F(80, "nginx", rank=43)]
        self.assertEqual(discover.classify(fs, "ha-proxy", "debian", "lxc"), ("Reverse proxy", "globe"))
        self.assertEqual(discover.classify([], "zzz", None, "qemu"), ("Virtual machine", "box"))


if __name__ == "__main__":
    unittest.main()
