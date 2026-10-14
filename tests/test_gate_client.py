import json
import subprocess
import unittest

import demo
import gate_client


class FakeRunner:
    def __init__(self, stdout="", code=0, exc=None):
        self.stdout, self.code, self.exc, self.calls = stdout, code, exc, []

    def __call__(self, argv, **kw):
        self.calls.append((argv, kw))
        if self.exc:
            raise self.exc
        return subprocess.CompletedProcess(argv, self.code, self.stdout, "ssh: oops")


class ClientTests(unittest.TestCase):
    def test_ssh_argv_and_quoting(self):
        r = FakeRunner(json.dumps({"ok": True, "init": "systemd"}))
        c = gate_client.GateClient("root@10.0.0.2", "/etc/homelab-pulse/heal_key", runner=r)
        self.assertEqual(c.inspect(101, 80)["init"], "systemd")
        argv = r.calls[0][0]
        self.assertEqual(argv[:3], ["ssh", "-i", "/etc/homelab-pulse/heal_key"])
        self.assertIn("BatchMode=yes", argv)
        self.assertIn("UserKnownHostsFile=/var/lib/homelab-pulse/heal_known_hosts", argv)
        self.assertEqual(argv[-2:], ["root@10.0.0.2", "inspect 101 80"])
        c.run("restart-port-owner", 101, 80, target={"unit": "AdGuardHome.service"}, dry_run=True)
        self.assertEqual(r.calls[1][0][-1], "run restart-port-owner 101 80 --target unit=AdGuardHome.service --dry-run")

    def test_refusal_is_returned_not_raised(self):
        r = FakeRunner(json.dumps({"ok": False, "error": "guest 101 is on the deny list"}), code=2)
        c = gate_client.GateClient("root@h", "/k", runner=r)
        self.assertEqual(c.run("x-y", 101, 80)["error"], "guest 101 is on the deny list")

    def test_errors_mapped(self):
        for runner, msg in ((FakeRunner(exc=subprocess.TimeoutExpired("ssh", 30)), "timed out"),
                            (FakeRunner(code=255), "ssh"),
                            (FakeRunner("not json at all"), "unexpected")):
            with self.assertRaisesRegex(gate_client.GateError, msg):
                gate_client.GateClient("root@h", "/k", runner=runner).version()


class DemoGateTests(unittest.TestCase):
    def test_demo_gate_inspect_and_run(self):
        net = demo.DemoNet()
        g = demo.DemoGate(net)
        self.assertTrue(g.version()["enabled"])
        ids = {r["id"] for r in g.list_recipes()["recipes"]}
        self.assertLessEqual({"restart-port-owner", "restart-port-container"}, ids)
        self.assertEqual(g.inspect(202, 443)["unit"], "truenas.service")
        self.assertEqual(g.inspect(105, 9443)["container"], "portainer")
        dry = g.run("restart-port-owner", 202, 443, target={"unit": "truenas.service"}, dry_run=True)
        self.assertEqual(dry["steps"], [{"argv": ["systemctl", "restart", "truenas.service"], "dry_run": True}])
        self.assertEqual(g.calls, [])
        res = g.run("restart-port-owner", 202, 443, target={"unit": "truenas.service"})
        self.assertTrue(res["ok"])
        self.assertEqual(len(g.calls), 1)
        self.assertFalse(g.run("nope-nope", 202, 443)["ok"])
