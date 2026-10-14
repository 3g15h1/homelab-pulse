"""pulse-heal-gate against stub pvesh/pct/qm/ssh: what it runs, what it refuses, and that it never
uses a shell. Every stub appends its argv (JSON) to $STUB_LOG."""
import json
import os
import stat
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GATE = ROOT / "heal" / "pulse-heal-gate"

STUB = r'''#!/usr/bin/env python3
import json, os, sys, time
name = os.path.basename(sys.argv[0]); args = sys.argv[1:]
with open(os.environ["STUB_LOG"], "a") as f:
    f.write(json.dumps([name] + args) + "\n")
RES = {"data": [
  {"vmid": 101, "type": "lxc", "node": "home", "status": "running", "name": "adguard"},
  {"vmid": 102, "type": "lxc", "node": "home", "status": "stopped", "name": "off"},
  {"vmid": 103, "type": "qemu", "node": "home", "status": "running", "name": "haos"},
  {"vmid": 104, "type": "lxc", "node": "home", "status": "running", "name": "alpine"},
  {"vmid": 105, "type": "lxc", "node": "home", "status": "running", "name": "dockerhost"},
  {"vmid": 110, "type": "lxc", "node": "home", "status": "running", "name": "pulse"},
  {"vmid": 201, "type": "lxc", "node": "pve2", "status": "running", "name": "far"}]}
if name == "pvesh":
    if "/cluster/resources" in args:
        print(json.dumps(RES["data"]))
    elif "/cluster/status" in args:
        print(json.dumps([{"type": "cluster", "name": "lab"},
                          {"type": "node", "name": "home", "ip": "10.0.0.2", "local": 1},
                          {"type": "node", "name": "pve2", "ip": "10.0.0.3", "local": 0}]))
    sys.exit(0)
if name == "ssh":                     # behave like the remote node: run the forwarded pct command
    import shlex, subprocess
    remote = shlex.split(args[-1])
    stub_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
    sys.exit(subprocess.run([os.path.join(stub_dir, remote[0])] + remote[1:]).returncode)
def guest_cmd(vmid, cmd):
    c = " ".join(cmd)
    if cmd[:2] == ["cat", "/proc/1/comm"]:
        print("init" if vmid == "104" else "systemd"); return 0
    if cmd[:1] == ["which"]:
        return 0 if vmid == "104" else 1
    if cmd[:1] == ["ss"]:
        if vmid == "101" and c.endswith(":80"):
            print('LISTEN 0 4096 *:80 *:* users:(("AdGuardHome",pid=321,fd=9))')
        if vmid == "105" and c.endswith(":1884"):
            print('LISTEN 0 4096 0.0.0.0:1884 0.0.0.0:* users:(("docker-proxy",pid=55,fd=4))')
        if vmid == "104" and c.endswith(":80"):
            print('LISTEN 0 128 0.0.0.0:80 0.0.0.0:* users:(("lighttpd",pid=77,fd=4))')
        return 0
    if cmd[:1] == ["cat"] and cmd[1].startswith("/proc/"):
        print({"/proc/321/cgroup": "0::/system.slice/AdGuardHome.service",
               "/proc/55/cgroup": "0::/system.slice/docker.service",
               "/proc/77/cgroup": "0::/"}.get(cmd[1], "")); return 0
    if cmd[:2] == ["docker", "ps"]:
        if "-a" in cmd:
            print("ring-mosquitto-1\nring-ring-mqtt-1")
        else:
            print("ring-mosquitto-1\t127.0.0.1:1883->1883/tcp, 0.0.0.0:1884->1884/tcp\n"
                  "ring-ring-mqtt-1\t0.0.0.0:8554->8554/tcp")
        return 0
    if cmd[:2] == ["systemctl", "cat"]:
        return 0 if cmd[2] == "AdGuardHome.service" else 1
    if cmd[:1] == ["sleep"]:
        time.sleep(float(cmd[1])); return 0
    if cmd[:1] == ["false"]:
        print("it failed"); return 1
    print("ok " + c); return 0
if name == "pct":
    assert args[0] == "exec" and args[2] == "--", args
    sys.exit(guest_cmd(args[1], args[3:]))
if name == "qm":
    assert args[:2] == ["guest", "exec"], args
    i = args.index("--")
    import io, contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = guest_cmd(args[2], args[i + 1:])
    print(json.dumps({"exitcode": code, "exited": 1, "out-data": buf.getvalue()}))
    sys.exit(0)
for bad in ("sh", "bash", "dash"):
    pass
sys.exit(127)
'''


class GateHarness:
    def __init__(self, test):
        self.dir = Path(tempfile.mkdtemp())
        self.bin, self.etc, self.share, self.state = (self.dir / x for x in ("bin", "etc", "share", "state"))
        for p in (self.bin, self.etc / "recipes.d", self.share, self.state):
            p.mkdir(parents=True)
        for name in ("pvesh", "pct", "qm", "ssh", "sh", "bash"):
            f = self.bin / name
            f.write_text(STUB)
            f.chmod(0o755)
        (self.etc / "enabled").write_text("1\n")
        (self.etc / "self").write_text("110\n")
        (self.etc / "deny").write_text("")
        self.log = self.dir / "stub.log"
        self.gatelog = self.dir / "gate.log"
        self.recipe("generic-unit", {"alert": "service_down"}, {"restart": "unit"})
        self.recipe("generic-container", {"alert": "service_down"}, {"restart": "container"})
        self.recipe("multi", {"alert": "service_down", "vmids": [101]},
                    {"exec": [["systemctl", "reload", "{unit}"], ["false"], ["echo", "never"]]})
        self.recipe("slow", {"alert": "service_down"}, {"exec": [["sleep", "8"]]}, safety={"timeout_s": 5})
        self.recipe("lxc-only", {"alert": "service_down"}, {"restart": "unit"}, guest=["lxc"])

    def recipe(self, rid, when, do, where="share", mode=0o644, **extra):
        doc = {"schema": 1, "id": rid, "name": rid, "when": when, "do": do, **extra}
        f = (self.share if where == "share" else self.etc / "recipes.d") / f"{rid}.json"
        f.write_text(json.dumps(doc))
        os.chmod(f, mode)
        return f

    def run(self, command, argv=()):
        env = dict(os.environ, PATH=f"{self.bin}:/usr/bin:/bin", STUB_LOG=str(self.log),
                   PULSE_HEAL_ETC=str(self.etc), PULSE_HEAL_SHARE=str(self.share), PULSE_HEAL_STATE=str(self.state),
                   PULSE_HEAL_LOG=str(self.gatelog), PULSE_HEAL_LIB=str(ROOT / "pulse"))
        if command is not None:
            env["SSH_ORIGINAL_COMMAND"] = command
        p = subprocess.run(["/usr/bin/python3", str(GATE), *argv], env=env, capture_output=True, text=True, timeout=60)
        try:
            out = json.loads(p.stdout.strip().splitlines()[-1]) if p.stdout.strip() else None
        except json.JSONDecodeError:
            out = {"raw": p.stdout}
        return p.returncode, out, p.stderr

    def calls(self):
        if not self.log.exists():
            return []
        return [json.loads(l) for l in self.log.read_text().splitlines()]

    def guest_calls(self):
        return [c for c in self.calls() if c[0] in ("pct", "qm", "ssh")]


class GateTests(unittest.TestCase):
    def setUp(self):
        self.g = GateHarness(self)

    def ok(self, cmd):
        code, out, err = self.g.run(cmd)
        self.assertEqual(code, 0, (out, err))
        self.assertTrue(out["ok"], out)
        return out

    def refused(self, cmd, why=None):
        code, out, err = self.g.run(cmd)
        self.assertEqual(code, 2, (cmd, out, err))
        self.assertFalse(out["ok"])
        if why:
            self.assertIn(why, out["error"])
        self.assertNotIn("Traceback", err)
        return out

    def test_version_and_list(self):
        v = self.ok("version")
        self.assertEqual((v["schema"], v["enabled"]), (1, True))
        lst = self.ok("list-recipes")["recipes"]
        self.assertEqual({r["id"] for r in lst}, {"generic-unit", "generic-container", "multi", "slow", "lxc-only"})
        self.assertEqual(lst[0]["source"], "built-in")

    def test_inspect_systemd_unit(self):
        out = self.ok("inspect 101 80")
        self.assertEqual((out["init"], out["unit"], out["container"]), ("systemd", "AdGuardHome.service", None))

    def test_inspect_docker_container(self):
        out = self.ok("inspect 105 1884")
        self.assertEqual((out["unit"], out["container"]), (None, "ring-mosquitto-1"))   # docker.service is never the target

    def test_inspect_openrc(self):
        out = self.ok("inspect 104 80")
        self.assertEqual((out["init"], out["unit"]), ("openrc", None))

    def test_inspect_nothing_listening(self):
        out = self.ok("inspect 101 8080")
        self.assertEqual((out["unit"], out["container"]), (None, None))

    def test_run_restart_unit_argv(self):
        out = self.ok("run generic-unit 101 80 --target unit=AdGuardHome.service")
        self.assertIn(["pct", "exec", "101", "--", "systemctl", "restart", "AdGuardHome.service"], self.g.guest_calls())
        self.assertEqual(out["steps"][0]["exit"], 0)

    def test_run_container_argv(self):
        self.ok("run generic-container 105 1884 --target container=ring-mosquitto-1")
        self.assertIn(["pct", "exec", "105", "--", "docker", "restart", "ring-mosquitto-1"], self.g.guest_calls())

    def test_run_exec_steps_stop_on_failure(self):
        code, out, _ = self.g.run("run multi 101 80 --target unit=AdGuardHome.service")
        self.assertEqual(code, 3)
        self.assertEqual([s["exit"] for s in out["steps"]], [0, 1])
        self.assertIn("it failed", out["output"])
        self.assertNotIn(["pct", "exec", "101", "--", "echo", "never"], self.g.guest_calls())

    def test_qemu_uses_guest_exec(self):
        self.g.recipe("q-exec", {"alert": "service_down"}, {"exec": [["true"]]})
        self.ok("run q-exec 103 8123")
        c = [c for c in self.g.guest_calls() if c[0] == "qm"]
        self.assertEqual(c[-1][:4], ["qm", "guest", "exec", "103"])
        self.assertEqual(c[-1][-1], "true")

    def test_other_node_forwards_over_ssh(self):
        self.ok("run generic-unit 201 80 --target unit=AdGuardHome.service")
        ssh = [c for c in self.g.guest_calls() if c[0] == "ssh"]
        self.assertTrue(ssh)
        self.assertIn("root@10.0.0.3", ssh[-1])
        self.assertIn("BatchMode=yes", ssh[-1])
        self.assertEqual(ssh[-1][-1], "pct exec 201 -- systemctl restart AdGuardHome.service")

    def test_warning_recipe_runs_without_port(self):
        self.g.recipe("cleanup", {"alert": "warning", "rule": "ct_disk"}, {"exec": [["apt-get", "clean"]]})
        self.ok("run cleanup 101 0")
        self.assertIn(["pct", "exec", "101", "--", "apt-get", "clean"], self.g.guest_calls())
        self.refused("run generic-unit 101 0 --target unit=AdGuardHome.service --target container=x", None)

    def test_dry_run_executes_nothing(self):
        out = self.ok("run generic-unit 101 80 --target unit=AdGuardHome.service --dry-run")
        self.assertEqual(out["steps"], [{"argv": ["systemctl", "restart", "AdGuardHome.service"], "dry_run": True}])
        self.assertFalse([c for c in self.g.guest_calls() if "restart" in c])

    def test_refusals(self):
        self.refused("run generic-unit 999 80 --target unit=AdGuardHome.service", "no such guest")
        self.refused("run generic-unit 102 80 --target unit=AdGuardHome.service", "not running")
        self.refused("run generic-unit 110 80 --target unit=AdGuardHome.service", "Pulse")
        (self.g.etc / "deny").write_text("101\n")
        self.refused("run generic-unit 101 80 --target unit=AdGuardHome.service", "deny")
        (self.g.etc / "deny").write_text("")
        self.refused("run nope 101 80", "unknown recipe")
        self.g.recipe("evil", {"alert": "service_down"}, {"exec": [["sh", "-c", "id"]]})
        self.refused("run evil 101 80", "lint")
        self.refused("run multi 105 1884 --target unit=AdGuardHome.service", "not for this guest")
        self.refused("run lxc-only 103 8123 --target unit=AdGuardHome.service", "not for this guest")
        self.refused("run generic-unit 101 80 --target unit=other.service", "does not exist")
        self.refused("run generic-container 105 1884 --target container=ghost", "does not exist")
        self.refused("run generic-unit 101 80", "no service")
        self.refused("frobnicate 101", "unknown verb")
        self.refused("", "unknown verb")

    def test_injection_refused(self):
        for cmd in ("inspect 101 80; rm -rf /", "inspect 101 $(id)", "inspect `id` 80", "run ../../etc/passwd 101 80",
                    "run generic-unit 101 80 --target unit=x;id.service", "run generic-unit 101 80 --target unit=$(id).service",
                    "run generic-container 105 1884 --target container=a&&b", "inspect 101 80\nrm -rf /",
                    "run generic-unit 101 80 --target unit=" + "a" * 500 + ".service", "inspect 101 99999",
                    "run generic-unit 101 80 --target path=/etc"):
            code, out, err = self.g.run(cmd)
            self.assertEqual(code, 2, cmd)
            self.assertNotIn("Traceback", err)
        self.assertFalse([c for c in self.g.guest_calls() if "restart" in c or "rm" in c or "id" in c])

    def test_writable_recipe_refused(self):
        self.g.recipe("tampered", {"alert": "service_down"}, {"restart": "unit"}, where="local", mode=0o666)
        lst = {r["id"]: r for r in self.ok("list-recipes")["recipes"]}
        self.assertIn("writable", lst["tampered"]["errors"][0])
        self.refused("run tampered 101 80 --target unit=AdGuardHome.service")

    def test_local_recipe_overrides(self):
        self.g.recipe("generic-unit", {"alert": "service_down"}, {"restart": "unit"}, where="local", name="Mine")
        lst = {r["id"]: r for r in self.ok("list-recipes")["recipes"]}
        self.assertEqual((lst["generic-unit"]["source"], lst["generic-unit"]["name"]), ("local override", "Mine"))

    def test_kill_switch(self):
        (self.g.etc / "enabled").write_text("0\n")
        self.refused("run generic-unit 101 80 --target unit=AdGuardHome.service", "disabled")
        self.ok("run generic-unit 101 80 --target unit=AdGuardHome.service --dry-run")    # dry runs still work
        (self.g.etc / "enabled").unlink()
        self.assertFalse(self.ok("version")["enabled"])

    def test_global_and_per_recipe_budget(self):
        for _ in range(2):
            self.ok("run generic-unit 101 80 --target unit=AdGuardHome.service")
        self.refused("run generic-unit 101 80 --target unit=AdGuardHome.service", "per hour")
        (self.g.etc / "gate.conf").write_text(json.dumps({"budget_per_hour": 3}))
        self.ok("run generic-container 105 1884 --target container=ring-mosquitto-1")
        self.refused("run generic-container 105 1884 --target container=ring-mosquitto-1", "budget")

    def test_timeout_reported(self):
        t0 = time.time()
        code, out, _ = self.g.run("run slow 101 80")
        self.assertEqual(code, 3)
        self.assertIn("timed out", out["output"])
        self.assertLess(time.time() - t0, 8)

    def test_log_line_per_request(self):
        self.ok("version")
        self.refused("run nope 101 80")
        lines = [json.loads(l) for l in self.g.gatelog.read_text().splitlines()]
        self.assertEqual([l["verb"] for l in lines], ["version", "run"])
        self.assertEqual((lines[1]["ok"], lines[1]["args"]), (False, ["nope", "101", "80"]))

    def test_no_shell_ever(self):
        self.ok("run generic-unit 101 80 --target unit=AdGuardHome.service")
        self.g.run("run multi 101 80 --target unit=AdGuardHome.service")
        self.g.run("inspect 105 1884")
        self.assertFalse([c for c in self.g.calls() if c[0] in ("sh", "bash")])

    def test_check_mode_lints_file(self):
        good = self.g.recipe("fine", {"alert": "service_down"}, {"restart": "unit"})
        bad = self.g.recipe("bad", {"alert": "service_down"}, {"exec": [["rm", "-rf", "/x"]]})
        code, out, _ = self.g.run(None, ["--check", str(good)])
        self.assertEqual(code, 0)
        code, out, _ = self.g.run(None, ["--check", str(good), str(bad)])
        self.assertEqual(code, 1)
        self.assertIn("recursive rm", json.dumps(out))


if __name__ == "__main__":
    unittest.main()
