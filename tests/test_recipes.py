import copy
import json
import os
import tempfile
import unittest
from pathlib import Path

import recipes

BASE = {"schema": 1, "id": "adguard-restart", "name": "Restart AdGuard Home",
        "when": {"alert": "service_down", "product": ["AdGuard Home"]}, "do": {"restart": "unit"}}


def r(**patch):
    d = copy.deepcopy(BASE)
    d.update(patch)
    return d


def ex(*steps, **kw):
    return recipes.validate(r(id="x-exec", do={"exec": [list(s) for s in steps]}, **kw))


class ValidateTests(unittest.TestCase):
    def test_validate_defaults_and_ranges(self):
        v = recipes.validate(r())
        self.assertEqual(v["safety"], {"max_per_hour": 2, "verify_s": 90, "timeout_s": 60, "default_mode": "auto"})
        self.assertEqual(v["guest"], ["lxc", "qemu"])
        self.assertEqual(v["description"], "")
        for bad in ({"max_per_hour": 7}, {"verify_s": 5}, {"timeout_s": 301}, {"default_mode": "yolo"}):
            with self.assertRaises(recipes.RecipeError):
                recipes.validate(r(safety=bad))

    def test_bad_id_and_unknown_keys(self):
        for bad in ("A", "has space", "x" * 65, "../etc"):
            with self.assertRaises(recipes.RecipeError):
                recipes.validate(r(id=bad))
        with self.assertRaisesRegex(recipes.RecipeError, "unknown"):
            recipes.validate(r(run_as="root"))
        with self.assertRaises(recipes.RecipeError):
            recipes.validate(r(schema=2))
        with self.assertRaises(recipes.RecipeError):
            recipes.validate(r(when={"alert": "service_down", "colour": "red"}))
        with self.assertRaises(recipes.RecipeError):                  # warning needs a rule
            recipes.validate(r(when={"alert": "warning"}))

    def test_do_exactly_one_kind(self):
        for bad in ({}, {"restart": "unit", "exec": [["true"]]}, {"restart": "machine"}, {"exec": []},
                    {"exec": [[]]}, {"exec": [["a"]] * 9}, {"exec": [["x" * 201]]}, {"exec": [["a\nb"]]},
                    {"exec": "systemctl restart x"}):
            with self.assertRaises(recipes.RecipeError, msg=bad):
                recipes.validate(r(do=bad))

    def test_placeholders_whole_args_only(self):
        ex(["systemctl", "reload", "{unit}"])
        for bad in ("x{unit}", "{unit}.bak", "{host}", "{{unit}}"):
            with self.assertRaises(recipes.RecipeError, msg=bad):
                ex(["echo", bad])


class LintTests(unittest.TestCase):
    def test_lint_each_forbidden_pattern(self):
        bad = [
            ["sh", "-c", "anything"], ["/bin/bash", "x"], ["busybox", "rm"], ["python3", "-c", "x"], ["perl", "-e", "1"],
            ["env", "X=1", "cmd"], ["sudo", "ls"], ["su", "-"], ["nsenter", "-t", "1"], ["xargs", "rm"],
            ["rm", "-rf", "/var/tmp/x"], ["rm", "-r", "x"], ["rm", "--recursive", "x"], ["dd", "if=/dev/zero"],
            ["mkfs.ext4", "/dev/sda"], ["fdisk", "/dev/sda"], ["shutdown", "-h", "now"], ["reboot"], ["init", "0"],
            ["apt-get", "purge", "x"], ["apt", "autoremove"], ["dnf", "remove", "x"], ["yum", "erase", "x"],
            ["docker", "system", "prune", "-f"], ["docker", "rm", "c"], ["docker", "volume", "rm", "v"],
            ["systemctl", "stop", "nginx"], ["systemctl", "disable", "x"], ["systemctl", "mask", "x"],
            ["sed", "-i", "s/a/b/", "/etc/hosts"], ["tee", "/etc/resolv.conf"], ["cp", "x", "/etc/x"],
        ]
        for argv in bad:
            self.assertTrue(recipes.lint(ex(argv)), argv)

    def test_lint_allows_good_commands(self):
        for argv in (["systemctl", "restart", "{unit}"], ["systemctl", "reload", "nginx"], ["journalctl", "--vacuum-size=200M"],
                     ["apt-get", "clean"], ["docker", "restart", "{container}"], ["nginx", "-t"], ["pihole", "restartdns"],
                     ["rm", "-f", "/var/run/app.pid"], ["sed", "-n", "1p", "/etc/hostname"]):
            self.assertEqual(recipes.lint(ex(argv)), [], argv)
        self.assertEqual(recipes.lint(recipes.validate(r())), [])


class MatchTests(unittest.TestCase):
    cond = {"key": "check:101:80", "kind": "service_down", "target": 101}
    check = {"id": "101:80", "product": "AdGuard Home", "port": 80}
    guest = {"vmid": 101, "type": "lxc", "tags": ["dns", "prod"]}

    def m(self, rec, cond=None, check="default", guest=None):
        return recipes.matches(recipes.validate(rec), cond or self.cond, self.check if check == "default" else check,
                               guest or self.guest)

    def test_matching_product_port_tags_vmids_guest_type(self):
        self.assertTrue(self.m(r()))
        self.assertTrue(self.m(r(when={"alert": "service_down", "product": ["adguard home"]})))     # case-insensitive
        self.assertFalse(self.m(r(when={"alert": "service_down", "product": ["Pi-hole"]})))
        self.assertTrue(self.m(r(when={"alert": "service_down", "port": [53, 80]})))
        self.assertFalse(self.m(r(when={"alert": "service_down", "port": [53]})))
        self.assertTrue(self.m(r(when={"alert": "service_down", "tags": ["dns"]})))
        self.assertFalse(self.m(r(when={"alert": "service_down", "tags": ["dns", "edge"]})))
        self.assertFalse(self.m(r(when={"alert": "service_down", "vmids": [102]})))
        self.assertFalse(self.m(r(guest=["qemu"])))
        self.assertTrue(self.m(r(when={"alert": "service_down"})))                                  # generic

    def test_warning_rule_matching(self):
        rec = r(id="ct-disk", when={"alert": "warning", "rule": "ct_disk"}, do={"exec": [["apt-get", "clean"]]})
        cond = {"key": "warn:ct_disk:101", "kind": "warning", "target": 101}
        self.assertTrue(self.m(rec, cond=cond, check=None))
        self.assertFalse(self.m(rec, cond={"key": "warn:storage_full:pve1/local", "kind": "warning", "target": "pve1"},
                                check=None))
        self.assertFalse(self.m(rec))                                                                # service_down
        self.assertFalse(self.m(r(), cond=cond, check=None))                                       # needs a check

    def test_recipe_with_errors_never_matches(self):
        rec = dict(recipes.validate(r()), errors=["lint: nope"])
        self.assertFalse(recipes.matches(rec, self.cond, self.check, self.guest))


class PriorityLoadTests(unittest.TestCase):
    def test_priority_order(self):
        generic = recipes.validate(r(id="gen", when={"alert": "service_down"}))
        port = recipes.validate(r(id="port", when={"alert": "service_down", "port": [80]}))
        product = recipes.validate(r(id="prod"))
        self.assertGreater(recipes.priority(product), recipes.priority(port))
        self.assertGreater(recipes.priority(port), recipes.priority(generic))
        local = dict(generic, source="local")
        self.assertGreater(recipes.priority(local), recipes.priority(dict(generic, source="built-in")))

    def write(self, d, name, doc, mode=0o644):
        p = Path(d) / name
        p.write_text(doc if isinstance(doc, str) else json.dumps(doc))
        os.chmod(p, mode)
        return p

    def test_load_dir_errors_and_writable_refused(self):
        d = tempfile.mkdtemp()
        self.write(d, "good.json", r())
        self.write(d, "bad.json", "{not json")
        self.write(d, "lint.json", r(id="lint-me", do={"exec": [["sh", "-c", "x"]]}))
        self.write(d, "open.json", r(id="open-perms"), mode=0o666)
        self.write(d, "readme.txt", "ignored")
        self.write(d, "example.json.disabled", r(id="disabled-one"))
        got = {x["id"]: x for x in recipes.load_dir(d, "local")}
        self.assertEqual(set(got), {"adguard-restart", "bad", "lint-me", "open"})
        self.assertEqual(got["adguard-restart"]["errors"], [])
        self.assertEqual(got["adguard-restart"]["source"], "local")
        self.assertIn("invalid JSON", got["bad"]["errors"][0])
        self.assertTrue(got["lint-me"]["errors"][0].startswith("lint: "))
        self.assertIn("writable", got["open"]["errors"][0])
        self.assertEqual(recipes.load_dir("/nonexistent", "local"), [])

    def test_local_override(self):
        b = [dict(recipes.validate(r()), source="built-in", errors=[])]
        l = [dict(recipes.validate(r(name="Mine")), source="local", errors=[]),
             dict(recipes.validate(r(id="extra")), source="local", errors=[])]
        out = {x["id"]: x for x in recipes.merge(b, l)}
        self.assertEqual((out["adguard-restart"]["name"], out["adguard-restart"]["source"]), ("Mine", "local override"))
        self.assertEqual(out["extra"]["source"], "local")


class ResolveTests(unittest.TestCase):
    def test_resolve_fills_and_requires_targets(self):
        self.assertEqual(recipes.resolve(recipes.validate(r()), {"init": "systemd", "unit": "AdGuardHome.service"}),
                         [["systemctl", "restart", "AdGuardHome.service"]])
        self.assertEqual(recipes.resolve(recipes.validate(r()), {"init": "openrc", "unit": "adguardhome"}),
                         [["rc-service", "adguardhome", "restart"]])
        self.assertEqual(recipes.resolve(recipes.validate(r(do={"restart": "container"})), {"container": "ring-mqtt-1"}),
                         [["docker", "restart", "ring-mqtt-1"]])
        self.assertEqual(recipes.resolve(ex(["systemctl", "reload", "{unit}"], ["ss", "-ltn", "sport", "=", "{port}"]),
                                         {"init": "systemd", "unit": "nginx.service", "port": 443}),
                         [["systemctl", "reload", "nginx.service"], ["ss", "-ltn", "sport", "=", "443"]])
        with self.assertRaises(recipes.RecipeError):
            recipes.resolve(recipes.validate(r()), {"init": "systemd"})                  # no unit learned
        with self.assertRaises(recipes.RecipeError):
            recipes.resolve(recipes.validate(r()), {"init": "systemd", "unit": "x; rm -rf /"})
        with self.assertRaises(recipes.RecipeError):
            recipes.resolve(recipes.validate(r(do={"restart": "container"})), {"container": "$(id)"})
        with self.assertRaises(recipes.RecipeError):
            recipes.resolve(recipes.validate(r()), {"init": "none", "unit": "a.service"})


if __name__ == "__main__":
    unittest.main()
