"""install.sh --dry-run against stub Proxmox commands: the plan it prints, and that it changes nothing."""
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

STUBS = {
    "pveversion": 'echo "pve-manager/9.2.20/49318c671b82f31e (running kernel: 7.0.14-19-pve)"',
    "pvesh": r'''case "$*" in
  "get /cluster/nextid"*) echo 112 ;;
  "get /cluster/status"*) echo '[{"type":"cluster","name":"lab"},{"type":"node","name":"home","ip":"192.168.0.50","local":1}]' ;;
  *) echo "[]" ;;
esac''',
    "pvesm": r'''case "$*" in
  *rootdir*) printf 'Name Type Status Total Used Available %%\nlocal-lvm lvmthin active 1 1 1 1%%\n' ;;
  *vztmpl*) printf 'Name Type Status Total Used Available %%\nlocal dir active 1 1 1 1%%\n' ;;
esac''',
    "pveam": r'''case "$1" in
  list) printf 'NAME SIZE\nlocal:vztmpl/debian-13-standard_13.6-1_amd64.tar.zst 123MB\n' ;;
  available) printf 'system debian-13-standard_13.6-1_amd64.tar.zst\n' ;;
esac''',
    "pct": r'''case "$1" in
  list) printf 'VMID Status Lock Name\n100 running  ring\n110 running  pulse\n' ;;
  config) case "$2" in
      110) echo "hostname: pulse"; if [ -n "$TAGGED" ]; then echo "tags: homelab-pulse"; fi ;;
      100) echo "hostname: ring" ;;
      *) echo "Configuration file 'nodes/home/lxc/$2.conf' does not exist" >&2; exit 2 ;;
    esac ;;
  status) echo "status: running" ;;
  exec) case "$*" in
      *"admin-password"*"cat"*|*"cat"*"admin-password"*) echo "old-pass-1234" ;;
      *"test -s"*"admin-password"*) if [ -n "$ADMINPW" ]; then exit 0; else exit 1; fi ;;
      *"test -s"*) exit 0 ;; *"grep -q PULSE_PVE_HOST"*) exit 1 ;; *) exit 0 ;; esac ;;
  *) echo "UNEXPECTED pct $*" >&2; exit 99 ;;
esac''',
    "pveum": r'''case "$1 $2" in
  "user list") echo '[{"userid":"root@pam"}]' ;;
  *) echo "UNEXPECTED pveum $*" >&2; exit 99 ;;
esac''',
}


class InstallDryRunTests(unittest.TestCase):
    def run_install(self, *args, env_extra=None):
        d = tempfile.mkdtemp()
        for name, body in STUBS.items():
            f = Path(d) / name
            f.write_text("#!/bin/sh\n" + body + "\n")
            f.chmod(f.stat().st_mode | stat.S_IEXEC)
        env = dict(os.environ, PATH=f"{d}:{os.environ['PATH']}", PULSE_ASSUME_ROOT="1", **(env_extra or {}))
        return subprocess.run(["bash", str(ROOT / "install.sh"), "--dry-run", *args], capture_output=True, text=True,
                              env=env, timeout=30)

    def test_fresh_install_plan(self):
        r = self.run_install()
        self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
        out = r.stdout
        self.assertIn("+ pct create 112 local:vztmpl/debian-13-standard_13.6-1_amd64.tar.zst", out)
        for part in ("--unprivileged 1", "--rootfs local-lvm:4", "--net0 name=eth0,bridge=vmbr0,ip=dhcp",
                     "--tags homelab-pulse", "--onboot 1", "--memory 512"):
            self.assertIn(part, out)
        self.assertIn("+ pveum user add pulse@pve", out)
        self.assertIn("+ pveum acl modify / --users pulse@pve --roles PVEAuditor", out)
        self.assertIn("+ pveum user token add pulse@pve ct112 --privsep 0", out)
        self.assertIn("PULSE_PVE_HOST=192.168.0.50", out)
        self.assertNotIn("UNEXPECTED", r.stderr)

    def test_static_ip_and_options(self):
        r = self.run_install("--vmid", "150", "--storage", "fast", "--bridge", "vmbr1", "--ip", "192.168.0.61/22",
                             "--gw", "192.168.0.1")
        self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
        self.assertIn("+ pct create 150 ", r.stdout)
        self.assertIn("--net0 name=eth0,bridge=vmbr1,ip=192.168.0.61/22,gw=192.168.0.1", r.stdout)
        self.assertIn("--rootfs fast:4", r.stdout)

    def test_upgrade_found_by_tag_keeps_token(self):
        r = self.run_install(env_extra={"TAGGED": "1"})
        self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
        self.assertIn("Upgrading Homelab Pulse in CT 110", r.stdout)
        self.assertNotIn("pct create", r.stdout)
        self.assertNotIn("token add", r.stdout)                      # existing token is kept
        self.assertIn("/opt/homelab-pulse.prev", r.stdout)           # previous app kept for rollback
        self.assertIn("PULSE_PVE_HOST=192.168.0.50", r.stdout)       # added to an env file that lacks it

    def test_upgrade_by_vmid_adds_tag(self):
        r = self.run_install("--vmid", "110")
        self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
        self.assertIn("Upgrading Homelab Pulse in CT 110", r.stdout)
        self.assertIn("+ pct set 110 --tags homelab-pulse", r.stdout)

    def test_rotate_token_on_upgrade(self):
        r = self.run_install("--rotate-token", env_extra={"TAGGED": "1"})
        self.assertIn("+ pveum user token add pulse@pve ct110 --privsep 0", r.stdout)

    def test_static_install_token_is_per_container(self):
        r = self.run_install("--vmid", "150", "--ip", "10.0.0.5/24", "--gw", "10.0.0.1")
        self.assertIn("+ pveum user token add pulse@pve ct150 --privsep 0", r.stdout)

    def test_admin_password_generated_when_missing(self):
        r = self.run_install()
        self.assertIn("/etc/homelab-pulse/admin-password --perms 640 --group pulse", r.stdout)
        r = self.run_install(env_extra={"TAGGED": "1"})                  # upgrade from 1.0: none yet
        self.assertIn("/etc/homelab-pulse/admin-password --perms 640 --group pulse", r.stdout)
        self.assertIn("/usr/local/bin/homelab-pulse-passwd", r.stdout)

    def test_existing_password_kept_and_not_printed(self):
        r = self.run_install(env_extra={"TAGGED": "1", "ADMINPW": "1"})
        self.assertNotIn("admin-password --perms", r.stdout)
        self.assertNotIn("old-pass-1234", r.stdout)
        r = self.run_install("--show-password", env_extra={"TAGGED": "1", "ADMINPW": "1"})
        self.assertIn("old-pass-1234", r.stdout)

    def test_enable_heal_plan(self):
        r = self.run_install("--enable-heal", env_extra={"TAGGED": "1", "ADMINPW": "1"})
        self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
        out = r.stdout
        for part in ("/heal/pulse-heal-gate /usr/local/sbin/pulse-heal-gate",
                     "/pulse/recipes.py /usr/local/lib/pulse-heal/recipes.py",
                     "/usr/share/pulse-heal/recipes",
                     "/etc/pulse-heal/recipes.d",
                     "ssh-keygen",
                     'restrict,command="/usr/local/sbin/pulse-heal-gate",from="',
                     "pulse-heal-ct110",
                     "PULSE_HEAL_GATE=root@192.168.0.50"):
            self.assertIn(part, out, part)
        self.assertIn("Self-healing: installed in dry-run mode", out)

    def test_disable_heal_plan(self):
        r = self.run_install("--disable-heal", env_extra={"TAGGED": "1", "ADMINPW": "1"})
        self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
        self.assertIn("remove pulse-heal-ct110 from /root/.ssh/authorized_keys", r.stdout)
        self.assertIn("rm -f /usr/local/sbin/pulse-heal-gate", r.stdout)
        self.assertIn("PULSE_HEAL_GATE", r.stdout)                      # removed from the env file
        self.assertNotIn("ssh-keygen", r.stdout)

    def test_enable_and_disable_conflict(self):
        r = self.run_install("--enable-heal", "--disable-heal")
        self.assertNotEqual(r.returncode, 0)

    def test_help(self):
        r = subprocess.run(["bash", str(ROOT / "install.sh"), "--help"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)
        self.assertIn("--dry-run", r.stdout)

    def test_unknown_flag_fails(self):
        r = self.run_install("--bogus")
        self.assertNotEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()
