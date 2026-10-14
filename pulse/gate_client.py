"""Talks to pulse-heal-gate on the Proxmox host over SSH (the key's forced command is the gate).

Pulse never gets a shell on the host: whatever we send arrives in SSH_ORIGINAL_COMMAND and the gate
validates it. Replies are one JSON line; a refusal comes back as {"ok": false, "error": ...}.
"""
import json
import shlex
import subprocess


class GateError(Exception):
    pass


class GateClient:
    def __init__(self, target, key_file, timeout=30, runner=subprocess.run,
                 known_hosts="/var/lib/homelab-pulse/heal_known_hosts"):     # /etc is read-only for the service
        self.target, self.key_file, self.timeout, self.runner = target, key_file, timeout, runner
        self.known_hosts = known_hosts

    def _call(self, *words, timeout=None):
        argv = ["ssh", "-i", self.key_file, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
                "-o", f"UserKnownHostsFile={self.known_hosts}", "-o", "ConnectTimeout=5", "-o", "LogLevel=ERROR",
                self.target, shlex.join(str(w) for w in words)]
        try:
            p = self.runner(argv, capture_output=True, text=True, timeout=timeout or self.timeout)
        except subprocess.TimeoutExpired:
            raise GateError("the heal gate timed out") from None
        except OSError as e:
            raise GateError(f"can't run ssh: {e.strerror}") from None
        if p.returncode == 255:
            raise GateError(f"ssh to the heal gate failed: {(p.stderr or '').strip()[:160]}")
        try:
            return json.loads((p.stdout or "").strip().splitlines()[-1])
        except (json.JSONDecodeError, IndexError):
            raise GateError(f"unexpected answer from the heal gate: {(p.stdout or p.stderr or '')[:120]!r}") from None

    def version(self):
        return self._call("version")

    def list_recipes(self):
        return self._call("list-recipes")

    def inspect(self, vmid, port):
        return self._call("inspect", vmid, port)

    def run(self, recipe_id, vmid, port, target=None, dry_run=False, timeout=None):
        words = ["run", recipe_id, vmid, port]
        for k in ("unit", "container"):
            if target and target.get(k):
                words += ["--target", f"{k}={target[k]}"]
        if dry_run:
            words.append("--dry-run")
        return self._call(*words, timeout=timeout or 600)
