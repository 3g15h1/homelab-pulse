"""Self-healing recipes: schema, safety lint, matching and resolution. Pure functions, stdlib only.

This file is shared by Pulse (which decides *when* a recipe applies) and the root-owned host gate
`pulse-heal-gate` (which decides *whether* it may run, and runs it). A recipe is JSON:

  {"schema": 1, "id": "adguard-restart", "name": "...", "description": "...",
   "when": {"alert": "service_down" | "warning", "product": [...], "port": [...], "rule": "...",
            "tags": [...], "vmids": [...]},
   "do": {"restart": "unit" | "container"}  or  {"exec": [["argv", "..."], ...]},
   "guest": ["lxc", "qemu"],
   "safety": {"max_per_hour": 2, "verify_s": 90, "timeout_s": 60, "default_mode": "auto" | "ask"}}

Commands are argv lists, never shell strings. Placeholders {unit}, {container}, {port} may only be a
whole argument, and are filled with values the gate verified. See docs/recipes.md.
"""
import json
import os
import re
import stat
from pathlib import Path

SCHEMA_VERSION = 1
ID_RE = re.compile(r"[a-z0-9][a-z0-9-]{2,63}")
UNIT_RE = re.compile(r"[A-Za-z0-9@._-]{1,120}\.service")
SERVICE_RE = re.compile(r"[A-Za-z0-9._-]{1,120}")               # OpenRC service names
CONTAINER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
PLACEHOLDERS = {"{unit}", "{container}", "{port}"}
ALERTS = {"service_down", "warning"}
GUESTS = {"lxc", "qemu"}
SAFETY = {"max_per_hour": (1, 6, 2), "verify_s": (10, 600, 90), "timeout_s": (5, 300, 60)}
MODES = {"auto", "ask"}


class RecipeError(ValueError):
    pass


def _strs(v, field, lo=0, hi=50, maxlen=120):
    if not isinstance(v, list) or not lo <= len(v) <= hi or not all(isinstance(x, str) and 0 < len(x) <= maxlen for x in v):
        raise RecipeError(f"{field} must be a list of text values")
    return v


def _ints(v, field, lo, hi):
    if not isinstance(v, list) or not v or not all(isinstance(x, int) and not isinstance(x, bool) and lo <= x <= hi for x in v):
        raise RecipeError(f"{field} must be a list of numbers from {lo} to {hi}")
    return v


def validate(doc):
    """Normalized copy of a recipe document (defaults filled in). Raises RecipeError."""
    if not isinstance(doc, dict):
        raise RecipeError("a recipe must be a JSON object")
    unknown = set(doc) - {"schema", "id", "name", "description", "when", "do", "guest", "safety"}
    if unknown:
        raise RecipeError(f"unknown key(s): {', '.join(sorted(unknown))}")
    if doc.get("schema") != SCHEMA_VERSION:
        raise RecipeError(f"schema must be {SCHEMA_VERSION}")
    rid = doc.get("id")
    if not isinstance(rid, str) or not ID_RE.fullmatch(rid):
        raise RecipeError("id must be 3-64 lowercase letters, digits or dashes")
    name = doc.get("name")
    if not isinstance(name, str) or not 0 < len(name) <= 80:
        raise RecipeError("name must be 1-80 characters")
    desc = doc.get("description", "")
    if not isinstance(desc, str) or len(desc) > 300:
        raise RecipeError("description must be at most 300 characters")

    when = doc.get("when")
    if not isinstance(when, dict):
        raise RecipeError("when must be an object")
    bad = set(when) - {"alert", "product", "port", "rule", "tags", "vmids"}
    if bad:
        raise RecipeError(f"unknown key(s) in when: {', '.join(sorted(bad))}")
    if when.get("alert") not in ALERTS:
        raise RecipeError("when.alert must be service_down or warning")
    w = {"alert": when["alert"]}
    if "product" in when:
        w["product"] = _strs(when["product"], "when.product", 1)
    if "port" in when:
        w["port"] = _ints(when["port"], "when.port", 1, 65535)
    if "tags" in when:
        w["tags"] = _strs(when["tags"], "when.tags", 1, maxlen=64)
    if "vmids" in when:
        w["vmids"] = _ints(when["vmids"], "when.vmids", 100, 999999999)
    if when["alert"] == "warning":
        if not isinstance(when.get("rule"), str) or not re.fullmatch(r"[a-z_]{2,40}", when["rule"]):
            raise RecipeError("when.rule (an early-warning rule such as ct_disk) is needed for warning recipes")
        w["rule"] = when["rule"]

    do = doc.get("do")
    if not isinstance(do, dict) or len(do) != 1:
        raise RecipeError("do must have exactly one of: restart, exec")
    if "restart" in do:
        if do["restart"] not in ("unit", "container"):
            raise RecipeError("do.restart must be unit or container")
        d = {"restart": do["restart"]}
    elif "exec" in do:
        steps = do["exec"]
        if not isinstance(steps, list) or not 1 <= len(steps) <= 8:
            raise RecipeError("do.exec must be a list of 1-8 commands")
        for i, argv in enumerate(steps):
            if not isinstance(argv, list) or not 1 <= len(argv) <= 16:
                raise RecipeError(f"do.exec[{i}] must be a command: a list of 1-16 arguments")
            for a in argv:
                if not isinstance(a, str) or not 0 < len(a) <= 200 or re.search(r"[\x00-\x1f]", a):
                    raise RecipeError(f"do.exec[{i}] has an invalid argument")
                if ("{" in a or "}" in a) and a not in PLACEHOLDERS:
                    raise RecipeError(f"do.exec[{i}]: placeholders must be a whole argument: {', '.join(sorted(PLACEHOLDERS))}")
        d = {"exec": [list(a) for a in steps]}
    else:
        raise RecipeError("do must have exactly one of: restart, exec")

    guest = doc.get("guest", ["lxc", "qemu"])
    if not isinstance(guest, list) or not guest or not set(guest) <= GUESTS:
        raise RecipeError("guest must be a list of lxc and/or qemu")
    safety_in = doc.get("safety", {})
    if not isinstance(safety_in, dict) or set(safety_in) - (set(SAFETY) | {"default_mode"}):
        raise RecipeError("safety has unknown keys")
    safety = {}
    for k, (lo, hi, dflt) in SAFETY.items():
        v = safety_in.get(k, dflt)
        if not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi:
            raise RecipeError(f"safety.{k} must be from {lo} to {hi}")
        safety[k] = v
    mode = safety_in.get("default_mode", "auto")
    if mode not in MODES:
        raise RecipeError("safety.default_mode must be auto or ask")
    safety["default_mode"] = mode
    return {"schema": SCHEMA_VERSION, "id": rid, "name": name, "description": desc, "when": w, "do": d,
            "guest": [g for g in ("lxc", "qemu") if g in guest], "safety": safety}


# ---------------------------------------------------------------- safety lint

SHELLS = {"sh", "bash", "dash", "zsh", "ash", "ksh", "fish", "busybox", "perl", "ruby", "node", "nodejs", "php",
          "lua", "env", "eval", "exec", "xargs", "sudo", "su", "doas", "nsenter", "chroot", "unshare", "setsid",
          "nohup", "timeout", "watch", "script", "expect", "awk", "gawk", "find"}
DESTRUCTIVE = {"dd", "fdisk", "sfdisk", "gdisk", "parted", "wipefs", "shred", "shutdown", "reboot", "poweroff",
               "halt", "init", "telinit", "kill", "killall", "pkill", "iptables", "nft", "ip", "userdel", "passwd",
               "crontab", "mount", "umount", "zpool", "zfs", "lvremove", "vgremove", "pvremove", "pct", "qm", "pvesh"}
WRITERS = {"tee", "cp", "mv", "truncate", "ln", "chmod", "chown", "install", "rsync"}


def _lint_argv(argv):
    cmd = os.path.basename(argv[0])
    args = argv[1:]
    words = [a for a in args if not a.startswith("-")]
    if cmd in SHELLS or re.fullmatch(r"python[0-9.]*|pypy[0-9.]*|perl[0-9.]*", cmd):
        return f"{cmd} can run anything; call the program directly"
    if cmd in DESTRUCTIVE or cmd.startswith("mkfs"):
        return f"{cmd} is not allowed in a first-response fix"
    if cmd == "rm" and any(a in ("-r", "-R", "-rf", "-fr", "-Rf", "-fR", "--recursive") or
                           (a.startswith("-") and not a.startswith("--") and ("r" in a or "R" in a)) for a in args):
        return "recursive rm is not allowed"
    if cmd in ("apt", "apt-get", "aptitude", "dpkg") and any(w in ("remove", "purge", "autoremove", "-r", "-P") for w in args):
        return "removing packages is not allowed"
    if cmd in ("dnf", "yum", "zypper", "apk", "pacman") and any(w in ("remove", "erase", "del", "-R", "autoremove") for w in args):
        return "removing packages is not allowed"
    if cmd in ("docker", "podman") and (words[:1] in (["rm"], ["rmi"], ["kill"]) or
                                        words[:2] in (["system", "prune"], ["volume", "rm"], ["volume", "prune"],
                                                      ["container", "prune"], ["image", "prune"], ["network", "rm"],
                                                      ["compose", "down"], ["container", "rm"], ["image", "rm"])):
        return f"{cmd} {' '.join(words[:2])} removes things; not allowed"
    if cmd == "systemctl" and words[:1] and words[0] in ("stop", "disable", "mask", "poweroff", "reboot", "halt",
                                                          "kexec", "kill", "isolate", "rescue", "emergency", "edit"):
        return f"systemctl {words[0]} is not allowed (restart/reload/start are)"
    if (cmd in WRITERS or (cmd == "sed" and any(a == "-i" or a.startswith("-i") or a == "--in-place" for a in args))) \
            and any("/etc/" in a or a == "/etc" for a in args):
        return "changing files under /etc is not allowed"
    return None


def lint(recipe):
    """Problems that make a recipe unsafe to run; empty list = clean."""
    out = []
    for i, argv in enumerate(recipe["do"].get("exec", [])):
        p = _lint_argv(argv)
        if p:
            out.append(f"step {i + 1}: {p}")
    return out


# ---------------------------------------------------------------- loading

def load_dir(path, source, require_root=False):
    """Recipes from *.json files in `path`. Each item carries source, file and errors (never raises)."""
    out = []
    p = Path(path)
    if not p.is_dir():
        return out
    for f in sorted(p.glob("*.json")):
        item_id = f.stem
        errors = []
        try:
            st = f.stat()
            if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                raise RecipeError("file is writable by group or others; fix with chmod 644")
            if require_root and st.st_uid != 0:
                raise RecipeError("file must be owned by root")
            doc = json.loads(f.read_text())
            rec = validate(doc)
            errors = [f"lint: {e}" for e in lint(rec)]
            out.append(dict(rec, source=source, file=str(f), errors=errors))
            continue
        except json.JSONDecodeError as e:
            errors = [f"invalid JSON (line {e.lineno})"]
        except (RecipeError, OSError, UnicodeDecodeError) as e:
            errors = [str(e)]
        out.append({"id": item_id if ID_RE.fullmatch(item_id) else "invalid-" + str(len(out)), "name": f.name,
                    "source": source, "file": str(f), "errors": errors})
    return out


def merge(builtin, local):
    by_id = {r["id"]: r for r in builtin}
    for r in local:
        if r["id"] in by_id:
            r = dict(r, source="local override")
        by_id[r["id"]] = r
    return sorted(by_id.values(), key=lambda r: r["id"])


# ---------------------------------------------------------------- matching

def matches(recipe, cond, check, guest):
    """Does this recipe apply to this firing condition? `check` is None for warnings."""
    if recipe.get("errors") or "when" not in recipe:
        return False
    w = recipe["when"]
    if cond.get("kind") != w["alert"]:
        return False
    if w["alert"] == "warning":
        parts = cond.get("key", "").split(":")
        if len(parts) < 2 or parts[1] != w["rule"]:
            return False
    if guest.get("type") not in recipe["guest"]:
        return False
    if "vmids" in w and guest.get("vmid") not in w["vmids"]:
        return False
    if "tags" in w and not set(t.lower() for t in w["tags"]) <= set(t.lower() for t in guest.get("tags", [])):
        return False
    if "product" in w:
        if not check or (check.get("product") or "").lower() not in {p.lower() for p in w["product"]}:
            return False
    if "port" in w:
        if not check or check.get("port") not in w["port"]:
            return False
    if w["alert"] == "service_down" and not check:
        return False
    return True


def priority(recipe):
    w = recipe.get("when", {})
    base = 3 if "product" in w else 2 if any(k in w for k in ("port", "tags", "vmids", "rule")) else 1
    return base + (0.5 if str(recipe.get("source", "")).startswith("local") else 0)


def resolve(recipe, target):
    """Concrete argv steps for a target {init, unit, container, port}. Raises RecipeError."""
    do = recipe["do"]
    unit, container, port = target.get("unit"), target.get("container"), target.get("port")
    if do.get("restart") == "unit":
        init = target.get("init")
        if not unit:
            raise RecipeError("no service learned for this check yet")
        if init == "systemd" and UNIT_RE.fullmatch(unit):
            return [["systemctl", "restart", unit]]
        if init == "openrc" and SERVICE_RE.fullmatch(unit):
            return [["rc-service", unit, "restart"]]
        raise RecipeError(f"can't restart {unit!r} (init: {init})")
    if do.get("restart") == "container":
        if not container or not CONTAINER_RE.fullmatch(container):
            raise RecipeError("no valid container learned for this check yet")
        return [["docker", "restart", container]]
    values = {}
    if unit is not None:
        if not (UNIT_RE.fullmatch(unit) or SERVICE_RE.fullmatch(unit)):
            raise RecipeError("invalid unit name")
        values["{unit}"] = unit
    if container is not None:
        if not CONTAINER_RE.fullmatch(container):
            raise RecipeError("invalid container name")
        values["{container}"] = container
    if port is not None:
        if not isinstance(port, int) or not 1 <= port <= 65535:
            raise RecipeError("invalid port")
        values["{port}"] = str(port)
    steps = []
    for argv in do["exec"]:
        step = []
        for a in argv:
            if a in PLACEHOLDERS:
                if a not in values:
                    raise RecipeError(f"{a} is needed but not known for this check")
                step.append(values[a])
            else:
                step.append(a)
        steps.append(step)
    return steps
