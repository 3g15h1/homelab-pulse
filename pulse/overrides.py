"""Owner overrides on top of discovery: Proxmox guest tags (`pulse-*`) and an optional JSON file.

Precedence (highest first): guest tags, overrides.json, inference.
"""
import ipaddress
import json
import re
from pathlib import Path


class OverrideError(Exception):
    pass


def parse_tags(tags):
    """Proxmox tags -> {ignore, noscan, role, icon, ip} (only the keys present). Tags can't contain
    dots or spaces, so `pulse-ip-192-168-0-75` and `pulse-role-shared-local-ai` use dashes."""
    out = {}
    for t in tags or ():
        t = t.strip().lower()
        if t == "pulse-ignore":
            out["ignore"] = True
        elif t == "pulse-noscan":
            out["noscan"] = True
        elif t.startswith("pulse-role-") and len(t) > 11:
            out["role"] = t[11:].replace("-", " ")
        elif t.startswith("pulse-icon-") and len(t) > 11:
            out["icon"] = t[11:]
        elif t.startswith("pulse-ip-"):
            try:
                out["ip"] = str(ipaddress.IPv4Address(t[9:].replace("-", ".")))
            except ValueError:
                pass
    return out


_TOP = {"internet": (dict, bool), "router": dict, "scan": dict, "guests": dict, "checks": list, "hide_checks": list,
        "http_contains": dict}
_KINDS = {"tcp": ("host", "port"), "http": ("url",), "tls": ("host", "port"), "dns": ("server", "qname")}


def _validate(data):
    if not isinstance(data, dict):
        raise OverrideError("top level must be an object")
    for k, v in data.items():
        if k not in _TOP:
            raise OverrideError(f"unknown key {k!r} (allowed: {', '.join(_TOP)})")
        if not isinstance(v, _TOP[k]):
            raise OverrideError(f"{k!r} has the wrong type")
    if data.get("internet") is True:
        raise OverrideError("'internet' must be an object or false")
    for i, c in enumerate(data.get("checks", [])):
        if not isinstance(c, dict) or c.get("kind") not in _KINDS:
            raise OverrideError(f"checks[{i}]: 'kind' must be one of {', '.join(_KINDS)}")
        missing = [f for f in ("id", "name", *_KINDS[c["kind"]]) if f not in c]
        if missing:
            raise OverrideError(f"checks[{i}]: missing {', '.join(missing)}")
    if not all(isinstance(v, str) and v for v in data.get("http_contains", {}).values()):
        raise OverrideError("http_contains values must be non-empty strings")
    for k in ("ports_add", "ports_remove"):
        if not all(isinstance(p, int) and 0 < p < 65536 for p in data.get("scan", {}).get(k, [])):
            raise OverrideError(f"scan.{k} must be a list of port numbers")


def load(path):
    """Missing file -> {}. Anything else wrong -> OverrideError (shown on the dashboard)."""
    try:
        text = Path(path).read_text()
    except FileNotFoundError:
        return {}
    except OSError as e:
        raise OverrideError(f"{path}: {e.strerror}") from None
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise OverrideError(f"{Path(path).name}: invalid JSON at line {e.lineno}") from None
    _validate(data)
    return data


_REF = re.compile(r"([a-z0-9][a-z0-9-]*)/(\d+)((?::\d+)?)")


def resolve_refs(data, slots, span):
    """Guests on an extra Proxmox host are written "<label>/<vmid>" (e.g. "gpu/105", or
    "gpu/105:80" for a check id), since their VMIDs may repeat the primary's. Translate those to
    Pulse's internal keys. `slots`: {label: slot}. An unknown label is an error, like a typo."""
    def one(ref):
        m = _REF.fullmatch(ref) if isinstance(ref, str) else None
        if not m:
            return ref
        if m.group(1) not in slots:
            raise OverrideError(f"{ref!r}: no Proxmox host called {m.group(1)!r} (known: {', '.join(slots) or 'none'})")
        return f"{slots[m.group(1)] * span + int(m.group(2))}{m.group(3)}"
    if not data:
        return data
    out = dict(data)
    if "guests" in out:
        out["guests"] = {one(k): v for k, v in out["guests"].items()}
    if "hide_checks" in out:
        out["hide_checks"] = [one(k) for k in out["hide_checks"]]
    if "http_contains" in out:
        out["http_contains"] = {one(k): v for k, v in out["http_contains"].items()}
    if "checks" in out:
        out["checks"] = [dict(c, target=one(c["target"])) if "target" in c else c for c in out["checks"]]
    return out
