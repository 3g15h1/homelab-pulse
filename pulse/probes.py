"""Credential-free health probes: HTTP, TCP, TLS (with cert expiry) and DNS (with ad-block check).

Each probe returns a Result. Nothing here logs in anywhere; a 401 from a service still proves it
is up.
"""
import calendar
import os
import socket
import ssl
import struct
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass


@dataclass
class Result:
    ok: bool
    latency_ms: float | None
    detail: str


def _ms(t0):
    return round((time.perf_counter() - t0) * 1000, 1)


def probe_tcp(host, port, timeout=3.0):
    t0 = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout):
            return Result(True, _ms(t0), f"port {port} open")
    except OSError as e:
        return Result(False, None, _short(e))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):
        return None


def insecure_context():
    """For services found by discovery: we can't know which CA they use, so don't verify."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


_opener = urllib.request.build_opener(_NoRedirect)
_insecure_opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=insecure_context()))


def probe_http(url, ok_codes=None, timeout=4.0, insecure=False, contains=None):
    """Up = any response below 500 (or one of ok_codes, if given). Redirects aren't followed.
    `insecure` skips certificate checks for https:// (self-signed services found by discovery).
    `contains`: when given, the first 64 KiB of the body must include this substring."""
    t0 = time.perf_counter()
    try:
        with (_insecure_opener if insecure else _opener).open(urllib.request.Request(url, headers={"User-Agent": "homelab-pulse"}), timeout=timeout) as r:
            code = r.status
            body = r.read(65536) if contains else None
    except urllib.error.HTTPError as e:
        code, body = e.code, None
    except (OSError, ValueError) as e:
        return Result(False, None, _short(e))
    ok = code in ok_codes if ok_codes else code < 500
    if ok and contains is not None:
        text = (body or b"").decode("utf-8", "replace")
        if contains not in text:
            return Result(False, None, f"keyword {contains!r} not found (HTTP {code})")
    return Result(ok, _ms(t0), f"HTTP {code}")


def private_ca_context(cafile):
    """Verifying context for a private CA such as Proxmox's. Python 3.13 turned on
    VERIFY_X509_STRICT by default, which rejects PVE's certs (no Authority Key Identifier).
    Chain and hostname are still verified; only that strictness check is dropped."""
    ctx = ssl.create_default_context(cafile=cafile)
    ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
    return ctx


def probe_tls(host, port, sni=None, cafile=None, timeout=4.0, now=None, verify=True):
    """TLS handshake; reports days until the cert expires. Verified against system CAs (or
    `cafile`) by default; `verify=False` only checks that TLS answers and reads the expiry."""
    t0 = time.perf_counter()
    try:
        if verify:
            ctx = private_ca_context(cafile) if cafile else ssl.create_default_context()
        else:
            ctx = insecure_context()
        with socket.create_connection((host, port), timeout) as sock, \
                ctx.wrap_socket(sock, server_hostname=sni or (host if verify else None)) as tls:
            if verify:
                not_after = ssl.cert_time_to_seconds(tls.getpeercert()["notAfter"])
            else:
                not_after = cert_info(tls.getpeercert(binary_form=True))["not_after"]
            latency = _ms(t0)
    except ssl.SSLCertVerificationError as e:
        return Result(False, None, "cert invalid: " + (e.verify_message or "verify failed"))
    except (OSError, ssl.SSLError, ValueError) as e:
        return Result(False, None, _short(e))
    days = int((not_after - (now or time.time())) // 86400)
    return Result(days >= 0, latency, f"cert {days} days left")


# ---------------------------------------------------------------- X.509 (just enough DER)

def _der(buf, i):
    """One DER element at i -> (tag, content start, content end)."""
    if i + 2 > len(buf):
        raise ValueError("truncated DER")
    tag, n = buf[i], buf[i + 1]
    i += 2
    if n & 0x80:
        k = n & 0x7F
        if not 0 < k <= 4 or i + k > len(buf):
            raise ValueError("bad DER length")
        n = int.from_bytes(buf[i:i + k], "big")
        i += k
    if i + n > len(buf):
        raise ValueError("truncated DER")
    return tag, i, i + n


def _children(buf, start, end):
    out, i = [], start
    while i < end:
        tag, s, e = _der(buf, i)
        out.append((tag, s, e))
        i = e
    return out


def _asn1_time(tag, raw):
    t = raw.decode("ascii").rstrip("Z")
    if tag == 0x17:                       # UTCTime YYMMDDHHMMSS
        y = int(t[:2])
        t = ("19" if y >= 50 else "20") + t
    return calendar.timegm((int(t[:4]), int(t[4:6]), int(t[6:8]), int(t[8:10]), int(t[10:12]), int(t[12:14] or 0)))


_CN_OID = bytes([0x55, 0x04, 0x03])


def cert_info(der):
    """DER certificate -> {"cn": subject CN or None, "not_after": epoch seconds}. Used when the
    handshake isn't verified, because getpeercert() then returns nothing but the raw bytes."""
    try:
        _, s, e = _der(der, 0)                              # Certificate
        _, s, e = _children(der, s, e)[0]                   # tbsCertificate
        f = _children(der, s, e)
        if f[0][0] == 0xA0:                                 # [0] version is optional
            f = f[1:]
        validity, subject = f[3], f[4]
        times = _children(der, validity[1], validity[2])
        not_after = _asn1_time(times[1][0], der[times[1][1]:times[1][2]])
        cn = None
        for _t, rs, re_ in _children(der, subject[1], subject[2]):      # RDN sets
            for _t2, as_, ae in _children(der, rs, re_):                  # AttributeTypeAndValue
                oid, val = _children(der, as_, ae)[:2]
                if der[oid[1]:oid[2]] == _CN_OID:
                    cn = der[val[1]:val[2]].decode("utf-8", "replace")[:80]
    except (IndexError, UnicodeDecodeError, ValueError) as e:
        raise ValueError(f"unreadable certificate: {e}") from None
    return {"cn": cn, "not_after": not_after}


# ---------------------------------------------------------------- DNS

def build_query(qname, qid=None, qtype=1):
    qid = qid if qid is not None else struct.unpack(">H", os.urandom(2))[0]
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)  # RD set, one question
    q = b"".join(bytes([len(p)]) + p.encode() for p in qname.rstrip(".").split(".")) + b"\0"
    return qid, header + q + struct.pack(">HH", qtype, 1)


def _skip_name(msg, i):
    while True:
        n = msg[i]
        if n == 0:
            return i + 1
        if n & 0xC0 == 0xC0:
            return i + 2
        i += n + 1


def parse_response(msg, qid):
    """Returns (rcode, [A-record IPs]). Raises ValueError on a malformed / mismatched reply."""
    if len(msg) < 12:
        raise ValueError("short DNS reply")
    rid, flags, qd, an, _ns, _ar = struct.unpack(">HHHHHH", msg[:12])
    if rid != qid or not flags & 0x8000:
        raise ValueError("not a reply to our query")
    i = 12
    for _ in range(qd):
        i = _skip_name(msg, i) + 4
    ips = []
    for _ in range(an):
        i = _skip_name(msg, i)
        rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", msg[i:i + 10])
        i += 10
        if rtype == 1 and rdlen == 4:
            ips.append(socket.inet_ntoa(msg[i:i + 4]))
        i += rdlen
    return flags & 0xF, ips


def probe_dns(server, qname, timeout=3.0, port=53):
    """Asks `server` for a known ad domain. Up = it answers; detail says whether it blocked it."""
    qid, packet = build_query(qname)
    t0 = time.perf_counter()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(packet, (server, port))
            msg, _ = s.recvfrom(1500)
        rcode, ips = parse_response(msg, qid)
    except (OSError, ValueError) as e:
        return Result(False, None, _short(e))
    latency = _ms(t0)
    blocked = rcode == 3 or not ips or all(ip == "0.0.0.0" for ip in ips)
    return Result(True, latency, "blocking ads" if blocked else "answering (not blocking)")


PING_TCP_PORTS = (53, 80, 443)    # a router answers on one of these, or at least refuses


def _not_permitted(cp):
    err = (cp.stderr or b"").decode("utf-8", "replace").lower()
    return cp.returncode == 2 and ("not permitted" in err or "cap_net_raw" in err or "permission" in err)


def probe_alive_tcp(host, ports=PING_TCP_PORTS, timeout=2.0):
    """Is the host there at all? A TCP connect that is accepted *or refused* proves it is; only
    silence (timeout, unreachable) means it isn't. For when ICMP isn't allowed."""
    t0 = time.perf_counter()
    for port in ports:
        try:
            with socket.create_connection((host, port), timeout):
                return Result(True, _ms(t0), f"answering on TCP {port} (ping not permitted)")
        except ConnectionRefusedError:
            return Result(True, _ms(t0), f"answering (TCP {port} refused; ping not permitted)")
        except OSError:
            continue
    return Result(False, None, "no reply (TCP; ping not permitted)")


def probe_ping(host, timeout=2.0):
    """One ICMP echo via the system ping binary (no raw sockets needed). Where the service user may
    not ping (no cap_net_raw on the binary and outside net.ipv4.ping_group_range, as in some
    unprivileged containers) it falls back to a TCP liveness check instead of reporting "down"."""
    t0 = time.perf_counter()
    try:
        cp = subprocess.run(["ping", "-c1", "-W%d" % max(1, round(timeout)), host],
                            capture_output=True, timeout=timeout + 5)
    except FileNotFoundError:
        return probe_alive_tcp(host, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as e:
        return Result(False, None, _short(e))
    if cp.returncode == 0:
        return Result(True, _ms(t0), "ping ok")
    if _not_permitted(cp):
        return probe_alive_tcp(host, timeout=timeout)
    return Result(False, None, "no reply")


def probe_resolve(server, qname="example.com", timeout=3.0):
    """Ask `server` for a real A record. Up = it resolves (unlike probe_dns, no ad-block semantics)."""
    qid, packet = build_query(qname)
    t0 = time.perf_counter()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(packet, (server, 53))
            msg, _ = s.recvfrom(1500)
        rcode, ips = parse_response(msg, qid)
    except (OSError, ValueError) as e:
        return Result(False, None, _short(e))
    if rcode != 0 or not ips:
        return Result(False, None, "no answer" if rcode == 0 else f"DNS rcode {rcode}")
    return Result(True, _ms(t0), f"resolved to {ips[0]}")


def run(spec):
    kind = spec["kind"]
    if kind == "tcp":
        return probe_tcp(spec["host"], spec["port"])
    if kind == "http":
        return probe_http(spec["url"], spec.get("ok"), insecure=spec.get("insecure", False),
                           contains=spec.get("contains"))
    if kind == "tls":
        return probe_tls(spec["host"], spec["port"], spec.get("sni"), spec.get("cafile"),
                         verify=spec.get("verify", True))
    if kind == "dns":
        return probe_dns(spec["server"], spec["qname"])
    if kind == "ping":
        return probe_ping(spec["host"], spec.get("timeout", 2.0))
    if kind == "resolve":
        return probe_resolve(spec["server"], spec.get("qname", "example.com"), spec.get("timeout", 3.0))
    raise ValueError(f"unknown probe kind {kind!r}")


def _short(e):
    if isinstance(e, socket.timeout | TimeoutError):
        return "timed out"
    if isinstance(e, ConnectionRefusedError):
        return "connection refused"
    if isinstance(e, urllib.error.URLError) and e.reason:
        return _short(e.reason) if isinstance(e.reason, OSError) else str(e.reason)[:60]
    return (str(e) or type(e).__name__)[:60]
