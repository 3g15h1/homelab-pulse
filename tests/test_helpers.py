"""Pure helpers (rates, disks, tasks, vzdump logs, probe debounce) and the credential-free probes."""
import socket
import struct
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import collect
import probes

NOW = 1_790_900_000.0



class HelperTests(unittest.TestCase):
    def test_rate_tracker_handles_first_sample_and_counter_reset(self):
        r = collect.RateTracker()
        self.assertEqual(r.rate("a", 1000, 10), 0.0)
        self.assertEqual(r.rate("a", 6000, 15), 1000.0)
        self.assertEqual(r.rate("a", 10, 20), 0.0)         # guest restarted, counter reset
        self.assertEqual(r.rate("a", 510, 25), 100.0)

    def test_rate_tracker_bridges_proxmox_10s_counter_refresh(self):
        # counters move every 10 s, we sample every 5 s: the rate must stay steady, not 0 / double
        r = collect.RateTracker()
        rates = [r.rate("a", v, t) for t, v in ((0, 0), (5, 0), (10, 10000), (15, 10000), (20, 20000), (25, 20000))]
        self.assertEqual(rates[2:], [1000.0, 1000.0, 1000.0, 1000.0])
        self.assertEqual(r.rate("a", 20000, 60), 0.0)      # really idle for > 30 s

    def test_disks_wearout_na_becomes_none(self):
        d = collect.build_disks([{"devpath": "/dev/sdb", "model": "ST2000 ", "wearout": "N/A", "health": "PASSED"},
                                 {"devpath": "/dev/sda", "model": "Samsung_SSD_840_EVO_500GB", "wearout": 81}])
        self.assertEqual((d[0]["wear_used"], d[0]["model"]), (None, "ST2000"))
        self.assertEqual((d[1]["wear_used"], d[1]["model"]), (19, "Samsung SSD 840 EVO 500GB"))  # 81% life left

    def test_task_events(self):
        tasks = [
            {"type": "vzdump", "starttime": 100, "endtime": 1360, "status": "OK"},
            {"type": "vzdump", "starttime": 200, "endtime": 210, "status": "job errors"},
            {"type": "vzstart", "id": "109", "starttime": 5, "endtime": 6, "status": "OK"},
            {"type": "vzdump", "starttime": 300},  # still running
            {"type": "aptupdate", "starttime": 1, "endtime": 2, "status": "OK"},
        ]
        ev = collect.task_events(tasks, {109: "ollama"})
        self.assertEqual([e["text"] for e in ev],
                         ["Backup finished (21 min)", "Backup problem: job errors", "Started ollama", "Backup running"])
        self.assertEqual(ev[1]["level"], "bad")

    def test_parse_vzdump_log_real_lines(self):
        lines = [  # from the real 2026-10-02 02:00 job, plus a synthetic failure
            "INFO: Starting Backup of VM 102 (lxc)",
            "INFO: creating vzdump archive '/mnt/backup/dump/vzdump-lxc-102-2026_10_02-02_00_44.tar.zst'",
            "INFO: Total bytes written: 16218644480 (16GiB, 157MiB/s)",
            "INFO: archive file size: 9.99GB",
            "INFO: Finished Backup of VM 102 (00:01:41)",
            "INFO: prune older backups with retention: keep-last=7",
            "INFO: removing backup 'backup:backup/vzdump-lxc-102-2026_09_25-02_00_44.tar.zst'",
            "INFO: Starting Backup of VM 103 (qemu)",
            "INFO: creating vzdump archive '/mnt/backup/dump/vzdump-qemu-103-2026_10_02-02_02_25.vma.zst'",
            "INFO: archive file size: 2.35GB",
            "INFO: Finished Backup of VM 103 (00:00:44)",
            "INFO: Starting Backup of VM 106 (lxc)",
            "ERROR: Backup of VM 106 failed - unable to create temporary directory",
        ]
        r = collect.parse_vzdump_log(lines)
        self.assertTrue(r[102]["ok"])
        self.assertEqual(r[102]["size"], int(9.99 * 1024 ** 3))
        self.assertEqual(time.localtime(r[102]["ts"])[:3], (2026, 10, 2))   # not the pruned 09-25 archive
        self.assertEqual(time.localtime(r[103]["ts"])[:6], (2026, 10, 2, 2, 2, 25))
        self.assertEqual((r[106]["ok"], r[106]["error"]), (False, "unable to create temporary directory"))

class ProbeStateTests(unittest.TestCase):
    def test_debounce_and_transitions(self):
        p = collect.ProbeState({"id": "x", "name": "X", "kind": "tcp"})
        up, down = probes.Result(True, 3.0, "ok"), probes.Result(False, None, "timed out")
        self.assertIsNone(p.update(up, 1))                 # first good result: no event
        self.assertIsNone(p.update(down, 2))               # one blip: still up
        self.assertTrue(p.up)
        ev = p.update(down, 3)
        self.assertEqual((p.up, ev["text"]), (False, "X is down (timed out)"))
        self.assertEqual(p.update(up, 4)["text"], "X is back")
        self.assertEqual(p.view()["history"], [3.0, None, None, 3.0])


class ProbeTests(unittest.TestCase):
    def test_dns_query_roundtrip_and_parse(self):
        qid, pkt = probes.build_query("doubleclick.net", qid=0x1234)
        self.assertEqual(pkt[:2], b"\x12\x34")
        question = pkt[12:]
        # reply: header (QR, RD, RA), question copied, one A answer using a name pointer to offset 12
        answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + bytes([0, 0, 0, 0])
        reply = struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0) + question + answer
        self.assertEqual(probes.parse_response(reply, 0x1234), (0, ["0.0.0.0"]))
        with self.assertRaises(ValueError):
            probes.parse_response(reply, 0x9999)

    def test_dns_probe_against_local_fake_server(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))

        def serve_one(ip):
            msg, addr = sock.recvfrom(512)
            qend = 12 + msg[12:].index(b"\0") + 5
            ans = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + socket.inet_aton(ip)
            sock.sendto(msg[:2] + struct.pack(">HHHHH", 0x8180, 1, 1, 0, 0) + msg[12:qend] + ans, addr)

        port = sock.getsockname()[1]
        try:
            for ip, want in (("0.0.0.0", "blocking ads"), ("142.250.1.1", "answering (not blocking)")):
                t = threading.Thread(target=serve_one, args=(ip,))
                t.start()
                r = probes.probe_dns("127.0.0.1", "doubleclick.net", port=port)
                t.join()
                self.assertTrue(r.ok, r.detail)
                self.assertEqual(r.detail, want)
        finally:
            sock.close()

    def test_private_ca_context_still_verifies_but_not_x509_strict(self):
        import ssl
        ca = Path(ssl.get_default_verify_paths().cafile or "/etc/ssl/certs/ca-certificates.crt")
        ctx = probes.private_ca_context(str(ca))
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(ctx.check_hostname)
        self.assertFalse(ctx.verify_flags & ssl.VERIFY_X509_STRICT)

    def test_tcp_probe_open_and_refused(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen()
        port = srv.getsockname()[1]
        self.assertTrue(probes.probe_tcp("127.0.0.1", port).ok)
        srv.close()
        r = probes.probe_tcp("127.0.0.1", port, timeout=1)
        self.assertFalse(r.ok)
        self.assertEqual(r.detail, "connection refused")

    def test_http_probe_status_rules(self):
        codes = iter([401, 302, 503, 200])

        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(next(codes))
                self.send_header("Location", "/elsewhere")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *a):
                pass

        srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        url = f"http://127.0.0.1:{srv.server_address[1]}/"
        try:
            self.assertEqual((probes.probe_http(url).ok, probes.probe_http(url).detail), (True, "HTTP 302"))
            self.assertFalse(probes.probe_http(url).ok)                 # 503
            self.assertTrue(probes.probe_http(url, ok_codes=[200]).ok)   # 200
        finally:
            srv.shutdown()
            srv.server_close()


if __name__ == "__main__":
    unittest.main()
