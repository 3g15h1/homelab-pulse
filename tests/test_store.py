import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

import store

H, D = 3600, 86400
NOW = 1_800_000_000.0


class Clock:
    def __init__(self, t=NOW):
        self.t = t

    def __call__(self):
        return self.t


def tmpdb():
    d = tempfile.mkdtemp()
    return str(Path(d) / "pulse.db")


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.path = tmpdb()
        self.s = store.Store(self.path, clock=self.clock)

    def test_schema_created(self):
        con = sqlite3.connect(self.path)
        tables = {r[0] for r in con.execute("select name from sqlite_master where type='table'")}
        self.assertLessEqual({"check_results", "check_hourly", "events", "alerts", "mutes", "settings",
                              "deliveries"}, tables)
        self.assertEqual(con.execute("pragma user_version").fetchone()[0], 1)
        self.assertIsNone(self.s.error)

    def test_uptime_raw_and_hourly(self):
        for i, up in enumerate([True, True, True, False]):
            self.s.record_checks([("a", up, 2.0), ("skip", None, None)], NOW - 600 + i * 15)
        # 3 days ago: hourly rows with 10 samples, 5 up
        self.s._conn().execute("insert into check_hourly values ('a', ?, 10, 5, 3.0)", (NOW - 3 * D,))
        u = self.s.uptime(NOW)
        self.assertEqual(u["a"]["24h"], 75.0)
        self.assertEqual(u["a"]["7d"], round(8 / 14 * 100, 2))
        self.assertEqual(u["a"]["30d"], u["a"]["7d"])
        self.assertNotIn("skip", u)

    def test_compact_moves_and_drops(self):
        self.s.record_checks([("a", True, 1.0)], NOW - 50 * H)
        self.s.record_checks([("a", False, None)], NOW - 50 * H + 60)
        self.s.record_checks([("a", True, 1.0)], NOW - 60)
        self.s._conn().execute("insert into check_hourly values ('a', ?, 4, 4, 1.0)", (NOW - 91 * D,))
        self.s.compact(NOW)
        con = self.s._conn()
        self.assertEqual(con.execute("select count(*) from check_results").fetchone()[0], 1)
        rows = con.execute("select samples, up_samples from check_hourly").fetchall()
        self.assertEqual(rows, [(2, 1)])                       # the 91-day-old row is gone
        self.assertEqual(self.s.uptime(NOW)["a"]["7d"], round(2 / 3 * 100, 2))

    def test_events_roundtrip_and_retention(self):
        self.s.add_event({"ts": NOW - 31 * D, "kind": "probe", "level": "bad", "text": "old"})
        self.s.add_event({"ts": NOW - 10, "kind": "alert", "level": "bad", "text": "new", "key": "check:x"})
        self.s.add_event({"ts": NOW - 5, "kind": "probe", "level": "ok", "text": "newer"})
        self.assertEqual([e["text"] for e in self.s.recent_events()], ["newer", "new", "old"])
        self.s.compact(NOW)
        self.assertEqual([e["text"] for e in self.s.recent_events(limit=1)], ["newer"])
        self.assertEqual(len(self.s.recent_events()), 2)

    def test_alerts_roundtrip(self):
        states = {"check:a": {"state": "firing", "first_ts": 1, "sent": True}, "_outbox": {"items": []}}
        self.s.save_alerts(states)
        self.assertEqual(store.Store(self.path, clock=self.clock).load_alerts(), states)
        self.s.save_alerts({})
        self.assertEqual(self.s.load_alerts(), {})

    def test_mutes_expire(self):
        self.s.add_mute("guest:101", NOW + 60, False)
        self.s.add_mute("check:x", None, True)
        self.assertEqual(sorted(m["target"] for m in self.s.list_mutes(NOW)), ["check:x", "guest:101"])
        self.assertEqual([m["target"] for m in self.s.list_mutes(NOW + 61)], ["check:x"])
        self.s.remove_mute("check:x")
        self.assertEqual(self.s.list_mutes(NOW + 61), [])

    def test_settings_kv(self):
        self.assertEqual(self.s.get("config", {"a": 1}), {"a": 1})
        self.s.put("config", {"b": [1, 2]})
        self.assertEqual(store.Store(self.path).get("config"), {"b": [1, 2]})

    def test_deliveries_capped(self):
        for i in range(210):
            self.s.add_delivery(NOW + i, "ntfy", i % 2 == 0, "200", None, f"t{i}")
        self.s.compact(NOW)
        self.assertEqual(self.s._conn().execute("select count(*) from deliveries").fetchone()[0], 200)
        last = self.s.deliveries(limit=2)
        self.assertEqual([d["title"] for d in last], ["t209", "t208"])
        self.assertEqual((last[0]["ok"], last[0]["channel"]), (False, "ntfy"))

    def test_corrupt_db_is_replaced(self):
        path = tmpdb()
        Path(path).write_bytes(b"this is not a database" * 100)
        s = store.Store(path)
        s.put("x", 1)
        self.assertEqual(s.get("x"), 1)
        self.assertIn("unreadable", s.error)
        self.assertTrue(any(p.name.startswith("pulse.db.broken-") for p in Path(path).parent.iterdir()))

    @unittest.skipIf(os.geteuid() == 0, "root can write anywhere")
    def test_unwritable_falls_back_to_memory(self):
        d = tempfile.mkdtemp()
        os.chmod(d, 0o500)
        self.addCleanup(os.chmod, d, 0o700)
        s = store.Store(str(Path(d) / "pulse.db"))
        s.put("x", 1)
        self.assertEqual(s.get("x"), 1)
        self.assertIn("memory", s.error)

    def test_unwritable_path_falls_back_to_memory(self):
        s = store.Store("/proc/definitely/not/here/pulse.db")
        s.put("x", 2)
        self.assertEqual(s.get("x"), 2)
        self.assertIn("memory", s.error)

    def test_threads_get_their_own_connection(self):
        import threading
        out = []
        t = threading.Thread(target=lambda: out.append(self.s.get("nothing", "dflt")))
        t.start()
        t.join()
        self.assertEqual(out, ["dflt"])


if __name__ == "__main__":
    unittest.main()
