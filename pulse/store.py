"""SQLite storage for what Pulse itself owns: health-check results (for uptime), the activity feed,
alert state, mutes, settings and the notification delivery log.

Metric history (CPU, memory, network, storage) is *not* stored here: Proxmox keeps a year of it in
its RRD database, and Pulse reads that on demand. One connection per thread; WAL mode.
"""
import json
import logging
import sqlite3
import threading
import time
from pathlib import Path

log = logging.getLogger("pulse")

H, D = 3600, 86400
RAW_KEEP_S = 48 * H
HOURLY_KEEP_S = 90 * D
EVENTS_KEEP_S = 30 * D
DELIVERIES_KEEP = 200

SCHEMA = """
create table if not exists check_results (check_id text not null, ts integer not null, up integer not null,
                                          latency_ms real);
create index if not exists check_results_ts on check_results (ts);
create table if not exists check_hourly (check_id text not null, hour_ts integer not null, samples integer not null,
                                         up_samples integer not null, avg_latency_ms real,
                                         primary key (check_id, hour_ts));
create table if not exists events (ts real not null, kind text, level text, text text, key text);
create index if not exists events_ts on events (ts);
create table if not exists alerts (key text primary key, value_json text not null);
create table if not exists mutes (target text primary key, until_ts real, until_recovered integer not null);
create table if not exists settings (key text primary key, value_json text not null);
create table if not exists deliveries (ts real not null, channel text, ok integer, status text, error text,
                                       title text);
"""

SCHEMA_V2 = """
create table if not exists heal_targets (check_id text primary key, vmid integer, port integer, init text, unit text,
                                         container text, override_json text, learned_ts real);
create table if not exists heal_runs (ts real not null, check_id text, vmid integer, recipe_id text, mode text,
                                      ok integer, recovered integer, detail text);
"""
HEAL_RUNS_KEEP_S = 90 * D


class Store:
    def __init__(self, path, clock=time.time):
        self.clock = clock
        self.error = None
        self._local = threading.local()
        self._memory = None          # shared connection when running in memory
        self.path = self._prepare(str(path))

    # -- connections --

    def _prepare(self, path):
        if path == ":memory:":
            return self._use_memory(None)
        try:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            con = self._open(path)
            con.execute("select count(*) from sqlite_master").fetchone()
            self._migrate(con)
            return path
        except sqlite3.DatabaseError as e:
            if not Path(path).exists() or "unable to open" in str(e):
                return self._use_memory(f"can't open {path} ({e}); history is kept in memory only")
            broken = f"{path}.broken-{int(self.clock())}"
            Path(path).rename(broken)
            for extra in ("-wal", "-shm"):
                Path(path + extra).unlink(missing_ok=True)
            self.error = f"database was unreadable ({e}); moved to {Path(broken).name}, started fresh"
            log.error(self.error)
            self._local = threading.local()
            self._migrate(self._open(path))
            return path
        except OSError as e:
            return self._use_memory(f"can't write {path} ({e.strerror}); history is kept in memory only")

    def _use_memory(self, reason):
        if reason:
            self.error = reason
            log.error(reason)
        self._memory = sqlite3.connect(":memory:", check_same_thread=False, isolation_level=None)
        self._memory_lock = threading.Lock()
        self._migrate(self._memory)
        return ":memory:"

    def _open(self, path):
        con = sqlite3.connect(path, timeout=10, isolation_level=None)
        con.execute("pragma journal_mode=wal")
        con.execute("pragma synchronous=normal")
        self._local.con = con
        return con

    def _conn(self):
        if self._memory is not None:
            return self._memory
        con = getattr(self._local, "con", None)
        return con if con is not None else self._open(self.path)

    def _x(self, sql, args=()):
        con = self._conn()
        if self._memory is not None:
            with self._memory_lock:
                return con.execute(sql, args).fetchall()
        return con.execute(sql, args).fetchall()

    @staticmethod
    def _migrate(con):
        version = con.execute("pragma user_version").fetchone()[0]
        if version < 1:
            con.executescript(SCHEMA)
        if version < 2:                  # 1.2: self-healing
            con.executescript(SCHEMA_V2)
        if version < 2:
            con.execute("pragma user_version = 2")

    # -- health-check results --

    def record_checks(self, rows, ts):
        rows = [(cid, int(ts), 1 if up else 0, lat) for cid, up, lat in rows if up is not None]
        if rows:
            con = self._conn()
            if self._memory is not None:
                with self._memory_lock:
                    con.executemany("insert into check_results values (?, ?, ?, ?)", rows)
            else:
                con.executemany("insert into check_results values (?, ?, ?, ?)", rows)

    def uptime(self, now):
        """{check_id: {"24h": %, "7d": %, "30d": %}} from raw rows plus hourly roll-ups."""
        out = {}
        for label, span in (("24h", D), ("7d", 7 * D), ("30d", 30 * D)):
            since = now - span
            totals = {}
            for cid, n, up in self._x("select check_id, count(*), sum(up) from check_results where ts >= ? "
                                      "group by check_id", (since,)):
                totals[cid] = [n, up]
            for cid, n, up in self._x("select check_id, sum(samples), sum(up_samples) from check_hourly "
                                      "where hour_ts >= ? group by check_id", (since,)):
                t = totals.setdefault(cid, [0, 0])
                t[0] += n
                t[1] += up
            for cid, (n, up) in totals.items():
                out.setdefault(cid, {"24h": None, "7d": None, "30d": None})[label] = round(up / n * 100, 2) if n else None
        return out

    def compact(self, now):
        cutoff = int(now - RAW_KEEP_S)
        self._x("insert into check_hourly (check_id, hour_ts, samples, up_samples, avg_latency_ms) "
                "select check_id, (ts / 3600) * 3600, count(*), sum(up), avg(latency_ms) from check_results "
                "where ts < ? group by check_id, ts / 3600 "
                "on conflict (check_id, hour_ts) do update set samples = samples + excluded.samples, "
                "up_samples = up_samples + excluded.up_samples", (cutoff,))
        self._x("delete from check_results where ts < ?", (cutoff,))
        self._x("delete from check_hourly where hour_ts < ?", (now - HOURLY_KEEP_S,))
        self._x("delete from events where ts < ?", (now - EVENTS_KEEP_S,))
        self._x("delete from deliveries where rowid not in (select rowid from deliveries order by ts desc limit ?)",
                (DELIVERIES_KEEP,))
        self._x("delete from heal_runs where ts < ?", (now - HEAL_RUNS_KEEP_S,))

    # -- activity feed --

    def add_event(self, ev):
        self._x("insert into events values (?, ?, ?, ?, ?)",
                (ev["ts"], ev.get("kind"), ev.get("level"), ev.get("text"), ev.get("key")))

    def recent_events(self, limit=30):
        rows = self._x("select ts, kind, level, text, key from events order by ts desc limit ?", (limit,))
        return [{"ts": r[0], "kind": r[1], "level": r[2], "text": r[3], **({"key": r[4]} if r[4] else {})}
                for r in rows]

    # -- alert state --

    def load_alerts(self):
        return {k: json.loads(v) for k, v in self._x("select key, value_json from alerts")}

    def save_alerts(self, states):
        con = self._conn()
        rows = [(k, json.dumps(v)) for k, v in states.items()]

        def write():
            con.execute("begin")
            con.execute("delete from alerts")
            con.executemany("insert into alerts values (?, ?)", rows)
            con.execute("commit")
        if self._memory is not None:
            with self._memory_lock:
                write()
        else:
            write()

    # -- mutes --

    def list_mutes(self, now):
        self._x("delete from mutes where until_ts is not null and until_ts <= ?", (now,))
        return [{"target": t, "until_ts": u, "until_recovered": bool(r)}
                for t, u, r in self._x("select target, until_ts, until_recovered from mutes order by target")]

    def add_mute(self, target, until_ts, until_recovered):
        self._x("insert or replace into mutes values (?, ?, ?)", (target, until_ts, int(bool(until_recovered))))

    def remove_mute(self, target):
        self._x("delete from mutes where target = ?", (target,))

    # -- settings (JSON values) --

    def get(self, key, default=None):
        rows = self._x("select value_json from settings where key = ?", (key,))
        return json.loads(rows[0][0]) if rows else default

    def put(self, key, value):
        self._x("insert or replace into settings values (?, ?)", (key, json.dumps(value)))

    # -- delivery log --

    def add_delivery(self, ts, channel, ok, status, error, title):
        self._x("insert into deliveries values (?, ?, ?, ?, ?, ?)", (ts, channel, int(bool(ok)), status, error, title))

    def deliveries(self, limit=50):
        return [{"ts": r[0], "channel": r[1], "ok": bool(r[2]), "status": r[3], "error": r[4], "title": r[5]}
                for r in self._x("select ts, channel, ok, status, error, title from deliveries "
                                 "order by ts desc limit ?", (limit,))]

    # -- self-healing: what owns each check's port, and what was done --

    def get_target(self, check_id):
        rows = self._x("select vmid, port, init, unit, container, override_json, learned_ts from heal_targets "
                       "where check_id = ?", (check_id,))
        if not rows:
            return None
        v, p, i, u, c, o, t = rows[0]
        return {"check_id": check_id, "vmid": v, "port": p, "init": i, "unit": u, "container": c,
                "override": json.loads(o) if o else None, "learned_ts": t}

    def put_target(self, check_id, vmid, port, init, unit, container, learned_ts):
        self._x("insert into heal_targets (check_id, vmid, port, init, unit, container, learned_ts) values "
                "(?, ?, ?, ?, ?, ?, ?) on conflict (check_id) do update set vmid = excluded.vmid, port = excluded.port, "
                "init = excluded.init, unit = excluded.unit, container = excluded.container, "
                "learned_ts = excluded.learned_ts", (check_id, vmid, port, init, unit, container, learned_ts))

    def set_override(self, check_id, override):
        self._x("insert into heal_targets (check_id, override_json) values (?, ?) on conflict (check_id) do update "
                "set override_json = excluded.override_json",
                (check_id, json.dumps(override) if override is not None else None))

    def add_heal_run(self, ts, check_id, vmid, recipe_id, mode, ok, recovered, detail):
        self._x("insert into heal_runs values (?, ?, ?, ?, ?, ?, ?, ?)",
                (ts, check_id, vmid, recipe_id, mode, None if ok is None else int(bool(ok)),
                 None if recovered is None else int(bool(recovered)), detail))

    def heal_runs(self, limit=50):
        return [{"ts": r[0], "check_id": r[1], "vmid": r[2], "recipe_id": r[3], "mode": r[4],
                 "ok": None if r[5] is None else bool(r[5]), "recovered": None if r[6] is None else bool(r[6]),
                 "detail": r[7]}
                for r in self._x("select ts, check_id, vmid, recipe_id, mode, ok, recovered, detail from heal_runs "
                                 "order by ts desc limit ?", (limit,))]
