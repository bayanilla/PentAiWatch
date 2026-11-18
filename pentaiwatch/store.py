"""Disk-backed storage for large log sets.

Taken from VulnScope MAX (vulnflow/store.py), trimmed to what PentAIWatch needs. Parsers stream
sessions into this module in batches. They are written to Parquet files inside a local working
directory, then de-duplicated and sorted with DuckDB SQL into a single on-disk ``flows`` table
that the detector queries. Each input file gets its own ``PartWriter``, so files can be parsed in
separate processes (see load.py) and write their parts side by side. Nothing here holds the whole
input in memory.
"""
from __future__ import annotations

import csv
import os
import shutil
import tempfile
import weakref
from datetime import datetime, timedelta, timezone

import duckdb

from . import resources
from .schema import START_ZEEK_TS, Flow

EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
DEFAULT_BATCH = 100_000
DEFAULT_SKEW_SECONDS = 2.0
# Records are numbered (file number << FID_SHIFT) | position in the file, so the order is the
# order the files were given in, whichever process parsed them.
FID_SHIFT = 40
# When two different sensors record the same session, keep the record from the sensor that
# knows the most about it: the firewall knows the policy action and zones, Zeek the byte counts.
SENSOR_RANK = {"paloalto": 0, "zeek": 1}

FLOW_COLUMNS = ["ord", "ts_us", "src_ip", "dst_ip", "src_port", "dst_port", "proto", "action",
                "established", "bytes_out", "bytes_in", "app", "src_zone", "dst_zone", "source",
                "sensor", "fid", "day", "state", "pkts_in", "start_method"]
_CSV_TYPES = {"ord": "BIGINT", "ts_us": "BIGINT", "src_ip": "VARCHAR", "dst_ip": "VARCHAR",
              "src_port": "INTEGER", "dst_port": "INTEGER", "proto": "VARCHAR", "action": "VARCHAR",
              "established": "BOOLEAN", "bytes_out": "BIGINT", "bytes_in": "BIGINT", "app": "VARCHAR",
              "src_zone": "VARCHAR", "dst_zone": "VARCHAR", "source": "VARCHAR", "sensor": "VARCHAR",
              "fid": "INTEGER", "day": "VARCHAR", "state": "VARCHAR", "pkts_in": "BIGINT",
              "start_method": "VARCHAR"}
_TEXT_COLUMNS = {"app", "src_zone", "dst_zone", "source", "state", "start_method"}
THREAT_COLUMNS = {"ts": "TIMESTAMP", "sensor": "VARCHAR", "src_ip": "VARCHAR", "dst_ip": "VARCHAR",
                  "dst_port": "INTEGER", "name": "VARCHAR", "severity": "VARCHAR", "action": "VARCHAR",
                  "source": "VARCHAR"}
# Columns read back into Flow objects, in Flow field order.
FLOW_SELECT = ("ts, src_ip, dst_ip, dst_port, proto, src_port, action, established, "
               "bytes_out, bytes_in, app, src_zone, dst_zone, source, state, pkts_in, start_method")
# The clean table's columns after ``seq``.
_FLOW_TABLE = ("ts TIMESTAMP, src_ip VARCHAR, dst_ip VARCHAR, src_port INTEGER, dst_port INTEGER, "
               "proto VARCHAR, action VARCHAR, established BOOLEAN, bytes_out BIGINT, bytes_in BIGINT, "
               "app VARCHAR, src_zone VARCHAR, dst_zone VARCHAR, source VARCHAR, sensor VARCHAR, "
               "state VARCHAR, pkts_in BIGINT, start_method VARCHAR")
_FLOW_TABLE_COLS = ("ts, src_ip, dst_ip, src_port, dst_port, proto, action, established, bytes_out, "
                    "bytes_in, app, src_zone, dst_zone, source, sensor, state, pkts_in, start_method")


def _us(ts: datetime | None) -> int | None:
    if ts is None:
        return None
    delta = ts - EPOCH
    return (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds


def utc(ts: datetime | None) -> datetime | None:
    """DuckDB TIMESTAMP values come back naive; they are always UTC here."""
    return ts.replace(tzinfo=timezone.utc) if ts is not None and ts.tzinfo is None else ts


def naive(ts: datetime | None) -> datetime | None:
    """Aware UTC datetime -> naive UTC, for binding to TIMESTAMP parameters."""
    return ts.astimezone(timezone.utc).replace(tzinfo=None) if ts is not None and ts.tzinfo else ts


def row_to_flow(r) -> Flow:
    return Flow(utc(r[0]), r[1], r[2], r[3], r[4], src_port=r[5], action=r[6], established=r[7],
                bytes_out=r[8], bytes_in=r[9], app=r[10], src_zone=r[11], dst_zone=r[12], source=r[13],
                state=r[14], pkts_in=r[15], start_method=r[16])


class Store:
    """One working directory + DuckDB database per analysis run."""

    def __init__(self, workdir: str | None = None, memory_limit: str | None = None,
                 budget: resources.Budget | None = None):
        """DuckDB's memory, threads and spill cap are sized to this machine (see resources.py);
        ``memory_limit`` or $PENTAIWATCH_DUCKDB_MEMORY override the memory, clamped to a safe ceiling."""
        base = workdir or os.environ.get("PENTAIWATCH_WORKDIR") or None
        if base:
            os.makedirs(base, exist_ok=True)
        self.dir = tempfile.mkdtemp(prefix="pentaiwatch-work-", dir=base)
        self.budget = budget or resources.plan(memory_limit, self.dir)
        self.con = duckdb.connect(os.path.join(self.dir, "work.duckdb"))
        tmp = os.path.join(self.dir, "duckdb_tmp")
        os.makedirs(tmp, exist_ok=True)
        self.con.execute(f"SET temp_directory = '{_q(tmp)}'")
        self.con.execute(f"SET memory_limit = '{self.budget.memory // resources.MiB}MiB'")
        self.con.execute(f"SET threads = {int(self.budget.threads)}")
        if self.budget.max_temp:
            self.con.execute(f"SET max_temp_directory_size = '{self.budget.max_temp // resources.MiB}MiB'")
        self.con.execute("SET preserve_insertion_order = false")
        self.parquet_dir = os.path.join(self.dir, "flows_parquet")
        self._batches = 0
        self._finalizer = weakref.finalize(self, _cleanup, self.con, self.dir)

    def close(self):
        self._finalizer()

    # -- bulk loading -------------------------------------------------------
    def _write_csv(self, rows, name: str) -> str:
        path = os.path.join(self.dir, name)
        with open(path, "w", newline="", encoding="utf-8") as fh:
            csv.writer(fh).writerows(rows)
        return path

    def _read_csv_sql(self, path: str, columns: dict[str, str]) -> str:
        cols = ", ".join(f"'{k}': '{v}'" for k, v in columns.items())
        return (f"read_csv('{_q(path)}', columns={{{cols}}}, header=false, delim=',', quote='\"', "
                f"escape='\"', nullstr='', auto_detect=false, strict_mode=false)")

    def write_flow_batch(self, rows: list[tuple]):
        """Append one batch of flow rows (FLOW_COLUMNS order) as a Parquet file."""
        if rows:
            self._batches += 1
            write_flow_parquet(self.con, self.dir, rows, f"main_{self._batches}")

    def finalize_flows(self, skew_seconds: float | None = DEFAULT_SKEW_SECONDS) -> tuple[int, int]:
        """Build the clean ``flows`` table from the Parquet partitions.

        1. Exact duplicates (same time, 5-tuple and action) are kept once: the most complete copy
           (preferred sensor, completed session, most bytes, then first read).
        2. The same session recorded by two different sensors (same 5-tuple, start times within
           ``skew_seconds``) is kept once, from the higher-ranked sensor. Two sensors of the same
           kind in different input files (e.g. two Zeek taps) count too: when they agree on the
           action, the most complete record (completed session, then most bytes) is kept.
        3. A firewall record kept in step 1 or 2 takes the START time of the Zeek record it
           replaced. Zeek's ts is always the session start, to the microsecond; the firewall's
           time is in whole seconds, may be worked out from an end time, or may be an end time.
           (PentAIWatch only: VulnScope MAX keeps the firewall's time.)
        Returns (exact duplicates removed, cross-sensor duplicates removed).
        """
        con = self.con
        if not self._batches and not _has_parquet(self.parquet_dir):
            con.execute(f"CREATE OR REPLACE TABLE flows (seq BIGINT, {_FLOW_TABLE})")
            con.execute("CREATE OR REPLACE TABLE source_sensors (src_ip VARCHAR, sensor VARCHAR)")
            return 0, 0
        rank = " ".join(f"WHEN '{k}' THEN {v}" for k, v in SENSOR_RANK.items())
        glob = _q(os.path.join(self.parquet_dir, "*.parquet"))
        # Which kinds of log recorded each source, taken BEFORE duplicates are removed: once a
        # session seen by Zeek and by the firewall is kept once, the kept row names one of them.
        con.execute(f"""
            CREATE OR REPLACE TABLE source_sensors AS
            SELECT DISTINCT src_ip, sensor FROM read_parquet('{glob}', hive_partitioning = false)""")
        same = "PARTITION BY ts_us, src_ip, src_port, dst_ip, dst_port, proto, action"
        con.execute(f"""
            CREATE OR REPLACE TABLE flows_exact AS
            SELECT * EXCLUDE (ts_us, day, start_method), make_timestamp(ts_us) AS ts,
                   CASE sensor {rank} ELSE 9 END AS sensor_rank,
                   -- the same instant in a Zeek record means that instant is the session START
                   CASE WHEN bool_or(start_method = '{START_ZEEK_TS}') OVER ({same}) THEN '{START_ZEEK_TS}'
                        ELSE start_method END AS start_method
            FROM read_parquet('{glob}', hive_partitioning = false)
            -- keep the most complete copy: preferred sensor, then a completed session (one tap may have
            -- seen only the SYN at the same instant), then most bytes, then the one read first
            QUALIFY row_number() OVER ({same}
                                       ORDER BY CASE sensor {rank} ELSE 9 END, established DESC,
                                                bytes_out + bytes_in DESC, ord) = 1""")
        total = con.execute(f"SELECT count(*) FROM read_parquet('{glob}')").fetchone()[0]
        kept = con.execute("SELECT count(*) FROM flows_exact").fetchone()[0]
        exact = total - kept
        if skew_seconds is not None and skew_seconds >= 0:
            # every (record that goes, record it is the same session as) pair
            con.execute(f"""
                CREATE OR REPLACE TEMP TABLE cross_pairs AS
                SELECT a.ord, b.ord AS kept_ord, a.ts, a.start_method, b.sensor_rank < a.sensor_rank AS outranked,
                       abs(epoch_us(a.ts) - epoch_us(b.ts)) AS apart
                FROM flows_exact a JOIN flows_exact b
                  ON a.src_ip = b.src_ip AND a.dst_ip = b.dst_ip AND a.src_port = b.src_port
                 AND a.dst_port = b.dst_port AND a.proto = b.proto
                WHERE (b.sensor_rank < a.sensor_rank
                       OR (b.sensor_rank = a.sensor_rank AND b.fid <> a.fid AND b.action = a.action
                           -- same kind of sensor: keep the most complete record (a tap that saw the
                           -- whole session beats one that saw only the SYN), then the one read first
                           AND (b.established AND NOT a.established
                                OR (b.established = a.established
                                    AND (b.bytes_out + b.bytes_in > a.bytes_out + a.bytes_in
                                         OR (b.bytes_out + b.bytes_in = a.bytes_out + a.bytes_in
                                             AND b.ord < a.ord))))))
                  AND abs(epoch_us(a.ts) - epoch_us(b.ts)) <= {int(skew_seconds * 1_000_000)}""")
            con.execute("CREATE OR REPLACE TEMP TABLE cross_dups AS SELECT DISTINCT ord FROM cross_pairs")
            # the start time a kept record takes from the Zeek record it replaced: the one closest
            # in time when several match (pings between two hosts all share one 5-tuple)
            con.execute(f"""
                CREATE OR REPLACE TEMP TABLE zeek_start AS
                SELECT kept_ord AS ord, ts FROM cross_pairs
                WHERE outranked AND start_method = '{START_ZEEK_TS}'
                  AND kept_ord NOT IN (SELECT ord FROM cross_dups)
                QUALIFY row_number() OVER (PARTITION BY kept_ord ORDER BY apart, ord) = 1""")
            con.execute("DROP TABLE cross_pairs")
        else:
            con.execute("CREATE OR REPLACE TEMP TABLE cross_dups (ord BIGINT)")
            con.execute("CREATE OR REPLACE TEMP TABLE zeek_start (ord BIGINT, ts TIMESTAMP)")
        cross = con.execute("SELECT count(*) FROM cross_dups").fetchone()[0]
        con.execute(f"""
            CREATE OR REPLACE TABLE flows AS
            WITH kept AS (
                SELECT f.* REPLACE (coalesce(z.ts, f.ts) AS ts,
                                    CASE WHEN z.ts IS NULL THEN f.start_method ELSE '{START_ZEEK_TS}' END
                                        AS start_method)
                FROM flows_exact f ANTI JOIN cross_dups USING (ord) LEFT JOIN zeek_start z USING (ord))
            SELECT row_number() OVER (ORDER BY ts NULLS LAST, ord) AS seq,
                   {_FLOW_TABLE_COLS}
            FROM kept""")
        con.execute("DROP TABLE flows_exact; DROP TABLE cross_dups; DROP TABLE zeek_start")
        shutil.rmtree(self.parquet_dir, ignore_errors=True)
        return exact, cross

    def save_threats(self, events) -> None:
        """Table ``threats``: the IPS/IDS alerts of the run, one row each. ``events`` yields
        (kind of log, ThreatEvent)."""
        self.insert_rows("threats", THREAT_COLUMNS, (
            (naive(t.ts), sensor, t.src_ip, t.dst_ip, t.dst_port, t.name, t.severity, t.action, t.source)
            for sensor, t in events))

    def load_flow_list(self, flows: list[Flow]):
        """Load an in-memory list (tests, small callers) as-is: no de-duplication."""
        writer = FlowWriter(self)
        for f in flows:
            writer.add(f, "list")
        writer.flush()
        self.finalize_flows(skew_seconds=None)

    def insert_rows(self, table: str, columns: dict[str, str], rows, append: bool = False) -> None:
        """Create ``table`` and bulk-load rows through a CSV file (fast, needs no numpy/arrow).
        ``append`` adds the rows to the table when it already exists."""
        cols = ", ".join(f"{k} {v}" for k, v in columns.items())
        self.con.execute(f"CREATE {'TABLE IF NOT EXISTS' if append else 'OR REPLACE TABLE'} {table} ({cols})")
        rows = list(rows)
        if not rows:
            return
        self._batches += 1
        path = self._write_csv(rows, f"{table}_{self._batches}.csv")
        try:
            self.con.execute(f"INSERT INTO {table} SELECT * FROM {self._read_csv_sql(path, columns)}")
        finally:
            os.remove(path)


class FlowWriter:
    """Buffers flows and writes one Parquet batch per ``batch_size`` rows."""

    def __init__(self, store: Store, batch_size: int = DEFAULT_BATCH):
        self.store, self.batch_size, self.rows, self.ord = store, batch_size, [], 0
        self._days: dict[int, str] = {}

    def add(self, f: Flow, sensor: str, fid: int = 0):
        """``fid`` numbers the input file, so sessions repeated by a second sensor of the same
        kind (another Zeek tap) can be told apart from records inside one file."""
        self.rows.append(flow_row(self.ord, f, sensor, fid, self._days))
        self.ord += 1
        if len(self.rows) >= self.batch_size:
            self.flush()

    def flush(self):
        self.store.write_flow_batch(self.rows)
        self.rows = []


class FlowView:
    """Read-only, sequence-like view of the clean flows table, in time order."""

    def __init__(self, store: Store):
        self.store = store
        self._len = None

    def __len__(self):
        if self._len is None:
            self._len = self.store.con.execute("SELECT count(*) FROM flows").fetchone()[0]
        return self._len

    def __bool__(self):
        return len(self) > 0

    def __iter__(self):
        cur = self.store.con.cursor()
        cur.execute(f"SELECT {FLOW_SELECT} FROM flows ORDER BY seq")
        while True:
            rows = cur.fetchmany(10_000)
            if not rows:
                break
            for r in rows:
                yield row_to_flow(r)
        cur.close()

    def __getitem__(self, i):
        if isinstance(i, slice):
            return list(self)[i]
        n = len(self)
        if i < 0:
            i += n
        if not 0 <= i < n:
            raise IndexError(i)
        r = self.store.con.execute(f"SELECT {FLOW_SELECT} FROM flows WHERE seq = ?", [i + 1]).fetchone()
        return row_to_flow(r)

    def __eq__(self, other):
        if isinstance(other, (list, FlowView)):
            return len(self) == len(other) and list(self) == list(other)
        return NotImplemented

    __hash__ = None


class PartWriter:
    """Writes one input file's sessions as Parquet files into a run's working directory.

    It has its own small in-memory DuckDB connection, so it works the same inside a parse worker
    process as in the main process. File names carry the file number, so writers for different
    files never touch the same file."""

    def __init__(self, workdir: str, fid: int, batch_size: int = DEFAULT_BATCH):
        self.dir, self.fid, self.batch_size = workdir, fid, batch_size
        self.con = None
        self.flows: list[tuple] = []
        self.n_flows = 0
        self.base = fid << FID_SHIFT
        self._batch = 0
        self._days: dict[int, str] = {}

    def _con(self):
        if self.con is None:
            self.con = duckdb.connect()
            # one batch at a time: little memory, no threads competing with the other workers
            self.con.execute("SET threads = 1")
            self.con.execute("SET memory_limit = '512MiB'")
            self.con.execute(f"SET temp_directory = '{_q(os.path.join(self.dir, 'duckdb_tmp'))}'")
        return self.con

    def add_flow(self, f: Flow, sensor: str):
        self.flows.append(flow_row(self.base + self.n_flows, f, sensor, self.fid, self._days))
        self.n_flows += 1
        if len(self.flows) >= self.batch_size:
            self._flush_flows()

    def _flush_flows(self):
        if self.flows:
            self._batch += 1
            write_flow_parquet(self._con(), self.dir, self.flows, f"f{self.fid}_{self._batch}")
            self.flows = []

    def close(self):
        """Write what is left and release the connection."""
        try:
            self._flush_flows()
        finally:
            if self.con is not None:
                self.con.close()
                self.con = None


def flow_row(ord_: int, f: Flow, sensor: str, fid: int, days: dict) -> tuple:
    """One flow as a row in FLOW_COLUMNS order. ``days`` caches day names."""
    us = _us(f.ts)
    if us is None:
        day = "untimed"
    else:
        d = us // 86_400_000_000
        day = days.get(d)
        if day is None:
            day = days[d] = (EPOCH + timedelta(days=d)).strftime("%Y-%m-%d")
    return (ord_, us, f.src_ip, f.dst_ip, f.src_port, f.dst_port, f.proto, f.action,
            f.established, f.bytes_out or 0, f.bytes_in or 0, f.app, f.src_zone,
            f.dst_zone, f.source, sensor, fid, day, f.state, f.pkts_in, f.start_method)


def write_flow_parquet(con, workdir: str, rows: list[tuple], name: str) -> None:
    """Write flow rows (FLOW_COLUMNS order) to ``flows_parquet/<name>.parquet`` through a CSV file
    (fast, needs no numpy/arrow)."""
    out = os.path.join(workdir, "flows_parquet")
    os.makedirs(out, exist_ok=True)
    path = os.path.join(workdir, f"{name}.csv")
    with open(path, "w", newline="", encoding="utf-8") as fh:
        csv.writer(fh).writerows(rows)
    try:
        cols = ", ".join(f"'{k}': '{v}'" for k, v in _CSV_TYPES.items())
        source = (f"read_csv('{_q(path)}', columns={{{cols}}}, header=false, delim=',', quote='\"', "
                  f"escape='\"', nullstr='', auto_detect=false, strict_mode=false)")
        # Empty strings are read back as NULL by nullstr=''; restore them for text columns.
        select = ", ".join(f"coalesce({c}, '') AS {c}" if c in _TEXT_COLUMNS else c for c in FLOW_COLUMNS)
        con.execute(f"COPY (SELECT {select} FROM {source}) TO '{_q(os.path.join(out, name + '.parquet'))}' "
                    f"(FORMAT parquet)")
    finally:
        os.remove(path)


def _has_parquet(path: str) -> bool:
    try:
        return any(n.endswith(".parquet") for n in os.listdir(path))
    except OSError:
        return False


def _q(s: str) -> str:
    return str(s).replace("'", "''")


def _cleanup(con, path):
    try:
        con.close()
    except Exception:
        pass
    shutil.rmtree(path, ignore_errors=True)
