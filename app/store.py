"""Durable run history + aggregate telemetry (SQLite).

Every completed detonation is recorded so the console can show past activity
and fleet-wide stats that survive restarts. Pure stdlib; the DB file lives at
$DC_DB or ./data/runs.db.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from pathlib import Path

_DB_PATH = os.environ.get("DC_DB") or str(
    Path(__file__).resolve().parent.parent / "data" / "runs.db")
_lock = threading.Lock()
_conn: sqlite3.Connection | None = None


def _db() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        Path(_DB_PATH).parent.mkdir(parents=True, exist_ok=True)
        _conn = sqlite3.connect(_DB_PATH, check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        _conn.execute("""
            CREATE TABLE IF NOT EXISTS runs (
                id TEXT PRIMARY KEY,
                created REAL, type TEXT, name TEXT, submitted TEXT,
                synthetic INTEGER, label TEXT, score INTEGER,
                event_count INTEGER, canary_hits INTEGER, egress_blocked INTEGER,
                sensitive INTEGER, process_count INTEGER,
                runtime TEXT, duration REAL, summary TEXT,
                iocs TEXT, evidence_sha256 TEXT
            )""")
        _conn.commit()
    return _conn


def record(job) -> None:
    """Persist a finished job. Metrics are derived from its observed events."""
    from .models import Kind
    ev = job.events
    canary = sum(1 for e in ev if e.kind == Kind.FILE and e.detail.get("canary"))
    egress = sum(1 for e in ev if e.kind == Kind.BLOCKED and e.op == "connect")
    sensitive = sum(1 for e in ev if e.kind == Kind.FILE and e.severity >= 1
                    and not e.detail.get("canary"))
    procs = sum(1 for e in ev if e.kind == Kind.PROCESS)
    duration = max((e.ts for e in ev), default=0.0)
    v = job.verdict
    row = (
        job.id, job.created, job.target.type, job.target.name, job.raw,
        1 if job.synthetic else 0,
        v.label.value if v else "pending", v.score if v else 0,
        len(ev), canary, egress, sensitive, procs,
        job.runtime or "", round(duration, 2), job.summary,
        json.dumps([i.to_dict() for i in (v.iocs if v else [])]),
        job.report().get("evidence_sha256", ""),
    )
    with _lock:
        db = _db()
        db.execute("""INSERT OR REPLACE INTO runs VALUES
            (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", row)
        db.commit()


def recent(limit: int = 20) -> list[dict]:
    with _lock:
        rows = _db().execute(
            "SELECT id,created,type,name,synthetic,label,score,event_count,"
            "canary_hits,egress_blocked,runtime,duration "
            "FROM runs ORDER BY created DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]


def get(run_id: str) -> dict | None:
    with _lock:
        r = _db().execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
    if not r:
        return None
    d = dict(r)
    d["iocs"] = json.loads(d.get("iocs") or "[]")
    return d


def stats() -> dict:
    with _lock:
        db = _db()
        agg = db.execute("""
            SELECT COUNT(*) total,
                   COALESCE(SUM(label='malicious'),0) malicious,
                   COALESCE(SUM(label='suspicious'),0) suspicious,
                   COALESCE(SUM(label='benign'),0) benign,
                   COALESCE(SUM(synthetic=0),0) live_runs,
                   COALESCE(SUM(canary_hits),0) canary_hits,
                   COALESCE(SUM(egress_blocked),0) egress_blocked,
                   COALESCE(SUM(sensitive),0) sensitive,
                   COALESCE(SUM(event_count),0) events,
                   COALESCE(SUM(process_count),0) processes,
                   COALESCE(ROUND(AVG(score),1),0) avg_score,
                   COALESCE(MAX(score),0) max_score,
                   COALESCE(ROUND(SUM(duration),1),0) compute_seconds,
                   MIN(created) first_seen, MAX(created) last_seen
            FROM runs""").fetchone()
        by_type = db.execute(
            "SELECT type, COUNT(*) n FROM runs GROUP BY type ORDER BY n DESC").fetchall()
        top_iocs = db.execute(
            "SELECT iocs FROM runs WHERE iocs != '[]'").fetchall()
    d = dict(agg)
    d["by_type"] = {r["type"]: r["n"] for r in by_type}
    # Most frequent indicator values across all runs.
    counts: dict[tuple, int] = {}
    for r in top_iocs:
        for i in json.loads(r["iocs"]):
            key = (i.get("type", ""), i.get("value", ""))
            counts[key] = counts.get(key, 0) + 1
    ranked = sorted(counts.items(), key=lambda kv: -kv[1])[:8]
    d["top_iocs"] = [{"type": k[0], "value": k[1], "count": n} for k, n in ranked]
    d["threats_contained"] = int(d["canary_hits"]) + int(d["egress_blocked"])
    return d
