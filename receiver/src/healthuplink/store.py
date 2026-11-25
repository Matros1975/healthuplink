"""Batch writes: one transaction per batch."""

import json
import logging
from datetime import datetime, timedelta, timezone

from .body import Body

log = logging.getLogger(__name__)

# A sample, daily row or night later than now + this comes from a wrong device clock: it is stored and returned by
# range queries, but never counts as the newest/last data (sources.last_seen, MCP `last`, the watchdog).
FUTURE_SKEW = timedelta(days=1)
_ISO = "%Y-%m-%dT%H:%M:%SZ"


def future_cutoff(now: datetime) -> str:
    """`now + FUTURE_SKEW` as a UTC timestamp string; stored ends later than this are future-dated."""
    return (now + FUTURE_SKEW).astimezone(timezone.utc).strftime(_ISO)


def write_batch(conn, *, batch_id, device_id, seq, ct_sha256, received_at, created_at,
                body: Body, flags: dict | None = None, queue_for_sink: bool = False) -> None:
    """`queue_for_sink`: also copy the body into `sink_queue` (only when an extension consumes it)."""
    flags = dict(flags or {})
    flags.setdefault("sink_done", False)
    if body.ignored:
        log.info("batch %s: ignored arrays %s", batch_id, ",".join(sorted(body.ignored)))
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute(
            "INSERT INTO batches(batch_id, device_id, seq, ciphertext_sha256, received_at, status, flags)"
            " VALUES (?,?,?,?,?,?,?)",
            (batch_id, device_id, seq, ct_sha256, received_at, "stored", json.dumps(flags)),
        )
        if queue_for_sink and not flags["sink_done"]:
            conn.execute(
                "INSERT INTO sink_queue(batch_id, body, enqueued_at) VALUES (?,?,?)",
                (batch_id, json.dumps({"samples": body.samples, "daily": body.daily,
                                       "sleep_nights": body.sleep_nights}), received_at),
            )
        for kind, seqs in (("abandoned", body.abandoned_seq), ("dead_letter", body.dead_letter_seq)):
            for s in seqs:
                conn.execute(
                    "INSERT OR REPLACE INTO seq_reports(device_id, seq, kind) VALUES (?,?,?)",
                    (device_id, s, kind),
                )
        cutoff = future_cutoff(datetime.strptime(received_at, _ISO).replace(tzinfo=timezone.utc))
        for s in body.samples:
            src = s["source"]
            # A future-dated end never raises last_seen; a source with only future samples keeps it NULL.
            # (SQLite's two-argument MAX returns NULL when either side is NULL, hence the CASE.)
            conn.execute(
                "INSERT INTO sources(source, name, product_type, first_seen, last_seen) VALUES (?,?,?,?,?)"
                " ON CONFLICT(source) DO UPDATE SET"
                " name=COALESCE(excluded.name, name), product_type=COALESCE(excluded.product_type, product_type),"
                " first_seen=MIN(first_seen, excluded.first_seen),"
                " last_seen=CASE WHEN excluded.last_seen IS NULL THEN last_seen"
                " WHEN last_seen IS NULL THEN excluded.last_seen ELSE MAX(last_seen, excluded.last_seen) END",
                (src["bundle"], src["name"], src["product_type"], s["start"], s["end"] if s["end"] <= cutoff else None),
            )
            conn.execute(
                "INSERT INTO samples(uuid, type, kind, start, end, value, value_label, unit, source, tz, metadata)"
                " SELECT ?,?,?,?,?,?,?,?,?,?,? WHERE NOT EXISTS (SELECT 1 FROM tombstones WHERE uuid=?)"
                " ON CONFLICT(uuid) DO UPDATE SET type=excluded.type, kind=excluded.kind, start=excluded.start,"
                " end=excluded.end, value=excluded.value, value_label=excluded.value_label, unit=excluded.unit,"
                " source=excluded.source, tz=excluded.tz, metadata=excluded.metadata",
                (s["uuid"], s["type"], s["kind"], s["start"], s["end"], s["value"], s["value_label"], s["unit"],
                 src["bundle"], s["tz"], None if s["metadata"] is None else json.dumps(s["metadata"]),
                 s["uuid"]),
            )
        for d in body.daily:
            conn.execute(
                "INSERT OR REPLACE INTO daily(type, source, day, tz, sum, avg, min, max, n, unit, partial)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (d["type"], d["source"], d["day"], d["tz"], d["sum"], d["avg"], d["min"], d["max"], d["n"],
                 d["unit"], int(d["partial"])),
            )
        for n in body.sleep_nights:
            conn.execute(
                "INSERT OR REPLACE INTO sleep_nights(night, source, tz, start, end, minutes, segments)"
                " VALUES (?,?,?,?,?,?,?)",
                (n["night"], n["source"], n["tz"], n["start"], n["end"],
                 json.dumps(n["minutes"]), json.dumps(n["segments"])),
            )
        for d in body.deleted:
            conn.execute("DELETE FROM samples WHERE uuid=?", (d["uuid"],))
            conn.execute(
                "INSERT OR IGNORE INTO tombstones(uuid, type, deleted_at) VALUES (?,?,?)",
                (d["uuid"], d["type"], received_at),
            )
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise


REPAIR_SQL = ("UPDATE sources SET last_seen=(SELECT end FROM samples WHERE samples.source=sources.source AND end<=?"
              " ORDER BY end DESC LIMIT 1) WHERE last_seen>?")


def repair_future_last_seen(conn, now: datetime) -> int:
    """One-time startup repair for stores written before the future-sample rule: every source whose last_seen is
    later than now + FUTURE_SKEW gets the latest sample end at or before that cutoff (NULL when it has none).
    Idempotent; returns the number of sources changed. Each affected source walks the `samples_end` index
    backwards from the cutoff to its newest real sample."""
    cutoff = future_cutoff(now)
    conn.execute("BEGIN IMMEDIATE")
    try:
        n = conn.execute(
            REPAIR_SQL, (cutoff, cutoff)).rowcount
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    if n:
        log.info("repaired last_seen of %d source(s) with future-dated samples", n)
    return n


MAX_GAPS = 10_000


def device_status(conn, device_id: str) -> dict:
    """Contract section 3 status JSON (direct mode). Gaps are capped at MAX_GAPS entries."""
    stored = {r[0] for r in conn.execute("SELECT seq FROM batches WHERE device_id=?", (device_id,))}
    reported = {r[0] for r in conn.execute("SELECT seq FROM seq_reports WHERE device_id=?", (device_id,))}
    last = conn.execute("SELECT MAX(received_at) FROM batches WHERE device_id=?", (device_id,)).fetchone()[0]
    known = stored | reported
    row = conn.execute("SELECT value FROM meta WHERE key=?", (f"pruned_floor:{device_id}",)).fetchone()
    floor = int(row[0]) if row else 0  # every seq up to here was received, then pruned
    high = floor
    while high + 1 in known:
        high += 1
    gaps: list[int] = []
    if stored:
        # Walk only the known seqs, so a huge seq cannot make this loop over billions of numbers.
        prev = floor
        top = max(stored)
        for s in sorted(k for k in known if floor < k < top) + [top]:
            for g in range(prev + 1, min(s, prev + 1 + MAX_GAPS - len(gaps))):
                gaps.append(g)
            if len(gaps) >= MAX_GAPS:
                break
            prev = s
    return {"high_contiguous_seq": high, "last_received_at": last, "gaps": gaps,
            "oldest_unacked_at": None, "expired_seq": []}
