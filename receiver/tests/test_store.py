import json

import pytest

from healthuplink.body import validate
from healthuplink.db import connect
from healthuplink.store import write_batch

HR = "HKQuantityTypeIdentifierHeartRate"
STEPS = "HKQuantityTypeIdentifierStepCount"
U1 = "3f2a0000-0000-4000-8000-000000000001"


@pytest.fixture
def conn(tmp_path):
    return connect(tmp_path / "s.db")


def sample(**kw):
    s = {"uuid": U1, "type": HR, "kind": "quantity", "start": "2026-11-22T03:12:00Z",
         "end": "2026-11-22T03:12:00Z", "value": 50, "unit": "count/min",
         "source": {"bundle": "com.apple.health.ABC", "name": "Watch", "product_type": "Watch7,5"}}
    s.update(kw)
    return s


def daily(**kw):
    d = {"type": STEPS, "day": "2026-11-21", "source": "@merged", "sum": 1, "unit": "count"}
    d.update(kw)
    return d


def write(conn, seq, samples=(), daily=(), deleted=(), abandoned=(), dead_letter=(), nights=(), flags=None):
    b = validate({"samples": list(samples), "daily": list(daily), "deleted": list(deleted),
                  "sleep_nights": list(nights), "abandoned_seq": list(abandoned),
                  "dead_letter_seq": list(dead_letter), "workouts": [{}]})
    write_batch(conn, batch_id=f"b{seq}", device_id="d1", seq=seq, ct_sha256="ab", received_at="2026-11-22T08:00:00Z",
                created_at="2026-11-22T07:59:00Z", body=b, flags=flags, queue_for_sink=True)


def test_schema_and_pragmas(conn):
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 1
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 5000


def test_readonly_connection_cannot_write(conn, tmp_path):
    ro = connect(tmp_path / "s.db", readonly=True)
    with pytest.raises(Exception):
        ro.execute("INSERT INTO meta VALUES ('a','b')")


def test_batch_row_status_and_flags(conn):
    write(conn, 1, flags={"low_power": True})
    status, flags = conn.execute("SELECT status, flags FROM batches").fetchone()
    assert status == "stored"
    assert json.loads(flags) == {"low_power": True, "sink_done": False}
    write(conn, 2, flags={"sink_done": True})
    assert json.loads(conn.execute("SELECT flags FROM batches WHERE seq=2").fetchone()[0])["sink_done"] is True


def test_sample_upsert_keeps_newest_value(conn):
    write(conn, 1, samples=[sample(value=50)])
    write(conn, 2, samples=[sample(value=52)])
    assert conn.execute("SELECT value FROM samples WHERE uuid=?", (U1,)).fetchone()[0] == 52


def test_sample_source_column_holds_bundle(conn):
    write(conn, 1, samples=[sample()])
    assert conn.execute("SELECT source FROM samples").fetchone()[0] == "com.apple.health.ABC"
    assert conn.execute("SELECT name, product_type FROM sources").fetchone() == ("Watch", "Watch7,5")


def test_tombstone_wins_over_later_batch(conn):
    write(conn, 1, samples=[sample()])
    write(conn, 2, deleted=[{"uuid": U1, "type": HR}])
    write(conn, 3, samples=[sample()])
    assert conn.execute("SELECT count(*) FROM samples WHERE uuid=?", (U1,)).fetchone()[0] == 0
    assert conn.execute("SELECT count(*) FROM tombstones").fetchone()[0] == 1


def test_daily_upsert_by_type_source_day(conn):
    write(conn, 1, daily=[daily(sum=100, partial=True)])
    write(conn, 2, daily=[daily(sum=250, partial=False)])
    assert conn.execute("SELECT sum, partial FROM daily").fetchall() == [(250, 0)]


def test_seq_reports_and_source_last_seen(conn):
    write(conn, 5, abandoned=[3], dead_letter=[4], samples=[sample(end="2026-11-22T07:10:00Z")])
    assert conn.execute("SELECT seq, kind FROM seq_reports ORDER BY seq").fetchall() == [(3, "abandoned"), (4, "dead_letter")]
    assert conn.execute("SELECT last_seen FROM sources").fetchone()[0] == "2026-11-22T07:10:00Z"


def test_source_first_last_seen_track_min_max(conn):
    write(conn, 1, samples=[sample(start="2026-11-22T05:00:00Z", end="2026-11-22T05:01:00Z")])
    write(conn, 2, samples=[sample(uuid="3f2a0000-0000-4000-8000-000000000002",
                                   start="2026-11-22T01:00:00Z", end="2026-11-22T01:01:00Z")])
    assert conn.execute("SELECT first_seen, last_seen FROM sources").fetchone() == (
        "2026-11-22T01:00:00Z", "2026-11-22T05:01:00Z")
    assert conn.execute("SELECT count(*) FROM sources WHERE source='@merged'").fetchone()[0] == 0


def test_sleep_night_stored(conn):
    n = {"night": "2026-11-22", "source": "@merged", "minutes": {"asleep": 381}, "segments": []}
    write(conn, 1, nights=[n])
    assert json.loads(conn.execute("SELECT minutes FROM sleep_nights").fetchone()[0]) == {"asleep": 381}


def test_failed_batch_rolls_back(conn):
    write(conn, 1, samples=[sample()])
    with pytest.raises(Exception):
        write(conn, 1, samples=[sample(uuid="3f2a0000-0000-4000-8000-000000000009")])  # duplicate batch_id
    assert conn.execute("SELECT count(*) FROM samples").fetchone()[0] == 1


def test_sink_queue_row_written_in_batch_transaction(conn):
    write(conn, 1, daily=[daily()])
    row = conn.execute("SELECT batch_id, body, enqueued_at FROM sink_queue").fetchone()
    assert row[0] == "b1" and row[2] == "2026-11-22T08:00:00Z"
    assert set(json.loads(row[1])) == {"samples", "daily", "sleep_nights"}
    write(conn, 2, flags={"sink_done": True})
    assert [r[0] for r in conn.execute("SELECT batch_id FROM sink_queue")] == ["b1"]


U2 = "3f2a0000-0000-4000-8000-000000000002"
U3 = "3f2a0000-0000-4000-8000-000000000003"
PHONE = {"bundle": "com.apple.health.PHONE", "name": "Phone", "product_type": "iPhone15,2"}


def test_future_sample_does_not_raise_last_seen(conn):
    # received_at is 2026-11-22T08:00:00Z, so anything ending after 2026-11-23T08:00:00Z is a wrong device clock.
    write(conn, 1, samples=[sample(start="2033-02-27T10:00:00Z", end="2033-02-27T11:00:00Z"),
                            sample(uuid=U2, start="2026-11-22T07:00:00Z", end="2026-11-22T07:10:00Z")])
    assert conn.execute("SELECT first_seen, last_seen FROM sources").fetchone() == (
        "2026-11-22T07:00:00Z", "2026-11-22T07:10:00Z")
    # The future sample is still stored.
    assert conn.execute("SELECT end FROM samples WHERE uuid=?", (U1,)).fetchone()[0] == "2033-02-27T11:00:00Z"


def test_future_only_source_has_null_last_seen_then_heals(conn):
    write(conn, 1, samples=[sample(start="2028-02-28T10:00:00Z", end="2028-02-28T11:00:00Z", source=PHONE)])
    assert conn.execute("SELECT first_seen, last_seen FROM sources").fetchone() == ("2028-02-28T10:00:00Z", None)
    # A later real sample sets last_seen (SQLite's MAX(NULL, x) would keep NULL).
    write(conn, 2, samples=[sample(uuid=U2, start="2026-11-22T06:00:00Z", end="2026-11-22T06:05:00Z", source=PHONE)])
    assert conn.execute("SELECT first_seen, last_seen FROM sources").fetchone() == (
        "2026-11-22T06:00:00Z", "2026-11-22T06:05:00Z")


def test_sample_ending_exactly_one_day_ahead_counts(conn):
    write(conn, 1, samples=[sample(start="2026-11-23T07:00:00Z", end="2026-11-23T08:00:00Z")])
    assert conn.execute("SELECT last_seen FROM sources").fetchone()[0] == "2026-11-23T08:00:00Z"
    write(conn, 2, samples=[sample(uuid=U2, start="2026-11-23T07:00:00Z", end="2026-11-23T08:00:01Z")])
    assert conn.execute("SELECT last_seen FROM sources").fetchone()[0] == "2026-11-23T08:00:00Z"


def test_startup_repairs_future_last_seen(conn):
    from datetime import datetime, timezone

    from healthuplink.store import repair_future_last_seen

    write(conn, 1, samples=[sample(start="2026-11-22T07:00:00Z", end="2026-11-22T07:10:00Z"),
                            sample(uuid=U2, start="2033-02-27T10:00:00Z", end="2033-02-27T11:00:00Z"),
                            sample(uuid=U3, start="2028-02-28T10:00:00Z", end="2028-02-28T11:00:00Z", source=PHONE)])
    other = dict(PHONE, bundle="com.example.OTHER")
    write(conn, 2, samples=[sample(uuid="3f2a0000-0000-4000-8000-000000000004", start="2026-11-22T05:00:00Z",
                                   end="2026-11-22T05:00:00Z", source=other)])
    # The state a store written before this rule existed holds (a long-running deployment).
    conn.execute("UPDATE sources SET last_seen='2033-02-27T11:00:00Z' WHERE source='com.apple.health.ABC'")
    conn.execute("UPDATE sources SET last_seen='2028-02-28T11:00:00Z' WHERE source='com.apple.health.PHONE'")
    now = datetime(2026, 11, 24, 12, 0, tzinfo=timezone.utc)
    assert repair_future_last_seen(conn, now) == 2
    rows = dict(conn.execute("SELECT source, last_seen FROM sources").fetchall())
    assert rows == {"com.apple.health.ABC": "2026-11-22T07:10:00Z", "com.apple.health.PHONE": None,
                    "com.example.OTHER": "2026-11-22T05:00:00Z"}
    assert conn.execute("SELECT first_seen FROM sources WHERE source='com.apple.health.ABC'").fetchone()[0] == (
        "2026-11-22T07:00:00Z")
    assert conn.execute("SELECT count(*) FROM samples").fetchone()[0] == 4  # nothing deleted
    assert repair_future_last_seen(conn, now) == 0  # idempotent
    assert dict(conn.execute("SELECT source, last_seen FROM sources").fetchall()) == rows


def test_samples_end_index_serves_future_count_and_repair(conn):
    names = {r[1] for r in conn.execute("PRAGMA index_list(samples)")}
    assert "samples_end" in names
    count_plan = " ".join(r[3] for r in conn.execute("EXPLAIN QUERY PLAN SELECT COUNT(*) FROM samples WHERE end>?",
                                                     ("x",)))
    assert "samples_end" in count_plan
    from healthuplink.store import REPAIR_SQL
    repair_plan = " ".join(r[3] for r in conn.execute("EXPLAIN QUERY PLAN " + REPAIR_SQL, ("x", "x")))
    assert "samples_end" in repair_plan


def test_end_index_added_to_existing_store(tmp_path):
    import sqlite3
    old = connect(tmp_path / "old.db")
    old.execute("DROP INDEX samples_end")  # a store created before the index existed (user_version already 1)
    old.close()
    c = connect(tmp_path / "old.db")
    assert "samples_end" in {r[1] for r in c.execute("PRAGMA index_list(samples)")}
