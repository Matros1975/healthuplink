import json
import os
import sqlite3
import stat
from datetime import datetime, timedelta, timezone

import pytest

from healthuplink.config import Settings
from healthuplink.db import connect
from healthuplink.scheduler import Scheduler

NOW = datetime(2026, 11, 22, 10, 0, 0, tzinfo=timezone.utc)  # 11:00 in Amsterdam
ISO = "%Y-%m-%dT%H:%M:%SZ"
LP = "Low Power Mode is probably pausing Health Uplink sync. Open the app or charge the phone."
OPEN = "Open Health Uplink on your iPhone."


class Clock:
    def __init__(self, t=NOW):
        self.t = t

    def __call__(self):
        return self.t


def make(tmp_path, *, paired=False, last_batch_hours=None, low_power=False, clock=None, **kw):
    # Times in these tests are Amsterdam local times (NOW is 11:00 there, backups after 03:30).
    settings = Settings(data_dir=str(tmp_path), telegram_token="t", telegram_chat_id="1", tz="Europe/Amsterdam")
    conn_factory = lambda: connect(tmp_path / "store.db")
    seed = conn_factory()
    if paired:
        seed.execute("INSERT INTO devices(device_id, name, signing_pk, paired_at) VALUES ('d1','phone','x',?)",
                     ((NOW - timedelta(days=30)).strftime(ISO),))
    if last_batch_hours is not None:
        seed.execute("INSERT INTO batches(batch_id, device_id, seq, received_at, status, flags) VALUES (?,?,?,?,?,?)",
                     ("b1", "d1", 1, (NOW - timedelta(hours=last_batch_hours)).strftime(ISO), "stored",
                      json.dumps({"low_power": low_power, "sink_done": True})))
    seed.close()
    sent = []  # notice texts
    clock = clock or Clock()
    sched = Scheduler(settings, conn_factory, clock, lambda n: (sent.append(n.text), sched.notices.append(n))[0],
                      **kw)
    sched.notices = []  # the Notice objects, with their kinds
    return sched, sent


def test_watchdog_silent_before_pairing(tmp_path):
    sched, sent = make(tmp_path)
    sched.tick()
    assert sent == []


def test_watchdog_silent_when_only_revoked_device(tmp_path):
    sched, sent = make(tmp_path, paired=True, last_batch_hours=30)
    sched.store.execute("UPDATE devices SET revoked_at='2026-11-01T00:00:00Z'")
    sched.tick()
    assert sent == []


def test_watchdog_silent_when_fresh(tmp_path):
    sched, sent = make(tmp_path, paired=True, last_batch_hours=2)
    sched.tick()
    assert sent == []


def test_watchdog_alerts_once_per_day(tmp_path):
    clock = Clock()
    sched, sent = make(tmp_path, paired=True, last_batch_hours=20, clock=clock)
    sched.tick()
    sched.tick()
    assert len(sent) == 1 and OPEN in sent[0] and "20 hours" in sent[0]
    clock.t = NOW + timedelta(hours=25)
    sched.tick()
    assert len(sent) == 2 and OPEN in sent[1]


def test_watchdog_low_power_text(tmp_path):
    sched, sent = make(tmp_path, paired=True, last_batch_hours=20, low_power=True)
    sched.tick()
    assert len(sent) == 1 and LP in sent[0]


def test_watchdog_failed_send_is_retried(tmp_path):
    sched, sent = make(tmp_path, paired=True, last_batch_hours=20)
    calls = []

    def flaky(notice):
        calls.append(notice.text)
        if len(calls) == 1:
            raise OSError("boom https://api.telegram.org/botSECRET/sendMessage")
    sched.send_notice = flaky
    sched.tick()
    sched._last["watchdog"] = None
    sched.tick()
    assert len(calls) == 2


def test_backup_keeps_14(tmp_path):
    sched, _ = make(tmp_path)
    bdir = tmp_path / "backups"
    bdir.mkdir()
    for i in range(20):
        (bdir / f"store-2026-10-{i + 1:02d}.db").write_bytes(b"x")
    path = sched.backup_now()
    files = sorted(os.listdir(bdir))
    assert len(files) == 14 and files[-1] == "store-2026-11-22.db" and path == bdir / files[-1]
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert sqlite3.connect(path).execute("PRAGMA integrity_check").fetchone() == ("ok",)


def test_backup_daily_after_0330_local_only(tmp_path):
    clock = Clock(datetime(2026, 11, 22, 1, 0, tzinfo=timezone.utc))  # 02:00 Amsterdam
    sched, _ = make(tmp_path, clock=clock)
    sched.tick()
    assert not (tmp_path / "backups").exists()
    clock.t = datetime(2026, 11, 22, 3, 0, tzinfo=timezone.utc)  # 04:00 Amsterdam
    sched.tick()
    assert os.listdir(tmp_path / "backups") == ["store-2026-11-22.db"]
    (tmp_path / "backups" / "store-2026-11-22.db").unlink()
    sched._last["backup"] = None
    sched.tick()
    assert not (tmp_path / "backups" / "store-2026-11-22.db").exists()  # already done today (meta)


def test_prune(tmp_path):
    sched, _ = make(tmp_path)
    c = sched.store
    old, new = (NOW - timedelta(days=401)).strftime(ISO), (NOW - timedelta(days=10)).strftime(ISO)
    c.execute("INSERT INTO tombstones VALUES ('u1','t',?)", (old,))
    c.execute("INSERT INTO tombstones VALUES ('u2','t',?)", (new,))
    for i, t in enumerate((old, new)):
        c.execute("INSERT INTO batches(batch_id, device_id, seq, received_at, status) VALUES (?,?,?,?,?)",
                  (f"x{i}", "d1", i, t, "stored"))
    c.execute("INSERT INTO pair_tokens VALUES ('h1',1,?,?)", (new, old))  # used
    c.execute("INSERT INTO pair_tokens VALUES ('h2',1,?,NULL)", (old,))  # expired
    c.execute("INSERT INTO pair_tokens VALUES ('h3',1,?,NULL)", ((NOW + timedelta(days=1)).strftime(ISO),))
    sched.prune_now()
    assert c.execute("SELECT uuid FROM tombstones").fetchall() == [("u2",)]
    assert c.execute("SELECT batch_id FROM batches").fetchall() == [("x1",)]
    assert c.execute("SELECT token_hash FROM pair_tokens").fetchall() == [("h3",)]


def test_prune_keeps_device_status_floor(tmp_path):
    from healthuplink.store import device_status
    sched, _ = make(tmp_path)
    c = sched.store
    old = (NOW - timedelta(days=401)).strftime(ISO)
    for seq in range(1, 6):
        c.execute("INSERT INTO batches(batch_id, device_id, seq, received_at, status) VALUES (?,?,?,?,?)",
                  (f"o{seq}", "d1", seq, old, "stored"))
    sched.prune_now()
    st = device_status(c, "d1")
    assert st["high_contiguous_seq"] == 5 and st["gaps"] == []
    c.execute("INSERT INTO batches(batch_id, device_id, seq, received_at, status) VALUES ('n7','d1',7,?,'stored')",
              (NOW.strftime(ISO),))
    st = device_status(c, "d1")
    assert st["high_contiguous_seq"] == 5 and st["gaps"] == [6]


# ---------------------------------------------------------------- dead letters and per-type silence

STEP_T = "HKQuantityTypeIdentifierStepCount"
HR_T = "HKQuantityTypeIdentifierHeartRate"
BANNED = ("alert", "monitor", "detect", "diagnos")


def _sample(c, uuid, type_, hours_ago):
    t = (NOW - timedelta(hours=hours_ago)).strftime(ISO)
    c.execute("INSERT OR IGNORE INTO sources(source, name, first_seen, last_seen) VALUES ('w','Watch',?,?)", (t, t))
    c.execute("INSERT INTO samples(uuid, type, kind, start, end, value, unit, source) VALUES (?,?,?,?,?,?,?,?)",
              (uuid, type_, "quantity", t, t, 1, "count", "w"))


def _night(c, night, end_hours_ago):
    end = (NOW - timedelta(hours=end_hours_ago)).strftime(ISO)
    c.execute("INSERT INTO sleep_nights(night, source, tz, start, end, minutes, segments) VALUES (?,?,?,?,?,?,?)",
              (night, "@merged", "Europe/Amsterdam", end, end, json.dumps({"asleep": 400, "in_bed": 450}), "[]"))


def _wording_ok(text):
    low = text.lower()
    return not any(b in low for b in BANNED)


def test_watchdog_new_dead_letters(tmp_path):
    clock = Clock()
    sched, sent = make(tmp_path, paired=True, last_batch_hours=1, clock=clock)
    sched.tick()
    assert sent == []
    for seq in (5, 6):
        sched.store.execute("INSERT INTO seq_reports(device_id, seq, kind) VALUES ('d1',?,'dead_letter')", (seq,))
    sched.store.execute("INSERT INTO seq_reports(device_id, seq, kind) VALUES ('d1',7,'abandoned')")
    sched._last["watchdog"] = None
    sched.tick()
    assert len(sent) == 1 and "2 batches" in sent[0] and _wording_ok(sent[0])
    clock.t = NOW + timedelta(hours=25)
    sched.store.execute("UPDATE batches SET received_at=?", (clock.t.strftime(ISO),))
    sched.tick()
    assert len(sent) == 1  # nothing new since the last message


def test_watchdog_dead_letters_wait_for_24h_window(tmp_path):
    clock = Clock()
    sched, sent = make(tmp_path, paired=True, last_batch_hours=20, clock=clock)
    sched.tick()
    assert len(sent) == 1
    sched.store.execute("INSERT INTO seq_reports(device_id, seq, kind) VALUES ('d1',5,'dead_letter')")
    sched.store.execute("UPDATE batches SET received_at=?", (NOW.strftime(ISO),))
    clock.t = NOW + timedelta(hours=2)
    sched.tick()
    assert len(sent) == 1
    clock.t = NOW + timedelta(hours=25)
    sched.store.execute("UPDATE batches SET received_at=?", (clock.t.strftime(ISO),))
    sched.tick()
    assert len(sent) == 2 and "deliver 1 batch." in sent[1]


@pytest.mark.parametrize("type_,word", [(HR_T, "heart rate"), (STEP_T, "step count")])
def test_watchdog_type_silent_48h(tmp_path, type_, word):
    sched, sent = make(tmp_path, paired=True, last_batch_hours=1)
    _sample(sched.store, "u1", type_, 50)
    sched.tick()
    assert len(sent) == 1 and word in sent[0] and "50 hours" in sent[0] and _wording_ok(sent[0])


@pytest.mark.parametrize("type_", [HR_T, STEP_T])
def test_watchdog_type_recent_is_quiet(tmp_path, type_):
    sched, sent = make(tmp_path, paired=True, last_batch_hours=1)
    _sample(sched.store, "u1", type_, 50)
    _sample(sched.store, "u2", type_, 47)
    sched.tick()
    assert sent == []


def test_watchdog_steps_from_daily_rows_count(tmp_path):
    sched, sent = make(tmp_path, paired=True, last_batch_hours=1)
    c = sched.store
    c.execute("INSERT INTO daily(type, source, day, tz, sum, unit) VALUES (?,?,?,?,?,?)",
              (STEP_T, "w", "2026-11-21", "Europe/Amsterdam", 5000, "count"))
    sched.tick()
    assert sent == []
    c.execute("UPDATE daily SET day='2026-11-19'")
    sched._last["watchdog"] = None
    sched.tick()
    assert len(sent) == 1 and "step count" in sent[0]


def test_watchdog_no_type_data_ever_is_quiet(tmp_path):
    sched, sent = make(tmp_path, paired=True, last_batch_hours=1)
    sched.tick()
    assert sent == []


def test_watchdog_sleep_no_night_60h(tmp_path):
    sched, sent = make(tmp_path, paired=True, last_batch_hours=1)
    _night(sched.store, "2026-11-19", 62)
    sched.tick()
    assert len(sent) == 1 and "sleep" in sent[0].lower() and "62 hours" in sent[0] and _wording_ok(sent[0])


def test_watchdog_sleep_recent_night_quiet(tmp_path):
    sched, sent = make(tmp_path, paired=True, last_batch_hours=1)
    _night(sched.store, "2026-11-19", 62)
    _night(sched.store, "2026-11-21", 30)
    sched.tick()
    assert sent == []


def test_watchdog_conditions_combined_in_one_message(tmp_path):
    sched, sent = make(tmp_path, paired=True, last_batch_hours=1)
    _sample(sched.store, "u1", HR_T, 50)
    _night(sched.store, "2026-11-19", 62)
    sched.tick()
    assert len(sent) == 1
    assert "heart rate" in sent[0] and "sleep" in sent[0].lower() and _wording_ok(sent[0])


def test_watchdog_outage_is_one_short_line(tmp_path):
    """M4: no uploads at all -> only the upload line; per-type silence follows from it and is not repeated."""
    sched, sent = make(tmp_path, paired=True, last_batch_hours=72)
    _sample(sched.store, "u1", HR_T, 72)
    _sample(sched.store, "u2", STEP_T, 59)
    _night(sched.store, "2026-11-19", 75)
    sched.tick()
    assert len(sent) == 1 and sent[0].count("\n") == 0 and OPEN in sent[0] and "heart rate" not in sent[0]


def test_watchdog_type_silence_needs_pairing(tmp_path):
    sched, sent = make(tmp_path, paired=False)
    _sample(sched.store, "u1", HR_T, 100)
    sched.tick()
    assert sent == []


def test_watchdog_texts_have_wellness_wording():
    from healthuplink import scheduler as s
    for text in (s.ALERT_OPEN, s.ALERT_LOW_POWER):
        assert _wording_ok(text)


def test_watchdog_dead_letter_replaced_by_abandoned_does_not_hide_new_ones(tmp_path):
    clock = Clock()
    sched, sent = make(tmp_path, paired=True, last_batch_hours=1, clock=clock)
    c = sched.store
    sched.tick()
    for seq in (5, 6):
        c.execute("INSERT INTO seq_reports(device_id, seq, kind) VALUES ('d1',?,'dead_letter')", (seq,))
    sched._last["watchdog"] = None
    sched.tick()
    assert len(sent) == 1
    c.execute("INSERT OR REPLACE INTO seq_reports(device_id, seq, kind) VALUES ('d1',5,'abandoned')")
    c.execute("INSERT INTO seq_reports(device_id, seq, kind) VALUES ('d1',9,'dead_letter')")
    clock.t = NOW + timedelta(hours=25)
    c.execute("UPDATE batches SET received_at=?", (clock.t.strftime(ISO),))
    sched.tick()
    assert len(sent) == 2 and "deliver 1 batch." in sent[1]


def test_watchdog_first_run_baselines_existing_dead_letters(tmp_path):
    sched, sent = make(tmp_path, paired=True, last_batch_hours=1)
    for seq in (5, 6, 7):
        sched.store.execute("INSERT INTO seq_reports(device_id, seq, kind) VALUES ('d1',?,'dead_letter')", (seq,))
    sched.tick()
    assert sent == []
    sched.store.execute("INSERT INTO seq_reports(device_id, seq, kind) VALUES ('d1',8,'dead_letter')")
    sched._last["watchdog"] = None
    sched.tick()
    assert len(sent) == 1 and "deliver 1 batch." in sent[0]


def test_watchdog_type_silence_stops_after_14_days(tmp_path):
    sched, sent = make(tmp_path, paired=True, last_batch_hours=1)
    _sample(sched.store, "u1", HR_T, 48 + 14 * 24 + 1)  # silent longer than window + 14 days
    _night(sched.store, "2026-11-01", 60 + 14 * 24 + 1)
    sched.tick()
    assert sent == []


def test_watchdog_type_silence_within_14_days_fires(tmp_path):
    sched, sent = make(tmp_path, paired=True, last_batch_hours=1)
    _sample(sched.store, "u1", HR_T, 48 + 14 * 24 - 1)
    sched.tick()
    assert len(sent) == 1 and "heart rate" in sent[0]


def test_watchdog_dead_letters_right_after_first_pairing_are_announced(tmp_path):
    """The baseline is taken while nothing is paired, so the first dead-letters after pairing count as new."""
    clock = Clock()
    sched, sent = make(tmp_path, clock=clock)
    sched.tick()  # startup, no device yet
    c = sched.store
    c.execute("INSERT INTO devices(device_id, name, signing_pk, paired_at) VALUES ('d1','phone','x',?)",
              ((NOW + timedelta(minutes=5)).strftime(ISO),))
    c.execute("INSERT INTO batches(batch_id, device_id, seq, received_at, status, flags) VALUES"
              " ('b1','d1',1,?,'stored','{}')", ((NOW + timedelta(minutes=10)).strftime(ISO),))
    for seq in (2, 3, 4):
        c.execute("INSERT INTO seq_reports(device_id, seq, kind) VALUES ('d1',?,'dead_letter')", (seq,))
    clock.t = NOW + timedelta(hours=1)
    sched.tick()
    assert len(sent) == 1 and "3 batches" in sent[0]


def test_watchdog_future_dated_data_does_not_hide_silence(tmp_path):
    """M3: evidence later than now + 1 day (wrong device clock) is ignored."""
    sched, sent = make(tmp_path, paired=True, last_batch_hours=1)
    c = sched.store
    _sample(c, "u1", HR_T, 120)
    _sample(c, "u2", HR_T, -24 * 200)
    c.execute("INSERT INTO daily(type, source, day, tz, avg, unit) VALUES (?,?,?,?,?,?)",
              (HR_T, "w", "2027-06-01", "Europe/Amsterdam", 60, "count/min"))
    _night(c, "2026-11-17", 100)
    _night(c, "2027-06-01", -24 * 200)
    sched.tick()
    assert len(sent) == 1 and "heart rate data for 120 hours" in sent[0] and "sleep" in sent[0].lower()


def _quiet_settings(tmp_path, **kw):
    return Settings(data_dir=str(tmp_path), tz="Europe/Amsterdam", **kw)


def _seed_stale(tmp_path):
    seed = connect(tmp_path / "store.db")
    seed.execute("INSERT INTO devices(device_id, name, signing_pk, paired_at) VALUES ('d1','phone','x',?)",
                 ((NOW - timedelta(days=30)).strftime(ISO),))
    seed.execute("INSERT INTO batches(batch_id, device_id, seq, received_at, status, flags) VALUES"
                 " ('b1','d1',1,?, 'stored', '{}')", ((NOW - timedelta(hours=20)).strftime(ISO),))
    seed.close()


def test_notice_kinds(tmp_path):
    sched, sent = make(tmp_path, paired=True, last_batch_hours=2)
    sched.tick()  # takes the dead-letter baseline; nothing to say
    sched.store.execute("INSERT INTO seq_reports(device_id, seq, kind) VALUES ('d1',5,'dead_letter')")
    sched._last["watchdog"] = None
    sched.tick()
    assert [n.kinds for n in sched.notices] == [("dead_letters",)]
    sched.store.execute("DELETE FROM meta WHERE key='last_alert_at'")
    sched.store.execute("INSERT INTO seq_reports(device_id, seq, kind) VALUES ('d1',6,'dead_letter')")
    sched.store.execute("UPDATE batches SET received_at=?", ((NOW - timedelta(hours=20)).strftime(ISO),))
    sched._last["watchdog"] = None
    sched.tick()
    assert sched.notices[-1].kinds == ("stale", "dead_letters")


def test_one_channel_failing_still_advances_alert_time(tmp_path, caplog, monkeypatch):
    from healthuplink import notify
    _seed_stale(tmp_path)
    tg = []
    monkeypatch.setattr(notify, "telegram_sender", lambda s: lambda text: tg.append(text))
    s = _quiet_settings(tmp_path, notify_webhook_url="http://127.0.0.1:9/hook", telegram_token="t",
                        telegram_chat_id="1")
    clock = Clock()
    sched = Scheduler(s, lambda: connect(tmp_path / "store.db"), clock)
    with caplog.at_level("INFO"):
        sched.tick()
    assert len(tg) == 1  # webhook refused the connection, Telegram went out
    assert sched.store.execute("SELECT value FROM meta WHERE key='last_alert_at'").fetchone() is not None
    failures = [r for r in caplog.records if "sync notice failed" in r.getMessage()]
    assert len(failures) == 1
    assert "127.0.0.1" not in caplog.text
    sched._last["watchdog"] = None
    clock.t = NOW + timedelta(hours=1)
    sched.tick()
    assert len(tg) == 1  # the working channel does not repeat every hour


def test_all_channels_failing_keeps_alert_time_unset(tmp_path):
    _seed_stale(tmp_path)
    s = _quiet_settings(tmp_path, notify_webhook_url="http://127.0.0.1:9/hook")
    sched = Scheduler(s, lambda: connect(tmp_path / "store.db"), Clock())
    sched.tick()
    assert sched.store.execute("SELECT value FROM meta WHERE key='last_alert_at'").fetchone() is None


def test_webhook_timeout_does_not_block_or_log_url(tmp_path, caplog):
    import socket
    import threading
    import time
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    held = []
    threading.Thread(target=lambda: held.append(srv.accept()), daemon=True).start()
    addr = f"127.0.0.1:{srv.getsockname()[1]}"
    url = f"http://{addr}/secret-topic"
    _seed_stale(tmp_path)
    s = _quiet_settings(tmp_path, notify_webhook_url=url)
    sched = Scheduler(s, lambda: connect(tmp_path / "store.db"), Clock())
    t0 = time.monotonic()
    with caplog.at_level("DEBUG"):
        sched.tick()
    srv.close()
    for conn, _ in held:
        conn.close()
    assert time.monotonic() - t0 < 12
    assert sched.store.execute("SELECT value FROM meta WHERE key='last_alert_at'").fetchone() is None
    assert "secret-topic" not in caplog.text and addr not in caplog.text
    assert "No upload" not in caplog.text and "Open Health Uplink" not in caplog.text


def test_no_channel_warns_once(tmp_path, caplog):
    _seed_stale(tmp_path)
    clock = Clock()
    sched = Scheduler(_quiet_settings(tmp_path), lambda: connect(tmp_path / "store.db"), clock)
    with caplog.at_level("WARNING"):
        sched.tick()
        sched._last["watchdog"] = None
        clock.t = NOW + timedelta(hours=1)
        sched.tick()
    warns = [r for r in caplog.records if "Sync notices are off: set HU_NOTIFY_WEBHOOK_URL" in r.getMessage()]
    assert len(warns) == 1
