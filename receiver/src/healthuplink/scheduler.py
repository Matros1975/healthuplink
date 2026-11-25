"""Background maintenance: upload watchdog, daily backup, daily prune, and the periodic jobs extensions register.

`tick()` is cheap and idempotent; `serve` calls it every 60 s from a daemon thread. Each job tracks its own last
run, and the daily jobs also record the day in `meta`. The scheduler owns its store connections (created lazily
on the thread that first uses them) and never touches the ingest worker's connection.
"""

import json
import logging
import os
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from . import notify
from .notify import Notice
from .store import FUTURE_SKEW  # evidence later than now + this (a wrong device clock) is ignored

log = logging.getLogger(__name__)

STALE_AFTER = timedelta(hours=18)
ALERT_EVERY = timedelta(hours=24)
TYPE_SILENT_AFTER = timedelta(hours=48)
SLEEP_SILENT_AFTER = timedelta(hours=60)
SILENCE_LOOKBACK = timedelta(days=14)  # (b)/(c) need data within 14 days before the silence window began
WATCHED_TYPES = {"HKQuantityTypeIdentifierHeartRate": "heart rate", "HKQuantityTypeIdentifierStepCount": "step count"}
KEEP_BACKUPS = 14
RETAIN_DAYS = 400
ALERT_OPEN = "Open Health Uplink on your iPhone."
ALERT_LOW_POWER = "Low Power Mode is probably pausing Health Uplink sync. Open the app or charge the phone."
_ISO = "%Y-%m-%dT%H:%M:%SZ"


def _iso(t: datetime) -> str:
    return t.astimezone(timezone.utc).strftime(_ISO)


def _parse(s: str) -> datetime:
    return datetime.strptime(s, _ISO).replace(tzinfo=timezone.utc)


def _hours(delta: timedelta) -> int:
    return int(delta.total_seconds() // 3600)


class Scheduler:
    def __init__(self, settings, conn_factory, now, send_notice=None, *, keys=None, periodic=()):
        """`send_notice`: Callable[[Notice], None] for the watchdog; default `notify.build_sender(settings)` (None
        when no channel is configured). `periodic`: (name, every, fn) jobs from extensions (`extensions.Context.periodic`); they run before the
        built-in jobs on each tick, each when `every` has passed since its last run, and open their own
        connections."""
        self.settings = settings
        self.conn_factory = conn_factory
        self.now = now
        self.send_notice = send_notice if send_notice is not None else notify.build_sender(settings)
        self.keys = keys
        self._store = None
        self._jobs: list[tuple[str, timedelta, object]] = list(periodic) + [
            ("watchdog", timedelta(hours=1), self._watchdog),
            ("backup", timedelta(minutes=10), self._maybe_backup),
            ("prune", timedelta(hours=1), self._maybe_prune),
        ]
        self._last: dict[str, datetime | None] = {name: None for name, _, _ in self._jobs}
        self._warned_disabled = False

    @property
    def store(self) -> sqlite3.Connection:
        if self._store is None:
            self._store = self.conn_factory()
        return self._store

    def _due(self, job: str, every: timedelta) -> bool:
        last, t = self._last[job], self.now()
        if last is not None and t - last < every:
            return False
        self._last[job] = t
        return True

    def tick(self) -> None:
        for job, every, fn in self._jobs:
            if self._due(job, every):
                try:
                    fn()
                except Exception:
                    log.exception("scheduler job %s failed", job)

    def run_forever(self, interval: float = 60.0) -> None:
        while True:
            self.tick()
            time.sleep(interval)

    def start_thread(self) -> threading.Thread:
        t = threading.Thread(target=self.run_forever, name="scheduler", daemon=True)
        t.start()
        return t

    # ------------------------------------------------------------------ meta

    def _meta(self, key: str) -> str | None:
        row = self.store.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row[0] if row else None

    def _set_meta(self, key: str, value: str) -> None:
        self.store.execute("INSERT INTO meta(key, value) VALUES (?,?)"
                           " ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))

    # ------------------------------------------------------------------ watchdog

    def _watchdog(self) -> None:
        """At most one notice per ALERT_EVERY, only while a device is paired. It names each condition:
        no upload for STALE_AFTER, new dead-letters reported by the phone since the last message, a watched type
        that had data and has nothing new for TYPE_SILENT_AFTER, no sleep night for SLEEP_SILENT_AFTER. The last two
        stop once the silence is SILENCE_LOOKBACK older than its window (the user stopped wearing the device), and
        are left out while uploads themselves are stale: one outage gives one line."""
        c, now = self.store, self.now()
        # Compare sets, not counts: a dead-letter later re-reported as abandoned must not hide new ones. The
        # baseline is taken on the first run, before the pairing check, so a fresh store starts empty and the
        # first dead-letters after pairing are announced.
        dead = {f"{d}:{q}" for d, q in c.execute("SELECT device_id, seq FROM seq_reports WHERE kind='dead_letter'")}
        stored = self._meta("watchdog_dead_letter_set")
        if stored is None:
            self._set_meta("watchdog_dead_letter_set", json.dumps(sorted(dead)))
            seen = dead
        else:
            try:
                seen = set(json.loads(stored))
            except (ValueError, TypeError):
                seen = set()
        paired = c.execute("SELECT MAX(paired_at) FROM devices WHERE revoked_at IS NULL").fetchone()[0]
        if paired is None:
            return
        lines: list[str] = []
        kinds: list[str] = []
        row = c.execute("SELECT received_at, flags FROM batches WHERE status='stored'"
                        " ORDER BY received_at DESC LIMIT 1").fetchone()
        reference = _parse(row[0] if row else paired)
        stale = now - reference > STALE_AFTER
        if stale:
            low_power = False
            if row:
                try:
                    low_power = bool(json.loads(row[1] or "{}").get("low_power"))
                except ValueError:
                    pass
            kinds.append("stale")
            lines.append(f"No upload from Health Uplink for {_hours(now - reference)} hours. "
                         + (ALERT_LOW_POWER if low_power else ALERT_OPEN))
        new_dead = len(dead - seen)
        if new_dead > 0:
            noun = "batch" if new_dead == 1 else "batches"
            kinds.append("dead_letters")
            lines.append(f"The phone could not deliver {new_dead} {noun}. Use Resend from date in the app.")
        if not stale:
            for type_, label in WATCHED_TYPES.items():
                last = self._last_data(type_, now + FUTURE_SKEW)
                if last is not None and TYPE_SILENT_AFTER < now - last <= TYPE_SILENT_AFTER + SILENCE_LOOKBACK:
                    kinds.append("type_quiet")
                    lines.append(f"No new {label} data for {_hours(now - last)} hours.")
            last_night = self._last_night(now + FUTURE_SKEW)
            if (last_night is not None
                    and SLEEP_SILENT_AFTER < now - last_night <= SLEEP_SILENT_AFTER + SILENCE_LOOKBACK):
                kinds.append("sleep_quiet")
                lines.append(f"No sleep night recorded for {_hours(now - last_night)} hours.")
        if not lines:
            return
        last_alert = self._meta("last_alert_at")
        if last_alert and now - _parse(last_alert) < ALERT_EVERY:
            return
        if self.send_notice is None:
            if not self._warned_disabled:
                log.warning("Sync notices are off: set HU_NOTIFY_WEBHOOK_URL")
                self._warned_disabled = True
            return
        notice = Notice(tuple(dict.fromkeys(kinds)), "\n".join(lines))
        try:
            self.send_notice(notice)
        except Exception as exc:  # class names only: a message can carry the webhook URL or the bot token
            if isinstance(exc, notify.NoticeFailed):
                reached, detail = bool(exc.succeeded), ", ".join(exc.failed)
            else:
                reached, detail = False, type(exc).__name__
            log.error("sync notice failed (%s)", detail)
            if not reached:
                return
        # One working channel is enough to stop the hourly repeat; a failing one is logged each time it is tried.
        self._set_meta("last_alert_at", _iso(now))
        self._set_meta("watchdog_dead_letter_set", json.dumps(sorted(dead)))

    def _last_data(self, type_: str, limit: datetime) -> datetime | None:
        """Newest evidence of data for a type: the latest sample end, or the end of the latest daily row with a
        value (end of that day in the row's time zone, so a day's row never looks older than its data)."""
        c = self.store
        found: list[datetime] = []
        end = c.execute("SELECT MAX(end) FROM samples WHERE type=? AND end<=?", (type_, _iso(limit))).fetchone()[0]
        if end:
            try:
                found.append(_parse(end))
            except ValueError:
                pass
        row = c.execute("SELECT day, tz FROM daily WHERE type=? AND (sum > 0 OR avg IS NOT NULL) AND day<=?"
                        " ORDER BY day DESC LIMIT 1", (type_, limit.date().isoformat())).fetchone()
        if row:
            found.append(self._day_end(row[0], row[1]))
        return max(found) if found else None

    def _last_night(self, limit: datetime) -> datetime | None:
        row = self.store.execute("SELECT night, end, tz FROM sleep_nights WHERE COALESCE(end, night) <= ?"
                                 " ORDER BY COALESCE(end, night) DESC LIMIT 1", (_iso(limit),)).fetchone()
        if row is None:
            return None
        if row[1]:
            try:
                return _parse(row[1])
            except ValueError:
                pass
        return self._day_end(row[0], row[2])

    def _day_end(self, day: str, tz: str | None) -> datetime:
        try:
            zone = ZoneInfo(tz or self.settings.tz)
        except Exception:
            zone = ZoneInfo(self.settings.tz)
        try:
            d = datetime.fromisoformat(day).date() + timedelta(days=1)
        except (ValueError, OverflowError):
            return datetime.min.replace(tzinfo=timezone.utc)
        return datetime(d.year, d.month, d.day, tzinfo=zone).astimezone(timezone.utc)

    # ------------------------------------------------------------------ backup

    def _local(self) -> datetime:
        return self.now().astimezone(ZoneInfo(self.settings.tz))

    def _maybe_backup(self) -> None:
        local = self._local()
        if (local.hour, local.minute) < (3, 30):
            return
        if self._meta("last_backup_day") == local.date().isoformat():
            return
        self.backup_now()

    def backup_now(self) -> Path:
        day = self._local().date().isoformat()
        bdir = Path(self.settings.data_dir) / "backups"
        bdir.mkdir(parents=True, exist_ok=True)
        dest = bdir / f"store-{day}.db"
        os.close(os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600))
        os.chmod(dest, 0o600)
        out = sqlite3.connect(dest)
        try:
            self.store.backup(out)
        finally:
            out.close()
        for old in sorted(bdir.glob("store-*.db"))[:-KEEP_BACKUPS]:
            old.unlink()
        self._set_meta("last_backup_day", day)
        return dest

    # ------------------------------------------------------------------ prune

    def _maybe_prune(self) -> None:
        today = self._local().date().isoformat()
        if self._meta("last_prune_day") == today:
            return
        self.prune_now()
        self._set_meta("last_prune_day", today)

    def prune_now(self) -> None:
        now = self.now()
        cutoff, ts = _iso(now - timedelta(days=RETAIN_DAYS)), _iso(now)
        c = self.store
        c.execute("DELETE FROM tombstones WHERE deleted_at < ?", (cutoff,))
        # Keep the per-device seq floor so device_status does not regress once old batch rows are gone.
        for device_id, top in c.execute("SELECT device_id, MAX(seq) FROM batches WHERE received_at < ?"
                                        " GROUP BY device_id", (cutoff,)).fetchall():
            key = f"pruned_floor:{device_id}"
            floor = max(int(self._meta(key) or 0), top)
            self._set_meta(key, str(floor))
        c.execute("DELETE FROM batches WHERE received_at < ?", (cutoff,))
        c.execute("DELETE FROM pair_tokens WHERE used_at IS NOT NULL OR expires_at < ?", (ts,))
        if self.keys is not None:
            self.keys.prune(now)
