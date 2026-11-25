import json
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from healthuplink import notify
from healthuplink.cli import main
from healthuplink.config import Settings
from healthuplink.db import connect
from healthuplink.notify import Notice
from healthuplink.scheduler import Scheduler

NOW = datetime(2026, 11, 22, 10, 0, 0, tzinfo=timezone.utc)
ISO = "%Y-%m-%dT%H:%M:%SZ"


@pytest.fixture
def no_uvicorn(monkeypatch):
    import uvicorn
    calls = []
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: calls.append(k))
    return calls


@pytest.fixture
def hook():
    """A local HTTP server that records POSTs; `.status` is the answer it gives."""
    seen = []

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            seen.append({"path": self.path, "headers": dict(self.headers), "body": body})
            self.send_response(srv.status)
            if srv.location:
                self.send_header("Location", srv.location)
            self.end_headers()

        def do_GET(self):
            seen.append({"method": "GET", "path": self.path})
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"<html>topic page</html>")

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    srv.status = 200
    srv.location = None
    srv.seen = seen
    srv.url = f"http://127.0.0.1:{srv.server_port}/topic"
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv
    srv.shutdown()
    srv.server_close()


def test_webhook_posts_json_without_health_values(tmp_path, hook):
    """A stale store holding heart-rate 73.123 and steps 8888: the POST says `stale` and carries neither value."""
    conn = connect(tmp_path / "store.db")
    conn.execute("INSERT INTO devices(device_id, name, signing_pk, paired_at) VALUES ('d1','phone','x',?)",
                 ((NOW - timedelta(days=30)).strftime(ISO),))
    conn.execute("INSERT INTO batches(batch_id, device_id, seq, received_at, status, flags) VALUES"
                 " ('b1','d1',1,?, 'stored', '{}')", ((NOW - timedelta(hours=20)).strftime(ISO),))
    conn.execute("INSERT INTO sources(source) VALUES ('w')")
    conn.execute("INSERT INTO samples(uuid, type, kind, start, end, value, unit, source) VALUES"
                 " ('u1','HKQuantityTypeIdentifierHeartRate','q','2026-11-21T13:00:00Z','2026-11-21T13:00:00Z',"
                 "73.123,'count/min','w')")
    conn.execute("INSERT INTO daily(type, source, day, tz, sum, unit) VALUES"
                 " ('HKQuantityTypeIdentifierStepCount','@merged','2026-11-21','UTC',8888,'count')")
    conn.close()
    s = Settings(data_dir=str(tmp_path), notify_webhook_url=hook.url)
    sched = Scheduler(s, lambda: connect(tmp_path / "store.db"), lambda: NOW)
    sched.tick()
    (req,) = hook.seen
    assert req["headers"]["Content-Type"] == "application/json"
    data = json.loads(req["body"])
    assert data["kinds"] == ["stale"] and data["source"] == "healthuplink"
    assert data["at"].endswith("Z") and "20 hours" in data["text"]
    assert set(data) == {"source", "kinds", "text", "at"}
    assert b"73.123" not in req["body"] and b"8888" not in req["body"]


def test_text_format_for_ntfy(hook):
    s = Settings(notify_webhook_url=hook.url, notify_format="text")
    send = notify.build_sender(s)
    assert send(Notice(("stale",), "No upload for 20 hours.")) == {"webhook"}
    (req,) = hook.seen
    assert req["body"] == b"No upload for 20 hours."
    assert req["headers"]["Title"] == "Health Uplink"
    assert req["headers"]["Content-Type"] == "text/plain; charset=utf-8"


def test_both_channels_when_both_configured(hook, monkeypatch):
    tg = []
    monkeypatch.setattr(notify, "telegram_sender", lambda s: lambda text: tg.append(text))
    s = Settings(notify_webhook_url=hook.url, telegram_token="t", telegram_chat_id="1")
    assert notify.build_sender(s)(Notice(("stale",), "hello")) == {"webhook", "telegram"}
    assert len(hook.seen) == 1 and tg == ["hello"]


def test_telegram_only_still_works(monkeypatch):
    tg = []
    monkeypatch.setattr(notify, "telegram_sender", lambda s: lambda text: tg.append(text))
    s = Settings(telegram_token="t", telegram_chat_id="1")
    assert notify.build_sender(s)(Notice(("stale",), "hello")) == {"telegram"}
    assert tg == ["hello"]


def test_no_channel_gives_no_sender():
    assert notify.build_sender(Settings()) is None


def test_non_2xx_raises_and_one_failure_still_tries_the_other(hook, monkeypatch):
    tg = []
    monkeypatch.setattr(notify, "telegram_sender", lambda s: lambda text: tg.append(text))
    hook.status = 500
    s = Settings(notify_webhook_url=hook.url, telegram_token="t", telegram_chat_id="1")
    with pytest.raises(notify.NoticeFailed) as e:
        notify.build_sender(s)(Notice(("stale",), "hello"))
    assert e.value.succeeded == {"telegram"} and tg == ["hello"]
    assert "127.0.0.1" not in str(e.value) and "hello" not in str(e.value)


def test_only_channel_failing_raises_with_nothing_succeeded(hook):
    hook.status = 404
    with pytest.raises(notify.NoticeFailed) as e:
        notify.build_sender(Settings(notify_webhook_url=hook.url))(Notice(("stale",), "x"))
    assert e.value.succeeded == set()


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://example.com/x", "example.com/x", "gopher://h/"])
def test_rejects_non_http_webhook(url, tmp_path, capsys, no_uvicorn):
    with pytest.raises(ValueError):
        notify.build_sender(Settings(notify_webhook_url=url))
    assert main(["serve"], Settings(data_dir=str(tmp_path), notify_webhook_url=url)) == 2
    assert no_uvicorn == []
    err = capsys.readouterr().err
    assert "HU_NOTIFY_WEBHOOK_URL" in err and "passwd" not in err and len(err.strip().splitlines()) == 1


def test_serve_rejects_bad_scheme_from_env(tmp_path, capsys, no_uvicorn):
    s = Settings.from_env({"HU_DATA_DIR": str(tmp_path), "HU_NOTIFY_WEBHOOK_URL": "file:///etc/passwd"})
    assert main(["serve"], s) == 2
    assert no_uvicorn == []


def test_notify_settings_from_env():
    s = Settings.from_env({"HU_NOTIFY_WEBHOOK_URL": " https://ntfy.example/t ", "HU_NOTIFY_FORMAT": "TEXT"})
    assert s.notify_webhook_url == "https://ntfy.example/t" and s.notify_format == "text"
    d = Settings.from_env({})
    assert d.notify_webhook_url == "" and d.notify_format == "json"
    with pytest.raises(ValueError):
        Settings.from_env({"HU_NOTIFY_FORMAT": "xml"})


@pytest.mark.parametrize("status", [301, 302, 303, 307])
@pytest.mark.parametrize("fmt", ["json", "text"])
def test_redirect_is_a_failure_not_followed(hook, status, fmt):
    """A proxy 301-ing http to https must not turn the POST into a GET that returns 200."""
    hook.status = status
    hook.location = hook.url + "/moved"
    s = Settings(notify_webhook_url=hook.url, notify_format=fmt)
    with pytest.raises(notify.NoticeFailed) as e:
        notify.build_sender(s)(Notice(("stale",), "x"))
    assert e.value.succeeded == set() and e.value.failed == ["webhook:HTTPError"]
    assert [r.get("method", "POST") for r in hook.seen] == ["POST"]  # the Location was never requested
