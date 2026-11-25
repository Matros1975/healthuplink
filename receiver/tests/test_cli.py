import json
import sqlite3
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from healthuplink.cli import main
from healthuplink.config import Settings
from healthuplink.encoding import b64d


@pytest.fixture
def cli_env(tmp_path):
    return Settings(data_dir=str(tmp_path), public_url="http://100.100.1.1:8796")


def _db(s):
    return sqlite3.connect(f"{s.data_dir}/store.db")


def test_pair_prints_payload_with_current_key(cli_env, capsys):
    assert main(["pair"], cli_env) == 0
    out = capsys.readouterr().out
    p = json.loads(out.strip().splitlines()[-1])
    assert list(p) == ["v", "mode", "url", "server_pk", "key_epoch", "pair_token"]
    assert p["v"] == 1 and p["mode"] == "direct" and p["key_epoch"] == 1
    assert p["url"] == "http://100.100.1.1:8796"
    assert len(b64d(p["pair_token"])) == 16 and len(b64d(p["server_pk"])) == 32
    assert len(out.strip().splitlines()) > 1  # QR above the payload


def test_tokens_create_then_list_hides_token(cli_env, capsys):
    assert main(["tokens", "create", "--name", "claude-code"], cli_env) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[1] == "Store it now; it is not shown again."
    tok = lines[0]
    assert main(["tokens", "list"], cli_env) == 0
    out = capsys.readouterr().out
    assert tok not in out and "claude-code" in out


def test_tokens_revoke(cli_env):
    main(["tokens", "create", "--name", "a"], cli_env)
    assert main(["tokens", "revoke", "a"], cli_env) == 0
    assert main(["tokens", "revoke", "a"], cli_env) == 1


def test_tokens_create_duplicate_name_exits_1(cli_env, capsys):
    main(["tokens", "create", "--name", "a"], cli_env)
    capsys.readouterr()
    assert main(["tokens", "create", "--name", "a"], cli_env) == 1
    assert capsys.readouterr().out == ""


def test_devices_list_and_revoke(cli_env, capsys):
    main(["pair"], cli_env)  # creates the store
    did = str(uuid4())
    c = _db(cli_env)
    c.execute("INSERT INTO devices VALUES (?,?,?,?,NULL)", (did, "iPhone", "SECRETPK", "2026-01-01T00:00:00Z"))
    c.commit()
    capsys.readouterr()
    assert main(["devices", "list"], cli_env) == 0
    out = capsys.readouterr().out
    assert did in out and "iPhone" in out and "SECRETPK" not in out
    assert main(["devices", "revoke", did], cli_env) == 0
    assert _db(cli_env).execute("SELECT revoked_at FROM devices").fetchone()[0] is not None
    assert main(["devices", "revoke", did], cli_env) == 1  # already revoked


def test_devices_revoke_unknown_exits_1(cli_env, capsys):
    assert main(["devices", "revoke", str(uuid4())], cli_env) == 1
    assert capsys.readouterr().err


def test_keys_rotate_prints_epoch_only(cli_env, capsys):
    main(["pair"], cli_env)
    capsys.readouterr()
    assert main(["keys", "rotate"], cli_env) == 0
    assert capsys.readouterr().out.strip() == "2"


def test_usage_error_exits_2(cli_env):
    assert main(["bogus"], cli_env) == 2


def test_backup_prints_path_of_mode_600_copy(cli_env, capsys):
    import os
    import stat
    assert main(["tokens", "create", "--name", "x"], cli_env) == 0
    capsys.readouterr()
    assert main(["backup"], cli_env) == 0
    path = capsys.readouterr().out.strip()
    assert path.startswith(f"{cli_env.data_dir}/backups/store-") and stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert sqlite3.connect(path).execute("SELECT name FROM api_tokens").fetchall() == [("x",)]


def test_build_server_repairs_future_last_seen(tmp_path):
    from healthuplink.cli import build_server
    from healthuplink.db import connect
    from healthuplink.keys import KeyStore

    conn = connect(tmp_path / "store.db")
    conn.execute("INSERT INTO sources(source, name, product_type, first_seen, last_seen)"
                 " VALUES ('com.apple.health.X', 'X', NULL, '2026-11-01T00:00:00Z', '2033-02-27T11:00:00Z')")
    conn.execute("INSERT INTO samples(uuid, type, kind, start, end, value, source) VALUES"
                 " ('3f2a0000-0000-4000-8000-000000000001', 'HKQuantityTypeIdentifierBasalEnergyBurned', 'quantity',"
                 " '2026-11-02T00:00:00Z', '2026-11-02T01:00:00Z', 1, 'com.apple.health.X'),"
                 " ('3f2a0000-0000-4000-8000-000000000002', 'HKQuantityTypeIdentifierBasalEnergyBurned', 'quantity',"
                 " '2033-02-27T10:00:00Z', '2033-02-27T11:00:00Z', 1, 'com.apple.health.X')")
    settings = Settings(data_dir=str(tmp_path))
    # In March 2033 the 2033 sample is no longer future: nothing to repair (the injected clock is what counts).
    build_server(settings, KeyStore(tmp_path), clock=lambda: datetime(2033, 3, 1, tzinfo=timezone.utc))
    assert conn.execute("SELECT last_seen FROM sources").fetchone()[0] == "2033-02-27T11:00:00Z"
    build_server(settings, KeyStore(tmp_path), clock=lambda: datetime(2026, 11, 24, tzinfo=timezone.utc))
    assert conn.execute("SELECT last_seen FROM sources").fetchone()[0] == "2026-11-02T01:00:00Z"


def test_build_server_survives_failed_repair(tmp_path, monkeypatch, caplog):
    from healthuplink.cli import build_server
    from healthuplink.keys import KeyStore

    def boom(conn, now):
        raise sqlite3.OperationalError("database is locked /secret/path")

    monkeypatch.setattr("healthuplink.store.repair_future_last_seen", boom)
    with caplog.at_level("WARNING"):
        app, sched = build_server(Settings(data_dir=str(tmp_path)),
                                  KeyStore(tmp_path))
    assert app is not None and sched is not None
    assert "last_seen repair failed" in caplog.text and "/secret/path" not in caplog.text


# --- TLS and the transport rule ---

from dataclasses import replace


def _pair_rows(s) -> int:
    from healthuplink.db import connect
    from pathlib import Path
    return connect(Path(s.data_dir) / "store.db").execute("SELECT COUNT(*) FROM pair_tokens").fetchone()[0]


def _payload(out: str) -> dict:
    return json.loads(out.strip().splitlines()[-1])


def test_pair_adds_pin_for_self_signed(cli_env, capsys):
    from pathlib import Path
    from healthuplink import tls
    s = replace(cli_env, tls="self-signed", public_url="https://192.168.1.10:8796")
    assert main(["pair"], s) == 0
    p = _payload(capsys.readouterr().out)
    assert list(p) == ["v", "mode", "url", "server_pk", "key_epoch", "pair_token", "tls_sha256"]
    cert = Path(s.data_dir) / "tls" / "cert.pem"
    assert p["tls_sha256"] == tls.spki_sha256(cert.read_bytes())


def test_pair_without_tls_has_no_pin(cli_env, capsys):
    assert main(["pair"], cli_env) == 0
    assert "tls_sha256" not in _payload(capsys.readouterr().out)


def test_pair_refuses_plain_http_off_tailnet(cli_env, capsys):
    main(["pair"], cli_env)
    capsys.readouterr()
    before = _pair_rows(cli_env)
    assert main(["pair"], replace(cli_env, public_url="http://192.168.1.10:8796")) == 2
    io = capsys.readouterr()
    assert "HU_PUBLIC_URL" in io.err and "https" in io.err and io.out == ""
    assert _pair_rows(cli_env) == before


def test_pair_refuses_tailnet_name(cli_env, capsys):
    assert main(["pair"], replace(cli_env, public_url="http://box.tail1234.ts.net:8796")) == 2
    err = capsys.readouterr().err
    assert "HU_PUBLIC_URL" in err and "ts.net" in err


def test_pair_refuses_self_signed_on_public_name(cli_env, capsys):
    from pathlib import Path
    s = replace(cli_env, tls="self-signed", public_url="https://health.example.com")
    assert main(["pair"], s) == 2
    err = capsys.readouterr().err
    assert "self-signed certificate works only with an IP address or a .local name" in err
    assert "HU_TLS=files" in err and "HU_TLS_PIN=false" in err
    assert not (Path(s.data_dir) / "tls").exists()  # refused before any certificate is made


def test_pair_refuses_empty_public_url(cli_env, capsys):
    assert main(["pair"], replace(cli_env, public_url="")) == 2
    assert "HU_PUBLIC_URL" in capsys.readouterr().err


def test_pair_without_pin_when_disabled(cli_env, capsys):
    s = replace(cli_env, tls="files", tls_pin=False, public_url="https://health.example.com",
                tls_cert="/nonexistent/cert.pem", tls_key="/nonexistent/key.pem")
    assert main(["pair"], s) == 0
    p = _payload(capsys.readouterr().out)
    assert "tls_sha256" not in p and p["url"] == "https://health.example.com"


def test_self_signed_always_pins(cli_env, capsys):
    """HU_TLS_PIN applies to HU_TLS=files only: a self-signed certificate without a pin would fail on the phone."""
    from pathlib import Path
    from healthuplink import tls
    s = replace(cli_env, tls="self-signed", tls_pin=False, public_url="https://192.168.1.10:8796")
    assert main(["pair"], s) == 0
    cert = Path(s.data_dir) / "tls" / "cert.pem"
    assert _payload(capsys.readouterr().out)["tls_sha256"] == tls.spki_sha256(cert.read_bytes())
    s = replace(s, public_url="https://health.example.com")  # and so the public-name refusal still applies
    assert main(["pair"], s) == 2
    assert "self-signed certificate works only" in capsys.readouterr().err


def test_pair_files_with_pin_uses_the_cert(cli_env, capsys, tmp_path):
    from healthuplink import tls
    cert, key = tls.ensure_self_signed(tmp_path / "elsewhere", ["192.168.1.10"])
    s = replace(cli_env, tls="files", tls_cert=str(cert), tls_key=str(key), public_url="https://192.168.1.10:8796")
    assert main(["pair"], s) == 0
    assert _payload(capsys.readouterr().out)["tls_sha256"] == tls.spki_sha256(cert.read_bytes())


def test_pair_files_with_pin_missing_cert_exits_2(cli_env, capsys):
    s = replace(cli_env, tls="files", tls_cert="/nonexistent/cert.pem", tls_key="/nonexistent/key.pem",
                public_url="https://192.168.1.10:8796")
    assert main(["pair"], s) == 2
    assert "HU_TLS_CERT" in capsys.readouterr().err


def test_unknown_tls_mode_exits_2(cli_env, capsys):
    assert main(["pair"], replace(cli_env, tls="on")) == 2
    assert "HU_TLS" in capsys.readouterr().err


def test_files_mode_needs_cert_and_key(cli_env, capsys):
    assert main(["pair"], replace(cli_env, tls="files", tls_pin=False, public_url="https://192.168.1.10")) == 2
    err = capsys.readouterr().err
    assert "HU_TLS_CERT" in err and "HU_TLS_KEY" in err


def test_bad_tls_pin_env_exits_2(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HU_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("HU_TLS_PIN", "maybe")
    assert main(["pair"]) == 2
    assert "HU_TLS_PIN" in capsys.readouterr().err


@pytest.fixture
def no_uvicorn(monkeypatch):
    import uvicorn
    calls = []
    from healthuplink.scheduler import Scheduler
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: calls.append((a, k)))
    monkeypatch.setattr(Scheduler, "start_thread", lambda self: None)  # no background jobs in these tests
    return calls


def test_serve_refuses_unsafe_public_url(cli_env, no_uvicorn, capsys):
    assert main(["serve"], replace(cli_env, public_url="http://192.168.1.10:8796")) == 2
    assert no_uvicorn == []
    assert "HU_PUBLIC_URL" in capsys.readouterr().err


def test_serve_refuses_self_signed_on_public_name_even_without_pin(cli_env, no_uvicorn, capsys):
    """HU_TLS_PIN=false does not turn a self-signed certificate into a CA-valid one: serve still refuses it."""
    s = replace(cli_env, tls="self-signed", tls_pin=False, public_url="https://health.example.com")
    assert main(["serve"], s) == 2
    assert no_uvicorn == []
    assert "self-signed certificate works only" in capsys.readouterr().err


def test_serve_allows_empty_public_url(cli_env, no_uvicorn):
    assert main(["serve"], replace(cli_env, public_url="", bind="127.0.0.1:0")) == 0
    (_, kw), = no_uvicorn
    assert "ssl_certfile" not in kw and kw["host"] == "127.0.0.1"


def test_serve_with_self_signed_passes_cert(cli_env, no_uvicorn):
    from pathlib import Path
    s = replace(cli_env, tls="self-signed", public_url="https://mac.local:8796", bind="0.0.0.0:8796")
    assert main(["serve"], s) == 0
    (_, kw), = no_uvicorn
    d = Path(s.data_dir) / "tls"
    assert kw["ssl_certfile"] == str(d / "cert.pem") and kw["ssl_keyfile"] == str(d / "key.pem")
    assert (d / "cert.pem").exists()


def _fake_urlopen(monkeypatch, status=200, exc=None):
    import urllib.request
    seen = {}

    class Resp:
        def __init__(self):
            self.status = status
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False

    def urlopen(url, timeout=None, context=None):
        seen.update(url=url, timeout=timeout, context=context)
        if exc:
            raise exc
        return Resp()

    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    return seen


def test_healthcheck_uses_https_when_tls_on(cli_env, monkeypatch):
    import ssl
    seen = _fake_urlopen(monkeypatch)
    assert main(["healthcheck"], replace(cli_env, tls="self-signed", bind="0.0.0.0:9123")) == 0
    assert seen["url"] == "https://127.0.0.1:9123/healthz"
    ctx = seen["context"]
    assert isinstance(ctx, ssl.SSLContext) and ctx.verify_mode == ssl.CERT_NONE and not ctx.check_hostname


def test_healthcheck_plain_http_when_tls_off(cli_env, monkeypatch):
    seen = _fake_urlopen(monkeypatch)
    assert main(["healthcheck"], replace(cli_env, bind="0.0.0.0:8796")) == 0
    assert seen["url"] == "http://127.0.0.1:8796/healthz" and seen["context"] is None


def test_healthcheck_fails_on_error_or_non_200(cli_env, monkeypatch):
    _fake_urlopen(monkeypatch, status=503)
    assert main(["healthcheck"], cli_env) == 1
    _fake_urlopen(monkeypatch, exc=OSError("refused"))
    assert main(["healthcheck"], cli_env) == 1


def test_tls_show_pem(cli_env, capsys):
    from pathlib import Path
    from healthuplink import tls
    s = replace(cli_env, tls="self-signed", public_url="https://192.168.1.10:8796")
    assert main(["tls", "show", "--pem"], s) == 0
    out = capsys.readouterr().out
    cert = Path(s.data_dir) / "tls" / "cert.pem"
    assert out == cert.read_text() and out.startswith("-----BEGIN CERTIFICATE-----")
    assert main(["tls", "show"], s) == 0
    out = capsys.readouterr().out
    assert tls.spki_sha256(cert.read_bytes()) in out and str(cert) in out


def test_tls_show_when_off_exits_1(cli_env, capsys):
    assert main(["tls", "show"], cli_env) == 1
    assert "HU_TLS" in capsys.readouterr().err


def test_image_binds_all_interfaces_and_uses_cli_healthcheck():
    """Outside the image the default bind is loopback; the image keeps 0.0.0.0 (Docker publishes one IP)."""
    from pathlib import Path
    text = (Path(__file__).resolve().parents[1] / "Dockerfile").read_text()
    assert "HU_BIND=0.0.0.0:8796" in text
    assert 'CMD ["healthuplink", "healthcheck"]' in text and "urlopen" not in text


# --- TLS floor, health check and startup checks ---

def test_served_tls_context_requires_tls_1_2(cli_env, no_uvicorn):
    import ssl
    s = replace(cli_env, tls="self-signed", public_url="https://192.168.1.10:8796")
    assert main(["serve"], s) == 0
    (_, kw), = no_uvicorn
    from pathlib import Path
    d = Path(s.data_dir) / "tls"

    def default():
        import warnings
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx.minimum_version = ssl.TLSVersion.TLSv1  # what a lax default could be; the factory must raise it
        ctx.load_cert_chain(d / "cert.pem", d / "key.pem")
        return ctx

    ctx = kw["ssl_context_factory"](None, default)
    assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2


def test_bind_with_empty_host_stays_on_loopback(cli_env, no_uvicorn):
    assert main(["serve"], replace(cli_env, bind=":8796")) == 0
    (_, kw), = no_uvicorn
    assert kw["host"] == "127.0.0.1" and kw["port"] == 8796


def test_healthcheck_never_exits_2(cli_env, monkeypatch, capsys):
    """Docker reserves exit code 2 for HEALTHCHECK; every failure of `healthcheck` is 1."""
    monkeypatch.setenv("HU_TLS_PIN", "maybe")  # settings error: 2 for every other command
    assert main(["healthcheck"]) == 1
    assert main(["healthcheck", "--bogus"], cli_env) == 1  # usage error
    _fake_urlopen(monkeypatch, exc=OSError("refused"))
    assert main(["healthcheck"], replace(cli_env, bind="nonsense")) == 1


def test_serve_with_empty_public_url_says_pairing_needs_it(cli_env, no_uvicorn, capsys):
    assert main(["serve"], replace(cli_env, public_url="")) == 0
    err = capsys.readouterr().err
    assert "HU_PUBLIC_URL" in err and "pair" in err


def test_unknown_hu_tz_stops_serve(tmp_path, monkeypatch, capsys, no_uvicorn):
    monkeypatch.setenv("HU_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("HU_TZ", "Mars/Olympus")
    assert main(["serve"]) == 2
    assert no_uvicorn == []
    err = capsys.readouterr().err
    assert "HU_TZ" in err and len(err.strip().splitlines()) == 1


def test_unknown_tz_in_settings_stops_serve(tmp_path, capsys, no_uvicorn):
    assert main(["serve"], Settings(data_dir=str(tmp_path), tz="Mars/Olympus")) == 2
    assert no_uvicorn == []
    assert "HU_TZ" in capsys.readouterr().err


def test_backup_with_bad_webhook_url_exits_2_in_one_line(tmp_path, capsys):
    s = Settings(data_dir=str(tmp_path), notify_webhook_url="file:///etc/passwd")
    assert main(["backup"], s) == 2
    err = capsys.readouterr().err
    assert "HU_NOTIFY_WEBHOOK_URL" in err and len(err.strip().splitlines()) == 1
