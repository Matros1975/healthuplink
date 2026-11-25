"""Packaging and neutral defaults: what a stranger gets from `pip install` or the published image."""

import os
import sqlite3
import textwrap
from datetime import datetime, timedelta, timezone
from importlib import resources
from pathlib import Path

import pytest

from healthuplink.config import Settings

REPO = Path(__file__).resolve().parents[2]


class Clock:
    def __init__(self, t):
        self.t = t

    def __call__(self):
        return self.t


def test_packaged_contract_matches_repo():
    data = resources.files("healthuplink") / "data"
    for name in ("units.json", "cumulative.json"):
        assert (data / name).read_bytes() == (REPO / "contract" / name).read_bytes(), name


def test_defaults_are_neutral(monkeypatch):
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    s = Settings.from_env({})
    assert s.public_url == ""
    assert s.extensions == ()
    assert s.tz == "UTC"
    assert s.bind == "127.0.0.1:8796"
    home = Path.home()
    assert Path(s.data_dir) == home / ".local" / "share" / "healthuplink"


def test_data_dir_follows_xdg_then_hu_data_dir(tmp_path):
    assert Settings.from_env({"XDG_DATA_HOME": str(tmp_path)}).data_dir == str(tmp_path / "healthuplink")
    assert Settings.from_env({"XDG_DATA_HOME": str(tmp_path), "HU_DATA_DIR": "/srv/hu"}).data_dir == "/srv/hu"
    # A relative XDG_DATA_HOME is invalid by the XDG spec and ignored.
    assert Settings.from_env({"XDG_DATA_HOME": "rel"}).data_dir.endswith(os.path.join(".local", "share", "healthuplink"))


class _BlockSinkModules:
    """Import hook that makes every `healthuplink.sink_*` module (optional, deployment-specific extensions) absent."""

    def find_spec(self, name, path=None, target=None):
        if name.startswith("healthuplink.sink_"):
            raise ModuleNotFoundError(f"blocked for the test: {name}", name=name)
        return None


def test_server_builds_without_optional_extension_modules(tmp_path, monkeypatch):
    """The core never imports an extension module: with every `healthuplink.sink_*` module missing, the server and
    its scheduler still build and run the built-in jobs."""
    import importlib
    import sys

    from healthuplink.keys import KeyStore
    for mod in [m for m in sys.modules if m.startswith("healthuplink.sink_")]:
        monkeypatch.delitem(sys.modules, mod)
    monkeypatch.setattr(sys, "meta_path", [_BlockSinkModules(), *sys.meta_path])
    for mod in ("healthuplink.extensions", "healthuplink.scheduler", "healthuplink.cli"):
        monkeypatch.delitem(sys.modules, mod, raising=False)
    scheduler = importlib.import_module("healthuplink.scheduler")
    cli = importlib.import_module("healthuplink.cli")
    t = datetime(2026, 11, 22, 12, 0, tzinfo=timezone.utc)
    app, sched = cli.build_server(Settings(data_dir=str(tmp_path)), KeyStore(tmp_path), clock=lambda: t)
    assert isinstance(sched, scheduler.Scheduler)
    sched.tick()
    assert sched.store.execute("SELECT value FROM meta WHERE key='last_prune_day'").fetchone() == ("2026-11-22",)
    assert not [m for m in sys.modules if m.startswith("healthuplink.sink_")]
    app.state.hook_executor.shutdown(wait=True)


def test_extensions_list_from_env():
    assert Settings.from_env({"HU_EXTENSIONS": " a.b , c ,,"}).extensions == ("a.b", "c")
    assert Settings.from_env({"HU_EXTENSIONS": ""}).extensions == ()


def test_units_load_packaged_data_and_honour_overrides(tmp_path, monkeypatch):
    from healthuplink import units
    monkeypatch.delenv("HU_UNITS_FILE", raising=False)
    monkeypatch.delenv("HU_CUMULATIVE_FILE", raising=False)
    assert units.load_units()["HKQuantityTypeIdentifierStepCount"] == "count"
    assert "HKQuantityTypeIdentifierStepCount" in units.load_cumulative()
    (tmp_path / "u.json").write_text('{"X": "kg"}')
    (tmp_path / "c.json").write_text('["Y"]')
    monkeypatch.setenv("HU_UNITS_FILE", str(tmp_path / "u.json"))
    monkeypatch.setenv("HU_CUMULATIVE_FILE", str(tmp_path / "c.json"))
    assert units.load_units() == {"X": "kg"}
    assert units.load_cumulative() == {"Y"}
    monkeypatch.setenv("HU_UNITS_FILE", str(tmp_path / "missing.json"))
    assert units.load_units() == {}
    with pytest.raises(OSError):
        units.load_units(strict=True)


_EXT = """
from datetime import timedelta

calls = {"hook": [], "periodic": 0}


def register(ctx):
    ctx.add_ingest_hook(lambda batch_id: calls["hook"].append(batch_id))

    def job():
        calls["periodic"] += 1
    ctx.add_periodic("probe", timedelta(minutes=30), job)
"""


def _ext(tmp_path, monkeypatch, name):
    (tmp_path / "ext").mkdir()
    (tmp_path / "ext" / f"{name}.py").write_text(textwrap.dedent(_EXT))
    monkeypatch.syspath_prepend(str(tmp_path / "ext"))
    return name


def _stored_batch_app(tmp_path, settings, clock):
    """build_server over a store with one paired device; returns (app, scheduler, IngestEnv)."""
    from healthuplink.cli import build_server
    from healthuplink.keys import KeyStore
    from test_ingest_batches import Env as IngestEnv
    ienv = IngestEnv(tmp_path)
    ienv.conn.close()
    os.replace(tmp_path / "s.db", tmp_path / "store.db")
    app, sched = build_server(settings, KeyStore(tmp_path), clock=clock)
    return app, sched, ienv


def test_extension_hooks_run(tmp_path, monkeypatch):
    import importlib

    from starlette.testclient import TestClient

    name = _ext(tmp_path, monkeypatch, "hu_probe_ext_hooks")
    t0 = datetime(2026, 11, 22, 12, 0, tzinfo=timezone.utc)
    clock = Clock(t0)
    settings = Settings(data_dir=str(tmp_path), extensions=(name,))
    app, sched, ienv = _stored_batch_app(tmp_path, settings, clock)
    mod = importlib.import_module(name)
    e = ienv.envelope(seq=1)
    with TestClient(app) as client:
        assert client.post("/v1/batches", json=e).json() == {"status": "stored"}
    app.state.hook_executor.shutdown(wait=True)
    assert mod.calls["hook"] == [e["batch_id"]]

    sched.tick()
    assert mod.calls["periodic"] == 1
    clock.t = t0 + timedelta(minutes=29)
    sched.tick()
    assert mod.calls["periodic"] == 1
    clock.t = t0 + timedelta(minutes=30)
    sched.tick()
    assert mod.calls["periodic"] == 2


def test_no_sink_queue_rows_without_a_consumer(tmp_path):
    """Without an extension that asks for it, stored batches are not copied into sink_queue (it would only grow)."""
    from starlette.testclient import TestClient
    settings = Settings(data_dir=str(tmp_path))
    app, _, ienv = _stored_batch_app(tmp_path, settings, Clock(datetime(2026, 11, 22, 12, 0, tzinfo=timezone.utc)))
    with TestClient(app) as client:
        assert client.post("/v1/batches", json=ienv.envelope(seq=1)).json() == {"status": "stored"}
    app.state.hook_executor.shutdown(wait=True)
    c = sqlite3.connect(tmp_path / "store.db")
    assert c.execute("SELECT COUNT(*) FROM batches").fetchone() == (1,)
    assert c.execute("SELECT COUNT(*) FROM sink_queue").fetchone() == (0,)


def test_extension_can_ask_for_the_sink_queue(tmp_path, monkeypatch):
    from starlette.testclient import TestClient
    (tmp_path / "ext").mkdir()
    (tmp_path / "ext" / "hu_probe_ext_queue.py").write_text("def register(ctx):\n    ctx.use_sink_queue()\n")
    monkeypatch.syspath_prepend(str(tmp_path / "ext"))
    settings = Settings(data_dir=str(tmp_path), extensions=("hu_probe_ext_queue",))
    app, _, ienv = _stored_batch_app(tmp_path, settings, Clock(datetime(2026, 11, 22, 12, 0, tzinfo=timezone.utc)))
    e = ienv.envelope(seq=1)
    with TestClient(app) as client:
        assert client.post("/v1/batches", json=e).json() == {"status": "stored"}
    app.state.hook_executor.shutdown(wait=True)
    c = sqlite3.connect(tmp_path / "store.db")
    assert c.execute("SELECT batch_id FROM sink_queue").fetchall() == [(e["batch_id"],)]


def test_periodic_name_must_be_unique(tmp_path):
    from healthuplink import extensions
    ctx = extensions.Context(Settings(data_dir=str(tmp_path)), tmp_path / "store.db", lambda: None)
    ctx.add_periodic("x", timedelta(minutes=1), lambda: None)
    with pytest.raises(ValueError):
        ctx.add_periodic("x", timedelta(minutes=1), lambda: None)
    with pytest.raises(ValueError):
        ctx.add_periodic("watchdog", timedelta(minutes=1), lambda: None)  # a built-in job name


def test_failing_extension_job_does_not_stop_other_jobs(tmp_path, monkeypatch):
    (tmp_path / "ext").mkdir()
    (tmp_path / "ext" / "hu_probe_ext_boom.py").write_text(textwrap.dedent("""
        from datetime import timedelta
        def register(ctx):
            def boom():
                raise RuntimeError("x")
            ctx.add_periodic("boom", timedelta(minutes=1), boom)
    """))
    monkeypatch.syspath_prepend(str(tmp_path / "ext"))
    from healthuplink.cli import build_server
    from healthuplink.keys import KeyStore
    t = datetime(2026, 11, 22, 12, 0, tzinfo=timezone.utc)
    app, sched = build_server(Settings(data_dir=str(tmp_path), extensions=("hu_probe_ext_boom",)), KeyStore(tmp_path),
                              clock=Clock(t))
    sched.tick()  # boom raises; backup and prune still run
    assert sched.store.execute("SELECT value FROM meta WHERE key='last_prune_day'").fetchone() == ("2026-11-22",)
    app.state.hook_executor.shutdown(wait=True)


def test_unknown_extension_stops_serve(tmp_path, monkeypatch, capsys):
    import uvicorn

    from healthuplink.cli import main
    calls = []
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: calls.append(1))
    s = Settings.from_env({"HU_DATA_DIR": str(tmp_path), "HU_EXTENSIONS": "no.such.module"})
    assert main(["serve"], s) == 2
    assert calls == []
    assert "no.such.module" in capsys.readouterr().err


def test_extension_without_register_stops_serve(tmp_path, monkeypatch, capsys):
    import uvicorn

    from healthuplink.cli import main
    (tmp_path / "ext").mkdir()
    (tmp_path / "ext" / "hu_probe_ext_noreg.py").write_text("X = 1\n")
    monkeypatch.syspath_prepend(str(tmp_path / "ext"))
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: None)
    s = Settings(data_dir=str(tmp_path), extensions=("hu_probe_ext_noreg",))
    assert main(["serve"], s) == 2
    assert "hu_probe_ext_noreg" in capsys.readouterr().err


def test_extension_command_is_dispatched(tmp_path, monkeypatch, capsys):
    from healthuplink.cli import main
    (tmp_path / "ext").mkdir()
    (tmp_path / "ext" / "hu_probe_ext_cmd.py").write_text(textwrap.dedent("""
        def register(ctx):
            def run(argv):
                print("ran", argv, ctx.store_path.name)
                return 0
            ctx.add_command("probe", "a test command", run)
    """))
    monkeypatch.syspath_prepend(str(tmp_path / "ext"))
    s = Settings(data_dir=str(tmp_path), extensions=("hu_probe_ext_cmd",))
    assert main(["probe", "x"], s) == 0
    assert capsys.readouterr().out.strip() == "ran ['x'] store.db"
    assert main(["probe"], Settings(data_dir=str(tmp_path))) == 2  # not registered without the extension


def test_mcp_summary_default_zone_follows_hu_tz(monkeypatch):
    from healthuplink_mcp import tools
    monkeypatch.delenv("HU_TZ", raising=False)
    assert tools.default_tz() == "UTC"
    monkeypatch.setenv("HU_TZ", "Asia/Tokyo")
    assert tools.default_tz() == "Asia/Tokyo"


def test_unknown_hu_tz_is_a_clear_error():
    with pytest.raises(ValueError, match="HU_TZ"):
        Settings.from_env({"HU_TZ": "Mars/Olympus"})
    assert Settings.from_env({"HU_TZ": "Europe/Berlin"}).tz == "Europe/Berlin"


def test_extensions_are_a_tuple():
    assert Settings.from_env({"HU_EXTENSIONS": "a.b, c"}).extensions == ("a.b", "c")
    assert Settings().extensions == ()


def test_register_failure_shows_only_the_exception_type(tmp_path, monkeypatch):
    from healthuplink import extensions
    (tmp_path / "ext").mkdir()
    (tmp_path / "ext" / "hu_probe_ext_leak.py").write_text(
        "def register(ctx):\n    raise RuntimeError('/secret/path token=abc')\n")
    monkeypatch.syspath_prepend(str(tmp_path / "ext"))
    ctx = extensions.Context(Settings(data_dir=str(tmp_path)), tmp_path / "store.db", lambda: None)
    with pytest.raises(extensions.ExtensionError) as e:
        extensions.load(("hu_probe_ext_leak",), ctx)
    msg = str(e.value)
    assert "hu_probe_ext_leak" in msg and "RuntimeError" in msg
    assert "/secret/path" not in msg and "token=abc" not in msg


def test_mcp_summary_survives_unknown_hu_tz(tmp_path, monkeypatch):
    """A bad HU_TZ must not make `summary` fail: with no daily row it falls back to UTC."""
    from healthuplink.db import connect
    from healthuplink_mcp import tools
    monkeypatch.setenv("HU_TZ", "Mars/Olympus")
    conn = connect(tmp_path / "store.db")
    out = tools.summary(conn, datetime(2026, 11, 22, 23, 30, tzinfo=timezone.utc), "day")
    assert out["end"] == "2026-11-21"  # UTC day before 2026-11-22


def test_write_batch_does_not_queue_for_sink_by_default(tmp_path):
    from healthuplink.body import validate
    from healthuplink.db import connect
    from healthuplink.store import write_batch
    conn = connect(tmp_path / "store.db")
    body = validate({"samples": [], "daily": [], "sleep_nights": [], "deleted": []})
    write_batch(conn, batch_id="b1", device_id="d1", seq=1, ct_sha256="ab", received_at="2026-11-22T08:00:00Z",
                created_at="2026-11-22T07:59:00Z", body=body)
    assert conn.execute("SELECT count(*) FROM sink_queue").fetchone()[0] == 0
