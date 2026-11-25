"""Operator CLI: pairing, devices, server keys, API tokens, TLS and the health check."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import logging
import sqlite3
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

import segno

from healthuplink import notify, tls, tokens, urlrule
from healthuplink.config import TLS_MODES, Settings, check_tz
from healthuplink.db import connect
from healthuplink.encoding import b64e
from healthuplink.keys import KeyStore

log = logging.getLogger(__name__)


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="healthuplink")
    top = ap.add_subparsers(dest="cmd", required=True)
    top.add_parser("pair", help="print a pairing QR and payload")

    devices = top.add_parser("devices").add_subparsers(dest="sub", required=True)
    devices.add_parser("list")
    dr = devices.add_parser("revoke")
    dr.add_argument("device_id")

    keys = top.add_parser("keys").add_subparsers(dest="sub", required=True)
    keys.add_parser("rotate")

    toks = top.add_parser("tokens").add_subparsers(dest="sub", required=True)
    tc = toks.add_parser("create")
    tc.add_argument("--name", required=True)
    tr = toks.add_parser("revoke")
    tr.add_argument("name")
    toks.add_parser("list")
    top.add_parser("serve", help="run the receiver and MCP endpoint")
    top.add_parser("backup", help="back up the store now and print the file path")
    top.add_parser("healthcheck", help="exit 0 when this receiver answers /healthz with 200")
    tshow = top.add_parser("tls").add_subparsers(dest="sub", required=True).add_parser(
        "show", help="print the certificate pin and path"
    )
    tshow.add_argument("--pem", action="store_true", help="print the certificate PEM instead")
    return ap


def _err(msg: str, code: int = 1) -> int:
    print(msg, file=sys.stderr)
    return code


# Any well-formed pin: the transport rule depends on whether a pin is sent, not on its value.
_SOME_PIN = b64e(bytes(32))


def _sends_pin(settings: Settings) -> bool:
    """A self-signed certificate is always pinned; HU_TLS_PIN applies to HU_TLS=files only."""
    return settings.tls == "self-signed" or (settings.tls == "files" and settings.tls_pin)


def _tz_error(settings: Settings) -> str | None:
    try:
        check_tz(settings.tz)
    except ValueError as e:
        return str(e)
    return None


def _tls_settings_error(settings: Settings) -> str | None:
    if settings.tls not in TLS_MODES:
        return f"HU_TLS must be one of {', '.join(TLS_MODES)}, got {settings.tls!r}"
    if settings.tls == "files" and not (settings.tls_cert and settings.tls_key):
        return "HU_TLS=files needs HU_TLS_CERT and HU_TLS_KEY (paths to PEM files)"
    return None


def _public_url_error(settings: Settings) -> str | None:
    """A one-line reason why the phone would refuse HU_PUBLIC_URL with this TLS setup, else None."""
    url = settings.public_url
    if not url.strip():
        return "HU_PUBLIC_URL is empty; set it to the address the phone uses, e.g. http://100.x.y.z:8796 on a tailnet"
    fault = urlrule.check(url, _SOME_PIN if _sends_pin(settings) else None)
    if fault is None:
        return None
    if fault == "tailnet_name":
        return f"HU_PUBLIC_URL {url}: the iPhone cannot resolve *.ts.net names; use the tailnet IP address (100.x.y.z)"
    if fault == "needs_https":
        if _sends_pin(settings):
            return f"HU_PUBLIC_URL {url}: with HU_TLS={settings.tls} the URL must start with https://"
        return (
            f"HU_PUBLIC_URL {url}: plain http is allowed only for a tailnet IPv4 address (100.64.0.0/10); "
            "use https:// and set HU_TLS=self-signed"
        )
    if fault == "pin_needs_local_host":
        return (
            f"HU_PUBLIC_URL {url}: a self-signed certificate works only with an IP address or a .local name "
            "(IPv4, or a name without dots); for a public name use a CA-signed certificate with HU_TLS=files "
            "and HU_TLS_PIN=false"
        )
    return f"HU_PUBLIC_URL {url!r} is not a usable http(s) URL with a host"


def _public_hosts(settings: Settings) -> list[str]:
    host = urlrule.host_of(settings.public_url) if settings.public_url.strip() else None
    return [host] if host else []


def _cert_pem(settings: Settings) -> tuple[Path, bytes]:
    """(path, PEM) of the serving certificate; creates the self-signed one if needed. TLS must be on.
    Raises OSError or ValueError with an operator-readable message."""
    if settings.tls == "self-signed":
        cert, _ = tls.ensure_self_signed(Path(settings.data_dir), _public_hosts(settings))
    else:
        cert, _ = tls.cert_paths(settings)
    try:
        return cert, cert.read_bytes()
    except OSError as e:
        raise OSError(f"cannot read the certificate {cert} (HU_TLS_CERT): {e.strerror}") from None


def _pin(settings: Settings) -> str | None:
    """The `tls_sha256` to put in the pairing code, or None. Raises like _cert_pem."""
    if not _sends_pin(settings):
        return None
    _, pem = _cert_pem(settings)
    try:
        return tls.spki_sha256(pem)
    except ValueError as e:
        raise ValueError(f"HU_TLS_CERT: {e}; use a P-256 certificate or set HU_TLS_PIN=false") from None


def _pair(conn, keys: KeyStore, settings: Settings) -> int:
    problem = _tz_error(settings) or notify.webhook_url_error(settings) or _tls_settings_error(settings) or _public_url_error(settings)
    if problem:
        return _err(problem, 2)
    try:
        pin = _pin(settings)  # creates the self-signed certificate on first use
    except (OSError, ValueError) as e:
        return _err(str(e), 2)
    key = keys.current()
    now = datetime.now(timezone.utc)
    token = tokens.create_pair_token(conn, key.epoch, now)
    payload = {
        "v": 1,
        "mode": "direct",
        "url": settings.public_url,
        "server_pk": b64e(key.pk),
        "key_epoch": key.epoch,
        "pair_token": b64e(token),
    }
    if pin is not None:
        payload["tls_sha256"] = pin
    text = json.dumps(payload)
    segno.make(text, error="m").terminal(compact=True)
    print(text)
    return 0


def _devices(conn, args) -> int:
    if args.sub == "list":
        for row in conn.execute("SELECT device_id, name, paired_at, revoked_at FROM devices ORDER BY paired_at"):
            print("\t".join("-" if v is None else str(v) for v in row))
        return 0
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    cur = conn.execute(
        "UPDATE devices SET revoked_at=? WHERE device_id=? AND revoked_at IS NULL", (now, args.device_id)
    )
    if cur.rowcount != 1:
        return _err(f"no active device {args.device_id}")
    return 0


def _tokens(conn, args) -> int:
    if args.sub == "create":
        try:
            token = tokens.create_api_token(conn, args.name)
        except sqlite3.IntegrityError:
            return _err(f"token name already exists: {args.name}")
        print(token)
        print("Store it now; it is not shown again.")
        return 0
    if args.sub == "revoke":
        if not tokens.revoke_api_token(conn, args.name):
            return _err(f"no token named {args.name}")
        return 0
    for name, created_at in tokens.list_api_tokens(conn):
        print(f"{name}\t{created_at}")
    return 0


def build_server(settings: Settings, keys: KeyStore, clock=None):
    """(ASGI app, Scheduler) wired together: MCP with bearer auth, the extensions in `settings.extensions`, the
    scheduler. `clock` (aware UTC `now`) defaults to the wall clock; tests inject a fixed one.
    Raises extensions.ExtensionError when an extension cannot be loaded."""
    from healthuplink import extensions
    from healthuplink.app import build_app
    from healthuplink.scheduler import Scheduler
    from healthuplink_mcp.server import BearerAuth, build

    from healthuplink.store import repair_future_last_seen

    path = Path(settings.data_dir) / "store.db"
    clock = clock or (lambda: datetime.now(timezone.utc))
    # One lock for every extension hook and periodic job (one drain at a time); hooks run on their own worker
    # with a 5 s limit on external databases, so an upload never waits for them.
    ctx = extensions.Context(settings, path, clock, timeout=5.0, lock=threading.Lock())
    extensions.load(settings.extensions, ctx)
    conn = connect(path)  # creates the schema too, so the read-only MCP connections find the tables
    try:
        repair_future_last_seen(conn, clock())
    except sqlite3.Error:
        # Never fatal: last_seen stays as it was and the next start retries. No message text (it can hold paths).
        log.warning("last_seen repair failed; retried at next start")
    finally:
        conn.close()
    read_only = lambda: connect(path, readonly=True)
    mcp_app = BearerAuth(build(read_only, clock), read_only)
    app = build_app(settings, lambda: connect(path), keys, mcp_app, sink_queue=ctx.sink_queue)

    hook_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="hooks")
    app.state.hook_executor = hook_executor

    def run_hook(fn, batch_id: str) -> None:
        try:
            fn(batch_id)
        except Exception:
            log.exception("extension hook failed for batch %s", batch_id)

    for fn in ctx.ingest_hooks:
        # Called on the ingest worker before the phone gets its response: never wait on the hook here.
        app.state.ingest_hooks.append(lambda batch_id, fn=fn: hook_executor.submit(run_hook, fn, batch_id))
    return app, Scheduler(settings, lambda: connect(path), clock, keys=keys, periodic=ctx.periodic)


def _tls_context_factory(config, default):
    """uvicorn's context with TLS 1.2 as the explicit floor (the phone speaks 1.2 and 1.3)."""
    import ssl
    ctx = default()
    if ctx.minimum_version < ssl.TLSVersion.TLSv1_2:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def _serve(settings: Settings, keys: KeyStore) -> int:
    import uvicorn

    # Refuse before binding. An empty HU_PUBLIC_URL is allowed (MCP and paired phones work), with a warning.
    problem = _tz_error(settings) or notify.webhook_url_error(settings) or _tls_settings_error(settings) or (_public_url_error(settings) if settings.public_url.strip() else None)
    if problem:
        return _err(problem, 2)
    if not settings.public_url.strip():
        print("warning: HU_PUBLIC_URL is empty; `healthuplink pair` needs it (the address the phone uses)",
              file=sys.stderr)
    ssl_kw = {}
    if settings.tls != "off":
        try:
            _cert_pem(settings)  # creates or reissues the self-signed certificate; checks HU_TLS_CERT is readable
        except (OSError, ValueError) as e:
            return _err(str(e), 2)
        cert, key = tls.cert_paths(settings)
        ssl_kw = {"ssl_certfile": str(cert), "ssl_keyfile": str(key), "ssl_context_factory": _tls_context_factory}

    logging.basicConfig(level=logging.INFO)
    from healthuplink.extensions import ExtensionError
    try:
        app, scheduler = build_server(settings, keys)
    except ExtensionError as e:
        return _err(str(e), 2)
    scheduler.start_thread()
    host, _, port = settings.bind.rpartition(":")
    try:
        uvicorn.run(app, host=host or "127.0.0.1", port=int(port), log_level="info", **ssl_kw)
    finally:
        app.state.hook_executor.shutdown(wait=False, cancel_futures=True)
    return 0


def _healthcheck(settings: Settings) -> int:
    """GET /healthz on this host's loopback; for the image's HEALTHCHECK. Certificate checks are off:
    this proves the server answers, not who it is."""
    import ssl
    import urllib.request

    port = settings.bind.rpartition(":")[2]
    context = None
    scheme = "http"
    if settings.tls != "off":
        scheme = "https"
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(f"{scheme}://127.0.0.1:{port}/healthz", timeout=3, context=context) as r:
            return 0 if r.status == 200 else 1
    except Exception as e:  # any failure is "unhealthy"; say which on stderr for `docker inspect`
        return _err(f"healthcheck failed: {type(e).__name__}")


def _tls_show(settings: Settings, pem: bool) -> int:
    problem = _tls_settings_error(settings)
    if problem:
        return _err(problem, 2)
    if settings.tls == "off":
        return _err("TLS is off (HU_TLS=off); set HU_TLS=self-signed or HU_TLS=files")
    try:
        path, data = _cert_pem(settings)
    except (OSError, ValueError) as e:
        return _err(str(e), 2)
    if pem:
        sys.stdout.write(data.decode())
        return 0
    try:
        pin = tls.spki_sha256(data)
    except ValueError as e:
        pin = f"- ({e})"
    print(f"tls_sha256\t{pin}")
    print(f"certificate\t{path}")
    return 0


_COMMANDS = ("pair", "devices", "keys", "tokens", "serve", "backup", "healthcheck", "tls")


def _extension_command(argv: list[str], settings: Settings | None) -> int | None:
    """Run `argv` as a command an extension registered, or None when no loaded extension has it."""
    from healthuplink import extensions
    if settings is None:
        try:
            settings = Settings.from_env()
        except ValueError as e:
            return _err(str(e), 2)
    if not settings.extensions:
        return None
    ctx = extensions.Context(settings, Path(settings.data_dir) / "store.db", lambda: datetime.now(timezone.utc))
    try:
        extensions.load(settings.extensions, ctx)
    except extensions.ExtensionError as e:
        return _err(str(e), 2)
    if argv[0] not in ctx.commands:
        return None
    Path(settings.data_dir).mkdir(parents=True, exist_ok=True)
    return ctx.commands[argv[0]][1](argv[1:])


def main(argv: list[str] | None = None, settings: Settings | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    code = _main(argv, settings)
    if argv[:1] == ["healthcheck"] and code == 2:
        return 1  # Docker reserves exit code 2 in HEALTHCHECK
    return code


def _main(argv: list[str], settings: Settings | None) -> int:
    if argv and argv[0] not in _COMMANDS and not argv[0].startswith("-"):
        code = _extension_command(argv, settings)
        if code is not None:
            return code
    try:
        args = _parser().parse_args(argv)
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 1
    if settings is None:
        try:
            settings = Settings.from_env()
        except ValueError as e:
            return _err(str(e), 2)
    if args.cmd == "healthcheck":
        return _healthcheck(settings)
    keys = KeyStore(Path(settings.data_dir))
    if args.cmd == "keys":
        print(keys.rotate(datetime.now(timezone.utc)).epoch)
        return 0
    Path(settings.data_dir).mkdir(parents=True, exist_ok=True)
    if args.cmd == "tls":
        return _tls_show(settings, args.pem)
    if args.cmd == "serve":
        return _serve(settings, keys)
    conn = connect(Path(settings.data_dir) / "store.db")
    try:
        if args.cmd == "backup":
            from healthuplink.scheduler import Scheduler
            try:
                sched = Scheduler(settings, lambda: conn, lambda: datetime.now(timezone.utc))
            except ValueError as e:  # a webhook URL that is not http(s)
                return _err(str(e), 2)
            print(sched.backup_now())
            return 0
        if args.cmd == "pair":
            return _pair(conn, keys, settings)
        if args.cmd == "devices":
            return _devices(conn, args)
        return _tokens(conn, args)
    finally:
        conn.close()


def run() -> None:
    sys.exit(main())
