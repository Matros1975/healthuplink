import pytest
from starlette.testclient import TestClient

from healthuplink.app import build_app
from healthuplink.config import Settings
from healthuplink.db import connect
from test_ingest_batches import Env

LIMIT = 1_572_864


@pytest.fixture
def env(tmp_path):
    return Env(tmp_path)


@pytest.fixture
def client(tmp_path, env):
    # Env's own connection only seeds the paired device; the app opens its own store connection.
    app = build_app(Settings(data_dir=str(tmp_path)), lambda: connect(tmp_path / "s.db"), env.keys, None, now=env.now)
    with TestClient(app) as c:
        yield c


def test_batch_roundtrip(client, env):
    r = client.post("/v1/batches", json=env.envelope(seq=1))
    assert r.status_code == 200 and r.json() == {"status": "stored"}


def test_body_over_limit_413_without_reading_all(client):
    r = client.post("/v1/batches", content=b"x" * (LIMIT + 1), headers={"content-type": "application/json"})
    assert r.status_code == 413


def test_content_length_over_limit_413_before_reading(client):
    r = client.post("/v1/batches", content=b"{}", headers={"content-length": str(LIMIT + 1)})
    assert r.status_code == 413


def test_chunked_stream_over_limit_413(client):
    def gen():
        for _ in range(3):
            yield b"x" * (LIMIT // 2)
    assert client.post("/v1/batches", content=gen()).status_code == 413


def test_not_json_400(client):
    r = client.post("/v1/batches", content=b"{")
    assert r.status_code == 400 and r.json() == {"error": "bad_request"}


def test_json_not_object_400(client):
    assert client.post("/v1/batches", content=b"[1]").status_code == 400


def test_status_needs_signature_headers(client):
    r = client.get("/v1/status")
    assert r.status_code == 401 and r.json() == {"error": "unauthorized"}


def test_status_bad_signature_goes_to_ingest(client, env):
    r = client.get("/v1/status", headers={"X-HU-Device": env.device_id, "X-HU-At": "2026-11-22T12:00:00Z", "X-HU-Sig": "AAAA"})
    assert r.status_code == 401


def test_pair_bad_request_400(client):
    assert client.post("/v1/pair", content=b"nope").status_code == 400


def test_unpair_bad_request_400(client):
    assert client.post("/v1/unpair", content=b"nope").status_code == 400


def test_healthz(client):
    assert client.get("/healthz").json() == {"ok": True}


def test_unknown_path_404_json(client):
    r = client.get("/nope")
    assert r.status_code == 404 and r.headers["content-type"].startswith("application/json")
    assert r.json() == {"error": "not_found"}


def test_wrong_method_405_json(client):
    r = client.get("/v1/batches")
    assert r.status_code == 405 and r.json() == {"error": "method_not_allowed"}


def test_unexpected_exception_500_json(tmp_path, env):
    app = build_app(Settings(data_dir=str(tmp_path)), lambda: connect(tmp_path / "s.db"), env.keys, None)
    with TestClient(app, raise_server_exceptions=False) as c:
        import healthuplink.ingest as ing
        orig = ing.Ingest.batch
        ing.Ingest.batch = lambda self, e: 1 / 0
        try:
            r = c.post("/v1/batches", json={"a": 1})
        finally:
            ing.Ingest.batch = orig
    assert r.status_code == 500 and r.json() == {"error": "internal"}


def test_ingest_calls_run_on_one_worker_thread(tmp_path, env):
    import threading
    import healthuplink.ingest as ing
    seen = set()
    orig = ing.Ingest.status
    def spy(self, *a):
        seen.add(threading.get_ident())
        return orig(self, *a)
    ing.Ingest.status = spy
    try:
        app = build_app(Settings(data_dir=str(tmp_path)), lambda: connect(tmp_path / "s.db"), env.keys, None)
        with TestClient(app) as c:
            for _ in range(3):
                c.get("/v1/status", headers={"X-HU-Device": "d", "X-HU-At": "a", "X-HU-Sig": "s"})
    finally:
        ing.Ingest.status = orig
    assert len(seen) == 1 and threading.get_ident() not in seen


# ---------------------------------------------------------------- response shapes on /v1/*

KNOWN_ERRORS = {"bad_request", "unauthorized", "conflict", "decrypt_failed", "invalid_body", "too_large",
                "rate_limited", "upgrade_required", "not_found", "method_not_allowed", "internal"}


def _assert_error(r, status, code):
    assert r.status_code == status
    assert r.headers["content-type"].startswith("application/json")
    body = r.json()
    assert body["error"] == code
    assert code in KNOWN_ERRORS


@pytest.mark.parametrize("kw", [
    {"content": b"x" * (LIMIT + 1), "headers": {"content-type": "application/json"}},
    {"content": b"{}", "headers": {"content-length": str(LIMIT + 1)}},
])
@pytest.mark.parametrize("path", ["/v1/batches", "/v1/pair", "/v1/unpair"])
def test_every_413_is_too_large(client, path, kw):
    _assert_error(client.post(path, **kw), 413, "too_large")


def test_413_from_ingest_is_too_large(client, env):
    import gzip
    r = client.post("/v1/batches", json=env.envelope(seq=1, raw_plaintext=gzip.compress(b"0" * (17 << 20))))
    _assert_error(r, 413, "too_large")


def test_426_carries_upgrade_required(client, env):
    r = client.post("/v1/batches", json=env.envelope(seq=1, envelope_version=2))
    _assert_error(r, 426, "upgrade_required")
    assert r.json()["supported"] == {"envelope": [1], "body": [1]}


def test_batch_error_shapes(client, env):
    import uuid as _uuid
    _assert_error(client.post("/v1/batches", content=b"{"), 400, "bad_request")
    _assert_error(client.post("/v1/batches", json={"a": 1}), 400, "bad_request")
    e = env.envelope(seq=1)
    e["device_id"] = str(_uuid.uuid4())
    _assert_error(client.post("/v1/batches", json=e), 401, "unauthorized")
    _assert_error(client.post("/v1/batches", json=env.envelope(seq=1, key_epoch=9)), 422, "decrypt_failed")
    _assert_error(client.post("/v1/batches", json=env.envelope(seq=1, body={"body_version": 1, "samples": 3})),
                  422, "invalid_body")
    first = env.envelope(seq=2)
    assert client.post("/v1/batches", json=first).json() == {"status": "stored"}
    assert client.post("/v1/batches", json=first).json() == {"status": "duplicate"}
    from test_ingest_batches import other_body
    _assert_error(client.post("/v1/batches", json=env.envelope(seq=2, batch_id=first["batch_id"], body=other_body())),
                  409, "conflict")
    _assert_error(client.get("/v1/batches"), 405, "method_not_allowed")
    _assert_error(client.get("/v1/nope"), 404, "not_found")


def test_pair_rate_limited_shape(client):
    codes = [client.post("/v1/pair", json={"pair_token": "x"}) for _ in range(6)]
    _assert_error(codes[-1], 429, "rate_limited")
    for r in codes[:-1]:
        _assert_error(r, 400, "bad_request")
