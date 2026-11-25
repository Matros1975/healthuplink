import gzip
import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from healthuplink import hpke
from healthuplink.db import connect
from healthuplink.encoding import b64d, b64e, batch_aad, batch_info, batch_sig_msg
from healthuplink.ingest import Ingest
from healthuplink.keys import KeyStore

NOW = datetime(2026, 11, 22, 12, 0, 0, tzinfo=timezone.utc)
HR = "HKQuantityTypeIdentifierHeartRate"
U1 = "3f2a0000-0000-4000-8000-000000000001"


def iso(t):
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def good_body(**kw):
    b = {"body_version": 1, "app": {"version": "1"}, "samples": [{
        "uuid": U1, "type": HR, "kind": "quantity", "start": "2026-11-22T03:12:00Z",
        "end": "2026-11-22T03:12:00Z", "value": 50, "unit": "count/min",
        "source": {"bundle": "com.apple.health.ABC", "name": "Watch", "product_type": "Watch7,5"}}]}
    b.update(kw)
    return b


def other_body():
    return good_body(app={"version": "2"})


class Env:
    def __init__(self, tmp_path):
        self.conn = connect(tmp_path / "s.db")
        self.keys = KeyStore(tmp_path)
        self.server = self.keys.current()
        self.sk = Ed25519PrivateKey.generate()
        self.pk = self.sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.device_id = str(uuid.uuid4())
        self.conn.execute("INSERT INTO devices(device_id, name, signing_pk, paired_at) VALUES (?,?,?,?)",
                          (self.device_id, "phone", b64e(self.pk), iso(NOW)))
        self.ingest = Ingest(self.conn, self.keys, self.now)

    def now(self):
        return NOW

    def revoke(self):
        self.conn.execute("UPDATE devices SET revoked_at=?", (iso(NOW),))

    def resign(self, e):
        aad = batch_aad(e["batch_id"], e["device_id"], e["key_epoch"], e["seq"], e["created_at"])
        e["sig"] = b64e(self.sk.sign(batch_sig_msg(aad, b64d(e["enc"]), b64d(e["ciphertext"]))))

    def envelope(self, seq, body=None, raw_plaintext=None, **over):
        e = {"envelope_version": 1, "batch_id": str(uuid.uuid4()), "device_id": self.device_id,
             "key_epoch": 1, "seq": seq, "created_at": iso(NOW - timedelta(minutes=1))}
        e.update({k: v for k, v in over.items() if k in e})
        pt = raw_plaintext if raw_plaintext is not None else gzip.compress(
            json.dumps(good_body() if body is None else body).encode())
        aad = batch_aad(e["batch_id"], e["device_id"], e["key_epoch"], e["seq"], e["created_at"])
        enc, ct = hpke.seal(self.server.pk, batch_info(e["device_id"], self.server.pk), aad, pt)
        e["enc"], e["ciphertext"] = b64e(enc), b64e(ct)
        self.resign(e)
        return e


@pytest.fixture
def env(tmp_path):
    return Env(tmp_path)


def test_stores_valid_batch(env):
    assert env.ingest.batch(env.envelope(seq=1)) == (200, {"status": "stored"})
    assert env.conn.execute("SELECT count(*) FROM samples").fetchone()[0] == 1


def test_same_batch_twice_is_duplicate(env):
    e = env.envelope(seq=1)
    env.ingest.batch(e)
    assert env.ingest.batch(e) == (200, {"status": "duplicate"})


def test_same_batch_id_other_ciphertext_is_409(env):
    e1 = env.envelope(seq=1)
    env.ingest.batch(e1)
    e2 = env.envelope(seq=1, batch_id=e1["batch_id"], body=other_body())
    assert env.ingest.batch(e2) == (409, {"error": "conflict"})


def test_seq_changed_after_signing_is_401(env):
    e = env.envelope(seq=1)
    e["seq"] = 2
    assert env.ingest.batch(e) == (401, {"error": "unauthorized"})


def test_resigned_with_other_seq_fails_decrypt(env):
    e = env.envelope(seq=1)
    e["seq"] = 2
    env.resign(e)
    assert env.ingest.batch(e) == (422, {"error": "decrypt_failed"})


def test_revoked_device_401(env):
    env.revoke()
    assert env.ingest.batch(env.envelope(seq=1))[0] == 401


def test_unknown_device_401(env):
    e = env.envelope(seq=1)
    e["device_id"] = str(uuid.uuid4())
    assert env.ingest.batch(e)[0] == 401


def test_unknown_epoch_422(env):
    assert env.ingest.batch(env.envelope(seq=1, key_epoch=9)) == (422, {"error": "decrypt_failed"})


def test_envelope_v2_426(env):
    assert env.ingest.batch(env.envelope(seq=1, envelope_version=2)) == (
        426, {"error": "upgrade_required", "supported": {"envelope": [1], "body": [1]}})


def test_body_v2_426(env):
    assert env.ingest.batch(env.envelope(seq=1, body={"body_version": 2}))[0] == 426


def test_gzip_bomb_413(env):
    e = env.envelope(seq=1, raw_plaintext=gzip.compress(b"0" * (17 << 20)))
    assert env.ingest.batch(e) == (413, {"error": "too_large"})


def test_ciphertext_over_1mib_413(env):
    import os
    e = env.envelope(seq=1, raw_plaintext=os.urandom(1 << 20))
    assert env.ingest.batch(e)[0] == 413


def test_future_created_at_stored_and_flagged(env):
    e = env.envelope(seq=1, created_at=iso(NOW + timedelta(days=2)))
    assert env.ingest.batch(e)[0] == 200
    flags = json.loads(env.conn.execute("SELECT flags FROM batches").fetchone()[0])
    assert flags["created_at_out_of_range"] is True
    assert flags["low_power"] is False


def test_in_range_created_at_not_flagged(env):
    env.ingest.batch(env.envelope(seq=1))
    flags = json.loads(env.conn.execute("SELECT flags FROM batches").fetchone()[0])
    assert flags["created_at_out_of_range"] is False


def test_old_created_at_flagged(env):
    env.ingest.batch(env.envelope(seq=1, created_at=iso(NOW - timedelta(days=401))))
    flags = json.loads(env.conn.execute("SELECT flags FROM batches").fetchone()[0])
    assert flags["created_at_out_of_range"] is True


def test_low_power_flag_from_app(env):
    env.ingest.batch(env.envelope(seq=1, body=good_body(app={"low_power": True})))
    flags = json.loads(env.conn.execute("SELECT flags FROM batches").fetchone()[0])
    assert flags["low_power"] is True


def test_unparseable_created_at_400(env):
    assert env.ingest.batch(env.envelope(seq=1, created_at="yesterday")) == (400, {"error": "bad_request"})


@pytest.mark.parametrize("field", ["batch_id", "device_id", "key_epoch", "seq", "created_at", "enc", "ciphertext", "sig"])
def test_missing_field_400(env, field):
    e = env.envelope(seq=1)
    del e[field]
    assert env.ingest.batch(e) == (400, {"error": "bad_request"})


def test_bad_base64_400(env):
    e = env.envelope(seq=1)
    e["sig"] = "!!!"
    assert env.ingest.batch(e)[0] == 400


def test_bool_seq_400(env):
    e = env.envelope(seq=1)
    e["seq"] = True
    assert env.ingest.batch(e)[0] == 400


def test_bad_gzip_422(env):
    assert env.ingest.batch(env.envelope(seq=1, raw_plaintext=b"not gzip")) == (422, {"error": "decrypt_failed"})


def test_invalid_body_422(env):
    s = good_body()["samples"][0]
    s["value"] = "x"
    code, resp = env.ingest.batch(env.envelope(seq=1, body=good_body(samples=[s])))
    assert code == 422 and resp["error"] == "invalid_body" and resp["reason"]


def test_too_many_items_413(env):
    s = good_body()["samples"][0]
    assert env.ingest.batch(env.envelope(seq=1, body=good_body(samples=[s] * 10_001)))[0] == 413


def test_callback_called_after_store(env):
    seen = []
    env.ingest.on_stored.append(lambda bid: seen.append((bid, env.conn.execute("SELECT count(*) FROM batches").fetchone()[0])))
    e = env.envelope(seq=1)
    env.ingest.batch(e)
    assert seen == [(e["batch_id"], 1)]


def test_callback_failure_does_not_change_response(env):
    env.ingest.on_stored.append(lambda _: 1 / 0)
    assert env.ingest.batch(env.envelope(seq=1))[0] == 200


def test_duplicate_does_not_call_callback(env):
    seen = []
    env.ingest.on_stored.append(seen.append)
    e = env.envelope(seq=1)
    env.ingest.batch(e)
    env.ingest.batch(e)
    assert len(seen) == 1


def test_surrogate_batch_id_400(env):
    e = env.envelope(seq=1)
    e["batch_id"] = "\ud800"
    assert env.ingest.batch(e) == (400, {"error": "bad_request"})


def test_surrogate_device_id_400(env):
    e = env.envelope(seq=1)
    e["device_id"] = "\ud800"
    assert env.ingest.batch(e) == (400, {"error": "bad_request"})


def test_huge_batch_id_400(env):
    assert env.ingest.batch(env.envelope(seq=1, batch_id="a" * 5000))[0] == 400


def test_uppercase_uuid_batch_id_400(env):
    assert env.ingest.batch(env.envelope(seq=1, batch_id=str(uuid.uuid4()).upper()))[0] == 400


@pytest.mark.parametrize("v", [True, 1.0])
def test_body_version_must_be_int_1(env, v):
    assert env.ingest.batch(env.envelope(seq=1, body=good_body(body_version=v)))[0] == 426


def test_seq_zero_400(env):
    assert env.ingest.batch(env.envelope(seq=0)) == (400, {"error": "bad_request"})


def test_created_at_with_offset_400(env):
    assert env.ingest.batch(env.envelope(seq=1, created_at="2026-11-22T12:00:00+01:00"))[0] == 400
