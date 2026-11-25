import gzip
import json
import re
import uuid
from datetime import timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from healthuplink import hpke
from healthuplink.encoding import (b64d, b64e, batch_aad, batch_info, batch_sig_msg, pair_confirm,
                                   pair_proof_msg, status_msg, unpair_msg)
from healthuplink.ingest import Ingest
from healthuplink import tokens
from healthuplink.db import connect
from healthuplink.keys import KeyStore
from test_ingest_batches import NOW, good_body, iso

UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def raw(pk):
    return pk.public_bytes(Encoding.Raw, PublicFormat.Raw)


def new_dev():
    return Ed25519PrivateKey.generate()


def pair_req(tok, dev, proof=None, proof_raw=None, proof_str=None, **over):
    if proof_raw is not None:
        proof = proof_raw
    pk = raw(dev.public_key())
    r = {"pair_token": b64e(tok), "device_signing_pk": b64e(pk), "device_name": "iPhone",
         "proof": b64e(proof if proof is not None else dev.sign(pair_proof_msg(tok, pk)))}
    if proof_str is not None:
        r["proof"] = proof_str
    r.update(over)
    return r


def unpair_req(dev, did, at):
    a = iso(at)
    return {"device_id": did, "at": a, "sig": b64e(dev.sign(unpair_msg(did, a)))}


def signed_status(dev, did, at):
    a = iso(at)
    return a, b64e(dev.sign(status_msg(did, a)))


class Env:
    def __init__(self, tmp_path):
        self.conn = connect(tmp_path / "s.db")
        self.keys = KeyStore(tmp_path)
        self.server_pk = self.keys.current().pk
        self.ingest = Ingest(self.conn, self.keys, self.now)

    def now(self):
        return NOW

    def pair_token(self, epoch=1):
        return tokens.create_pair_token(self.conn, epoch, NOW)

    def paired(self):
        dev = new_dev()
        code, out = self.ingest.pair(pair_req(self.pair_token(), dev), "ip-paired")
        assert code == 200
        return dev, out["device_id"]

    def envelope(self, seq, device, device_id, abandoned_seq=()):
        server = self.keys.current()
        body = good_body()
        if abandoned_seq:
            body["abandoned_seq"] = list(abandoned_seq)
        e = {"envelope_version": 1, "batch_id": str(uuid.uuid4()), "device_id": device_id,
             "key_epoch": server.epoch, "seq": seq, "created_at": iso(NOW - timedelta(minutes=1))}
        aad = batch_aad(e["batch_id"], device_id, e["key_epoch"], seq, e["created_at"])
        enc, ct = hpke.seal(server.pk, batch_info(device_id, server.pk), aad, gzip.compress(json.dumps(body).encode()))
        e["enc"], e["ciphertext"] = b64e(enc), b64e(ct)
        e["sig"] = b64e(device.sign(batch_sig_msg(aad, enc, ct)))
        return e


@pytest.fixture
def env(tmp_path):
    return Env(tmp_path)


def test_pair_returns_device_and_confirm(env):
    tok = env.pair_token(); dev = Ed25519PrivateKey.generate()
    code, out = env.ingest.pair(pair_req(tok, dev), "ip1")
    assert code == 200 and UUID_RE.fullmatch(out["device_id"])
    assert b64d(out["confirm"]) == pair_confirm(tok, raw(dev.public_key()), env.server_pk)
    row = env.conn.execute("SELECT name, signing_pk, paired_at, revoked_at FROM devices").fetchone()
    assert row == ("iPhone", b64e(raw(dev.public_key())), iso(NOW), None)


def test_pair_token_reuse_401(env):
    tok = env.pair_token(); env.ingest.pair(pair_req(tok, new_dev()), "ip1")
    assert env.ingest.pair(pair_req(tok, new_dev()), "ip1")[0] == 401


def test_pair_bad_proof_401_and_token_not_burned(env):
    tok = env.pair_token()
    dev = new_dev()
    assert env.ingest.pair(pair_req(tok, dev, proof=b"x" * 64), "ip1")[0] == 401
    assert env.conn.execute("SELECT count(*) FROM devices").fetchone()[0] == 0
    assert env.ingest.pair(pair_req(tok, new_dev()), "ip1")[0] == 200


def test_pair_proof_by_other_key_401(env):
    tok = env.pair_token(); dev = new_dev(); other = new_dev()
    pk = raw(dev.public_key())
    assert env.ingest.pair(pair_req(tok, dev, proof=other.sign(pair_proof_msg(tok, pk))), "ip1")[0] == 401


def test_pair_unknown_token_401(env):
    assert env.ingest.pair(pair_req(b"\x01" * 16, new_dev()), "ip1")[0] == 401


def test_pair_expired_token_401(env):
    tok = tokens.create_pair_token(env.conn, 1, NOW - timedelta(minutes=11))
    assert env.ingest.pair(pair_req(tok, new_dev()), "ip1")[0] == 401


def test_pair_rate_limit(env):
    for _ in range(5): env.ingest.pair({"pair_token": "AAAA"}, "ip1")
    assert env.ingest.pair({"pair_token": "AAAA"}, "ip1")[0] == 429


def test_pair_rate_limit_is_per_client_then_total(env):
    for i in range(20):
        assert env.ingest.pair({}, f"ip{i // 4}")[0] == 400
    assert env.ingest.pair({}, "fresh")[0] == 429


def test_pair_rate_limit_window_slides(env):
    t = [NOW]
    env.ingest.now = lambda: t[0]
    for _ in range(5): env.ingest.pair({}, "ip1")
    assert env.ingest.pair({}, "ip1")[0] == 429
    t[0] = NOW + timedelta(seconds=61)
    assert env.ingest.pair({}, "ip1")[0] == 400


@pytest.mark.parametrize("over", [
    {"pair_token": b64e(b"x" * 15)}, {"pair_token": 5}, {"device_signing_pk": b64e(b"x" * 31)},
    {"proof_raw": b"x" * 63}, {"proof_str": "!!!!"}, {"device_name": 7}, {"device_name": None},
])
def test_pair_validation_400_without_touching_token(env, over):
    tok = env.pair_token()
    assert env.ingest.pair(pair_req(tok, new_dev(), **over), "ip1")[0] == 400
    assert env.conn.execute("SELECT used_at FROM pair_tokens").fetchone()[0] is None


def test_pair_missing_field_and_non_dict_400(env):
    req = pair_req(env.pair_token(), new_dev()); del req["proof"]
    assert env.ingest.pair(req, "ip1")[0] == 400
    assert env.ingest.pair([], "ip1")[0] == 400


def test_pair_device_name_cleaned(env):
    code, _ = env.ingest.pair(pair_req(env.pair_token(), new_dev(), device_name="a\x00b\n" + "z" * 300), "ip1")
    assert code == 200
    name = env.conn.execute("SELECT name FROM devices").fetchone()[0]
    assert name.startswith("ab") and len(name) == 200 and "\x00" not in name and "\n" not in name


def test_pair_confirm_uses_token_epoch(env):
    env.keys.rotate(NOW)
    old = env.keys.get(1)
    tok = env.pair_token(epoch=1); dev = new_dev()
    code, out = env.ingest.pair(pair_req(tok, dev), "ip1")
    assert code == 200 and b64d(out["confirm"]) == pair_confirm(tok, raw(dev.public_key()), old.pk)


def test_unpair_revokes(env):
    dev, did = env.paired()
    assert env.ingest.unpair(unpair_req(dev, did, env.now())) == (200, {"status": "unpaired"})
    assert env.ingest.batch(env.envelope(1, dev, did))[0] == 401
    assert env.conn.execute("SELECT revoked_at FROM devices").fetchone()[0] == iso(NOW)


def test_unpair_twice_401(env):
    dev, did = env.paired()
    env.ingest.unpair(unpair_req(dev, did, env.now()))
    assert env.ingest.unpair(unpair_req(dev, did, env.now()))[0] == 401


def test_unpair_old_timestamp_401(env):
    dev, did = env.paired()
    assert env.ingest.unpair(unpair_req(dev, did, env.now() - timedelta(minutes=11)))[0] == 401
    assert env.ingest.unpair(unpair_req(dev, did, env.now() + timedelta(minutes=11)))[0] == 401
    assert env.ingest.unpair(unpair_req(dev, did, env.now() - timedelta(minutes=9)))[0] == 200


def test_unpair_bad_sig_and_unknown_device_401(env):
    dev, did = env.paired()
    req = unpair_req(new_dev(), did, env.now())
    assert env.ingest.unpair(req)[0] == 401
    assert env.ingest.unpair(unpair_req(dev, str(uuid.uuid4()), env.now()))[0] == 401


def test_unpair_malformed_at_401_and_bad_shape_400(env):
    dev, did = env.paired()
    req = unpair_req(dev, did, env.now()); req["at"] += "\n"
    assert env.ingest.unpair(req)[0] == 401
    assert env.ingest.unpair({"device_id": did})[0] == 400
    assert env.ingest.unpair("x")[0] == 400


def test_status_gaps_ignore_reported_seqs(env):
    dev, did = env.paired()
    for s in (1, 2, 5):
        assert env.ingest.batch(env.envelope(s, dev, did, abandoned_seq=[3] if s == 5 else []))[0] == 200
    code, st = env.ingest.status(did, *signed_status(dev, did, env.now()))
    assert code == 200 and st["high_contiguous_seq"] == 3 and st["gaps"] == [4]
    assert st["oldest_unacked_at"] is None and st["expired_seq"] == []
    assert st["last_received_at"] == iso(NOW)


def test_status_without_batches(env):
    dev, did = env.paired()
    code, st = env.ingest.status(did, *signed_status(dev, did, env.now()))
    assert code == 200 and st == {"high_contiguous_seq": 0, "last_received_at": None, "gaps": [],
                                  "oldest_unacked_at": None, "expired_seq": []}


def test_status_gap_list_is_bounded_for_huge_seq(env):
    dev, did = env.paired()
    assert env.ingest.batch(env.envelope(2 ** 40, dev, did))[0] == 200
    code, st = env.ingest.status(did, *signed_status(dev, did, env.now()))
    assert code == 200 and st["high_contiguous_seq"] == 0 and len(st["gaps"]) <= 10000


def test_status_rejects_revoked_stale_and_forged(env):
    dev, did = env.paired()
    assert env.ingest.status(did, *signed_status(dev, did, env.now() - timedelta(minutes=11)))[0] == 401
    at, _ = signed_status(dev, did, env.now())
    assert env.ingest.status(did, at, b64e(new_dev().sign(status_msg(did, at))))[0] == 401
    assert env.ingest.status(did, at, "!!!")[0] in (400, 401)
    env.ingest.unpair(unpair_req(dev, did, env.now()))
    assert env.ingest.status(did, *signed_status(dev, did, env.now()))[0] == 401


def test_status_other_device_data_not_counted(env):
    dev, did = env.paired(); dev2, did2 = env.paired()
    env.ingest.batch(env.envelope(1, dev2, did2))
    _, st = env.ingest.status(did, *signed_status(dev, did, env.now()))
    assert st["high_contiguous_seq"] == 0 and st["last_received_at"] is None


def test_trailing_newline_batch_id_400(env):
    dev, did = env.paired()
    e = env.envelope(1, dev, did); e["batch_id"] += "\n"
    assert env.ingest.batch(e)[0] == 400
    e = env.envelope(1, dev, did); e["created_at"] += "\n"
    assert env.ingest.batch(e)[0] == 400
