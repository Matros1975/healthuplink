import gzip
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

import make_vectors
from healthuplink import encoding as enc_
from healthuplink.hpke import open_

VECTORS = Path(__file__).resolve().parents[2] / "contract" / "vectors" / "v1.json"


def test_vectors_file_matches_generator_and_verifies():
    v = json.loads(VECTORS.read_text())
    assert v == make_vectors.build(), "contract/vectors/v1.json drifted; rerun tests/make_vectors.py"

    h = {k: bytes.fromhex(x) for k, x in v.items() if isinstance(x, str) and k not in ("body_json", "device_id", "batch_id", "created_at", "at")}
    assert len(h["pair_token"]) == 16
    assert h["pair_proof_msg"][len(b"HUv1-pair"):][:4] == bytes.fromhex("00000010")
    assert "00000000-0000-4000-8000-0000000000A1" in v["body_json"]
    env = v["envelope"]
    aad = enc_.batch_aad(v["batch_id"], v["device_id"], 1, 7, v["created_at"])
    info = enc_.batch_info(v["device_id"], h["server_pk"])
    assert aad == h["aad"] and info == h["info"]
    assert enc_.b64d(env["enc"]) == h["enc"] and enc_.b64d(env["ciphertext"]) == h["ciphertext"]
    assert enc_.b64d(env["sig"]) == h["sig"]
    sig_msg = enc_.batch_sig_msg(aad, h["enc"], h["ciphertext"])
    assert sig_msg == h["sig_msg"]
    Ed25519PublicKey.from_public_bytes(h["device_pk"]).verify(h["sig"], sig_msg)
    assert Ed25519PrivateKey.from_private_bytes(h["device_sk"]).sign(sig_msg) == h["sig"]

    plain = open_(h["server_sk"], h["enc"], info, aad, h["ciphertext"])
    assert gzip.decompress(plain).decode() == v["body_json"]
    assert json.loads(v["body_json"])["body_version"] == 1
    assert hashlib.sha256(h["ciphertext"]).hexdigest() == v["ciphertext_sha256"]

    assert h["pair_proof_msg"] == enc_.pair_proof_msg(h["pair_token"], h["device_pk"])
    assert h["pair_confirm"] == enc_.pair_confirm(h["pair_token"], h["device_pk"], h["server_pk"])
    assert h["unpair_msg"] == enc_.unpair_msg(v["device_id"], v["at"])
    assert h["status_msg"] == enc_.status_msg(v["device_id"], v["at"])


def test_ios_sealed_vector_opens():
    v = json.loads((VECTORS.parent / "ios-v1.json").read_text())
    base = json.loads(VECTORS.read_text())
    e = v["envelope"]
    aad = enc_.batch_aad(e["batch_id"], e["device_id"], e["key_epoch"], e["seq"], e["created_at"])
    enc, ct = enc_.b64d(e["enc"]), enc_.b64d(e["ciphertext"])
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(v["device_pk"])).verify(enc_.b64d(e["sig"]), enc_.batch_sig_msg(aad, enc, ct))
    pt = open_(bytes.fromhex(base["server_sk"]), enc, enc_.batch_info(e["device_id"], bytes.fromhex(v["server_pk"])), aad, ct)
    assert gzip.decompress(pt) == v["body_json"].encode()
