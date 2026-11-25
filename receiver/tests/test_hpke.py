import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hpke
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from healthuplink.hpke import HPKEError, open_, seal


def load(name):
    raw = json.loads((Path(__file__).parent / "vectors" / name).read_text())
    return {k: bytes.fromhex(v) for k, v in raw.items()}


def raw_pk(k):
    return k.public_bytes(Encoding.Raw, PublicFormat.Raw)


def raw_sk(k):
    return k.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


def test_rfc9180_a2_1_open():
    v = load("rfc9180_a2_1.json")
    assert open_(v["skRm"], v["enc"], v["info"], v["aad"], v["ct"]) == v["pt"]


def test_rfc9180_a2_1_seal_with_fixed_ephemeral():
    v = load("rfc9180_a2_1.json")
    assert seal(v["pkRm"], v["info"], v["aad"], v["pt"], _sk_e=v["skEm"]) == (v["enc"], v["ct"])


def test_interop_with_cryptography_suite_empty_aad():
    suite = hpke.Suite(hpke.KEM.X25519, hpke.KDF.HKDF_SHA256, hpke.AEAD.CHACHA20_POLY1305)
    sk = X25519PrivateKey.generate()
    pk = raw_pk(sk.public_key())
    out = suite.encrypt(b"hello", sk.public_key(), info=b"i")
    assert open_(raw_sk(sk), out[:32], b"i", b"", out[32:]) == b"hello"
    enc, ct = seal(pk, b"i", b"", b"world")
    assert suite.decrypt(enc + ct, sk, info=b"i") == b"world"


def test_wrong_aad_fails():
    sk = X25519PrivateKey.generate()
    enc, ct = seal(raw_pk(sk.public_key()), b"i", b"aad1", b"x")
    with pytest.raises(HPKEError):
        open_(raw_sk(sk), enc, b"i", b"aad2", ct)
