import hashlib
import hmac

import pytest

from healthuplink.encoding import (
    b64d,
    batch_aad,
    batch_info,
    batch_sig_msg,
    lp,
    pair_confirm,
    pair_proof_msg,
    status_msg,
    unpair_msg,
)


def test_lp_prefixes_big_endian_length():
    assert lp(b"ab") == b"\x00\x00\x00\x02ab"
    assert lp("é") == b"\x00\x00\x00\x02\xc3\xa9"


def test_aad_layout():
    aad = batch_aad("b1", "d1", 1, 1842, "2026-11-22T07:30:12Z")
    assert aad == lp("b1") + lp("d1") + (1).to_bytes(4, "big") + (1842).to_bytes(8, "big") + lp("2026-11-22T07:30:12Z")


def test_info_and_sig_msg():
    assert batch_info("d1", b"K" * 32) == b"healthuplink/v1" + lp("d1") + b"K" * 32
    m = batch_sig_msg(b"AAD", b"E" * 32, b"ct")
    assert m == b"HUv1-batch" + b"AAD" + lp(b"E" * 32) + hashlib.sha256(b"ct").digest()


def test_pair_messages():
    t, d, s = b"T" * 16, b"D" * 32, b"S" * 32
    assert pair_proof_msg(t, d) == b"HUv1-pair" + lp(t) + lp(d)
    assert pair_confirm(t, d, s) == hmac.new(t, d + s, "sha256").digest()
    assert unpair_msg("d1", "2026-11-22T07:30:12Z") == b"HUv1-unpair" + lp("d1") + lp("2026-11-22T07:30:12Z")
    assert status_msg("d1", "x") == b"HUv1-status" + lp("d1") + lp("x")


def test_b64d_is_strict():
    assert b64d("YWI=") == b"ab"
    for bad in ("YWI", "YW I=", "YWI=!"):
        with pytest.raises(ValueError):
            b64d(bad)
