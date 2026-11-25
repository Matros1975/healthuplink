"""Wire encoding helpers from the data contract (length prefixes, base64, signed messages)."""

import base64
import hashlib
import hmac


def lp(x: bytes | str) -> bytes:
    """4-byte big-endian length prefix followed by the bytes (str is UTF-8)."""
    b = x.encode("utf-8") if isinstance(x, str) else bytes(x)
    return len(b).to_bytes(4, "big") + b


def u32(n: int) -> bytes:
    return int(n).to_bytes(4, "big")


def u64(n: int) -> bytes:
    return int(n).to_bytes(8, "big")


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    """Strict standard base64: alphabet only, padding required."""
    if len(s) % 4 != 0:
        raise ValueError("base64 length must be a multiple of 4")
    try:
        return base64.b64decode(s, validate=True)
    except Exception as e:  # binascii.Error, ValueError on non-ASCII
        raise ValueError(f"invalid base64: {e}") from e


def batch_aad(batch_id: str, device_id: str, key_epoch: int, seq: int, created_at: str) -> bytes:
    return lp(batch_id) + lp(device_id) + u32(key_epoch) + u64(seq) + lp(created_at)


def batch_info(device_id: str, server_pk: bytes) -> bytes:
    return b"healthuplink/v1" + lp(device_id) + server_pk


def batch_sig_msg(aad: bytes, enc: bytes, ciphertext: bytes) -> bytes:
    return b"HUv1-batch" + aad + lp(enc) + hashlib.sha256(ciphertext).digest()


def pair_proof_msg(pair_token: bytes, device_pk: bytes) -> bytes:
    return b"HUv1-pair" + lp(pair_token) + lp(device_pk)


def pair_confirm(pair_token: bytes, device_pk: bytes, server_pk: bytes) -> bytes:
    return hmac.new(pair_token, device_pk + server_pk, "sha256").digest()


def unpair_msg(device_id: str, at: str) -> bytes:
    return b"HUv1-unpair" + lp(device_id) + lp(at)


def status_msg(device_id: str, at: str) -> bytes:
    return b"HUv1-status" + lp(device_id) + lp(at)
