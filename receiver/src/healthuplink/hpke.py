"""RFC 9180 HPKE base mode, single-shot, sequence number 0, with AAD.

Suite: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305.
`cryptography`'s hpke module has no AAD parameter, hence this module.
"""

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

KEM_SUITE_ID = b"KEM" + (0x0020).to_bytes(2, "big")
HPKE_SUITE_ID = b"HPKE" + (0x0020).to_bytes(2, "big") + (0x0001).to_bytes(2, "big") + (0x0003).to_bytes(2, "big")
NK = 32
NN = 12
NH = 32
MODE_BASE = 0


class HPKEError(Exception):
    pass


def _hmac(key: bytes, data: bytes) -> bytes:
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()


def _labeled_extract(suite_id: bytes, salt: bytes, label: bytes, ikm: bytes) -> bytes:
    return _hmac(salt or bytes(NH), b"HPKE-v1" + suite_id + label + ikm)


def _labeled_expand(suite_id: bytes, prk: bytes, label: bytes, info: bytes, length: int) -> bytes:
    labeled = length.to_bytes(2, "big") + b"HPKE-v1" + suite_id + label + info
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = _hmac(prk, t + labeled + bytes([i]))
        out += t
        i += 1
    return out[:length]


def _pub(sk: X25519PrivateKey) -> bytes:
    return sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _dh(sk: X25519PrivateKey, pk_raw: bytes) -> bytes:
    try:
        return sk.exchange(X25519PublicKey.from_public_bytes(pk_raw))
    except ValueError as e:
        raise HPKEError("bad key or low-order point") from e


def _extract_and_expand(dh: bytes, kem_context: bytes) -> bytes:
    eae_prk = _labeled_extract(KEM_SUITE_ID, b"", b"eae_prk", dh)
    return _labeled_expand(KEM_SUITE_ID, eae_prk, b"shared_secret", kem_context, NH)


def _key_schedule(shared_secret: bytes, info: bytes) -> tuple[bytes, bytes]:
    psk_id_hash = _labeled_extract(HPKE_SUITE_ID, b"", b"psk_id_hash", b"")
    info_hash = _labeled_extract(HPKE_SUITE_ID, b"", b"info_hash", info)
    context = bytes([MODE_BASE]) + psk_id_hash + info_hash
    secret = _labeled_extract(HPKE_SUITE_ID, shared_secret, b"secret", b"")
    key = _labeled_expand(HPKE_SUITE_ID, secret, b"key", context, NK)
    base_nonce = _labeled_expand(HPKE_SUITE_ID, secret, b"base_nonce", context, NN)
    return key, base_nonce


def seal(
    pk_r: bytes, info: bytes, aad: bytes, pt: bytes, *, _sk_e: bytes | None = None
) -> tuple[bytes, bytes]:
    """Return (enc, ciphertext). `_sk_e` fixes the ephemeral key, for test vectors only."""
    try:
        sk_e = X25519PrivateKey.from_private_bytes(_sk_e) if _sk_e else X25519PrivateKey.generate()
    except ValueError as e:
        raise HPKEError("bad ephemeral key") from e
    enc = _pub(sk_e)
    shared = _extract_and_expand(_dh(sk_e, pk_r), enc + pk_r)
    key, nonce = _key_schedule(shared, info)
    return enc, ChaCha20Poly1305(key).encrypt(nonce, pt, aad)


def open_(sk_r: bytes, enc: bytes, info: bytes, aad: bytes, ct: bytes) -> bytes:
    try:
        sk = X25519PrivateKey.from_private_bytes(sk_r)
    except ValueError as e:
        raise HPKEError("bad private key") from e
    shared = _extract_and_expand(_dh(sk, enc), enc + _pub(sk))
    key, nonce = _key_schedule(shared, info)
    try:
        return ChaCha20Poly1305(key).decrypt(nonce, ct, aad)
    except InvalidTag as e:
        raise HPKEError("decryption failed") from e
