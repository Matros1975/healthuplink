"""Generate contract/vectors/v1.json, tls-v1.json and pairing-v1.json from fixed, test-only inputs.

Run: python tests/make_vectors.py. Deterministic: HPKE gets a fixed ephemeral key,
Ed25519 signatures are deterministic (RFC 8032), gzip uses mtime=0, the TLS certificate
has a fixed key, serial and dates and a deterministic ECDSA signature (RFC 6979).
Byte fields in v1.json are lowercase hex; in tls-v1.json and pairing-v1.json they are standard
base64, as in the pairing payload. The receiver and the iOS tests consume these files.
"""

import base64
import datetime
import gzip
import hashlib
import json
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from healthuplink import encoding as e
from healthuplink.hpke import seal

OUT = Path(__file__).resolve().parents[2] / "contract" / "vectors" / "v1.json"
TLS_OUT = OUT.parent / "tls-v1.json"
PAIRING_OUT = OUT.parent / "pairing-v1.json"

# Test-only keys. Never used in production.
SERVER_SK = bytes(range(0x01, 0x21))
DEVICE_SK = bytes(range(0x21, 0x41))
EPHEMERAL_SK = bytes(range(0x41, 0x61))
PAIR_TOKEN = bytes(range(0x61, 0x71))  # 128 bits

DEVICE_ID = "6f1d2c3a-8b4e-4f5a-9c7d-0e1f2a3b4c5d"
BATCH_ID = "01935f2e-7a10-7c3b-8d4e-5f6a7b8c9d0e"
SEQ = 7
KEY_EPOCH = 1
CREATED_AT = "2026-11-22T07:30:12Z"
AT = "2026-11-22T07:31:00Z"

BODY = {
    "body_version": 1,
    "app": {"version": "1.0", "build": "12", "os": "26.1", "model": "iPhone16,1", "low_power": False},
    "abandoned_seq": [],
    "dead_letter_seq": [],
    "samples": [
        {
            "uuid": "3f2a8c1e-5b7d-4e9f-a1c3-2d4e6f801a2b",
            "type": "HKQuantityTypeIdentifierHeartRate",
            "kind": "quantity",
            "start": "2026-11-22T03:12:00Z",
            "end": "2026-11-22T03:12:00Z",
            "value": 52,
            "unit": "count/min",
            "source": {
                "bundle": "com.apple.health.00000000-0000-4000-8000-0000000000A1",
                "name": "Apple Watch",
                "product_type": "Watch7,5",
            },
            "tz": "Europe/Amsterdam",
            "metadata": {"HKMetadataKeyHeartRateMotionContext": 1},
        },
        {
            "uuid": "9b10d4f2-3c6a-4b8e-8f1d-7a5c3e2b1f09",
            "type": "HKCategoryTypeIdentifierSleepAnalysis",
            "kind": "category",
            "start": "2026-11-22T01:40:00Z",
            "end": "2026-11-22T02:05:00Z",
            "value": 5,
            "value_label": "asleepREM",
            "source": {"bundle": "com.apple.health.00000000-0000-4000-8000-0000000000A1", "name": "Apple Watch"},
        },
    ],
}


def _x_pk(sk: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(sk).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _gzip(data: bytes) -> bytes:
    """gzip with mtime 0 and a fixed header OS byte, so the vector is the same on every platform and Python version.

    The OS byte (header offset 9) is 19 from zlib on macOS, 3 on Linux and 255 from Python 3.13's gzip.compress;
    readers ignore it. It stays 19, the value v1.json was generated with, so the committed vector does not change.
    """
    out = bytearray(gzip.compress(data, mtime=0))
    out[9] = 19
    return bytes(out)


def build() -> dict:
    server_pk = _x_pk(SERVER_SK)
    device = Ed25519PrivateKey.from_private_bytes(DEVICE_SK)
    device_pk = device.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    body_json = json.dumps(BODY, separators=(",", ":"), ensure_ascii=False)
    plaintext = _gzip(body_json.encode("utf-8"))
    aad = e.batch_aad(BATCH_ID, DEVICE_ID, KEY_EPOCH, SEQ, CREATED_AT)
    info = e.batch_info(DEVICE_ID, server_pk)
    enc, ct = seal(server_pk, info, aad, plaintext, _sk_e=EPHEMERAL_SK)
    sig_msg = e.batch_sig_msg(aad, enc, ct)
    sig = device.sign(sig_msg)

    envelope = {
        "envelope_version": 1,
        "batch_id": BATCH_ID,
        "device_id": DEVICE_ID,
        "key_epoch": KEY_EPOCH,
        "seq": SEQ,
        "created_at": CREATED_AT,
        "enc": e.b64e(enc),
        "ciphertext": e.b64e(ct),
        "sig": e.b64e(sig),
    }
    return {
        "server_sk": SERVER_SK.hex(),
        "server_pk": server_pk.hex(),
        "device_sk": DEVICE_SK.hex(),
        "device_pk": device_pk.hex(),
        "ephemeral_sk": EPHEMERAL_SK.hex(),
        "pair_token": PAIR_TOKEN.hex(),
        "device_id": DEVICE_ID,
        "batch_id": BATCH_ID,
        "seq": SEQ,
        "key_epoch": KEY_EPOCH,
        "created_at": CREATED_AT,
        "at": AT,
        "body_json": body_json,
        "pair_proof_msg": e.pair_proof_msg(PAIR_TOKEN, device_pk).hex(),
        "pair_confirm": e.pair_confirm(PAIR_TOKEN, device_pk, server_pk).hex(),
        "info": info.hex(),
        "aad": aad.hex(),
        "enc": enc.hex(),
        "ciphertext": ct.hex(),
        "ciphertext_sha256": hashlib.sha256(ct).hexdigest(),
        "sig_msg": sig_msg.hex(),
        "sig": sig.hex(),
        "envelope": envelope,
        "unpair_msg": e.unpair_msg(DEVICE_ID, AT).hex(),
        "status_msg": e.status_msg(DEVICE_ID, AT).hex(),
    }


# --- TLS pin vector (contract section 2, `tls_sha256`) ---

P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
TLS_KEY = ec.derive_private_key(
    int.from_bytes(hashlib.sha256(b"healthuplink tls vector").digest(), "big") % P256_ORDER, ec.SECP256R1()
)
TLS_SERIAL = 0x4855_7631  # "HUv1"
TLS_NOT_BEFORE = datetime.datetime(2026, 11, 24, tzinfo=datetime.timezone.utc)
TLS_NOT_AFTER = TLS_NOT_BEFORE + datetime.timedelta(days=3650)


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _tls_cert() -> x509.Certificate:
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "healthuplink-vector")])
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(TLS_KEY.public_key())
        .serial_number(TLS_SERIAL)
        .not_valid_before(TLS_NOT_BEFORE)
        .not_valid_after(TLS_NOT_AFTER)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("mac.local")]), critical=False)
        .sign(TLS_KEY, hashes.SHA256(), ecdsa_deterministic=True)
    )


def build_tls() -> dict:
    cert = _tls_cert()
    pk = TLS_KEY.public_key()
    spki = pk.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return {
        "cert_der": _b64(cert.public_bytes(Encoding.DER)),
        "spki_der": _b64(spki),
        "p256_uncompressed": _b64(pk.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)),
        "tls_sha256": _b64(hashlib.sha256(spki).digest()),
    }


# --- Pairing payload cases (contract section 2, URL rules and `tls_sha256`) ---

_ABSENT = object()


def _case(name: str, url: str, expect: str, pin: object = _ABSENT, note: str | None = None, **overrides) -> dict:
    """One pairing case. `overrides` replace payload fields; a value of _ABSENT drops the field."""
    payload = {
        "v": 1,
        "mode": "direct",
        "url": url,
        "server_pk": _b64(_x_pk(SERVER_SK)),
        "key_epoch": KEY_EPOCH,
        "pair_token": _b64(PAIR_TOKEN),
    }
    if pin is not _ABSENT:
        payload["tls_sha256"] = pin
    for key, value in overrides.items():
        if value is _ABSENT:
            payload.pop(key, None)
        else:
            payload[key] = value
    case = {
        "name": name,
        "url": url,
        "tls_sha256": None if pin is _ABSENT else pin,
        "payload": json.dumps(payload),
        "expect": expect,
    }
    if note:
        case["note"] = note
    return case


def build_pairing() -> dict:
    pin = build_tls()["tls_sha256"]
    return {
        "cases": [
            # Plain http: IPv4 literals in 100.64.0.0/10 only.
            _case("http_tailnet", "http://100.100.1.1:8796", "ok"),
            _case("http_tailnet_lowest", "http://100.64.0.1", "ok", note="first address of 100.64.0.0/10, no port"),
            _case("http_above_tailnet", "http://100.128.0.1", "needs_https", note="first address after 100.64.0.0/10"),
            _case("http_lan_ip", "http://192.168.1.10:8796", "needs_https"),
            _case("http_local_name", "http://mac.local:8796", "needs_https"),
            _case("http_unqualified_name", "http://mac:8796", "needs_https", note="only tailnet IPv4 literals may use http"),
            _case(
                "http_ipv6_tailnet",
                "http://[fd7a:115c:a1e0::1]:8796",
                "needs_https",
                note="Tailscale's IPv6 range does not count: plain http is allowed for IPv4 literals in 100.64.0.0/10 only",
            ),
            _case("http_leading_zero", "http://0100.100.1.1", "needs_https", note="an octet with a leading zero is not a dotted-quad literal"),
            # https with and without a pin.
            _case("https_local_name_pin", "https://mac.local:8796", "ok", pin),
            _case("https_lan_ip_pin", "https://192.168.1.10:8796", "ok", pin),
            _case("https_tailnet_pin", "https://100.100.1.1:8796", "ok", pin),
            _case(
                "https_unqualified_name_pin",
                "https://mac:8796",
                "ok",
                pin,
                note="an unqualified name (no dot) counts as a local name, so a pin is allowed",
            ),
            _case("https_lan_ip_no_pin", "https://192.168.1.10:8796", "ok", note="https without a pin needs a CA-valid certificate at connect time"),
            _case("https_public_name_no_pin", "https://health.example.com", "ok"),
            _case(
                "https_public_name_pin",
                "https://health.example.com",
                "pin_needs_local_host",
                pin,
                note="iOS does not let an app loosen server trust for a public DNS name; use a CA-valid certificate and no pin",
            ),
            _case(
                "https_ipv6_pin",
                "https://[fd00::10]:8796",
                "pin_needs_local_host",
                pin,
                note="in v1 the IP literals that may carry a pin are IPv4 dotted quads only; an IPv6 literal with a pin is refused like a public name",
            ),
            _case("http_tailnet_pin", "http://100.100.1.1:8796", "needs_https", pin, note="a pin requires https, even on the tailnet"),
            _case("https_tailnet_name", "https://x.tail1234.ts.net", "tailnet_name", note="the iPhone cannot resolve *.ts.net"),
            _case(
                "http_tailnet_name",
                "http://x.tail1234.ts.net",
                "tailnet_name",
                note="two faults (a *.ts.net name and plain http): the name is checked first, since the iPhone cannot resolve it either way",
            ),
            # Malformed pins.
            _case("pin_31_bytes", "https://192.168.1.10:8796", "bad_pin", _b64(bytes(range(31)))),
            _case("pin_not_base64", "https://192.168.1.10:8796", "bad_pin", "not base64!"),
            _case("pin_number", "https://192.168.1.10:8796", "bad_pin", 12345, note="tls_sha256 is a JSON number, not a string"),
            # Other payload faults.
            _case("version_2", "http://100.100.1.1:8796", "unsupported_version", v=2),
            _case("mode_mailbox", "http://100.100.1.1:8796", "unsupported_mode", mode="mailbox"),
            _case("missing_pair_token", "http://100.100.1.1:8796", "bad_payload", pair_token=_ABSENT),
        ]
    }


def _write(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
    print(f"wrote {path}")


if __name__ == "__main__":
    _write(OUT, build())
    _write(TLS_OUT, build_tls())
    _write(PAIRING_OUT, build_pairing())
