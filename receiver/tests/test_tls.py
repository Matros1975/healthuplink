import base64
import ipaddress
import json
import os
import stat
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from healthuplink import tls
from healthuplink.config import Settings

VECTORS = Path(__file__).resolve().parents[2] / "contract" / "vectors"


def _san(cert_path: Path) -> tuple[list[str], list[str]]:
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    return san.get_values_for_type(x509.DNSName), [str(i) for i in san.get_values_for_type(x509.IPAddress)]


def test_spki_sha256_matches_vector():
    v = json.loads((VECTORS / "tls-v1.json").read_text())
    body = "\n".join(v["cert_der"][i : i + 64] for i in range(0, len(v["cert_der"]), 64))
    pem = f"-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n".encode()
    assert tls.spki_sha256(pem) == v["tls_sha256"]


def test_self_signed_is_p256_reused_and_private(tmp_path):
    cert, key = tls.ensure_self_signed(tmp_path, ["192.168.1.10", "mac.local"])
    assert (cert, key) == (tmp_path / "tls" / "cert.pem", tmp_path / "tls" / "key.pem")
    assert stat.S_IMODE(os.stat(tmp_path / "tls").st_mode) == 0o700
    for p in (cert, key):
        assert stat.S_IMODE(os.stat(p).st_mode) == 0o600
    first = (cert.read_bytes(), key.read_bytes())
    assert tls.ensure_self_signed(tmp_path, ["192.168.1.10", "mac.local"]) == (cert, key)
    assert (cert.read_bytes(), key.read_bytes()) == first
    k = load_pem_private_key(key.read_bytes(), None)
    assert isinstance(k, ec.EllipticCurvePrivateKey) and k.curve.name == "secp256r1"
    dns, ips = _san(cert)
    assert "mac.local" in dns and "localhost" in dns and "192.168.1.10" not in dns
    assert "192.168.1.10" in ips and "127.0.0.1" in ips
    c = x509.load_pem_x509_certificate(cert.read_bytes())
    assert (c.not_valid_after_utc - c.not_valid_before_utc).days == 3650
    c.verify_directly_issued_by(c)


def test_new_host_reissues_with_same_key(tmp_path):
    cert, key = tls.ensure_self_signed(tmp_path, ["192.168.1.10"])
    old_cert, old_key = cert.read_bytes(), key.read_bytes()
    pin = tls.spki_sha256(old_cert)
    tls.ensure_self_signed(tmp_path, ["192.168.1.10", "mac.local"])
    assert cert.read_bytes() != old_cert
    assert key.read_bytes() == old_key
    assert tls.spki_sha256(cert.read_bytes()) == pin
    assert "mac.local" in _san(cert)[0]
    assert stat.S_IMODE(os.stat(cert).st_mode) == 0o600


def test_ip_hosts_are_normalised(tmp_path):
    cert, _ = tls.ensure_self_signed(tmp_path, ["fd00::10", "Mac.Local."])
    dns, ips = _san(cert)
    assert "mac.local" in dns and ipaddress.ip_address("fd00::10") in map(ipaddress.ip_address, ips)


def test_cert_paths(tmp_path):
    assert tls.cert_paths(Settings(data_dir=str(tmp_path))) is None
    assert tls.cert_paths(Settings(data_dir=str(tmp_path), tls="self-signed")) == (
        tmp_path / "tls" / "cert.pem",
        tmp_path / "tls" / "key.pem",
    )
    s = Settings(data_dir=str(tmp_path), tls="files", tls_cert="/tls/fullchain.pem", tls_key="/tls/privkey.pem")
    assert tls.cert_paths(s) == (Path("/tls/fullchain.pem"), Path("/tls/privkey.pem"))


def test_spki_sha256_refuses_non_p256(tmp_path):
    import datetime

    import pytest
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.serialization import Encoding

    k = ec.generate_private_key(ec.SECP384R1())
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "x")])
    now = datetime.datetime.now(datetime.timezone.utc)
    c = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(k.public_key())
        .serial_number(1).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
        .sign(k, hashes.SHA256())
    )
    with pytest.raises(ValueError):
        tls.spki_sha256(c.public_bytes(Encoding.PEM))


def test_settings_from_env_tls():
    s = Settings.from_env({})
    assert (s.tls, s.tls_cert, s.tls_key, s.tls_pin) == ("off", "", "", True)
    s = Settings.from_env({"HU_TLS": "files", "HU_TLS_CERT": "/c", "HU_TLS_KEY": "/k", "HU_TLS_PIN": "false"})
    assert (s.tls, s.tls_cert, s.tls_key, s.tls_pin) == ("files", "/c", "/k", False)
    assert Settings.from_env({}).bind == "127.0.0.1:8796"  # outside the image; the image sets 0.0.0.0
