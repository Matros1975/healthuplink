"""Receiver TLS: a self-signed ECDSA P-256 certificate with a stable pin, or operator-provided files.

The pin (`tls_sha256`, data contract section 2) is the SHA-256 of the certificate's DER
SubjectPublicKeyInfo. The self-signed key is created once and never replaced; the certificate
is reissued with the same key when its names no longer cover the public host, so the pin and
every paired phone survive a change of HU_PUBLIC_URL.
"""

import base64
import datetime
import hashlib
import ipaddress
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
)
from cryptography.x509.oid import NameOID

from healthuplink.config import Settings

VALIDITY_DAYS = 3650
RENEW_BEFORE = datetime.timedelta(days=30)  # reissue (same key) this long before expiry
DEFAULT_HOSTS = ("localhost", "127.0.0.1")


def spki_sha256(cert_pem: bytes) -> str:
    """Standard base64 of SHA-256 over the DER SubjectPublicKeyInfo. Raises ValueError unless the key is P-256,
    because the phone pins P-256 keys only (any other key type counts as a mismatch)."""
    key = x509.load_pem_x509_certificate(cert_pem).public_key()
    if not (isinstance(key, ec.EllipticCurvePublicKey) and key.curve.name == "secp256r1"):
        raise ValueError("the certificate key is not ECDSA P-256, so it cannot be pinned")
    spki = key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(hashlib.sha256(spki).digest()).decode()


def cert_paths(settings: Settings) -> tuple[Path, Path] | None:
    """(certificate, key) for the configured mode; None when TLS is off."""
    if settings.tls == "self-signed":
        d = Path(settings.data_dir) / "tls"
        return d / "cert.pem", d / "key.pem"
    if settings.tls == "files":
        return Path(settings.tls_cert), Path(settings.tls_key)
    return None


def _write_private(path: Path, data: bytes) -> None:
    """Write via a temp file and rename, mode 600 throughout."""
    tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def _general_name(host: str) -> x509.GeneralName:
    try:
        return x509.IPAddress(ipaddress.ip_address(host))
    except ValueError:
        return x509.DNSName(host)


def _wanted_names(hosts: list[str]) -> list[x509.GeneralName]:
    names: list[x509.GeneralName] = []
    for h in [*hosts, *DEFAULT_HOSTS]:
        h = h.strip().strip("[]").rstrip(".").lower()
        if h:
            n = _general_name(h)
            if n not in names:
                names.append(n)
    return names


def _load_or_create_key(path: Path) -> ec.EllipticCurvePrivateKey:
    if not path.exists():
        # Create-if-absent: link() fails when another process (serve vs. `pair`) won the race,
        # and then everybody uses the winner's key.
        key = ec.generate_private_key(ec.SECP256R1())
        tmp = path.with_name(f"{path.name}.{os.getpid()}.new")
        _write_private(tmp, key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
        try:
            os.link(tmp, path)
        except FileExistsError:
            pass
        finally:
            tmp.unlink()
    key = load_pem_private_key(path.read_bytes(), None)
    if not (isinstance(key, ec.EllipticCurvePrivateKey) and key.curve.name == "secp256r1"):
        # Never replace a key on our own: that would break every paired phone's pin.
        raise ValueError(f"{path} is not an ECDSA P-256 key")
    return key


def _cert_is_current(path: Path, key: ec.EllipticCurvePrivateKey, names: list[x509.GeneralName]) -> bool:
    if not path.exists():
        return False
    try:
        cert = x509.load_pem_x509_certificate(path.read_bytes())
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except (ValueError, x509.ExtensionNotFound):
        return False
    same_key = cert.public_key().public_numbers() == key.public_key().public_numbers()
    fresh = cert.not_valid_after_utc - datetime.datetime.now(datetime.timezone.utc) > RENEW_BEFORE
    return same_key and fresh and all(n in san for n in names)


def _issue(key: ec.EllipticCurvePrivateKey, names: list[x509.GeneralName]) -> bytes:
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Health Uplink receiver")])
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now - datetime.timedelta(minutes=5) + datetime.timedelta(days=VALIDITY_DAYS))
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(Encoding.PEM)


def ensure_self_signed(data_dir: Path, hosts: list[str]) -> tuple[Path, Path]:
    """(cert.pem, key.pem) under `<data_dir>/tls`, created on first use. The key is kept forever; the
    certificate is reissued with that key when it does not name every host in `hosts` or nears expiry."""
    d = Path(data_dir) / "tls"
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    cert_path, key_path = d / "cert.pem", d / "key.pem"
    key = _load_or_create_key(key_path)
    names = _wanted_names(hosts)
    if not _cert_is_current(cert_path, key, names):
        _write_private(cert_path, _issue(key, names))
    return cert_path, key_path
