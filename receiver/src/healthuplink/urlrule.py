"""The transport rule for the receiver's public URL (data contract section 2: URL rules and `tls_sha256`).

Same checks, in the same order, as the app's PairingPayload.parse, so the receiver refuses
to print a pairing code the phone would reject. Tested against contract/vectors/pairing-v1.json.
"""

import base64
import binascii
from urllib.parse import urlsplit


def _ipv4_octets(host: str) -> list[int] | None:
    """Four decimal octets without leading zeros, else None."""
    parts = host.split(".")
    if len(parts) != 4:
        return None
    octets = []
    for p in parts:
        if not (1 <= len(p) <= 3 and p.isascii() and p.isdigit()) or (len(p) > 1 and p[0] == "0"):
            return None
        n = int(p)
        if n > 255:
            return None
        octets.append(n)
    return octets


def _is_tailnet_ipv4(host: str) -> bool:
    o = _ipv4_octets(host)
    return o is not None and o[0] == 100 and 64 <= o[1] <= 127  # 100.64.0.0/10


def _pin_ok(pin: object) -> bool:
    if not isinstance(pin, str):
        return False
    try:
        return len(base64.b64decode(pin, validate=True)) == 32
    except (binascii.Error, ValueError):
        return False


def _is_local_host(host: str) -> bool:
    """Hosts that may carry a pin: IPv4 literals, `.local` names, names without a dot. Not IPv6."""
    if ":" in host:
        return False
    return _ipv4_octets(host) is not None or host.endswith(".local") or "." not in host


def host_of(url: str) -> str | None:
    """Lowercased host without brackets or trailing dots, or None when the URL has none."""
    try:
        parts = urlsplit(url)
        host = parts.hostname
        if parts.username is not None or parts.password is not None:
            return None
    except ValueError:
        return None
    host = (host or "").rstrip(".")
    return host or None


def check(url: str, tls_sha256: object | None) -> str | None:
    """None when the phone would accept `url` with this raw `tls_sha256` value (None = no pin).

    Otherwise the pairing-v1.json error name: `bad_payload` (no usable host), `tailnet_name`,
    `needs_https`, `bad_pin` or `pin_needs_local_host`. A *.ts.net name wins over plain http,
    because the phone cannot resolve it either way.
    """
    host = host_of(url)
    if host is None:
        return "bad_payload"
    if host == "ts.net" or host.endswith(".ts.net"):
        return "tailnet_name"
    scheme = urlsplit(url).scheme.lower()
    if not (scheme == "https" or (scheme == "http" and _is_tailnet_ipv4(host))):
        return "needs_https"
    if tls_sha256 is None:
        return None
    if scheme != "https":
        return "needs_https"  # a pin requires https, even on the tailnet
    if not _pin_ok(tls_sha256):
        return "bad_pin"
    if not _is_local_host(host):
        return "pin_needs_local_host"
    return None
