"""The transport rule for HU_PUBLIC_URL, checked against contract/vectors/pairing-v1.json."""

import json
from pathlib import Path

import pytest

from healthuplink import urlrule

VECTORS = Path(__file__).resolve().parents[2] / "contract" / "vectors"
URL_EXPECTS = {"ok", "needs_https", "tailnet_name", "bad_pin", "pin_needs_local_host"}


def _cases() -> list[dict]:
    return [c for c in json.loads((VECTORS / "pairing-v1.json").read_text())["cases"] if c["expect"] in URL_EXPECTS]


def test_matches_pairing_vectors():
    cases = _cases()
    assert {c["expect"] for c in cases} == URL_EXPECTS
    for c in cases:
        want = None if c["expect"] == "ok" else c["expect"]
        assert urlrule.check(c["url"], c["tls_sha256"]) == want, c["name"]


PIN = json.loads((VECTORS / "tls-v1.json").read_text())["tls_sha256"]


@pytest.mark.parametrize(
    "url, pin, want",
    [
        ("HTTP://100.100.1.1:8796", None, None),  # scheme is case-insensitive
        ("http://X.TS.NET.", None, "tailnet_name"),  # host case and trailing dot
        ("http://ts.net", None, "tailnet_name"),
        ("http://100.127.255.255", None, None),  # last address of 100.64.0.0/10
        ("http://100.63.255.255", None, "needs_https"),
        ("http://100.100.1.256", None, "needs_https"),
        ("http://100.100.1", None, "needs_https"),
        ("ftp://100.100.1.1", None, "needs_https"),
        ("https://Mac.Local.:8796", PIN, None),
        ("https://0100.100.1.1", PIN, "pin_needs_local_host"),
        ("https://192.168.1.10", "", "bad_pin"),
        ("https://192.168.1.10", PIN.rstrip("="), "bad_pin"),  # standard base64 with padding only
        ("", None, "bad_payload"),
        ("https://", None, "bad_payload"),
        ("https://user:pw@192.168.1.10", None, "bad_payload"),
        ("https://[::1", None, "bad_payload"),
    ],
)
def test_edge_cases(url, pin, want):
    assert urlrule.check(url, pin) == want
