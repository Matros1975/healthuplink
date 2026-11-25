"""API tokens and pairing tokens. Only SHA-256 hashes are stored."""

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

PAIR_TTL = timedelta(minutes=10)


def _h(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _iso(t: datetime) -> str:
    return t.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def create_api_token(conn, name: str) -> str:
    token = secrets.token_urlsafe(32)
    conn.execute(
        "INSERT INTO api_tokens(name, token_hash, created_at) VALUES (?,?,?)",
        (name, _h(token.encode()), _iso(datetime.now(timezone.utc))),
    )
    return token


def verify_api_token(conn, token: str) -> str | None:
    row = conn.execute(
        "SELECT name FROM api_tokens WHERE token_hash=?", (_h(token.encode()),)
    ).fetchone()
    return row[0] if row else None


def revoke_api_token(conn, name: str) -> bool:
    return conn.execute("DELETE FROM api_tokens WHERE name=?", (name,)).rowcount > 0


def create_pair_token(conn, key_epoch: int, now: datetime) -> bytes:
    token = secrets.token_bytes(16)
    conn.execute(
        "INSERT INTO pair_tokens(token_hash, key_epoch, expires_at) VALUES (?,?,?)",
        (_h(token), key_epoch, _iso(now + PAIR_TTL)),
    )
    return token


def consume_pair_token(conn, token: bytes, now: datetime) -> int | None:
    """Single use: the UPDATE only matches an unused, unexpired token."""
    h = _h(token)
    cur = conn.execute(
        "UPDATE pair_tokens SET used_at=? WHERE token_hash=? AND used_at IS NULL AND expires_at>?",
        (_iso(now), h, _iso(now)),
    )
    if cur.rowcount != 1:
        return None
    return conn.execute("SELECT key_epoch FROM pair_tokens WHERE token_hash=?", (h,)).fetchone()[0]


def peek_pair_token(conn, token: bytes, now: datetime) -> int | None:
    """key_epoch of an unused, unexpired token, without consuming it."""
    row = conn.execute(
        "SELECT key_epoch FROM pair_tokens WHERE token_hash=? AND used_at IS NULL AND expires_at>?",
        (_h(token), _iso(now)),
    ).fetchone()
    return row[0] if row else None


def list_api_tokens(conn) -> list[tuple[str, str]]:
    """(name, created_at) pairs; never the token or its hash."""
    return conn.execute("SELECT name, created_at FROM api_tokens ORDER BY created_at, name").fetchall()
