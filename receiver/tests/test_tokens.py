from datetime import datetime, timedelta, timezone

import pytest

from healthuplink.db import connect
from healthuplink.tokens import (consume_pair_token, create_api_token, create_pair_token,
                                 revoke_api_token, verify_api_token)

T0 = datetime(2026, 11, 22, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def conn(tmp_path):
    return connect(tmp_path / "s.db")


def test_pair_token_single_use_and_ttl(conn):
    t = create_pair_token(conn, 1, now=T0)
    assert len(t) == 16
    assert consume_pair_token(conn, t, now=T0 + timedelta(minutes=9)) == 1
    assert consume_pair_token(conn, t, now=T0 + timedelta(minutes=9)) is None
    t2 = create_pair_token(conn, 1, now=T0)
    assert consume_pair_token(conn, t2, now=T0 + timedelta(minutes=11)) is None


def test_unknown_pair_token_rejected(conn):
    assert consume_pair_token(conn, b"x" * 16, now=T0) is None


def test_api_token_hashed_and_revocable(conn):
    tok = create_api_token(conn, "claude-code")
    assert len(tok) == 43
    assert verify_api_token(conn, tok) == "claude-code"
    assert tok not in str(conn.execute("SELECT * FROM api_tokens").fetchall())
    assert verify_api_token(conn, tok + "x") is None
    assert revoke_api_token(conn, "claude-code") and verify_api_token(conn, tok) is None
    assert not revoke_api_token(conn, "claude-code")
