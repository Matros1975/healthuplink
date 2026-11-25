import asyncio
import socket
import threading
import time
from datetime import datetime, timezone

import httpx
import pytest
import uvicorn
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client

from healthuplink import tokens
from healthuplink.app import build_app
from healthuplink.config import Settings
from healthuplink.db import connect
from healthuplink.body import validate
from healthuplink.keys import KeyStore
from healthuplink.store import write_batch
from healthuplink_mcp import tools
from healthuplink_mcp.server import BearerAuth, build

STEPS = "HKQuantityTypeIdentifierStepCount"
NOW = datetime(2026, 11, 22, 10, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def served(tmp_path):
    path = tmp_path / "store.db"
    seed = connect(path)
    token = tokens.create_api_token(seed, "claude")
    body = validate({"samples": [{"uuid": "3f2a0000-0000-4000-8000-000000000001", "type": STEPS, "kind": "quantity",
                                  "start": "2026-11-21T08:00:00Z", "end": "2026-11-21T08:05:00Z", "value": 120,
                                  "unit": "count", "source": {"bundle": "com.apple.health.W", "name": "W",
                                                              "product_type": None}}],
                     "sleep_nights": [{"night": "2026-11-21", "source": "com.apple.health.W", "tz": "Europe/Amsterdam",
                                       "start": "2026-11-20T22:00:00Z", "end": "2026-11-21T06:00:00Z",
                                       "minutes": {"asleep": 450}, "segments": []}]})
    write_batch(seed, batch_id="b1", device_id="d1", seq=1, ct_sha256="ab", received_at="2026-11-21T09:00:00Z",
                created_at="2026-11-21T08:59:00Z", body=body)
    seed.close()
    mcp = BearerAuth(build(lambda: connect(path, readonly=True), lambda: NOW), lambda: connect(path, readonly=True))
    app = build_app(Settings(data_dir=str(tmp_path)), lambda: connect(path), KeyStore(tmp_path), mcp,
                    now=lambda: NOW)
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, log_level="warning"))
    t = threading.Thread(target=lambda: server.run(sockets=[sock]), daemon=True)
    t.start()
    while not server.started:
        time.sleep(0.02)
    yield f"http://127.0.0.1:{port}", token, path
    server.should_exit = True
    t.join(10)


def run_client(served, fn, token=None):
    base, tok, _ = served

    async def go():
        http = create_mcp_http_client(headers={"Authorization": f"Bearer {token or tok}"})
        async with Client(streamable_http_client(f"{base}/mcp", http_client=http)) as c:
            return await fn(c)
    return asyncio.run(go())


def test_mcp_lists_six_tools_with_token(served):
    async def fn(c):
        return {t.name: t for t in (await c.list_tools()).tools}
    tools = run_client(served, fn)
    assert set(tools) == {"list_types", "list_sources", "query", "summary", "get_sleep", "sync_status"}
    assert "from" in tools["query"].input_schema["properties"]
    assert "Query one data type" in tools["query"].description


def test_mcp_without_token_401(served):
    base, _, _ = served
    r = httpx.post(f"{base}/mcp", json={})
    assert r.status_code == 401 and r.json() == {"error": "unauthorized"}
    r = httpx.post(f"{base}/mcp", json={}, headers={"Authorization": "Bearer wrong"})
    assert r.status_code == 401


def test_bare_mcp_path_does_not_redirect(served):
    base, tok, _ = served
    r = httpx.post(f"{base}/mcp", json={}, headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code != 307 and r.status_code != 401


def test_phone_routes_need_no_bearer(served):
    base, _, _ = served
    assert httpx.get(f"{base}/healthz").status_code == 200


def test_mcp_tool_call_returns_data(served):
    async def fn(c):
        return await c.call_tool("sync_status", {})
    r = run_client(served, fn)
    assert not r.is_error and r.structured_content["devices"] == []


def test_mcp_query_with_from_argument(served):
    async def fn(c):
        return await c.call_tool("query", {"type": STEPS, "from": "2026-11-21", "to": "2026-11-22",
                                           "aggregation": "raw"})
    r = run_client(served, fn)
    assert not r.is_error
    sc = r.structured_content
    assert sc["type"] == STEPS and sc["points"][0]["value"] == 120 and sc["tools_version"] == 1


def test_mcp_get_sleep_with_from_argument(served):
    async def fn(c):
        return await c.call_tool("get_sleep", {"from": "2026-11-21", "to": "2026-11-22", "source": "com.apple.health.W"})
    r = run_client(served, fn)
    assert not r.is_error
    assert r.structured_content["nights"][0]["minutes"]["asleep"] == 450


def test_mcp_tool_error_carries_its_message(served):
    args = {"type": "nope", "from": "2026-11-21", "to": "2026-11-22", "aggregation": "raw"}
    conn = connect(served[2], readonly=True)
    with pytest.raises(tools.ToolError) as exc:
        tools.query(conn, NOW, args["type"], args["from"], args["to"], args["aggregation"])
    conn.close()

    async def fn(c):
        return await c.call_tool("query", args)
    r = run_client(served, fn)
    assert r.is_error
    assert str(exc.value) in r.content[0].text
