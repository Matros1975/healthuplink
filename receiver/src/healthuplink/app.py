"""ASGI app for the phone endpoints (and the /mcp mount provided by the MCP module)."""

import asyncio
import contextlib
import json
import logging
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from starlette.applications import Starlette
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.types import ASGIApp

from .ingest import Ingest

log = logging.getLogger(__name__)

MAX_BODY = 1_572_864  # 1.5 MiB


class _TooLarge(Exception):
    pass


class _BadRequest(Exception):
    pass


def _err(code: int, name: str) -> JSONResponse:
    return JSONResponse({"error": name}, status_code=code)


async def _read_json_object(request: Request) -> dict:
    """Read the body with a hard cap, never buffering more than MAX_BODY + 1 bytes."""
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            if int(declared) > MAX_BODY:
                raise _TooLarge
        except ValueError:
            raise _BadRequest
    buf = bytearray()
    async for chunk in request.stream():
        buf += chunk
        if len(buf) > MAX_BODY:
            raise _TooLarge
    try:
        obj = json.loads(bytes(buf))
    except (ValueError, UnicodeDecodeError):
        raise _BadRequest
    if not isinstance(obj, dict):
        raise _BadRequest
    return obj


def build_app(settings, conn_factory, keys, mcp_app: ASGIApp | None, now=None, *, sink_queue: bool = False) -> Starlette:
    """Build the Starlette app.

    All Ingest calls run on ONE worker thread (max_workers=1): the store connection from
    `conn_factory()` and the single `Ingest` instance are created there on first use, because
    Ingest holds the pair rate-limiter state and runs manual BEGIN IMMEDIATE transactions.

    `app.state.ingest_hooks` is the list Ingest iterates as `on_stored` (callables taking a
    batch_id); append to it, e.g. an extension's hook, before or after startup. `now` is an
    optional clock for tests (default: UTC wall clock). `sink_queue`: copy stored bodies into
    `sink_queue` (an extension consumes them).
    """
    executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="ingest")
    hooks: list = []
    clock = now or (lambda: datetime.now(timezone.utc))
    holder: dict = {}

    def _ingest() -> Ingest:  # only ever called on the worker thread
        if "ingest" not in holder:
            ing = Ingest(conn_factory(), keys, clock)
            ing.on_stored = hooks
            ing.queue_for_sink = sink_queue
            holder["ingest"] = ing
        return holder["ingest"]

    async def run(fn, *args):
        return await asyncio.get_running_loop().run_in_executor(executor, lambda: fn(_ingest(), *args))

    def post_endpoint(method_name, with_client):
        async def endpoint(request: Request):
            try:
                obj = await _read_json_object(request)
            except _TooLarge:
                return _err(413, "too_large")
            except _BadRequest:
                return _err(400, "bad_request")
            if with_client:
                client = request.client.host if request.client else "unknown"
                code, payload = await run(lambda ing, o, c: getattr(ing, method_name)(o, c), obj, client)
            else:
                code, payload = await run(lambda ing, o: getattr(ing, method_name)(o), obj)
            return JSONResponse(payload, status_code=code)
        return endpoint

    async def status(request: Request):
        h = request.headers
        device, at, sig = h.get("x-hu-device"), h.get("x-hu-at"), h.get("x-hu-sig")
        if not (device and at and sig):
            return _err(401, "unauthorized")
        code, payload = await run(lambda ing, d, a, s: ing.status(d, a, s), device, at, sig)
        return JSONResponse(payload, status_code=code)

    async def healthz(request: Request):
        return JSONResponse({"ok": True})

    async def http_exc(request: Request, exc: HTTPException):
        names = {400: "bad_request", 404: "not_found", 405: "method_not_allowed", 413: "too_large"}
        return _err(exc.status_code, names.get(exc.status_code, "error"))

    async def internal(request: Request, exc: Exception):
        log.error("unhandled error on %s %s", request.method, request.url.path, exc_info=exc)
        return _err(500, "internal")

    @asynccontextmanager
    async def lifespan(app):
        try:
            # The mounted MCP app's own lifespan is not run by Starlette: run it here (session manager).
            async with contextlib.AsyncExitStack() as stack:
                inner = getattr(mcp_app, "lifespan", None)  # optional: callable returning an async context
                if inner is not None:
                    await stack.enter_async_context(inner())
                yield
        finally:
            executor.shutdown(wait=True)

    routes = [
        Route("/v1/pair", post_endpoint("pair", True), methods=["POST"]),
        Route("/v1/batches", post_endpoint("batch", False), methods=["POST"]),
        Route("/v1/unpair", post_endpoint("unpair", False), methods=["POST"]),
        Route("/v1/status", status, methods=["GET"]),
        Route("/healthz", healthz, methods=["GET"]),
    ]
    if mcp_app is not None:
        # A Route (not Mount) so bare /mcp is served without Starlette's 307 redirect to /mcp/.
        routes.append(Route("/mcp", endpoint=mcp_app))
    app = Starlette(routes=routes, lifespan=lifespan,
                    exception_handlers={HTTPException: http_exc, Exception: internal})
    app.state.ingest_hooks = hooks
    return app
