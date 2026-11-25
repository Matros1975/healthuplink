"""Sync notices: a generic webhook (JSON, or plain text for ntfy) and, optionally, Telegram.

A notice never carries health values: its text is built by the scheduler from hours and counts only. Failures are
reported by exception class name; the webhook URL, the notice text and the bot token never reach a log or a
message.
"""

import json
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

TIMEOUT = 10  # seconds, per channel
KINDS = ("stale", "dead_letters", "type_quiet", "sleep_quiet")
WEBHOOK_SCHEME_ERROR = "HU_NOTIFY_WEBHOOK_URL must start with http:// or https://"


@dataclass(frozen=True)
class Notice:
    kinds: tuple[str, ...]  # from KINDS
    text: str


class NoticeFailed(Exception):
    """At least one channel failed. `succeeded` names the channels that went out; `failed` is a list of
    `channel:ExceptionClass` strings. Safe to log."""

    def __init__(self, succeeded: set[str], failed: list[str]):
        super().__init__(", ".join(failed))
        self.succeeded = succeeded
        self.failed = failed


def webhook_url_error(settings) -> str | None:
    """None when the webhook is unset or http(s); only those schemes are opened (urllib would also open file:)."""
    url = settings.notify_webhook_url.strip()
    if not url:
        return None
    parts = urllib.parse.urlsplit(url)
    if parts.scheme.lower() not in ("http", "https") or not parts.netloc:
        return WEBHOOK_SCHEME_ERROR
    return None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A 3xx answer is an error: following it would re-send the POST as a GET (a 200 page would pass for
    delivery) and may leave http(s)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)
MAX_RESPONSE = 65536


def _post(url: str, data: bytes, headers: dict[str, str]) -> None:
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with _OPENER.open(req, timeout=TIMEOUT) as resp:
        resp.read(MAX_RESPONSE)
        if not 200 <= resp.status < 300:
            raise OSError(f"status {resp.status}")


def webhook_sender(settings) -> Callable[[Notice], None]:
    url, fmt = settings.notify_webhook_url.strip(), settings.notify_format

    def send(notice: Notice) -> None:
        if fmt == "text":
            _post(url, notice.text.encode("utf-8"),
                  {"Content-Type": "text/plain; charset=utf-8", "Title": "Health Uplink"})
            return
        body = {"source": "healthuplink", "kinds": list(notice.kinds), "text": notice.text,
                "at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
        _post(url, json.dumps(body).encode("utf-8"), {"Content-Type": "application/json"})
    return send


def telegram_sender(settings) -> Callable[[str], None] | None:
    """Callable(text) posting to a Telegram chat, or None when token or chat id is not configured.
    Never logs the URL (it contains the bot token)."""
    if not (settings.telegram_token and settings.telegram_chat_id):
        return None

    def send(text: str) -> None:
        url = f"https://api.telegram.org/bot{settings.telegram_token}/sendMessage"
        data = urllib.parse.urlencode({"chat_id": settings.telegram_chat_id, "text": text}).encode()
        req = urllib.request.Request(url, data=data, method="POST")
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            resp.read()
    return send


def build_sender(settings) -> Callable[[Notice], set[str]] | None:
    """The sender for the configured channels, or None when there is none. It tries every channel, returns the
    set of channel names that succeeded and raises NoticeFailed afterwards if any failed.
    Raises ValueError for a webhook URL that is not http(s)."""
    problem = webhook_url_error(settings)
    if problem:
        raise ValueError(problem)
    channels: list[tuple[str, Callable[[Notice], None]]] = []
    if settings.notify_webhook_url.strip():
        channels.append(("webhook", webhook_sender(settings)))
    tg = telegram_sender(settings)
    if tg is not None:
        channels.append(("telegram", lambda notice, tg=tg: tg(notice.text)))
    if not channels:
        return None

    def send(notice: Notice) -> set[str]:
        ok: set[str] = set()
        failed: list[str] = []
        for name, fn in channels:
            try:
                fn(notice)
                ok.add(name)
            except Exception as exc:  # class name only: the message can hold the URL or the bot token
                failed.append(f"{name}:{type(exc).__name__}")
        if failed:
            raise NoticeFailed(ok, failed)
        return ok
    return send
