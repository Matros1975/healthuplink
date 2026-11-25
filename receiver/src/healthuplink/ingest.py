"""Batch ingest (data contract section 3, receiver checks)."""

import hashlib
import json
import logging
import re
import sqlite3
import uuid
import zlib
from collections import deque
from collections.abc import Callable
from datetime import datetime, timedelta, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import body as body_mod
from . import hpke, store, tokens
from .encoding import (b64d, b64e, batch_aad, batch_info, batch_sig_msg, pair_confirm, pair_proof_msg,
                       status_msg, unpair_msg)
from .keys import KeyStore

log = logging.getLogger("healthuplink")

MAX_CIPHERTEXT = 1 << 20
MAX_PLAINTEXT = 16 << 20
FUTURE_LIMIT = timedelta(days=1)
PAST_LIMIT = timedelta(days=400)

BAD_REQUEST = (400, {"error": "bad_request"})
UNAUTHORIZED = (401, {"error": "unauthorized"})
TOO_LARGE = (413, {"error": "too_large"})
DECRYPT_FAILED = (422, {"error": "decrypt_failed"})
UNSUPPORTED = (426, {"error": "upgrade_required", "supported": {"envelope": [1], "body": [1]}})

SIGNED_AT_SKEW = timedelta(minutes=10)
PAIR_WINDOW = timedelta(minutes=1)
PAIR_PER_CLIENT = 5
PAIR_TOTAL = 20
TOO_MANY = (429, {"error": "rate_limited"})

_STR_FIELDS = ("batch_id", "device_id", "created_at", "enc", "ciphertext", "sig")
_INT_FIELDS = ("envelope_version", "key_epoch", "seq")


def _is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


_UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_TS_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z")


def _parse_created_at(s: str) -> datetime | None:
    if not _TS_RE.fullmatch(s):
        return None
    try:
        return datetime.fromisoformat(s[:-1] + "+00:00")
    except ValueError:
        return None


def _gunzip_capped(data: bytes) -> bytes | None:
    """Decompressed bytes, or None when the data is not a complete gzip stream. Raises OverflowError over the cap."""
    d = zlib.decompressobj(31)
    try:
        out = d.decompress(data, MAX_PLAINTEXT + 1)
    except zlib.error:
        return None
    if len(out) > MAX_PLAINTEXT:
        raise OverflowError
    return out if d.eof else None


class Ingest:
    def __init__(self, conn: sqlite3.Connection, keys: KeyStore, now: Callable[[], datetime]):
        self.conn = conn
        self.keys = keys
        self.now = now
        self.on_stored: list[Callable[[str], None]] = []
        self.queue_for_sink = False  # set by build_app when an extension consumes sink_queue
        self._pair_attempts: dict[str, deque] = {}
        self._pair_total: deque = deque()

    def batch(self, envelope: dict) -> tuple[int, dict]:
        if not isinstance(envelope, dict):
            return BAD_REQUEST
        if not all(isinstance(envelope.get(k), str) for k in _STR_FIELDS):
            return BAD_REQUEST
        if not all(_is_int(envelope.get(k)) for k in _INT_FIELDS):
            return BAD_REQUEST
        if not (_UUID_RE.fullmatch(envelope["batch_id"]) and _UUID_RE.fullmatch(envelope["device_id"])):
            return BAD_REQUEST
        if envelope["seq"] < 1 or envelope["key_epoch"] < 0 or envelope["key_epoch"] >= 1 << 32:
            return BAD_REQUEST
        if envelope["seq"] >= 1 << 64:
            return BAD_REQUEST
        try:
            enc = b64d(envelope["enc"])
            ciphertext = b64d(envelope["ciphertext"])
            sig = b64d(envelope["sig"])
        except ValueError:
            return BAD_REQUEST
        created_at = _parse_created_at(envelope["created_at"])
        if created_at is None:
            return BAD_REQUEST
        if envelope["envelope_version"] != 1:
            return UNSUPPORTED

        device_id = envelope["device_id"]
        batch_id = envelope["batch_id"]
        aad = batch_aad(batch_id, device_id, envelope["key_epoch"], envelope["seq"], envelope["created_at"])
        if not self._authentic(device_id, sig, batch_sig_msg(aad, enc, ciphertext)):
            return UNAUTHORIZED
        if len(ciphertext) > MAX_CIPHERTEXT:
            return TOO_LARGE

        ct_sha = hashlib.sha256(ciphertext).hexdigest()
        row = self.conn.execute("SELECT ciphertext_sha256 FROM batches WHERE batch_id=?", (batch_id,)).fetchone()
        if row is not None:
            if row[0] == ct_sha:
                return 200, {"status": "duplicate"}
            return 409, {"error": "conflict"}

        key = self.keys.get(envelope["key_epoch"])
        if key is None:
            return DECRYPT_FAILED
        try:
            compressed = hpke.open_(key.sk, enc, batch_info(device_id, key.pk), aad, ciphertext)
        except hpke.HPKEError:
            return DECRYPT_FAILED
        try:
            raw = _gunzip_capped(compressed)
        except OverflowError:
            return TOO_LARGE
        if raw is None:
            return DECRYPT_FAILED
        try:
            obj = json.loads(raw)
        except (ValueError, RecursionError):
            return 422, {"error": "invalid_body", "reason": "not valid JSON"}
        bv = obj.get("body_version") if isinstance(obj, dict) else 1
        if not _is_int(bv) or bv != 1:
            return UNSUPPORTED
        try:
            parsed = body_mod.validate(obj)
        except body_mod.TooLarge:
            return TOO_LARGE
        except body_mod.Invalid as e:
            return 422, {"error": "invalid_body", "reason": str(e)}

        now = self.now()
        flags = {
            "app": parsed.app,
            "low_power": bool(parsed.app.get("low_power", False)),
            "created_at_out_of_range": created_at > now + FUTURE_LIMIT or created_at < now - PAST_LIMIT,
        }
        try:
            store.write_batch(
                self.conn, batch_id=batch_id, device_id=device_id, seq=envelope["seq"], ct_sha256=ct_sha,
                received_at=now.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                created_at=envelope["created_at"], body=parsed, flags=flags, queue_for_sink=self.queue_for_sink,
            )
        except sqlite3.IntegrityError:
            # A concurrent request stored the same batch_id between the check and the insert.
            row = self.conn.execute("SELECT ciphertext_sha256 FROM batches WHERE batch_id=?", (batch_id,)).fetchone()
            if row is not None and row[0] == ct_sha:
                return 200, {"status": "duplicate"}
            return 409, {"error": "conflict"}
        for cb in list(self.on_stored):
            try:
                cb(batch_id)
            except Exception:
                log.exception("on_stored callback failed for batch %s", batch_id)
        return 200, {"status": "stored"}

    def _authentic(self, device_id: str, sig: bytes, msg: bytes) -> bool:
        row = self.conn.execute(
            "SELECT signing_pk, revoked_at FROM devices WHERE device_id=?", (device_id,)).fetchone()
        if row is None or row[1] is not None:
            return False
        try:
            Ed25519PublicKey.from_public_bytes(b64d(row[0])).verify(sig, msg)
        except (InvalidSignature, ValueError):
            return False
        return True

    def _pair_rate_ok(self, client_key: str, now: datetime) -> bool:
        """Sliding window. Only admitted attempts count, so a flood cannot extend its own lockout."""
        cutoff = now - PAIR_WINDOW
        while self._pair_total and self._pair_total[0] <= cutoff:
            self._pair_total.popleft()
        for k in [k for k, q in self._pair_attempts.items() if q[-1] <= cutoff]:
            del self._pair_attempts[k]
        q = self._pair_attempts.get(client_key)
        if q is not None:
            while q and q[0] <= cutoff:
                q.popleft()
        if len(self._pair_total) >= PAIR_TOTAL or (q is not None and len(q) >= PAIR_PER_CLIENT):
            return False
        self._pair_attempts.setdefault(client_key, deque()).append(now)
        self._pair_total.append(now)
        return True

    def pair(self, req: dict, client_key: str) -> tuple[int, dict]:
        now = self.now()
        if not self._pair_rate_ok(client_key, now):
            return TOO_MANY
        if not isinstance(req, dict):
            return BAD_REQUEST
        if not all(isinstance(req.get(k), str) for k in ("pair_token", "device_signing_pk", "proof", "device_name")):
            return BAD_REQUEST
        try:
            token = b64d(req["pair_token"])
            device_pk = b64d(req["device_signing_pk"])
            proof = b64d(req["proof"])
        except ValueError:
            return BAD_REQUEST
        if len(token) != 16 or len(device_pk) != 32 or len(proof) != 64:
            return BAD_REQUEST
        name = body_mod.clean_text(req["device_name"])

        epoch = tokens.peek_pair_token(self.conn, token, now)
        if epoch is None:
            return UNAUTHORIZED
        key = self.keys.get(epoch)
        if key is None:
            return UNAUTHORIZED
        try:
            Ed25519PublicKey.from_public_bytes(device_pk).verify(proof, pair_proof_msg(token, device_pk))
        except (InvalidSignature, ValueError):
            return UNAUTHORIZED

        device_id = str(uuid.uuid4())
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            if tokens.consume_pair_token(self.conn, token, now) is None:
                self.conn.execute("ROLLBACK")
                return UNAUTHORIZED
            self.conn.execute(
                "INSERT INTO devices(device_id, name, signing_pk, paired_at) VALUES (?,?,?,?)",
                (device_id, name, b64e(device_pk), _iso(now)),
            )
            self.conn.execute("COMMIT")
        except BaseException:
            self.conn.execute("ROLLBACK")
            raise
        return 200, {"device_id": device_id, "confirm": b64e(pair_confirm(token, device_pk, key.pk))}

    def _signed_request_ok(self, device_id, at, sig, msg_fn) -> tuple[int, dict] | None:
        """None when device_id/at/sig is a valid signed request from an active device, else the error response."""
        if not (isinstance(device_id, str) and isinstance(at, str) and isinstance(sig, str)):
            return BAD_REQUEST
        if not _UUID_RE.fullmatch(device_id):
            return BAD_REQUEST
        try:
            sig_b = b64d(sig)
        except ValueError:
            return BAD_REQUEST
        at_t = _parse_created_at(at)
        if at_t is None or abs(self.now() - at_t) > SIGNED_AT_SKEW:
            return UNAUTHORIZED
        if not self._authentic(device_id, sig_b, msg_fn(device_id, at)):
            return UNAUTHORIZED
        return None

    def unpair(self, req: dict) -> tuple[int, dict]:
        if not isinstance(req, dict):
            return BAD_REQUEST
        device_id, at = req.get("device_id"), req.get("at")
        err = self._signed_request_ok(device_id, at, req.get("sig"), unpair_msg)
        if err is not None:
            return err
        self.conn.execute("UPDATE devices SET revoked_at=? WHERE device_id=? AND revoked_at IS NULL",
                          (_iso(self.now()), device_id))
        return 200, {"status": "unpaired"}

    def status(self, device_id: str, at: str, sig: str) -> tuple[int, dict]:
        err = self._signed_request_ok(device_id, at, sig, status_msg)
        if err is not None:
            return err
        return 200, store.device_status(self.conn, device_id)


def _iso(t: datetime) -> str:
    return t.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
