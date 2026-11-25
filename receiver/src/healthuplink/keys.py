"""Server X25519 key store: `<dir>/keys/server-<epoch>.json`, mode 600, with rotation and pruning."""

import json
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from healthuplink.encoding import b64d, b64e

RETENTION = timedelta(days=30)


@dataclass(frozen=True)
class ServerKey:
    epoch: int
    sk: bytes
    pk: bytes
    created_at: datetime
    retired_at: datetime | None


def _iso(t: datetime) -> str:
    return t.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse(s: str) -> datetime:
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


class KeyStore:
    def __init__(self, dir: Path):
        self._dir = Path(dir) / "keys"

    def _path(self, epoch: int) -> Path:
        return self._dir / f"server-{epoch}.json"

    def _epochs(self) -> list[int]:
        return sorted(int(p.stem.split("-")[1]) for p in self._dir.glob("server-*.json"))

    def _write(self, k: ServerKey) -> None:
        self._dir.mkdir(parents=True, exist_ok=True)
        data = {
            "epoch": k.epoch,
            "sk": b64e(k.sk),
            "pk": b64e(k.pk),
            "created_at": _iso(k.created_at),
            "retired_at": _iso(k.retired_at) if k.retired_at else None,
        }
        tmp = self._path(k.epoch).with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps(data))
        os.chmod(tmp, 0o600)
        os.replace(tmp, self._path(k.epoch))

    def _new(self, epoch: int, now: datetime) -> ServerKey:
        sk = X25519PrivateKey.generate()
        k = ServerKey(
            epoch=epoch,
            sk=sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()),
            pk=sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
            created_at=now.replace(microsecond=0),
            retired_at=None,
        )
        self._write(k)
        return k

    def get(self, epoch: int) -> ServerKey | None:
        try:
            d = json.loads(self._path(epoch).read_text())
        except FileNotFoundError:
            return None
        return ServerKey(
            epoch=d["epoch"],
            sk=b64d(d["sk"]),
            pk=b64d(d["pk"]),
            created_at=_parse(d["created_at"]),
            retired_at=_parse(d["retired_at"]) if d["retired_at"] else None,
        )

    def current(self) -> ServerKey:
        epochs = self._epochs()
        if not epochs:
            return self._new(1, datetime.now(timezone.utc))
        return self.get(epochs[-1])

    def rotate(self, now: datetime) -> ServerKey:
        old = self.current()
        self._write(ServerKey(old.epoch, old.sk, old.pk, old.created_at, now.replace(microsecond=0)))
        return self._new(old.epoch + 1, now)

    def prune(self, now: datetime) -> None:
        current = self.current().epoch
        for epoch in self._epochs():
            k = self.get(epoch)
            if epoch != current and k.retired_at and now - k.retired_at > RETENTION:
                self._path(epoch).unlink()
