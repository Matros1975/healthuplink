import json
import stat
from datetime import datetime, timedelta, timezone

from healthuplink.keys import KeyStore

T0 = datetime(2026, 11, 22, 12, 0, 0, tzinfo=timezone.utc)


def test_first_key_is_epoch_1_and_mode_600(tmp_path):
    k = KeyStore(tmp_path).current()
    assert k.epoch == 1 and len(k.pk) == 32 and len(k.sk) == 32
    assert stat.S_IMODE((tmp_path / "keys" / "server-1.json").stat().st_mode) == 0o600


def test_rotate_keeps_old_key_30_days(tmp_path):
    ks = KeyStore(tmp_path)
    ks.current()
    new = ks.rotate(now=T0)
    assert new.epoch == 2 and ks.current().epoch == 2
    assert ks.get(1).retired_at == T0
    ks.prune(now=T0 + timedelta(days=29))
    assert ks.get(1) is not None
    ks.prune(now=T0 + timedelta(days=31))
    assert ks.get(1) is None
    assert ks.get(2) is not None


def test_current_is_stable_across_instances_and_never_pruned(tmp_path):
    a = KeyStore(tmp_path).current()
    b = KeyStore(tmp_path).current()
    assert a == b
    KeyStore(tmp_path).prune(now=T0 + timedelta(days=3650))
    assert KeyStore(tmp_path).get(1) == a


def test_file_format_and_get_unknown(tmp_path):
    ks = KeyStore(tmp_path)
    ks.current()
    data = json.loads((tmp_path / "keys" / "server-1.json").read_text())
    assert set(data) == {"epoch", "sk", "pk", "created_at", "retired_at"}
    assert data["retired_at"] is None and data["created_at"].endswith("Z")
    assert ks.get(99) is None
