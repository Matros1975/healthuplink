"""Receiver settings read from the environment."""

import os
from dataclasses import dataclass, field
from pathlib import Path
from zoneinfo import ZoneInfo

TLS_MODES = ("off", "self-signed", "files")
NOTIFY_FORMATS = ("json", "text")


def _bool(name: str, value: str) -> bool:
    v = value.strip().lower()
    if v in ("1", "true", "yes", "on"):
        return True
    if v in ("0", "false", "no", "off"):
        return False
    raise ValueError(f"{name} must be true or false, got {value!r}")


def default_data_dir(env) -> str:
    """$XDG_DATA_HOME/healthuplink (only an absolute XDG_DATA_HOME counts), else ~/.local/share/healthuplink."""
    xdg = env.get("XDG_DATA_HOME", "")
    if xdg and os.path.isabs(xdg):
        return str(Path(xdg) / "healthuplink")
    return str(Path.home() / ".local" / "share" / "healthuplink")


def _list(value: str) -> tuple[str, ...]:
    return tuple(part.strip() for part in value.split(",") if part.strip())


def check_tz(name: str) -> None:
    """Raises ValueError (a one-line message, no value echoed beyond the zone name) for an unknown IANA zone."""
    try:
        ZoneInfo(name)
    except Exception:  # ZoneInfoNotFoundError, ValueError (malformed key), OSError
        raise ValueError(f"HU_TZ is not a known time zone: {name!r} (use an IANA name such as Europe/Berlin)") from None


@dataclass(frozen=True)
class Settings:
    data_dir: str = field(default_factory=lambda: default_data_dir(os.environ))  # the image sets HU_DATA_DIR=/data
    bind: str = "127.0.0.1:8796"  # loopback outside the image; the image sets HU_BIND=0.0.0.0:8796
    public_url: str = ""  # the address the phone uses; `pair` refuses to run without it
    extensions: tuple[str, ...] = ()  # module names, each with register(ctx)
    telegram_token: str = ""
    telegram_chat_id: str = ""
    tz: str = "UTC"  # home time zone for the daily jobs (backup, prune)
    notify_webhook_url: str = ""  # POST target for sync notices; http or https (checked by notify and the CLI)
    notify_format: str = "json"  # one of NOTIFY_FORMATS
    tls: str = "off"  # one of TLS_MODES; checked by the CLI
    tls_cert: str = ""  # HU_TLS=files: certificate chain (PEM)
    tls_key: str = ""  # HU_TLS=files: private key (PEM)
    tls_pin: bool = True  # HU_TLS=files only; false: no tls_sha256 in the pairing code (CA-valid certificate)

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "Settings":
        """Raises ValueError for a malformed boolean, an unknown HU_TZ or an unknown HU_NOTIFY_FORMAT."""
        e = os.environ if env is None else env
        d = cls(data_dir="")
        tz = e.get("HU_TZ", "").strip() or d.tz
        check_tz(tz)
        notify_format = e.get("HU_NOTIFY_FORMAT", "").strip().lower() or d.notify_format
        if notify_format not in NOTIFY_FORMATS:
            raise ValueError(f"HU_NOTIFY_FORMAT must be json or text, got {notify_format!r}")
        return cls(
            data_dir=e.get("HU_DATA_DIR", "") or default_data_dir(e),
            bind=e.get("HU_BIND", d.bind),
            public_url=e.get("HU_PUBLIC_URL", d.public_url),
            extensions=_list(e.get("HU_EXTENSIONS", "")),
            telegram_token=e.get("HU_TELEGRAM_TOKEN", d.telegram_token),
            telegram_chat_id=e.get("HU_TELEGRAM_CHAT_ID", d.telegram_chat_id),
            tz=tz,
            notify_webhook_url=e.get("HU_NOTIFY_WEBHOOK_URL", d.notify_webhook_url).strip(),
            notify_format=notify_format,
            tls=e.get("HU_TLS", d.tls).strip().lower() or d.tls,
            tls_cert=e.get("HU_TLS_CERT", d.tls_cert),
            tls_key=e.get("HU_TLS_KEY", d.tls_key),
            tls_pin=_bool("HU_TLS_PIN", e["HU_TLS_PIN"]) if e.get("HU_TLS_PIN", "").strip() else d.tls_pin,
        )
