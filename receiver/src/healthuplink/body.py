"""Body (body_version 1) validation. Returns cleaned, store-ready structures."""

import math
import re
import unicodedata
from dataclasses import dataclass, field
from datetime import date, datetime

MAX_ITEMS = 10_000
MAX_TYPES = 300
TEXT_MAX = 200

TYPE_RE = re.compile(r"HK[A-Za-z]+TypeIdentifier[A-Za-z0-9]+")
UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
DAY_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
TS_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")  # whole seconds only
IGNORED_ARRAYS = ("workouts", "routes", "ecg", "state_of_mind")


class TooLarge(Exception):
    pass


class Invalid(Exception):
    pass


@dataclass
class Body:
    app: dict = field(default_factory=dict)
    abandoned_seq: list = field(default_factory=list)
    dead_letter_seq: list = field(default_factory=list)
    samples: list = field(default_factory=list)
    daily: list = field(default_factory=list)
    sleep_nights: list = field(default_factory=list)
    deleted: list = field(default_factory=list)
    ignored: list = field(default_factory=list)


def clean_text(s) -> str:
    if not isinstance(s, str):
        raise Invalid("expected string")
    s = "".join(c for c in s if not unicodedata.category(c).startswith("C"))
    return s[:TEXT_MAX]


def _opt_text(d: dict, key: str):
    v = d.get(key)
    return None if v is None else clean_text(v)


def _ts(v, what: str) -> str:
    if not isinstance(v, str) or not TS_RE.fullmatch(v):
        raise Invalid(f"{what}: bad timestamp")
    try:
        datetime.fromisoformat(v[:-1] + "+00:00")
    except ValueError:
        raise Invalid(f"{what}: bad timestamp") from None
    return v


def _ts_key(v: str) -> datetime:
    return datetime.fromisoformat(v[:-1] + "+00:00")


def _num(v, what: str, nullable: bool = False):
    if v is None and nullable:
        return None
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v):
        raise Invalid(f"{what}: not a finite number")
    return v


def _type(v, what: str = "type") -> str:
    if not isinstance(v, str) or not TYPE_RE.fullmatch(v):
        raise Invalid(f"{what}: bad type identifier")
    return v


def _uuid(v) -> str:
    if not isinstance(v, str) or not UUID_RE.fullmatch(v):
        raise Invalid("uuid must be a lowercase UUID")
    return v


def _day(v, what: str) -> str:
    if not isinstance(v, str) or not DAY_RE.fullmatch(v):
        raise Invalid(f"{what}: bad date")
    try:
        date.fromisoformat(v)
    except ValueError:
        raise Invalid(f"{what}: bad date") from None
    return v


def _obj(v, what: str) -> dict:
    if not isinstance(v, dict):
        raise Invalid(f"{what}: expected object")
    return v


def _arr(obj: dict, key: str) -> list:
    v = obj.get(key)
    if v is None:
        return []
    if not isinstance(v, list):
        raise Invalid(f"{key}: expected array")
    return v


def _clean_json(v, depth=0):
    if depth > 4:
        raise Invalid("metadata too deep")
    if isinstance(v, str):
        return clean_text(v)
    if isinstance(v, bool) or v is None:
        return v
    if isinstance(v, (int, float)):
        return _num(v, "metadata")
    if isinstance(v, list):
        return [_clean_json(x, depth + 1) for x in v]
    if isinstance(v, dict):
        return {clean_text(k): _clean_json(x, depth + 1) for k, x in v.items()}
    raise Invalid("metadata: unsupported value")


def _source_str(v) -> str:
    if not isinstance(v, str) or not v or len(v) > 200:
        raise Invalid("source: bad value")
    return v


def _sample(s) -> dict:
    s = _obj(s, "sample")
    kind = s.get("kind")
    if kind not in ("quantity", "category"):
        raise Invalid("sample: bad kind")
    start, end = _ts(s.get("start"), "start"), _ts(s.get("end"), "end")
    if _ts_key(start) > _ts_key(end):
        raise Invalid("sample: start after end")
    src = _obj(s.get("source"), "source")
    unit = s.get("unit")
    meta = s.get("metadata")
    return {
        "uuid": _uuid(s.get("uuid")),
        "type": _type(s.get("type")),
        "kind": kind,
        "start": start,
        "end": end,
        "value": _num(s.get("value"), "value"),
        "value_label": _opt_text(s, "value_label"),
        "unit": None if unit is None else clean_text(unit),
        "source": {
            "bundle": _source_str(src.get("bundle")),
            "name": _opt_text(src, "name"),
            "product_type": _opt_text(src, "product_type"),
        },
        "tz": _opt_text(s, "tz"),
        "metadata": None if meta is None else _clean_json(_obj(meta, "metadata")),
    }


def _daily(d) -> dict:
    d = _obj(d, "daily")
    src = d.get("source")
    if src != "@merged":
        src = _source_str(src)
    partial = d.get("partial", False)
    if not isinstance(partial, bool):
        raise Invalid("daily: partial must be boolean")
    unit = d.get("unit")
    return {
        "type": _type(d.get("type")),
        "day": _day(d.get("day"), "day"),
        "tz": _opt_text(d, "tz"),
        "source": src,
        **{k: _num(d.get(k), k, nullable=True) for k in ("sum", "avg", "min", "max", "n")},
        "unit": None if unit is None else clean_text(unit),
        "partial": partial,
    }


def _night(n) -> dict:
    n = _obj(n, "sleep_night")
    src = n.get("source")
    if src != "@merged":
        src = _source_str(src)
    start = None if n.get("start") is None else _ts(n["start"], "start")
    end = None if n.get("end") is None else _ts(n["end"], "end")
    minutes = _obj(n.get("minutes", {}), "minutes")
    for k, v in minutes.items():
        if _num(v, f"minutes.{k}") < 0:
            raise Invalid("minutes must be >= 0")
    segs = []
    for sg in _arr(n, "segments"):
        sg = _obj(sg, "segment")
        segs.append({
            "start": _ts(sg.get("start"), "segment start"),
            "end": _ts(sg.get("end"), "segment end"),
            "stage": clean_text(sg.get("stage")),
        })
    return {
        "night": _day(n.get("night"), "night"),
        "tz": _opt_text(n, "tz"),
        "source": src,
        "start": start,
        "end": end,
        "minutes": {clean_text(k): v for k, v in minutes.items()},
        "segments": segs,
    }


def _deleted(d) -> dict:
    d = _obj(d, "deleted")
    return {"uuid": _uuid(d.get("uuid")), "type": _type(d.get("type"))}


def _seqs(obj: dict, key: str) -> list:
    out = []
    for v in _arr(obj, key):
        if isinstance(v, bool) or not isinstance(v, int) or v < 1:
            raise Invalid(f"{key}: bad seq")
        out.append(v)
    return out


def validate(obj: dict) -> Body:
    if not isinstance(obj, dict):
        raise Invalid("body must be an object")
    ignored = [k for k in IGNORED_ARRAYS if obj.get(k)]
    for k in ignored:
        if not isinstance(obj[k], list):
            raise Invalid(f"{k}: expected array")
    raw = {k: _arr(obj, k) for k in ("samples", "daily", "sleep_nights", "deleted")}
    items = sum(len(v) for v in raw.values()) + sum(len(obj[k]) for k in ignored)
    if items > MAX_ITEMS:
        raise TooLarge(f"{items} items")
    app = obj.get("app")
    app = {} if app is None else _clean_json(_obj(app, "app"))
    body = Body(
        app=app,
        abandoned_seq=_seqs(obj, "abandoned_seq"),
        dead_letter_seq=_seqs(obj, "dead_letter_seq"),
        samples=[_sample(s) for s in raw["samples"]],
        daily=[_daily(d) for d in raw["daily"]],
        sleep_nights=[_night(n) for n in raw["sleep_nights"]],
        deleted=[_deleted(d) for d in raw["deleted"]],
        ignored=ignored,
    )
    types = {s["type"] for s in body.samples} | {d["type"] for d in body.daily} | {d["type"] for d in body.deleted}
    if len(types) > MAX_TYPES:
        raise Invalid("too many distinct types")
    return body
