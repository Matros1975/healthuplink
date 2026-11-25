import pytest

from healthuplink.body import Invalid, TooLarge, validate

HR = "HKQuantityTypeIdentifierHeartRate"
U1 = "3f2a0000-0000-4000-8000-000000000001"


def sample(**kw):
    s = {"uuid": U1, "type": HR, "kind": "quantity", "start": "2026-11-22T03:12:00Z",
         "end": "2026-11-22T03:12:00Z", "value": 52, "unit": "count/min",
         "source": {"bundle": "com.apple.health.ABC", "name": "Apple Watch"}}
    s.update(kw)
    return s


def body(**kw):
    return {"body_version": 1, **kw}


def test_valid_body_roundtrip():
    b = validate(body(samples=[sample()], daily=[{"type": HR, "day": "2026-11-21", "source": "@merged",
                                                  "sum": 1, "n": None, "unit": "count"}],
                      deleted=[{"uuid": U1, "type": HR}]))
    assert len(b.samples) == 1 and b.daily[0]["partial"] is False and len(b.deleted) == 1


def test_rejects_bad_type_identifier():
    with pytest.raises(Invalid):
        validate(body(samples=[sample(type="HKFoo")]))


def test_more_than_10000_items_is_too_large():
    with pytest.raises(TooLarge):
        validate(body(samples=[sample() for _ in range(10_001)]))


def test_items_count_includes_ignored_arrays():
    with pytest.raises(TooLarge):
        validate(body(samples=[sample() for _ in range(5_000)], workouts=[{}] * 5_001))


def test_free_text_cut_and_control_chars_removed():
    b = validate(body(samples=[sample(source={"bundle": "x", "name": "Watch\x07" + "a" * 300})]))
    assert b.samples[0]["source"]["name"] == "Watch" + "a" * 195


def test_unknown_arrays_ignored_not_rejected():
    b = validate(body(workouts=[{}], ecg=[{}]))
    assert sorted(b.ignored) == ["ecg", "workouts"]


@pytest.mark.parametrize("kw", [
    {"uuid": U1.upper()},
    {"kind": "other"},
    {"start": "2026-11-22T03:13:00Z"},
    {"start": "2026-11-22 03:12:00"},
    {"value": float("inf")},
    {"value": "52"},
    {"source": {"bundle": ""}},
    {"source": {"bundle": "x" * 201}},
])
def test_rejects_bad_sample(kw):
    with pytest.raises(Invalid):
        validate(body(samples=[sample(**kw)]))


def test_source_bundle_case_preserved():
    b = validate(body(samples=[sample(source={"bundle": "com.Apple.ABC"})]))
    assert b.samples[0]["source"]["bundle"] == "com.Apple.ABC"


def test_rejects_bad_daily_and_sleep():
    d = {"type": HR, "day": "2026-11-21", "source": "@merged"}
    for bad in ({"day": "21-11-2026"}, {"source": ""}, {"sum": float("nan")}):
        with pytest.raises(Invalid):
            validate(body(daily=[{**d, **bad}]))
    n = {"night": "2026-11-22", "source": "@merged", "minutes": {"asleep": 10}}
    validate(body(sleep_nights=[n]))
    for bad in ({"minutes": {"asleep": -1}}, {"night": "x"}, {"minutes": {"a": float("inf")}}):
        with pytest.raises(Invalid):
            validate(body(sleep_nights=[{**n, **bad}]))


def test_more_than_300_types_invalid():
    ss = [sample(uuid=f"3f2a0000-0000-4000-8000-{i:012x}", type=f"HKQuantityTypeIdentifierT{i}")
          for i in range(301)]
    with pytest.raises(Invalid):
        validate(body(samples=ss))


@pytest.mark.parametrize("kw", [{"start": "2026-11-22T03:12:00.5Z", "end": "2026-11-22T03:13:00Z"},
                                {"end": "2026-11-22T03:12:00.5Z"}])
def test_fractional_second_sample_timestamp_is_rejected(kw):
    with pytest.raises(Invalid):
        validate(body(samples=[sample(**kw)]))


def test_fractional_second_sleep_timestamps_are_rejected():
    night = {"night": "2026-11-21", "source": "@merged", "start": "2026-11-21T22:00:00.250Z",
             "end": "2026-11-22T06:00:00Z", "minutes": {}, "segments": []}
    with pytest.raises(Invalid):
        validate(body(sleep_nights=[night]))
    night.update(start="2026-11-21T22:00:00Z",
                 segments=[{"start": "2026-11-21T22:00:00Z", "end": "2026-11-21T23:00:00.1Z", "stage": "deep"}])
    with pytest.raises(Invalid):
        validate(body(sleep_nights=[night]))


@pytest.mark.parametrize("bad", [
    {"samples": [sample(uuid=U1 + "\n")]},
    {"samples": [sample(type=HR + "\n")]},
    {"deleted": [{"uuid": U1 + "\n", "type": HR}]},
    {"deleted": [{"uuid": U1, "type": HR + "\n"}]},
    {"daily": [{"type": HR, "day": "2026-11-21\n", "source": "@merged", "sum": 1, "unit": "count"}]},
    {"samples": [sample(start="2026-11-22T03:12:00Z\n")]},
    {"daily": [{"type": HR, "day": "2026-11-2١", "source": "@merged", "sum": 1, "unit": "count"}]},
])
def test_trailing_newline_and_unicode_digits_rejected(bad):
    with pytest.raises(Invalid):
        validate(body(**bad))


@pytest.mark.parametrize("day", ["2026-02-30", "2026-13-01", "0000-01-01"])
def test_impossible_calendar_day_rejected(day):
    with pytest.raises(Invalid):
        validate(body(daily=[{"type": HR, "day": day, "source": "@merged", "sum": 1, "unit": "count"}]))
    with pytest.raises(Invalid):
        validate(body(sleep_nights=[{"night": day, "source": "@merged", "minutes": {}, "segments": []}]))
