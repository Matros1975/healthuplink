"""Contract data shipped inside the package: canonical units (contract/units.json) and the identifiers HealthKit
aggregates cumulatively (contract/cumulative.json). `test_packaging.py` keeps the packaged copies equal to the
contract. HU_UNITS_FILE and HU_CUMULATIVE_FILE point at other files instead."""

import json
import os
from importlib import resources


def _read(env_var: str, name: str):
    """Parsed JSON from the override file, else the packaged copy. Raises OSError or ValueError."""
    override = os.environ.get(env_var)
    if override:
        with open(override, encoding="utf-8") as f:
            return json.load(f)
    return json.loads((resources.files("healthuplink") / "data" / name).read_text(encoding="utf-8"))


def load_units(*, strict: bool = False) -> dict[str, str]:
    """Canonical unit per identifier. An unreadable or malformed file gives {} (no unit filtering), or raises
    OSError/ValueError when `strict`."""
    try:
        data = _read("HU_UNITS_FILE", "units.json")
        if not isinstance(data, dict):
            raise ValueError("units file is not a JSON object")
    except (OSError, ValueError):
        if strict:
            raise
        return {}
    return {k: v for k, v in data.items() if isinstance(k, str) and isinstance(v, str)}


def load_cumulative() -> set[str]:
    """Identifiers HealthKit aggregates cumulatively. An unreadable or malformed file gives an empty set."""
    try:
        data = _read("HU_CUMULATIVE_FILE", "cumulative.json")
    except (OSError, ValueError):
        return set()
    return {v for v in data if isinstance(v, str)} if isinstance(data, list) else set()
