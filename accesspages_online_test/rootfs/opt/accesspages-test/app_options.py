"""Validated HA app options; contains no provider or HA credentials."""
import json
from pathlib import Path
import re

FILTERS = ("include_domains", "include_areas", "exclude_domains", "exclude_entities")


def read_options(root):
    path = Path(root) / "options.json"
    if not path.exists():
        return {}
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError("Invalid app configuration")
    return value


def device_mode(options, *, demo_only=False, default="demo"):
    if demo_only:
        return "demo"
    value = options.get("device_mode", default)
    if value not in {"demo", "homeassistant"}:
        raise ValueError("Device data must be demo or homeassistant")
    return value


def discovery_environment(options):
    result = {}
    for name in FILTERS:
        raw = options.get(name, "")
        if not isinstance(raw, str) or len(raw) > 32768:
            raise ValueError(f"{name} must contain comma-separated identifiers")
        values = [value.strip() for value in raw.split(",") if value.strip()]
        if len(values) > 256:
            raise ValueError(f"{name} must contain at most 256 identifiers")
        if any(not isinstance(value, str) or len(value) > 128 or not re.fullmatch(r"[a-z0-9_.-]+", value) for value in values):
            raise ValueError(f"{name} contains an invalid identifier")
        result["HA_ENTITY_" + name.upper()] = ",".join(dict.fromkeys(values))
    return result
