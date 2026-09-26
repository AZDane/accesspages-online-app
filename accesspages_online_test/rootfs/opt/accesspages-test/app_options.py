"""Validated HA app options; contains no provider or HA credentials."""
import json
from pathlib import Path
import re

FILTERS = ("include_domains", "include_areas", "exclude_domains", "exclude_entities")


def resource_isolation(options):
    value = options.get('resource_isolation', 'page')
    if value not in ('page', 'guest'):
        raise ValueError('Resource isolation must be page or guest')
    return value


def read_options(root):
    path = Path(root) / "options.json"
    if not path.exists():
        return {}
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError("Invalid app configuration")
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
