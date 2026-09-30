"""
kb.py -- knowledge base loader for reconote.

The actual service data lives in data/services.yaml (not in this file),
so it can be extended without touching any Python code. This module
just loads it once and exposes a lookup() function.
"""

from __future__ import annotations

import functools
from importlib import resources

import yaml

_DATA_PACKAGE = "reconote.data"
_DATA_FILE = "services.yaml"


@functools.lru_cache(maxsize=1)
def _load() -> dict:
    raw = resources.files(_DATA_PACKAGE).joinpath(_DATA_FILE).read_text(encoding="utf-8")
    data = yaml.safe_load(raw) or {}
    if "generic" not in data:
        raise ValueError(f"{_DATA_FILE} is missing the required 'generic' fallback entry")
    return data


def lookup(port: int, service_hint: str = "") -> dict:
    """Return the KB entry for a port, falling back to the generic entry."""
    data = _load()
    entry = data.get(str(port))
    if entry:
        return entry
    return data["generic"]


def all_known_ports() -> list[int]:
    """Every port number the KB has a specific (non-generic) entry for."""
    data = _load()
    return sorted(int(p) for p in data if p != "generic")


def reload() -> None:
    """Clear the cache so the next lookup() re-reads the YAML from disk.

    Mainly useful for tests, or if you edit services.yaml and want changes
    to take effect without restarting the interactive menu.
    """
    _load.cache_clear()
