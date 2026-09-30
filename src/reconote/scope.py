"""
scope.py -- authorized-target allowlist for reconote.

If a scope file is present, reconote refuses to scan any target that
doesn't resolve into one of the listed networks. This is a safety rail
against fat-fingering a target -- accidentally scanning a box you don't
have permission for, especially once this tool is used for real
engagements and not just CTF/lab boxes.

Scope file format: one CIDR or bare IP per line, '#' starts a comment,
blank lines ignored. Example:

    # engagement: acme-corp-2026
    10.10.10.0/24
    192.168.56.10
"""

from __future__ import annotations

import ipaddress
from pathlib import Path

DEFAULT_SCOPE_FILENAMES = ("scope.txt", ".reconote-scope.txt")


class ScopeError(Exception):
    """Raised when a target is not covered by an active scope file."""


def find_default_scope_file(start_dir: str | Path = ".") -> Path | None:
    """Look for a scope file in the given directory. Returns None if absent."""
    start = Path(start_dir)
    for name in DEFAULT_SCOPE_FILENAMES:
        candidate = start / name
        if candidate.is_file():
            return candidate
    return None


def load_scope(path: str | Path) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Parse a scope file into a list of networks. Raises ValueError on a bad line."""
    networks = []
    text = Path(path).read_text(encoding="utf-8")
    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        try:
            networks.append(ipaddress.ip_network(line, strict=False))
        except ValueError as exc:
            raise ValueError(f"{path}:{lineno}: invalid CIDR/IP {raw_line!r} ({exc})") from exc
    return networks


def in_scope(ip: str, networks: list) -> bool:
    """True if the given IP address falls inside any of the networks."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in networks)


def check(target_ip: str, scope_path: str | Path | None) -> None:
    """Raise ScopeError if a scope file is active and target_ip isn't covered.

    A missing/None scope_path means "no scope file configured" -- this is
    intentionally permissive (reconote works fine for casual CTF use
    without one), the enforcement only kicks in once a scope file exists.
    """
    if scope_path is None:
        return
    networks = load_scope(scope_path)
    if not networks:
        return
    if not in_scope(target_ip, networks):
        allowed = ", ".join(str(n) for n in networks)
        raise ScopeError(
            f"{target_ip} is not covered by the scope file ({scope_path}). "
            f"Allowed ranges: {allowed}. "
            f"Add it to the scope file if you're authorized to test it, "
            f"or pass --no-scope-check to bypass (not recommended)."
        )
