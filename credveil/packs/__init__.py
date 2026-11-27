"""Vendor packs: everything credveil knows about one kind of system, one module per system.

A pack is a `Pack` registered at import. Every module in this package is imported on first use,
so adding a system means adding one file (and its test fixture); nothing else changes.
"""
import importlib
import pkgutil
import re
from dataclasses import dataclass
from typing import Callable, Optional


@dataclass(frozen=True)
class ApiProfile:
    """How `credveil get` talks to the system's REST API (GET only)."""
    prefixes: tuple                 # allowed path prefixes
    auth_header: str = 'Authorization'
    auth_scheme: str = 'Bearer'     # header value is f'{scheme} {token}', or the bare token if ''
    context_param: str = ''         # query parameter that --vdom (context) maps to
    forbidden_params: tuple = ()    # never accepted from -p (e.g. a token in the query string)


@dataclass(frozen=True)
class Pack:
    name: str
    aliases: tuple
    line_masker: Callable[[], object]   # factory: object with .line(line, counts) -> str, state per stream
    json_secret_keys: frozenset = frozenset()
    fingerprints: tuple = ()            # compiled regexes that identify this system's raw text
    wrap_commands: Optional[Callable] = None  # (cmds, context: dict) -> cmds
    api: Optional[ApiProfile] = None


_PACKS = {}
_ALIASES = {}


def register(pack):
    for name in (pack.name,) + tuple(pack.aliases):
        if _ALIASES.get(name, pack.name) != pack.name:
            raise ValueError(f'vendor alias {name!r} registered twice')
        _ALIASES[name] = pack.name
    _PACKS[pack.name] = pack
    return pack


def _discover():
    if not _PACKS:
        for mod in pkgutil.iter_modules(__path__):
            importlib.import_module(f'{__name__}.{mod.name}')


def get(vendor):
    _discover()
    name = _ALIASES.get((vendor or 'generic').lower())
    if name is None:
        raise ValueError(f'unknown vendor {vendor!r}; known: {", ".join(sorted(_ALIASES))}')
    return _PACKS[name]


def all_packs():
    _discover()
    return list(_PACKS.values())


def detect(text):
    """The pack whose fingerprint matches raw text (a config export), or None."""
    head = text[:4096]
    for p in all_packs():
        if any(rx.search(head) for rx in p.fingerprints):
            return p
    return None


def fingerprints(*patterns):
    return tuple(re.compile(p, re.M) for p in patterns)
