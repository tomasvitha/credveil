"""Transports to devices. Each returns a Result; none ever puts a credential on a command line.

The CLI looks transports up here by name ('ssh', 'https'), never from the inventory, so the
inventory cannot make credveil run an arbitrary local program. Tests swap one in with `use()`.
"""
import contextlib
from dataclasses import dataclass


class TransportError(Exception):
    """Client missing, timeout, TLS pin mismatch (exit 93)."""


@dataclass
class Result:
    stdout: str
    stderr: str
    rc: int


def decode(b):
    if b is None:
        return ''
    return b.decode('utf-8', 'replace') if isinstance(b, bytes) else b


_REGISTRY = {}


def register(name, transport):
    _REGISTRY[name] = transport


def get(name):
    if not _REGISTRY:
        from . import https, ssh  # noqa: F401  (they register themselves)
    return _REGISTRY[name]


@contextlib.contextmanager
def use(name, transport):
    """Replace a transport for the duration of a test."""
    get(name)
    old = _REGISTRY[name]
    _REGISTRY[name] = transport
    try:
        yield
    finally:
        _REGISTRY[name] = old
