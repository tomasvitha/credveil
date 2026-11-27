"""The inventory: one loader for the CLI, the guard and the output net.

$CREDVEIL_HOME/inventory.toml (default ~/.config/credveil/) names devices and the files that
hold their credentials; it holds no secret itself. See inventory.example.toml.
"""
import os
import tomllib
from dataclasses import dataclass, field

CRED_KEYS = ('password_file', 'token_file', 'key_file')


class UsageError(Exception):
    """Bad inventory, alias or arguments (exit 92)."""


def home():
    return os.path.expanduser(os.environ.get('CREDVEIL_HOME') or '~/.config/credveil')


def _resolve(base, p):
    if not p:
        return None
    p = os.path.expanduser(p)
    return p if os.path.isabs(p) else os.path.join(base, p)


@dataclass
class Inventory:
    home: str
    devices: dict
    guard_hosts: list = field(default_factory=list)
    guard_protect: list = field(default_factory=list)

    @property
    def path(self):
        return os.path.join(self.home, 'inventory.toml')

    def device(self, alias):
        from . import packs
        d = self.devices.get(alias)
        if d is None:
            raise UsageError(f'unknown device {alias!r}; known: {", ".join(sorted(self.devices)) or "none"}')
        d = dict(d, alias=alias)
        for k in ('host', 'vendor'):
            if not d.get(k):
                raise UsageError(f'device {alias!r}: missing {k}')
        packs.get(d['vendor'])  # validates the vendor name
        for k in CRED_KEYS:
            d[k] = _resolve(self.home, d.get(k))
        return d

    def credential_files(self):
        """Every credential file the inventory names, plus creds/ and [guard] protect."""
        out = [os.path.join(self.home, 'creds')] + [os.path.expanduser(p) for p in self.guard_protect]
        for d in self.devices.values():
            out += [_resolve(self.home, d[k]) for k in CRED_KEYS if d.get(k)]
        return out

    def hosts(self):
        return [h for h in self.guard_hosts + [d.get('host', '') for d in self.devices.values()] if h]

    def known_secrets(self):
        """Passwords and tokens of every device: the values that must never appear in output."""
        out = []
        for d in self.devices.values():
            for k in ('password_file', 'token_file'):
                v = read_secret(_resolve(self.home, d.get(k)), missing_ok=True)
                if v:
                    out.append(v)
        return out


def read_secret(path, missing_ok=False):
    if not path:
        return None
    try:
        with open(path, encoding='utf-8') as fh:
            return fh.read().strip()
    except FileNotFoundError:
        if missing_ok:
            return None
        raise


def load(base=None, required=True):
    """The inventory, or None when there is none and required is False."""
    base = base or home()
    path = os.path.join(base, 'inventory.toml')
    if not os.path.exists(path):
        if required:
            raise UsageError(f'no inventory at {path} (copy inventory.example.toml there)')
        return None
    with open(path, 'rb') as fh:
        raw = tomllib.load(fh)
    guard = raw.get('guard', {})
    return Inventory(home=base, devices=raw.get('device', {}),
                     guard_hosts=list(guard.get('hosts', [])), guard_protect=list(guard.get('protect', [])))
