"""MikroTik RouterOS: `key=value` parameters under a `/menu` path."""
from ..mask.syntax import AssignRules
from . import Pack, fingerprints, register

PARAMS = AssignRules(
    keys=frozenset({
        'password', 'secret', 'passphrase', 'private-key', 'preshared-key', 'pre-shared-key',
        'wpa-pre-shared-key', 'wpa2-pre-shared-key', 'authentication-key', 'auth-key',
        'authentication-password', 'encryption-password', 'auth-password', 'priv-password',
        'radius-secret', 'shared-secret', 'psk'}),
    suffixes=('-password', '-secret', '-key'),
    not_secret=frozenset({'public-key', 'host-key', 'key-size', 'auth-key-id'}),
)
MENU_WORDS = ('add', 'set', 'remove', 'print', 'edit', 'export')


class Lines:
    def __init__(self):
        self.menu = ''

    def line(self, line, counts):
        s = line.strip()
        if s.startswith('/'):
            parts = []
            for t in s.split():
                if '=' in t or t in MENU_WORDS or t.startswith('['):
                    break
                parts.append(t)
            self.menu = '/' + ' '.join(parts).replace('/', ' ').strip()
        community = self.menu.startswith('/snmp community')
        return PARAMS.mask(line, counts, extra=lambda k: community and k == 'name')


register(Pack(
    name='routeros',
    aliases=('mikrotik',),
    line_masker=Lines,
    json_secret_keys=PARAMS.keys,
    fingerprints=fingerprints(r'^# .* by RouterOS \d'),
))
