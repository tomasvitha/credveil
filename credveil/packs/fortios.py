"""FortiOS (FortiGate, FortiAnalyzer, FortiManager): `set <key> <value>` inside `config` paths.

SNMP v1/v2c community names are not masked here (design decision: not a secret); the cli and
routeros packs still mask them. `ENC` blobs are caught by the generic rules whatever the key.
"""
import re

from ..mask.generic import MASK
from ..mask.syntax import RegexRule
from . import ApiProfile, Pack, fingerprints, register

SECRET_KEYS = frozenset({
    'passwd', 'password', 'old-password', 'psksecret', 'psksecret-remote', 'ppk-secret',
    'private-key', 'secret', 'key', 'key-string', 'md5-key', 'authentication-key',
    'auth-pwd', 'priv-pwd', 'authpasswd', 'passphrase', 'sae-password', 'api-key'})
SECRET_SUFFIXES = ('-password', '-passwd', '-pwd', '-secret', '-private-key', '-key-string')
NOT_SECRET_PATHS = ('gui-dashboard',)        # dashboard widgets use `key` as a field name

SET_RE = re.compile(r'^(\s*set\s+)([A-Za-z0-9_-]+)(\s+)(.+?)\s*$')
IKE_KEY = RegexRule(re.compile(
    r'\b(?:SKEYSEED|SK_[a-z]{1,3}|PSK|psk|pre-?shared[- _]?key|shared secret|'
    r'enc[- _]key|auth[- _]key|integ[- _]key|ESP[- _]key|AH[- _]key)(?:\s*[:=]\s*|\s+)'
    r'(?!<masked|<hex)((?=[^\s"]*\d)[A-Za-z0-9+/=:._-]{8,})'), category='ike')  # a digit: not "mismatch"


def is_secret(path, key, val):
    """The FortiOS rule for one parsed `set key val` at config path `path`."""
    if val.startswith('ENC '):
        return True
    if any(n in path for n in NOT_SECRET_PATHS):
        return False
    return key in SECRET_KEYS or key.startswith('hostkey-') or key.endswith(SECRET_SUFFIXES)


class Lines:
    def __init__(self):
        self.path = []

    def line(self, line, counts):
        s = line.strip()
        if s.startswith('config '):
            self.path.append(s[7:].strip())
        elif s == 'end' and self.path:
            self.path.pop()
        m = SET_RE.match(line)
        if m and MASK not in m.group(4) and is_secret('/'.join(self.path), m.group(2), m.group(4)):
            counts['set'] += 1
            return m.group(1) + m.group(2) + m.group(3) + MASK
        return IKE_KEY.mask(line, counts)


def wrap(cmds, context):
    if context.get('vdom'):
        return ['config vdom', f'edit {context["vdom"]}'] + cmds + ['end']
    if context.get('global'):
        return ['config global'] + cmds + ['end']
    return cmds


register(Pack(
    name='fortios',
    aliases=('fortigate', 'fortianalyzer', 'faz', 'fortimanager', 'fmg'),
    line_masker=Lines,
    json_secret_keys=SECRET_KEYS,
    fingerprints=fingerprints(r'^#config-version=F', r'^config system global\s*$'),
    wrap_commands=wrap,
    api=ApiProfile(prefixes=('/api/v2/monitor/', '/api/v2/cmdb/', '/api/v2/log/'),
                   context_param='vdom', forbidden_params=('access_token',)),
))
