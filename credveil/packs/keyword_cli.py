"""Keyword-then-value CLIs: Cisco IOS/IOS-XE/NX-OS, Aruba AOS-CX/AOS-S, HPE Comware, Arista EOS,
Juniper Junos (set and curly format). Running configs and the common `show` outputs."""
import re

from ..mask.syntax import KeywordRules, RegexRule, TableMasker
from . import Pack, fingerprints, register

HASH_ALGOS = frozenset({'md5', 'sha', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512',
                        'aes', 'aes128', 'aes192', 'aes256', 'aes-128', 'aes-192', 'aes-256',
                        'des', '3des', 'des56'})

WORDS = KeywordRules(
    secret_words=frozenset({
        'password', 'passwd', 'secret', 'key', 'key-string', 'pre-shared-key', 'psk', 'passphrase',
        'encrypted-password', 'authentication-key', 'auth-key', 'md5', 'message-digest-key',
        'community', 'auth-pass', 'priv-pass', 'auth-password', 'priv-password', 'shared-secret',
        'wpa-passphrase', 'wpa-psk', 'ciphertext', 'tacacs-key', 'radius-key', 'server-key',
        'ike-psk', 'secret-key', 'authentication-password', 'privacy-password', 'enable-password',
        'auth', 'priv', 'authentication-mode', 'privacy-mode'}),
    type_tokens=frozenset({
        '0', '3', '4', '5', '6', '7', '8', '9', '128', '192', '256', 'ciphertext', 'plaintext',
        'encrypted', 'hash', 'cipher', 'simple', 'irreversible-cipher', 'ascii', 'ascii-text',
        'hex', 'hexadecimal', 'unencrypted', 'local', 'remote'} | HASH_ALGOS),
    not_after={
        'key': {'chain', 'config-key', 'exchange', 'generate', 'pair', 'rsa', 'ec', 'zeroize',
                'storage', 'source', 'id', 'timeout', 'recovery', 'type', 'string', 'mypubkey',
                'pubkey', 'import', 'export', 'decrypt'},
        'password': {'manager', 'operator', 'complexity', 'encryption', 'policy', 'minimum-length',
                     'history', 'aging', 'recovery', 'all', 'port-access', 'include-credentials'},
        'pre-shared-key': {'address', 'hostname'},
        'community': {'read', 'write'},            # Comware `community read cipher <hash>`
    },
    # `auth`/`priv` name a secret only in SNMPv3 form: `auth sha <pw>`, `priv aes 128 <pw>`
    needs_next={'auth': HASH_ALGOS, 'priv': HASH_ALGOS},
    skip_prefixes=('description', 'remark', 'alias'),
)

RULES = (
    # positional community: `snmp-server host <h> [traps|informs] [vrf v] [version 1|2c] <community>`
    RegexRule(re.compile(r'^\s*snmp-server host \S+(?: (?:traps|informs))?(?: vrf \S+)?'
                         r'(?: version (?:1|2c))? (?!version\b|traps\b|informs\b|vrf\b)(\S+)'),
              category='community'),
    # HSRP / VRRP / GLBP plain-text authentication
    RegexRule(re.compile(r'^\s*(?:standby|vrrp|glbp)(?: \d+)? authentication (?:text )?'
                         r'(?!md5\b|text\b|key-chain\b)(\S+)\s*$'), category='fhrp'),
    RegexRule(re.compile(r'\b(?:sha1|sha256|plaintext)\s+"([^"]+)"'), category='word'),  # AOS-S
    RegexRule(re.compile(r'"([^"]+)"(?=[^"]*## SECRET-DATA)'), category='word'),       # Junos
)
TABLE_COLUMNS = ('preshared key', 'pre-shared key', 'psk', 'password', 'secret', 'shared secret',
                 'key string', 'community', 'community name')


class Lines:
    def __init__(self):
        self.table = TableMasker(TABLE_COLUMNS)

    def line(self, line, counts):
        line = self.table.mask(line, counts)
        for r in RULES:
            line = r.mask(line, counts)
        return WORDS.mask(line, counts)


register(Pack(
    name='cli',
    aliases=('ios', 'iosxe', 'ios-xe', 'nxos', 'nx-os', 'cisco', 'aoscx', 'aos-cx', 'arubacx',
             'aos-s', 'procurve', 'comware', 'arista', 'eos', 'junos', 'juniper'),
    line_masker=Lines,
    fingerprints=fingerprints(
        r'^Building configuration\.\.\.', r'^Current configuration : \d+ bytes',
        r'^! Last configuration change', r'^!Command: show running-config', r'^!Version ArubaOS-CX',
        r'^; \w+ Configuration Editor', r'^ ?version \d+\.\d+\.\d+, Release', r'^## Last commit:',
        r'^set version \S+', r'^! device: \S+ \(.*EOS'),
))
