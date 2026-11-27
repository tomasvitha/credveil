#!/usr/bin/env python3
"""One-way masking of secrets in network-device output before an LLM reads it.

    from secretmask import Masker, mask_json
    m = Masker('fortios', known=[password, token])
    clean = m.text(raw)            # str -> str; m.counts says what was masked
    m.leaks(clean)                 # line numbers where a known secret survived

The single source of the secret rules shared by credveil.py (live SSH/API output), the credveil hooks
and any tool that imports it. Rules come in layers:

  generic   every vendor: PEM blocks (private keys masked, certificates reduced to a sha),
            hex-dump lines (Cisco certificate chains, packet dumps), FortiOS `ENC` blobs,
            crypt/Junos/Comware hashes, `key=N <hex>` session keys, 0x hex keys, hex runs
            of 32+ digits, and a base64 backstop for long mixed-case runs.
  fortios   `set <secret-key> <value>` (FortiOS key names), IKE debug key material
            (SKEYSEED, SK_*, PSK). SNMP v1/v2c community names stay (design decision: not a
            secret); the cli and routeros packs still mask them.
  cli       keyword-then-value statements of Cisco IOS/NX-OS, Aruba AOS-CX/AOS-S, HPE Comware,
            Arista and Juniper set format (`secret 9 <hash>`, `ciphertext <blob>`, communities).
  routeros  MikroTik `key=value` parameters (`password=`, `secret=`, `*-key=` …).

Masking is a denylist and therefore best-effort: a secret it misses is a bug to fix here,
with a test case. Callers that know the actual secret (credveil.py knows the password and token
it loaded) pass it as `known=` and must withhold output for which `leaks()` is non-empty.

Stdlib only.
"""
import base64
import hashlib
import re
import urllib.parse
from collections import Counter

MASK = '<masked>'

# ---------------------------------------------------------------------------------------------
# Vendor names -> rule pack
# ---------------------------------------------------------------------------------------------
PACKS = ('generic', 'fortios', 'cli', 'routeros')
VENDORS = {
    'generic': 'generic',
    'fortios': 'fortios', 'fortigate': 'fortios', 'fortianalyzer': 'fortios', 'faz': 'fortios',
    'fortimanager': 'fortios', 'fmg': 'fortios',
    'ios': 'cli', 'iosxe': 'cli', 'ios-xe': 'cli', 'nxos': 'cli', 'nx-os': 'cli', 'cisco': 'cli',
    'aoscx': 'cli', 'aos-cx': 'cli', 'arubacx': 'cli', 'aos-s': 'cli', 'procurve': 'cli',
    'comware': 'cli', 'arista': 'cli', 'eos': 'cli', 'junos': 'cli', 'juniper': 'cli',
    'cli': 'cli',
    'routeros': 'routeros', 'mikrotik': 'routeros',
}


def pack_of(vendor):
    try:
        return VENDORS[(vendor or 'generic').lower()]
    except KeyError:
        raise ValueError(f'unknown vendor {vendor!r}; known: {", ".join(sorted(VENDORS))}')


def _sha(text):
    return hashlib.sha256(text.encode('utf-8', 'replace')).hexdigest()[:8]


# ---------------------------------------------------------------------------------------------
# Generic rules (every vendor)
# ---------------------------------------------------------------------------------------------
PEM_BEGIN_RE = re.compile(r'-----BEGIN ([A-Z0-9 ]+)-----')
PEM_INLINE_RE = re.compile(r'-----BEGIN ([A-Z0-9 ]+)-----.*?-----END \1-----', re.S)
ENC_RE = re.compile(r'\bENC\s+(?!<masked)[A-Za-z0-9+/=]{8,}')
HASH_RE = re.compile(r'"?\$(?:1|5|6|8|9|c|h|y|2[aby]?)\$[^\s"]*"?')  # crypt, Junos $9$, Comware
HEX0X_RE = re.compile(r'\b0x[0-9A-Fa-f]{16,}\b')  # NX-OS SNMPv3 localized keys
KEYHEX_RE = re.compile(r'\b((?:key|Key|KEY)=\d+\s+)[0-9A-Fa-f]{8,}')  # FortiOS tunnel list
LONGHEX_RE = re.compile(r'(?<![0-9A-Za-z])[0-9A-Fa-f]{32,}(?![0-9A-Za-z])')
B64_RE = re.compile(r'(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])')
QUOTED_HASH_RE = re.compile(r'\b(sha1|sha256|plaintext)\s+"[^"]*"')  # ProCurve include-credentials
# A line that is nothing but groups of hex digits: certificate chains, packet dumps.
HEXLINE_RE = re.compile(r'^\s*(?:0x[0-9a-fA-F]+:?\s+)?(?:[0-9A-Fa-f]{2,8}\s+){2,}[0-9A-Fa-f]{2,8}\s*$')


def _b64_suspicious(tok):
    up = sum(c.isupper() for c in tok)
    lo = sum(c.islower() for c in tok)
    di = sum(c.isdigit() for c in tok)
    return up >= 3 and lo >= 3 and di >= 3


# Identity fields carry user and group names, which troubleshooting needs. The
# broad hex/base64 backstops skip a value right after one of these keys (a SAML user id can be
# 32 hex); the explicit secret forms (PEM, ENC, crypt hashes, known credentials) still apply.
IDENTITY_KEYS = frozenset({
    'user', 'username', 'user-name', 'user_name', 'xauthuser', 'xauth-user', 'xauth_user',
    'srcuser', 'dstuser', 'unauthuser', 'login', 'group', 'groups', 'xauthgroup', 'usergroup'})
IDENTITY_CTX_RE = re.compile(
    r'(?i)(?:^|[\s,{;(\[])["\']?(?:xauth[ _-]?user|'
    + '|'.join(re.escape(k) for k in sorted(IDENTITY_KEYS, key=len, reverse=True))
    + r')["\']?\s*[=:]\s*["\']?$')


def _identity_value(line, start):
    return bool(IDENTITY_CTX_RE.search(line[max(0, start - 40):start]))


def mask_inline_generic(line, counts, backstops=True):
    """Single-line generic rules. Order matters: specific patterns before the broad ones.

    backstops=False (an identity value from JSON) skips the broad hex/base64 rules."""
    def sub(rx, repl, s, cat):
        new, n = rx.subn(repl, s)
        if n:
            counts[cat] += n
        return new

    def backstop(rx, mask_it, s, cat):
        n = 0

        def repl(m):
            nonlocal n
            if _identity_value(s, m.start()) or not mask_it(m.group(0)):
                return m.group(0)
            n += 1
            return '<masked:b64>' if cat == 'b64' else f'<hex:{len(m.group(0))}>'
        new = rx.sub(repl, s)
        if n:
            counts[cat] += n
        return new

    line = sub(PEM_INLINE_RE, lambda m: _pem_marker(m.group(1), m.group(0)), line, 'pem')
    line = sub(ENC_RE, 'ENC ' + MASK, line, 'enc')
    line = sub(HASH_RE, MASK, line, 'hash')
    line = sub(HEX0X_RE, MASK, line, 'hex')
    line = sub(KEYHEX_RE, lambda m: m.group(1) + MASK, line, 'session-key')
    if backstops:
        line = backstop(LONGHEX_RE, lambda t: True, line, 'hex')
        if B64_RE.search(line):
            line = backstop(B64_RE, _b64_suspicious, line, 'b64')
    return line


def _pem_marker(label, block):
    if 'PRIVATE' in label or 'ENCRYPTED' in label:
        return f'<masked:{label.lower().replace(" ", "-")}>'
    return f'<pem:{label.lower().replace(" ", "-")} sha={_sha(block)}>'


# ---------------------------------------------------------------------------------------------
# FortiOS rules
# ---------------------------------------------------------------------------------------------
FORTI_SECRET_KEYS = {
    'passwd', 'password', 'old-password', 'psksecret', 'psksecret-remote', 'ppk-secret',
    'private-key', 'secret', 'key', 'key-string', 'md5-key', 'authentication-key',
    'auth-pwd', 'priv-pwd', 'authpasswd', 'passphrase', 'sae-password'}
FORTI_SECRET_SUFFIXES = ('-password', '-passwd', '-pwd', '-secret', '-private-key')
FORTI_NOT_SECRET_PATHS = ('gui-dashboard',)  # dashboard filters use `key` as a field name


def fortios_is_secret(path, key, val):
    """The FortiOS rule for one parsed `set key val` at config path `path`."""
    if val.startswith('ENC '):
        return True
    if any(n in path for n in FORTI_NOT_SECRET_PATHS):
        return False
    return key in FORTI_SECRET_KEYS or key.startswith('hostkey-') or key.endswith(FORTI_SECRET_SUFFIXES)


FORTI_SET_RE = re.compile(r'^(\s*set\s+)([A-Za-z0-9_-]+)(\s+)(.+?)\s*$')
IKE_KEY_RE = re.compile(
    r'\b(SKEYSEED|SK_[a-z]{1,3}|PSK|psk|pre-?shared[- _]?key|shared secret|'
    r'enc[- _]key|auth[- _]key|integ[- _]key|ESP[- _]key|AH[- _]key)(\s*[:=]\s*|\s+)'
    r'(?!<masked|<hex)((?=[^\s"]*\d)[A-Za-z0-9+/=:._-]{8,})')  # a value with a digit: not "mismatch"


def mask_fortios_line(line, ctx, counts):
    s = line.strip()
    if s.startswith('config '):
        ctx.append(s[7:].strip())
    elif s == 'end' and ctx:
        ctx.pop()
    m = FORTI_SET_RE.match(line)
    if m:
        key, val = m.group(2), m.group(4)
        path = '/'.join(ctx)
        if fortios_is_secret(path, key, val) and MASK not in val:
            counts['set'] += 1
            return m.group(1) + key + m.group(3) + MASK
    new, n = IKE_KEY_RE.subn(lambda mm: mm.group(1) + mm.group(2) + MASK, line)
    if n:
        counts['ike'] += n
    return new


# ---------------------------------------------------------------------------------------------
# Keyword-then-value CLIs (Cisco, Aruba, Comware, Arista, Junos set)
# ---------------------------------------------------------------------------------------------
SECRET_WORDS = {
    'password', 'passwd', 'secret', 'key', 'key-string', 'pre-shared-key', 'psk', 'passphrase',
    'encrypted-password', 'authentication-key', 'auth-key', 'md5', 'message-digest-key',
    'community', 'auth-pass', 'priv-pass', 'auth-password', 'priv-password', 'shared-secret',
    'wpa-passphrase', 'ciphertext', 'tacacs-key', 'radius-key', 'server-key', 'ike-psk',
    'authentication-password', 'privacy-password', 'enable-password', 'priv',
}
# Tokens between a secret keyword and its value that only say how the value is encoded.
TYPE_TOKENS = {
    '0', '3', '4', '5', '6', '7', '8', '9', 'ciphertext', 'plaintext', 'encrypted', 'hash', 'cipher',
    'simple', 'ascii-text', 'hexadecimal', 'unencrypted', 'sha', 'sha1', 'md5', 'local',
    'aes', 'aes-128', 'aes128', 'aes-256', 'des', '3des',
}
# Words that look like SECRET_WORDS but introduce a non-secret value.
NOT_SECRET_AFTER = {
    'key': {'chain', 'config-key', 'exchange', 'generate', 'pair', 'rsa', 'ec', 'zeroize',
            'storage', 'source', 'id', 'timeout', 'recovery', 'type', 'string'},
    'password': {'manager', 'operator', 'complexity', 'encryption', 'policy', 'minimum-length',
                 'history', 'aging', 'recovery', 'all', 'port-access', 'include-credentials'},
    'secret': set(),
    'community': {'read', 'write'},  # Comware `snmp-agent community read cipher <hash>`
}
PEM_PRIV_RE = re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----')


def mask_words(line):
    """Mask the value following any secret keyword in a space-separated statement.

    The keyword-then-value rule for line-oriented CLIs.
    """
    if PEM_PRIV_RE.search(line):
        return PEM_PRIV_RE.split(line)[0] + MASK
    line = HASH_RE.sub(MASK, line)
    line = HEX0X_RE.sub(MASK, line)
    line = QUOTED_HASH_RE.sub(lambda m: f'{m.group(1)} {MASK}', line)
    if '## SECRET-DATA' in line:
        line = re.sub(r'"[^"]*"', '"' + MASK + '"', line).replace('## SECRET-DATA', '').rstrip()
    tok = line.split(' ')
    out, i = [], 0
    while i < len(tok):
        t = tok[i]
        out.append(t)
        low = t.lower()
        if low in SECRET_WORDS and i + 1 < len(tok):
            nxt = tok[i + 1].lower()
            if nxt in NOT_SECRET_AFTER.get(low, set()) or nxt == MASK or nxt == f'"{MASK}"':
                i += 1
                continue
            j = i + 1
            while j < len(tok) - 1 and tok[j].lower() in TYPE_TOKENS:
                out.append(tok[j])
                j += 1
            if tok[j] not in (MASK, f'"{MASK}"'):
                out.append(MASK)
                i = j + 1
                continue
            i = j
            continue
        i += 1
    return ' '.join(out)


def mask_cli_line(line, counts):
    stripped = line.lstrip(' ')
    if not stripped:
        return line
    lead = line[:len(line) - len(stripped)]
    new = mask_words(stripped)
    if new != stripped:
        counts['word'] += 1
    return lead + new


# ---------------------------------------------------------------------------------------------
# MikroTik RouterOS
# ---------------------------------------------------------------------------------------------
ROS_SECRET_KEYS = {
    'password', 'secret', 'passphrase', 'private-key', 'preshared-key', 'pre-shared-key',
    'wpa-pre-shared-key', 'wpa2-pre-shared-key', 'authentication-key', 'auth-key',
    'authentication-password', 'encryption-password', 'auth-password', 'priv-password',
    'radius-secret', 'shared-secret', 'psk',
}
ROS_NOT_SECRET = {'public-key', 'host-key', 'key-size', 'auth-key-id'}
ROS_KV_RE = re.compile(r'(?P<k>[A-Za-z0-9-]+)=(?P<v>"(?:[^"\\]|\\.)*"|\S+)')


def mask_ros(menu, stmt):
    """Mask secret `key=value` parameters of one RouterOS statement under menu `menu`."""
    def repl(m):
        k = m.group('k')
        secret = k in ROS_SECRET_KEYS or k.endswith(('-password', '-secret', '-key')) and k not in ROS_NOT_SECRET
        if menu.startswith('/snmp community') and k == 'name':
            secret = True
        return f'{k}={MASK}' if secret else m.group(0)
    return ROS_KV_RE.sub(repl, stmt)


def mask_ros_line(line, state, counts):
    s = line.strip()
    if s.startswith('/'):
        parts = []
        for t in s.split():
            if '=' in t or t in ('add', 'set', 'remove', 'print', 'edit', 'export') or t.startswith('['):
                break
            parts.append(t)
        state['menu'] = '/' + ' '.join(parts).replace('/', ' ').strip()
    new = mask_ros(state.get('menu', ''), line)
    if new != line:
        counts['kv'] += 1
    return new


# ---------------------------------------------------------------------------------------------
# The streaming masker
# ---------------------------------------------------------------------------------------------
class Masker:
    """Line-oriented masker with state for multi-line blocks (PEM, hex dumps, config paths)."""

    def __init__(self, vendor='generic', known=()):
        self.pack = pack_of(vendor)
        self.known = [k for k in (s.strip() for s in known if s) if len(k) >= 4]
        self.counts = Counter()
        self._ctx = []           # FortiOS config path
        self._ros = {}           # RouterOS menu
        self._pem = None         # [prefix, label, lines] while inside a PEM block
        self._hexrun = 0         # consecutive hex-dump lines being collapsed
        self._hexlead = ''
        self._identity = False   # set by mask_json for identity-keyed values

    # one physical line in, zero or more lines out
    def feed(self, line):
        out = []
        if self._pem is not None:
            prefix, label, body = self._pem
            body.append(line)
            end = f'-----END {label}-----'
            if end in line:
                rest = line.split(end, 1)[1]
                out.append(prefix + _pem_marker(label, '\n'.join(body)) + rest)
                self.counts['pem'] += 1
                self._pem = None
            return out
        m = PEM_BEGIN_RE.search(line)
        if m and f'-----END {m.group(1)}-----' not in line[m.end():]:
            out.extend(self._flush_hex())
            self._pem = [line[:m.start()], m.group(1), [line[m.start():]]]
            return out
        if HEXLINE_RE.match(line) and re.search(r'[A-Fa-f]', line):
            if not self._hexrun:
                self._hexlead = line[:len(line) - len(line.lstrip())]
            self._hexrun += 1
            return out
        out.extend(self._flush_hex())
        out.append(self._line(line))
        return out

    def _flush_hex(self):
        if not self._hexrun:
            return []
        n, self._hexrun = self._hexrun, 0
        self.counts['hexdump'] += 1
        return [f'{self._hexlead}<hexdump:{n} lines>']

    def _line(self, line):
        if self.pack == 'fortios':
            line = mask_fortios_line(line, self._ctx, self.counts)
        elif self.pack == 'cli':
            line = mask_cli_line(line, self.counts)
        elif self.pack == 'routeros':
            line = mask_ros_line(line, self._ros, self.counts)
        line = mask_inline_generic(line, self.counts, backstops=not self._identity)
        return self._mask_known(line)

    def _mask_known(self, line):
        for k in self.known:
            for v in _variants(k):
                if v in line:
                    line = line.replace(v, '<masked:known>')
                    self.counts['known'] += 1
        return line

    def close(self):
        out = self._flush_hex()
        if self._pem is not None:  # unterminated block: never let the body through
            prefix, label, _ = self._pem
            out.append(prefix + f'<masked:unterminated-{label.lower().replace(" ", "-")}>')
            self.counts['pem'] += 1
            self._pem = None
        return out

    def text(self, raw):
        if not raw:
            return raw
        trailing_nl = raw.endswith('\n')
        out = []
        for line in raw.replace('\r\n', '\n').replace('\r', '\n').split('\n')[:-1 if trailing_nl else None]:
            out.extend(self.feed(line))
        out.extend(self.close())
        return '\n'.join(out) + ('\n' if trailing_nl else '')

    def leaks(self, text):
        """1-based line numbers where any known secret (or an encoding of it) still appears."""
        hits = []
        for i, line in enumerate(text.split('\n'), 1):
            if any(v in line for k in self.known for v in _variants(k)):
                hits.append(i)
        return hits

    def summary(self):
        return ', '.join(f'{k}={v}' for k, v in sorted(self.counts.items())) or 'nothing'


def _variants(secret):
    vs = {secret, urllib.parse.quote(secret, safe=''), urllib.parse.quote_plus(secret)}
    b = base64.b64encode(secret.encode()).decode()
    vs.add(b)
    vs.add(b.rstrip('='))
    return [v for v in vs if len(v) >= 4]


# ---------------------------------------------------------------------------------------------
# JSON (REST API bodies)
# ---------------------------------------------------------------------------------------------
JSON_SECRET_KEYS = (FORTI_SECRET_KEYS | ROS_SECRET_KEYS | {
    'psk', 'pre-shared-key', 'shared-secret', 'community', 'token', 'api-key', 'apikey',
    'access_token', 'client-secret', 'client_secret', 'ciphertext', 'session_key'})
JSON_SECRET_SUFFIXES = FORTI_SECRET_SUFFIXES + ('_password', '_secret', '-token', '_token', '-psk')


def mask_json(obj, masker):
    """Mask a parsed JSON value in place-safe fashion (returns a new structure)."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            kl = str(k).lower()
            if (kl in JSON_SECRET_KEYS or kl.endswith(JSON_SECRET_SUFFIXES)) and isinstance(v, str) and v:
                masker.counts['json-key'] += 1
                out[k] = MASK
            elif kl in IDENTITY_KEYS and isinstance(v, str):
                masker._identity = True
                try:
                    out[k] = masker.text(v)
                finally:
                    masker._identity = False
            else:
                out[k] = mask_json(v, masker)
        return out
    if isinstance(obj, list):
        return [mask_json(v, masker) for v in obj]
    if isinstance(obj, str):
        return masker.text(obj)
    return obj


# ---------------------------------------------------------------------------------------------
# High-precision subset for the output safety net (arbitrary tool output, source code included)
# ---------------------------------------------------------------------------------------------
NET_RULES = (
    (PEM_INLINE_RE, lambda m: _pem_marker(m.group(1), m.group(0)) if 'PRIVATE' in m.group(1) else m.group(0), 'pem'),
    (re.compile(r'\bENC\s+(?!<masked)[A-Za-z0-9+/=]{24,}'), lambda m: 'ENC ' + MASK, 'enc'),
    (re.compile(r'\$(?:1|5|6|y|2[aby])\$[./A-Za-z0-9]{2,}\$[./A-Za-z0-9]{20,}'), lambda m: MASK, 'hash'),
    (re.compile(r'\$9\$[./A-Za-z0-9]{8,}'), lambda m: MASK, 'hash'),
    (KEYHEX_RE, lambda m: m.group(1) + MASK, 'session-key'),
)
# A private-key block: the BEGIN line, then only lines that look like key body (base64 without
# spaces, PEM headers, blank), then END if present. Stops at the first ordinary line, so a lone
# BEGIN in grep output or source code does not swallow the rest of the output. Real newlines or
# JSON-escaped ones.
NET_PRIV_BLOCK_RE = re.compile(
    r'-----BEGIN ([A-Z ]*PRIVATE KEY)-----'
    r'(?:(?:\r?\n|\\n)(?:[A-Za-z0-9+/=]+|Proc-Type:[^\r\n\\]*|DEK-Info:[^\r\n\\]*)?)*'
    r'(?:(?:\r?\n|\\n)?-----END \1-----)?')
# Key-body-sized base64 runs (PEM lines are 64 chars) that survive elsewhere, e.g. grep-prefixed.
NET_B64_RE = re.compile(r'(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{60,}={0,2}(?![A-Za-z0-9+/=])')


def net_mask(text, known=(), counts=None):
    """Mask only what is unambiguous in any text: used where the vendor is unknown."""
    counts = Counter() if counts is None else counts
    if not isinstance(text, str) or not text:
        return text
    new, n = NET_PRIV_BLOCK_RE.subn(lambda m: f'<masked:{m.group(1).lower().replace(" ", "-")}>', text)
    counts['pem'] += n
    for rx, repl, cat in NET_RULES:
        new, n = rx.subn(repl, new)
        counts[cat] += n
    new, n = NET_B64_RE.subn(lambda m: '<masked:b64>' if _b64_suspicious(m.group(0)) else m.group(0), new)
    counts['b64'] += n
    for k in known:
        k = k.strip()
        if len(k) < 6:
            continue
        for v in _variants(k):
            if v in new:
                new = new.replace(v, '<masked:known>')
                counts['known'] += 1
    return new
