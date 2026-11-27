"""Vendor-neutral rules, applied after the vendor pack on every line, and the output net."""
import base64
import hashlib
import re
import urllib.parse
from collections import Counter

MASK = '<masked>'


def sha8(text):
    return hashlib.sha256(text.encode('utf-8', 'replace')).hexdigest()[:8]


def pem_marker(label, block):
    slug = label.lower().replace(' ', '-')
    if 'PRIVATE' in label or 'ENCRYPTED' in label:
        return f'<masked:{slug}>'
    return f'<pem:{slug} sha={sha8(block)}>'


PEM_BEGIN_RE = re.compile(r'-----BEGIN ([A-Z0-9 ]+)-----')
PEM_INLINE_RE = re.compile(r'-----BEGIN ([A-Z0-9 ]+)-----.*?-----END \1-----', re.S)
PPK_RE = re.compile(r'^\s*Private-Lines:\s*(\d+)\s*$')
HEXLINE_RE = re.compile(r'^\s*(?:0x[0-9a-fA-F]+:?\s+)?(?:[0-9A-Fa-f]{2,8}\s+){2,}[0-9A-Fa-f]{2,8}\s*$')

ENC_RE = re.compile(r'\bENC\s+(?!<masked)[A-Za-z0-9+/=]{8,}')
# crypt ($1$ $5$ $6$ $y$ $2b$, Cisco type 8/9 $8$ $9$), Junos $9$, Comware $c$ $h$
HASH_RE = re.compile(r'"?\$(?:1|5|6|8|9|c|h|y|2[aby]?)\$[^\s"]*"?')
HEX0X_RE = re.compile(r'\b0x[0-9A-Fa-f]{16,}\b')       # NX-OS SNMPv3 localized keys
KEYHEX_RE = re.compile(r'\b((?:key|Key|KEY)=\d+\s+)[0-9A-Fa-f]{8,}')  # FortiOS tunnel list
LONGHEX_RE = re.compile(r'(?<![0-9A-Za-z])[0-9A-Fa-f]{32,}(?![0-9A-Za-z])')
B64_RE = re.compile(r'(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])')
AUTH_HEADER_RE = re.compile(
    r'(?i)\b((?:proxy-)?authorization\s*:\s*(?:bearer|basic|token|apikey)?\s*|'
    r'x-(?:api-key|auth-token|api-token)\s*:\s*)(?!<masked)\S+')

# JSON-shaped `"key": "value"` in plain text (a JSON body printed by a CLI, a log line)
JSON_BASE_KEYS = frozenset({
    'password', 'passwd', 'secret', 'psk', 'pre-shared-key', 'preshared-key', 'passphrase',
    'private-key', 'private_key', 'token', 'api-key', 'api_key', 'apikey', 'access_token',
    'refresh_token', 'client_secret', 'client-secret', 'shared-secret', 'community',
    'ciphertext', 'session_key', 'auth-password', 'priv-password', 'key-string'})
JSON_SECRET_SUFFIXES = ('-password', '_password', '-passwd', '-pwd', '-secret', '_secret',
                        '-token', '_token', '-psk', '_psk', '-private-key', '_private_key',
                        '-access-key', '_access_key')
JSON_PAIR_RE = re.compile(r'("([A-Za-z0-9_.-]+)"\s*:\s*)"((?:[^"\\]|\\.)*)"')


def json_key_is_secret(key, extra=frozenset()):
    k = key.lower()
    return k in JSON_BASE_KEYS or k in extra or k.endswith(JSON_SECRET_SUFFIXES)


# Values right after these labels skip the broad hex/base64 backstops: they identify, they do
# not authenticate. Explicit secret forms (PEM, ENC, crypt hashes, known credentials) still apply.
IDENTITY_KEYS = frozenset({
    'user', 'username', 'user-name', 'user_name', 'xauthuser', 'xauth-user', 'xauth_user',
    'srcuser', 'dstuser', 'unauthuser', 'login', 'group', 'groups', 'xauthgroup', 'usergroup'})
PUBLIC_ID_LABELS = (r'fingerprint', r'thumbprint', r'serial(?:[ _-]?number)?(?:\s*\(hex\))?',
                    r'commit', r'uuid', r'object[ _-]?id')
_CTX_RE = re.compile(
    r'(?i)(?:^|[\s,{;(\[])["\']?(?:xauth[ _-]?user|'
    + '|'.join(re.escape(k) for k in sorted(IDENTITY_KEYS, key=len, reverse=True))
    + r')["\']?\s*[=:]\s*["\']?$'
    + r'|\b(?:' + '|'.join(PUBLIC_ID_LABELS) + r')\s*[=:]?\s*["\']?$')


def _exempt(line, start):
    return bool(_CTX_RE.search(line[max(0, start - 40):start]))


def b64_suspicious(tok):
    return (sum(c.isupper() for c in tok) >= 3 and sum(c.islower() for c in tok) >= 3
            and sum(c.isdigit() for c in tok) >= 3)


def _sub(rx, repl, s, counts, cat):
    new, n = rx.subn(repl, s)
    if n:
        counts[cat] += n
    return new


def _sub_where(rx, cond, repl, s, counts, cat):
    n = 0

    def f(m):
        nonlocal n
        if not cond(m):
            return m.group(0)
        n += 1
        return repl(m)
    new = rx.sub(f, s)
    if n:
        counts[cat] += n
    return new


def _backstop(rx, keep, s, counts, cat):
    n = 0

    def repl(m):
        nonlocal n
        if _exempt(s, m.start()) or keep(m.group(0)):
            return m.group(0)
        n += 1
        return '<masked:b64>' if cat == 'b64' else f'<hex:{len(m.group(0))}>'
    new = rx.sub(repl, s)
    if n:
        counts[cat] += n
    return new


# ---------------------------------------------------------------------------------------------
# Credential families: the shape itself is the evidence, so no vendor context is needed
# ---------------------------------------------------------------------------------------------
# A JWT used to lose only its payload: `-`/`_` split it out of the base64 backstop, so the
# header and the signature still reached the model. One token, one marker.
# One alternation, one pass: a device export is masked line by line, so each extra rule is
# another full scan of every line.
_FAMILY_PATTERNS = (
    ('jwt', 'jwt',
     (r'(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}'
      r'(?![A-Za-z0-9_-])')),
    # Platform tokens: the issuer is in the prefix, which device output never produces otherwise.
    ('github-token', 'github', r'\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b'),
    ('gitlab-token', 'gitlab', r'\bglpat-[A-Za-z0-9_-]{20,}'),
    ('slack-token', 'slack', r'\bxox[abposr]-[A-Za-z0-9-]{10,}'),
    ('stripe-key', 'stripe', r'\b[rs]k_live_[A-Za-z0-9]{20,}'),
    ('google-key', 'google', r'\bAIza[0-9A-Za-z_-]{35}\b'),
    ('aws-key-id', 'aws', r'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b'),
    ('api-key', 'apikey', r'\bsk-[A-Za-z0-9_-]{32,}'),
    # Password hashes: keep the scheme (it says what the system stores, not the password) and
    # mask the digest. The `$` may be missing: Django and passlib store `pbkdf2_sha256$…` so.
    ('hash', 'hash',
     (r'(?<![A-Za-z0-9])\$?(?P<scheme>argon2(?:id|i|d)?|pbkdf2(?:[_-]sha(?:1|256|512))?|scrypt|'
      r'bcrypt[_-]sha256)\$[^\s"\']{10,}')),
    ('hash', 'ldap',
     r'(?P<ldapscheme>\{(?:SSHA(?:256|512)?|SHA|SMD5|MD5|CRYPT)\})[A-Za-z0-9+/=.]{6,}'),
    # Credentials in a URL's userinfo: `curl -v` prints them, and `-u` takes them.
    ('url-userinfo', 'url', r'(?i:\b)(?P<urlpre>[a-z][a-z0-9+.-]*://[^\s/:@]+):[^\s/@]+@'),
)
FAMILY_RE = re.compile('|'.join(f'(?P<{name}>{pat})' for _, name, pat in _FAMILY_PATTERNS))
# The alternation costs ~10 us a line and almost no device line carries one of these markers, so
# a substring gate keeps the extra rules off the hot path (measured: 10 us -> 3 us per plain line).
_FAMILY_HINTS = ('eyj', 'ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_', 'github_pat_', 'glpat-', 'xox',
                 'k_live_', 'aiza', 'akia', 'asia', 'sk-', '://', '$', 'pbkdf2', 'scrypt',
                 'argon2', 'bcrypt_sha256', '{ssha', '{smd5', '{sha', '{md5', '{crypt')


def mask_families(line, counts):
    """Rules whose evidence is inside the token; they run before the broad backstops."""
    low = line.lower()
    if not any(h in low for h in _FAMILY_HINTS):
        return line

    def repl(m):
        whole = m.group(0)
        if MASK in whole:                   # already masked: keep counts honest, do not double-wrap
            return whole
        for cat, name, _ in _FAMILY_PATTERNS:
            if m.group(name) is not None:
                counts[cat] += 1
                if name == 'jwt':
                    return '<masked:jwt>'
                if name == 'hash':
                    return m.group('scheme') + '$<masked:hash>'
                if name == 'ldap':
                    return m.group('ldapscheme') + '<masked:hash>'
                if name == 'url':
                    return m.group('urlpre') + ':<masked:url-password>@'
                return f'<masked:{cat}>'
        return whole
    return FAMILY_RE.sub(repl, line)


def b64url_suspicious(tok):
    """Base64url runs: `-`/`_` are exactly what the standard base64 backstop cannot see."""
    core = tok.rstrip('=')
    return ('-' in core or '_' in core) and b64_suspicious(core)


def mask_line(line, counts, json_keys=frozenset(), backstops=True):
    """Vendor-neutral rules for one line. Specific forms first, the broad backstops last."""
    line = _sub(PEM_INLINE_RE, lambda m: pem_marker(m.group(1), m.group(0)), line, counts, 'pem')
    line = _sub(ENC_RE, 'ENC ' + MASK, line, counts, 'enc')
    line = _sub(HASH_RE, MASK, line, counts, 'hash')
    line = _sub(HEX0X_RE, MASK, line, counts, 'hex')
    line = _sub(KEYHEX_RE, lambda m: m.group(1) + MASK, line, counts, 'session-key')
    line = _sub(AUTH_HEADER_RE, lambda m: m.group(1) + MASK, line, counts, 'header')
    line = mask_families(line, counts)
    line = _sub_where(JSON_PAIR_RE, lambda m: json_key_is_secret(m.group(2), json_keys)
                      and m.group(3) and MASK not in m.group(3),
                      lambda m: m.group(1) + f'"{MASK}"', line, counts, 'json')
    if backstops:
        line = _backstop(LONGHEX_RE, lambda t: False, line, counts, 'hex')
        line = _backstop(B64URL_RE, lambda t: not b64url_suspicious(t), line, counts, 'b64')
        if B64_RE.search(line):
            line = _backstop(B64_RE, lambda t: not b64_suspicious(t), line, counts, 'b64')
    return line


def variants(secret, min_len):
    """The secret and the encodings it is likely to appear in."""
    vs = {secret, urllib.parse.quote(secret, safe=''), urllib.parse.quote_plus(secret)}
    b = base64.b64encode(secret.encode()).decode()
    vs.update((b, b.rstrip('=')))
    return [v for v in vs if len(v) >= min_len]


# Shortest known credential that is checked. The CLI checks one device's own credentials, so 4
# is affordable; the output net checks every device's in any text, where short values ("admin")
# would mask ordinary output.
MIN_KNOWN, MIN_KNOWN_NET = 4, 6


# ---------------------------------------------------------------------------------------------
# The output net: only what is unambiguous in ANY text, source code included
# ---------------------------------------------------------------------------------------------
NET_PRIV_BLOCK_RE = re.compile(
    r'-----BEGIN ([A-Z ]*PRIVATE KEY)-----'
    r'(?:(?:\r?\n|\\n)(?:[A-Za-z0-9+/=]+|Proc-Type:[^\r\n\\]*|DEK-Info:[^\r\n\\]*)?)*'
    r'(?:(?:\r?\n|\\n)?-----END \1-----)?')
NET_PPK_RE = re.compile(r'Private-Lines:\s*(\d+)')
NET_RULES = (
    (re.compile(r'\bENC\s+(?!<masked)[A-Za-z0-9+/=]{24,}'), lambda m: 'ENC ' + MASK, 'enc'),
    (re.compile(r'\$(?:1|5|6|8|9|y|2[aby])\$[./A-Za-z0-9]{2,}\$[./A-Za-z0-9]{20,}'), lambda m: MASK, 'hash'),
    (re.compile(r'\$9\$[./A-Za-z0-9-]{8,}'), lambda m: MASK, 'hash'),           # Junos
    (re.compile(r'\$[ch]\$\d+\$[A-Za-z0-9+/=$]{8,}'), lambda m: MASK, 'hash'),   # Comware
    (KEYHEX_RE, lambda m: m.group(1) + MASK, 'session-key'),
)
NET_B64_RE = re.compile(r'(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{60,}={0,2}(?![A-Za-z0-9+/=])')
# Base64url runs: `-`/`_` are outside the standard alphabet, so the rule above cannot see them
# and a JWT or a URL-safe token used to pass whole (or lose only one segment to a fragment match).
B64URL_RE = re.compile(r'(?<![A-Za-z0-9+_-])[A-Za-z0-9_-]{40,}={0,2}(?![A-Za-z0-9+/=_-])')


def net_mask(text, known=(), counts=None):
    """Mask only unambiguous secret forms; used where the text's system is unknown."""
    counts = Counter() if counts is None else counts
    if not isinstance(text, str) or not text:
        return text
    new = _sub(NET_PRIV_BLOCK_RE, lambda m: f'<masked:{m.group(1).lower().replace(" ", "-")}>',
               text, counts, 'pem')
    new = _mask_ppk(new, counts)
    for rx, repl, cat in NET_RULES:
        new = _sub(rx, repl, new, counts, cat)
    new = mask_families(new, counts)
    new = _backstop(B64URL_RE, lambda t: not b64url_suspicious(t), new, counts, 'b64')
    new = _sub_where(NET_B64_RE, lambda m: b64_suspicious(m.group(0)), lambda m: '<masked:b64>',
                     new, counts, 'b64')
    return mask_known(new, known, counts, MIN_KNOWN_NET)


def _mask_ppk(text, counts):
    """`Private-Lines: N` and the N key lines after it (real newlines or JSON-escaped ones)."""
    m = NET_PPK_RE.search(text)
    while m:
        nl = '\\n' if text[m.end():m.end() + 2] == '\\n' else '\n'
        parts = text[m.end():].split(nl, int(m.group(1)) + 1)
        rest = parts[-1] if len(parts) > int(m.group(1)) + 1 else ''
        text = text[:m.end()] + nl + '<masked:ppk-private-lines>' + (nl + rest if rest or len(parts) > 1 else '')
        counts['pem'] += 1
        m = NET_PPK_RE.search(text, m.end() + len(nl) + 26)
    return text


def mask_known(text, known, counts, min_len=MIN_KNOWN):
    for k in known:
        if len(k.strip()) < min_len:
            continue
        for v in variants(k.strip(), min_len):
            if v in text:
                text = text.replace(v, '<masked:known>')
                counts['known'] += 1
    return text
