"""HTTPS GET with a pinned public key and a token header, shaped by the pack's ApiProfile."""
import os
import re
import shutil
import subprocess
import tempfile
import urllib.parse
from types import SimpleNamespace

from .. import config
from . import Result, TransportError, decode, register

MSYS_RE = re.compile(r'^[A-Za-z]:[\\/](?:.*[\\/])?(api[\\/].*)$')


def undo_msys_path(path):
    """Git Bash rewrites an argument `/api/...` to `C:/Program Files/Git/api/...`; take it back."""
    m = MSYS_RE.match(path)
    return '/' + m.group(1).replace('\\', '/') if m else path


def build_url(d, profile, path, context, params):
    path = undo_msys_path(path)
    if not path.startswith('/'):
        path = '/' + path
    if not path.startswith(profile.prefixes) or '?' in path or '..' in path:
        raise config.UsageError(f'path must start with one of {profile.prefixes}, without a query string '
                                f'(use --vdom / -p k=v)')
    q = []
    if context:
        if not profile.context_param:
            raise config.UsageError('this API takes no --vdom')
        q.append((profile.context_param, context))
    for kv in params or []:
        k, sep, v = kv.partition('=')
        if not sep or k in profile.forbidden_params:
            raise config.UsageError(f'bad parameter {kv!r}')
        q.append((k, v))
    port = d.get('https_port', 443)
    base = f'https://{d["host"]}' + ('' if port == 443 else f':{port}')
    return base + path + ('?' + urllib.parse.urlencode(q) if q else '')


def get(d, profile, url, timeout):
    if not d.get('token_file'):
        raise config.UsageError(f'device {d["alias"]!r}: no token_file')
    if not d.get('tls_pin'):
        raise config.UsageError(f'device {d["alias"]!r}: no tls_pin (sha256//<base64 SPKI hash>)')
    curl = shutil.which('curl')
    if not curl:
        raise TransportError('curl not found on PATH')
    token = config.read_secret(d['token_file'])
    value = f'{profile.auth_scheme} {token}' if profile.auth_scheme else token
    with tempfile.TemporaryDirectory(prefix='credveil-') as tmp:
        hdr = os.path.join(tmp, 'auth.hdr')
        with open(hdr, 'w', encoding='utf-8', newline='\n') as fh:
            fh.write(f'{profile.auth_header}: {value}\n')
        argv = [curl, '-sS', '-k', '--pinnedpubkey', d['tls_pin'], '-H', f'@{hdr}',
                '--max-time', str(timeout), '-w', '\\n', url]
        try:
            p = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout + 5)
        except subprocess.TimeoutExpired:
            raise TransportError('timeout')
    rc, err = p.returncode, decode(p.stderr)
    if rc:
        # curl's own codes overlap credveil's 90-93 (90 = pinned key mismatch): report, map to 93
        hint = ' - TLS public key does not match tls_pin' if rc == 90 else ''
        err += f'\ncredveil: curl exit {rc}{hint}'
        rc = 93
    return Result(decode(p.stdout), err, rc)


register('https', SimpleNamespace(build_url=build_url, get=get))
