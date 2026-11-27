#!/usr/bin/env python3
"""credveil - masked, credential-free access to network devices for agents.

    credveil list                                   devices in the inventory (no secrets)
    credveil run ALIAS [-c CMD ...] [--vdom V | --global] [--timeout S]
                                                SSH; commands from -c or stdin, one exec
    credveil get ALIAS PATH [--vdom V] [-p k=v ...] REST GET (FortiOS bearer token)
    credveil mask [--vendor V] [FILE ...]           mask a file/stdin (exports, log dumps)
    credveil audit [--vendor V] FILE ...            for the operator: what masking finds in raw files,
                                                counts and line numbers only, never values
    credveil hostkey ALIAS                          print the device's SSH host-key fingerprint

The agent never sees a credential: credveil reads password and token files named in the
inventory, hands them to plink/ssh/curl through files (not argv), and masks stdout and stderr
with secretmask.py before printing. Fail-closed: if a known credential survives masking, or
masking itself crashes, nothing of the output is printed.

Inventory: $CREDVEIL_HOME/inventory.toml (default ~/.config/credveil/), see inventory.example.toml.

Exit codes: the remote command's own code (run), 0 (get), or
  90  output withheld: a known credential survived masking (line numbers on stderr)
  91  output withheld: masking failed
  92  inventory or usage error
  93  transport error (plink/ssh/curl missing, timeout, any curl failure incl. pin mismatch)

Stdlib only (Python 3.11+, tomllib).
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
import secretmask as sm  # noqa: E402

WINDOWS = os.name == 'nt'
EXIT_LEAK, EXIT_MASKFAIL, EXIT_USAGE, EXIT_TRANSPORT = 90, 91, 92, 93
API_PREFIXES = ('/api/v2/monitor/', '/api/v2/cmdb/', '/api/v2/log/')


class UsageError(Exception):
    pass


# ---------------------------------------------------------------------------------------------
# Inventory
# ---------------------------------------------------------------------------------------------
def credveil_home():
    return os.path.expanduser(os.environ.get('CREDVEIL_HOME') or '~/.config/credveil')


def load_inventory(home=None):
    home = home or credveil_home()
    path = os.path.join(home, 'inventory.toml')
    if not os.path.exists(path):
        raise UsageError(f'no inventory at {path} (copy inventory.example.toml there)')
    with open(path, 'rb') as fh:
        inv = tomllib.load(fh)
    inv.setdefault('device', {})
    inv['_home'] = home
    return inv


def resolve(home, p):
    if not p:
        return None
    p = os.path.expanduser(p)
    return p if os.path.isabs(p) else os.path.join(home, p)


def device(inv, alias):
    d = inv['device'].get(alias)
    if d is None:
        raise UsageError(f'unknown device {alias!r}; known: {", ".join(sorted(inv["device"])) or "none"}')
    d = dict(d)
    for k in ('host', 'vendor'):
        if not d.get(k):
            raise UsageError(f'device {alias!r}: missing {k}')
    sm.pack_of(d['vendor'])  # validates
    home = inv['_home']
    for k in ('password_file', 'token_file', 'key_file'):
        d[k] = resolve(home, d.get(k))
    d['alias'] = alias
    return d


def read_secret(path):
    if not path:
        return None
    with open(path, encoding='utf-8') as fh:
        return fh.read().strip()


def known_secrets(d):
    return [s for s in (read_secret(d.get('password_file')), read_secret(d.get('token_file'))) if s]


# ---------------------------------------------------------------------------------------------
# Output: mask, check, print - or withhold
# ---------------------------------------------------------------------------------------------
def emit(vendor, known, stdout, stderr, rc, as_json=False):
    """Mask both streams; print them only if no known secret survives. Returns the exit code."""
    try:
        m = sm.Masker(vendor, known=known)
        # A credential in the raw output means the device echoed it somewhere no rule expects:
        # withhold everything rather than trust the rest of the masking.
        raw_out, raw_err = m.leaks(stdout), m.leaks(stderr)
        if raw_out or raw_err:
            print(f'credveil: output withheld - the device output contains a known credential '
                  f'(stdout lines {raw_out}, stderr lines {raw_err}). Tell the operator; do not retry '
                  f'around it.', file=sys.stderr)
            return EXIT_LEAK
        if as_json:
            try:
                out = json.dumps(sm.mask_json(json.loads(stdout), m), indent=2, ensure_ascii=False) + '\n'
            except ValueError:
                out = m.text(stdout)
        else:
            out = m.text(stdout)
        err = sm.Masker(vendor, known=known).text(stderr)
        leaks_out, leaks_err = m.leaks(out), m.leaks(err)
    except Exception as e:  # noqa: BLE001 - any failure means nothing is printed
        print(f'credveil: output withheld, masking failed ({type(e).__name__})', file=sys.stderr)
        return EXIT_MASKFAIL
    if leaks_out or leaks_err:
        print(f'credveil: output withheld - a known credential survived masking '
              f'(stdout lines {leaks_out}, stderr lines {leaks_err}). Report this as a '
              f'secretmask bug; do not retry around it.', file=sys.stderr)
        return EXIT_LEAK
    sys.stdout.write(out)
    sys.stdout.flush()
    if err.strip():
        sys.stderr.write(err if err.endswith('\n') else err + '\n')
    print(f'credveil: masked {m.summary()}', file=sys.stderr)
    return rc


# ---------------------------------------------------------------------------------------------
# SSH
# ---------------------------------------------------------------------------------------------
def wrap_context(d, cmds, vdom, glob):
    if sm.pack_of(d['vendor']) != 'fortios':
        if vdom or glob:
            raise UsageError('--vdom/--global apply to FortiOS devices only')
        return cmds
    if vdom:
        return ['config vdom', f'edit {vdom}'] + cmds + ['end']
    if glob:
        return ['config global'] + cmds + ['end']
    return cmds


def ssh_argv(d, cmdfile, tmp):
    """argv and env for one non-interactive SSH exec reading its commands from cmdfile."""
    user, host, port = d.get('user'), d['host'], str(d.get('port', 22))
    target = f'{user}@{host}' if user else host
    pw = d.get('password_file')
    if WINDOWS or d.get('ssh_client') == 'plink':
        plink = shutil.which('plink') or shutil.which('plink.exe')
        if not plink:
            raise FileNotFoundError('plink not found on PATH')
        if not d.get('hostkey'):
            raise UsageError(f'device {d["alias"]!r}: no hostkey pin (run: credveil hostkey {d["alias"]})')
        argv = [plink, '-ssh', '-batch', '-P', port, '-hostkey', d['hostkey'], '-m', cmdfile]
        if pw:
            argv += ['-pwfile', pw]
        if d.get('key_file'):
            argv += ['-i', d['key_file']]
        return argv + [target], None
    ssh = shutil.which('ssh')
    if not ssh:
        raise FileNotFoundError('ssh not found on PATH')
    kh = os.path.join(credveil_home(), 'known_hosts')
    argv = [ssh, '-T', '-p', port, '-o', 'StrictHostKeyChecking=yes', '-o', f'UserKnownHostsFile={kh}',
            '-o', 'BatchMode=no' if pw else 'BatchMode=yes', '-o', 'NumberOfPasswordPrompts=1']
    if d.get('key_file'):
        argv += ['-i', d['key_file']]
    env = None
    if pw:
        helper = os.path.join(tmp, 'askpass.sh')
        with open(helper, 'w') as fh:
            fh.write('#!/bin/sh\nexec cat "$CREDVEIL_PWFILE"\n')
        os.chmod(helper, 0o700)
        env = dict(os.environ, SSH_ASKPASS=helper, SSH_ASKPASS_REQUIRE='force', CREDVEIL_PWFILE=pw,
                   DISPLAY=os.environ.get('DISPLAY', 'credveil:0'))
    # OpenSSH sends the remote command as one string; FortiOS/most NOS CLIs run it line by line.
    with open(cmdfile, encoding='utf-8') as fh:
        remote = fh.read()
    return argv + [target, remote], env


def cmd_run(a):
    inv = load_inventory()
    d = device(inv, a.alias)
    cmds = a.c or [l for l in sys.stdin.read().splitlines() if l.strip()]
    if not cmds:
        raise UsageError('no commands (use -c or stdin)')
    cmds = wrap_context(d, cmds, a.vdom, a.glob)
    known = known_secrets(d)
    with tempfile.TemporaryDirectory(prefix='credveil-') as tmp:
        cmdfile = os.path.join(tmp, 'cmds.txt')
        with open(cmdfile, 'w', encoding='utf-8', newline='\n') as fh:
            fh.write('\n'.join(cmds) + '\n')
        if d.get('transport') == 'exec':  # tests only: a local command plays the device
            argv, env = list(d['exec']) + [cmdfile], None
        else:
            argv, env = ssh_argv(d, cmdfile, tmp)
        try:
            p = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, env=env,
                               timeout=a.timeout)
        except subprocess.TimeoutExpired as e:
            return emit(d['vendor'], known, _dec(e.stdout), _dec(e.stderr) + f'\ncredveil: timeout after {a.timeout}s',
                        EXIT_TRANSPORT)
    return emit(d['vendor'], known, _dec(p.stdout), _dec(p.stderr), p.returncode)


def _dec(b):
    if b is None:
        return ''
    return b.decode('utf-8', 'replace') if isinstance(b, bytes) else b


# ---------------------------------------------------------------------------------------------
# REST GET
# ---------------------------------------------------------------------------------------------
MSYS_API_RE = re.compile(r'^[A-Za-z]:[\\/](?:.*[\\/])?(api[\\/]v2[\\/].*)$')


def undo_msys_path(path):
    """TF-1: Git Bash rewrites an argument `/api/v2/...` to `C:/Program Files/Git/api/v2/...`
    (MSYS path conversion). An API path never starts with a drive, so take back the API part."""
    m = MSYS_API_RE.match(path)
    return '/' + m.group(1).replace('\\', '/') if m else path


def build_url(d, path, vdom, params):
    if sm.pack_of(d['vendor']) != 'fortios':
        raise UsageError('credveil get supports FortiOS only for now (bearer token)')
    path = undo_msys_path(path)
    if not path.startswith('/'):
        path = '/' + path
    if not path.startswith(API_PREFIXES) or '?' in path or '..' in path:
        raise UsageError(f'path must start with one of {API_PREFIXES}, without a query string '
                         f'(use --vdom / -p k=v)')
    q = []
    if vdom:
        q.append(('vdom', vdom))
    for kv in params or []:
        k, sep, v = kv.partition('=')
        if not sep or k in ('access_token',):
            raise UsageError(f'bad parameter {kv!r}')
        q.append((k, v))
    port = d.get('https_port', 443)
    base = f'https://{d["host"]}' + ('' if port == 443 else f':{port}')
    return base + path + ('?' + urllib.parse.urlencode(q) if q else '')


def cmd_get(a):
    inv = load_inventory()
    d = device(inv, a.alias)
    url = build_url(d, a.path, a.vdom, a.param)
    if not d.get('token_file'):
        raise UsageError(f'device {a.alias!r}: no token_file')
    if not d.get('tls_pin'):
        raise UsageError(f'device {a.alias!r}: no tls_pin (sha256//<base64 SPKI hash>)')
    curl = shutil.which('curl')
    if not curl:
        raise FileNotFoundError('curl not found on PATH')
    known = known_secrets(d)
    with tempfile.TemporaryDirectory(prefix='credveil-') as tmp:
        hdr = os.path.join(tmp, 'auth.hdr')
        with open(hdr, 'w', encoding='utf-8', newline='\n') as fh:
            fh.write(f'Authorization: Bearer {read_secret(d["token_file"])}\n')
        argv = [curl, '-sS', '-k', '--pinnedpubkey', d['tls_pin'], '-H', f'@{hdr}',
                '--max-time', str(a.timeout), '-w', '\\n', url]
        if d.get('transport') == 'exec':
            argv = list(d['exec']) + [url]
        try:
            p = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=a.timeout + 5)
        except subprocess.TimeoutExpired:
            print('credveil: timeout', file=sys.stderr)
            return EXIT_TRANSPORT
    rc = p.returncode
    if rc and d.get('transport') != 'exec':
        # curl's own codes overlap credveil's 90-93 (90 = pinned key mismatch): report, map to 93.
        hint = ' - TLS public key does not match tls_pin' if rc == 90 else ''
        print(f'credveil: curl exit {rc}{hint}', file=sys.stderr)
        rc = EXIT_TRANSPORT
    return emit(d['vendor'], known, _dec(p.stdout), _dec(p.stderr), rc, as_json=True)


# ---------------------------------------------------------------------------------------------
# Offline: mask / audit
# ---------------------------------------------------------------------------------------------
def _read_inputs(files):
    """Raw text with its line endings untouched (newline=''), so `mask` can give them back."""
    if not files:
        if hasattr(sys.stdin, 'reconfigure'):
            sys.stdin.reconfigure(newline='')
        return [('<stdin>', sys.stdin.read())]
    out = []
    for f in files:
        with open(f, encoding='utf-8', errors='replace', newline='') as fh:
            out.append((f, fh.read()))
    return out


def _eol_of(text):
    """TF-2: the input's own line ending. Following the file, not the OS, keeps `diff raw masked`
    clean on both: a Windows box sees LF exports too, and a Linux box CRLF device captures."""
    crlf = text.count('\r\n')
    return '\r\n' if crlf and crlf * 2 >= text.count('\n') else '\n'


def cmd_mask(a):
    rc = 0
    for name, text in _read_inputs(a.files):
        try:
            masked = sm.Masker(a.vendor).text(text)
            sys.stdout.write(masked.replace('\n', '\r\n') if _eol_of(text) == '\r\n' else masked)
        except Exception as e:  # noqa: BLE001
            print(f'credveil: {name}: withheld, masking failed ({type(e).__name__})', file=sys.stderr)
            rc = EXIT_MASKFAIL
    return rc


def cmd_audit(a):
    """Counts and line numbers only - safe to show an agent, meant for the operator's raw captures."""
    for name, text in _read_inputs(a.files):
        m = sm.Masker(a.vendor)
        lines = text.replace('\r\n', '\n').split('\n')
        changed = []
        for i, line in enumerate(lines, 1):
            before = sum(m.counts.values())
            outs = m.feed(line)
            if sum(m.counts.values()) != before or (outs and outs != [line]) or not outs:
                changed.append(i)
        m.close()
        print(f'{name}: {len(lines)} lines, {len(changed)} touched; masked {m.summary()}')
        if changed:
            print('  touched lines: ' + _ranges(changed))
    return 0


def _ranges(nums):
    out, start, prev = [], None, None
    for n in nums + [None]:
        if start is None:
            start = prev = n
        elif n is not None and n == prev + 1:
            prev = n
        else:
            out.append(str(start) if start == prev else f'{start}-{prev}')
            start = prev = n
    return ', '.join(out[:200]) + (' …' if len(out) > 200 else '')


# ---------------------------------------------------------------------------------------------
# list / hostkey
# ---------------------------------------------------------------------------------------------
def cmd_list(a):
    inv = load_inventory()
    for alias in sorted(inv['device']):
        d = inv['device'][alias]
        has = [k for k in ('password_file', 'token_file', 'key_file', 'hostkey', 'tls_pin') if d.get(k)]
        print(f'{alias:24} {d.get("vendor", "?"):10} {d.get("host", "?"):20} {d.get("user", "-"):16} '
              f'{",".join(has)}  {d.get("comment", "")}')
    return 0


def cmd_hostkey(a):
    inv = load_inventory()
    d = device(inv, a.alias)
    port = str(d.get('port', 22))
    if WINDOWS or d.get('ssh_client') == 'plink':
        plink = shutil.which('plink') or shutil.which('plink.exe')
        p = subprocess.run([plink, '-ssh', '-batch', '-P', port, f'credveil-probe@{d["host"]}', 'exit'],
                           stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
        text = _dec(p.stdout) + _dec(p.stderr)
        fps = sorted({w.strip('.,') for w in text.split() if w.startswith('SHA256:')})
    else:
        p = subprocess.run(['ssh-keyscan', '-p', port, d['host']], capture_output=True, timeout=30)
        q = subprocess.run(['ssh-keygen', '-lf', '-'], input=p.stdout, capture_output=True)
        fps = [l for l in _dec(q.stdout).splitlines() if l.strip()]
    if not fps:
        print('credveil: no host key fingerprint found', file=sys.stderr)
        return EXIT_TRANSPORT
    for f in fps:
        print(f)
    print('Verify out of band, then pin it: hostkey = "SHA256:…" in the inventory (plink); on Linux '
          f'append `ssh-keyscan -p {port} {d["host"]}` to {os.path.join(credveil_home(), "known_hosts")}.',
          file=sys.stderr)
    return 0


# ---------------------------------------------------------------------------------------------
def main(argv=None):
    for s in (sys.stdout, sys.stderr):
        if hasattr(s, 'reconfigure'):
            # TF-2: no newline translation on any OS. run/get go to the agent as LF; mask writes
            # the input file's own line ending (see _eol_of)
            s.reconfigure(encoding='utf-8', errors='replace', newline='\n')
    ap = argparse.ArgumentParser(prog='credveil', description=__doc__.split('\n')[0])
    sub = ap.add_subparsers(dest='cmd', required=True)
    sub.add_parser('list')
    r = sub.add_parser('run')
    r.add_argument('alias')
    r.add_argument('-c', action='append', metavar='CMD')
    g = r.add_mutually_exclusive_group()
    g.add_argument('--vdom')
    g.add_argument('--global', dest='glob', action='store_true')
    r.add_argument('--timeout', type=int, default=120)
    t = sub.add_parser('get')
    t.add_argument('alias')
    t.add_argument('path')
    t.add_argument('--vdom')
    t.add_argument('-p', '--param', action='append', metavar='K=V')
    t.add_argument('--timeout', type=int, default=60)
    for name in ('mask', 'audit'):
        x = sub.add_parser(name)
        x.add_argument('--vendor', default='generic')
        x.add_argument('files', nargs='*' if name == 'mask' else '+')
    h = sub.add_parser('hostkey')
    h.add_argument('alias')
    a = ap.parse_args(argv)
    fn = {'list': cmd_list, 'run': cmd_run, 'get': cmd_get, 'mask': cmd_mask, 'audit': cmd_audit,
          'hostkey': cmd_hostkey}[a.cmd]
    try:
        return fn(a)
    except (UsageError, ValueError, OSError, tomllib.TOMLDecodeError) as e:
        if isinstance(e, FileNotFoundError) and 'not found on PATH' not in str(e):
            print(f'credveil: {e.__class__.__name__}: {e.filename or e}', file=sys.stderr)
            return EXIT_USAGE
        print(f'credveil: {e}', file=sys.stderr)
        return EXIT_TRANSPORT if 'not found on PATH' in str(e) else EXIT_USAGE


if __name__ == '__main__':
    sys.exit(main())
