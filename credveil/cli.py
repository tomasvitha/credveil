"""credveil - masked, credential-free access to network devices for agents.

    credveil list                                   devices in the inventory (no secrets)
    credveil run ALIAS [-c CMD ...] [--vdom V | --global] [--timeout S]
                                                    SSH; commands from -c or stdin, one exec
    credveil get ALIAS PATH [--vdom V] [-p k=v ...] REST GET (token from the inventory)
    credveil mask [--vendor V] [FILE ...]           mask a file/stdin (exports, log dumps)
    credveil audit [--vendor V] FILE ...            counts and line numbers only, never values
    credveil hostkey ALIAS                          the device's SSH host-key fingerprint
    credveil vendors                                known vendor names

The agent never sees a credential: credveil reads the password and token files named in the
inventory, hands them to plink/ssh/curl through files (not argv), and masks stdout and stderr
before printing. Fail-closed: if a known credential survives masking, or masking itself
crashes, nothing of the output is printed.

Exit codes: the remote command's own code (run), 0 (get), or
  90  output withheld: a known credential is in the output
  91  output withheld: masking failed
  92  inventory or usage error
  93  transport error (client missing, timeout, curl failure incl. TLS pin mismatch)
"""
import argparse
import json
import sys
import tomllib

from . import config, connectors, packs
from .mask import Masker, mask_json

EXIT_LEAK, EXIT_MASKFAIL, EXIT_USAGE, EXIT_TRANSPORT = 90, 91, 92, 93


def emit(vendor, known, res, as_json=False):
    """Mask both streams; print them only if no known secret survives. Returns the exit code."""
    try:
        m = Masker(vendor, known=known)
        # A credential in the raw output means the device echoed it where no rule expects it:
        # withhold everything rather than trust the rest of the masking.
        raw_out, raw_err = m.leaks(res.stdout), m.leaks(res.stderr)
        if raw_out or raw_err:
            print(f'credveil: output withheld - the device output contains a known credential '
                  f'(stdout lines {raw_out}, stderr lines {raw_err}). Tell the operator; do not retry '
                  f'around it.', file=sys.stderr)
            return EXIT_LEAK
        out = None
        if as_json:
            try:
                out = json.dumps(mask_json(json.loads(res.stdout), m), indent=2, ensure_ascii=False) + '\n'
            except ValueError:
                pass
        out = out if out is not None else m.text(res.stdout)
        err = Masker(vendor, known=known).text(res.stderr)
        leaks_out, leaks_err = m.leaks(out), m.leaks(err)
    except Exception as e:  # noqa: BLE001 - any failure means nothing is printed
        print(f'credveil: output withheld, masking failed ({type(e).__name__})', file=sys.stderr)
        return EXIT_MASKFAIL
    if leaks_out or leaks_err:
        print(f'credveil: output withheld - a known credential survived masking '
              f'(stdout lines {leaks_out}, stderr lines {leaks_err}). Report this as a '
              f'masking bug; do not retry around it.', file=sys.stderr)
        return EXIT_LEAK
    sys.stdout.write(out)
    sys.stdout.flush()
    if err.strip():
        sys.stderr.write(err if err.endswith('\n') else err + '\n')
    print(f'credveil: masked {m.summary()}', file=sys.stderr)
    return res.rc


def _context(a):
    return {k: v for k, v in (('vdom', getattr(a, 'vdom', None)), ('global', getattr(a, 'glob', False))) if v}


def cmd_run(a):
    inv = config.load()
    d = inv.device(a.alias)
    pack = packs.get(d['vendor'])
    cmds = a.c or [line for line in sys.stdin.read().splitlines() if line.strip()]
    if not cmds:
        raise config.UsageError('no commands (use -c or stdin)')
    ctx = _context(a)
    if ctx:
        if not pack.wrap_commands:
            raise config.UsageError(f'--vdom/--global do not apply to {pack.name} devices')
        cmds = pack.wrap_commands(cmds, ctx)
    res = connectors.get('ssh').run(d, cmds, a.timeout)
    return emit(d['vendor'], inv.known_secrets(), res)


def cmd_get(a):
    inv = config.load()
    d = inv.device(a.alias)
    pack = packs.get(d['vendor'])
    if not pack.api:
        raise config.UsageError(f'credveil get: no REST profile for {pack.name} devices')
    https = connectors.get('https')
    url = https.build_url(d, pack.api, a.path, a.vdom, a.param)
    res = https.get(d, pack.api, url, a.timeout)
    return emit(d['vendor'], inv.known_secrets(), res, as_json=True)


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
    """The input's own line ending, so `diff raw masked` shows only what masking changed."""
    crlf = text.count('\r\n')
    return '\r\n' if crlf and crlf * 2 >= text.count('\n') else '\n'


def cmd_mask(a):
    rc = 0
    for name, text in _read_inputs(a.files):
        try:
            masked = Masker(a.vendor).text(text)
            sys.stdout.write(masked.replace('\n', '\r\n') if _eol_of(text) == '\r\n' else masked)
        except Exception as e:  # noqa: BLE001
            print(f'credveil: {name}: withheld, masking failed ({type(e).__name__})', file=sys.stderr)
            rc = EXIT_MASKFAIL
    return rc


def cmd_audit(a):
    """Counts and line numbers only - safe to show an agent, meant for the operator's raw captures."""
    for name, text in _read_inputs(a.files):
        m = Masker(a.vendor)
        lines = text.replace('\r\n', '\n').split('\n')
        changed = []
        for i, line in enumerate(lines, 1):
            before = sum(m.counts.values())
            outs = m.feed(line)
            if sum(m.counts.values()) != before or outs != [line]:
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


def cmd_list(a):
    inv = config.load()
    for alias in sorted(inv.devices):
        d = inv.devices[alias]
        has = [k for k in ('password_file', 'token_file', 'key_file', 'hostkey', 'tls_pin') if d.get(k)]
        print(f'{alias:24} {d.get("vendor", "?"):10} {d.get("host", "?"):20} {d.get("user", "-"):16} '
              f'{",".join(has)}  {d.get("comment", "")}')
    return 0


def cmd_hostkey(a):
    d = config.load().device(a.alias)
    fps = connectors.get('ssh').fingerprints(d)
    if not fps:
        print('credveil: no host key fingerprint found', file=sys.stderr)
        return EXIT_TRANSPORT
    print('\n'.join(fps))
    port = d.get('port', 22)
    print(f'Verify out of band, then pin it: hostkey = "SHA256:…" in the inventory (plink); with OpenSSH '
          f'append `ssh-keyscan -p {port} {d["host"]}` to {config.home()}/known_hosts.', file=sys.stderr)
    return 0


def cmd_vendors(a):
    for p in sorted(packs.all_packs(), key=lambda p: p.name):
        print(f'{p.name:10} {", ".join(sorted(p.aliases))}' + ('   [REST]' if p.api else ''))
    return 0


def parser():
    ap = argparse.ArgumentParser(prog='credveil', description=__doc__.split('\n')[0])
    sub = ap.add_subparsers(dest='cmd', required=True)
    sub.add_parser('list')
    sub.add_parser('vendors')
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
    sub.add_parser('hostkey').add_argument('alias')
    return ap


COMMANDS = {'list': cmd_list, 'run': cmd_run, 'get': cmd_get, 'mask': cmd_mask, 'audit': cmd_audit,
            'hostkey': cmd_hostkey, 'vendors': cmd_vendors}


def main(argv=None):
    for s in (sys.stdout, sys.stderr):
        if hasattr(s, 'reconfigure'):   # no newline translation on any OS: run/get print LF
            s.reconfigure(encoding='utf-8', errors='replace', newline='\n')
    a = parser().parse_args(argv)
    try:
        return COMMANDS[a.cmd](a)
    except connectors.TransportError as e:
        print(f'credveil: {e}', file=sys.stderr)
        return EXIT_TRANSPORT
    except (config.UsageError, ValueError, OSError, tomllib.TOMLDecodeError) as e:
        detail = e.filename if isinstance(e, FileNotFoundError) and e.filename else e
        print(f'credveil: {detail}', file=sys.stderr)
        return EXIT_USAGE
