"""SSH: one non-interactive exec carrying all commands. plink on Windows, OpenSSH elsewhere."""
import os
import shutil
import subprocess
import tempfile
from types import SimpleNamespace

from .. import config
from . import Result, TransportError, decode, register

WINDOWS = os.name == 'nt'


def _which(*names):
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    raise TransportError(f'{names[0]} not found on PATH')


def _uses_plink(d):
    return WINDOWS or d.get('ssh_client') == 'plink'


def argv(d, cmdfile, tmp):
    """argv and env for one exec that reads its commands from cmdfile."""
    port, host, user = str(d.get('port', 22)), d['host'], d.get('user')
    target = f'{user}@{host}' if user else host
    pw = d.get('password_file')
    if _uses_plink(d):
        if not d.get('hostkey'):
            raise config.UsageError(f'device {d["alias"]!r}: no hostkey pin (run: credveil hostkey {d["alias"]})')
        a = [_which('plink', 'plink.exe'), '-ssh', '-batch', '-P', port, '-hostkey', d['hostkey'], '-m', cmdfile]
        if pw:
            a += ['-pwfile', pw]
        if d.get('key_file'):
            a += ['-i', d['key_file']]
        return a + [target], None
    kh = os.path.join(config.home(), 'known_hosts')
    a = [_which('ssh'), '-T', '-p', port, '-o', 'StrictHostKeyChecking=yes', '-o', f'UserKnownHostsFile={kh}',
         '-o', 'BatchMode=no' if pw else 'BatchMode=yes', '-o', 'NumberOfPasswordPrompts=1']
    if d.get('key_file'):
        a += ['-i', d['key_file']]
    env = None
    if pw:
        helper = os.path.join(tmp, 'askpass.sh')
        with open(helper, 'w') as fh:
            fh.write('#!/bin/sh\nexec cat "$CREDVEIL_PWFILE"\n')
        os.chmod(helper, 0o700)
        env = dict(os.environ, SSH_ASKPASS=helper, SSH_ASKPASS_REQUIRE='force', CREDVEIL_PWFILE=pw,
                   DISPLAY=os.environ.get('DISPLAY', 'credveil:0'))
    # OpenSSH sends the remote command as one string; verified line by line on FortiOS only.
    with open(cmdfile, encoding='utf-8') as fh:
        return a + [target, fh.read()], env


def run(d, cmds, timeout):
    with tempfile.TemporaryDirectory(prefix='credveil-') as tmp:
        cmdfile = os.path.join(tmp, 'cmds.txt')
        with open(cmdfile, 'w', encoding='utf-8', newline='\n') as fh:
            fh.write('\n'.join(cmds) + '\n')
        a, env = argv(d, cmdfile, tmp)
        try:
            p = subprocess.run(a, stdin=subprocess.DEVNULL, capture_output=True, env=env, timeout=timeout)
        except subprocess.TimeoutExpired as e:
            return Result(decode(e.stdout), decode(e.stderr) + f'\ncredveil: timeout after {timeout}s', 93)
    return Result(decode(p.stdout), decode(p.stderr), p.returncode)


def fingerprints(d):
    """The device's host-key fingerprints, for the operator to verify and pin."""
    port = str(d.get('port', 22))
    if _uses_plink(d):
        p = subprocess.run([_which('plink', 'plink.exe'), '-ssh', '-batch', '-P', port,
                            f'credveil-probe@{d["host"]}', 'exit'],
                           stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
        text = decode(p.stdout) + decode(p.stderr)
        return sorted({w.strip('.,') for w in text.split() if w.startswith('SHA256:')})
    p = subprocess.run([_which('ssh-keyscan'), '-p', port, d['host']], capture_output=True, timeout=30)
    q = subprocess.run([_which('ssh-keygen'), '-lf', '-'], input=p.stdout, capture_output=True)
    return [line for line in decode(q.stdout).splitlines() if line.strip()]


register('ssh', SimpleNamespace(run=run, fingerprints=fingerprints))
