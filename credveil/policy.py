"""Guard decisions, independent of any agent harness. Each check returns a reason or None.

Two scopes:
  home  always on: credential files stay unread, $CREDVEIL_HOME stays unwritten and cannot be
        swapped for another inventory. No inventory yet: nothing to protect, so setup is free.
  full  while the skill is active, also: no direct ssh/plink/curl/… to an inventory device.

A seatbelt against an agent's mistake or a prompt injection, not a sandbox: a determined
workaround (an encoded command, a script file) gets past string matching.
"""
import os
import re
from dataclasses import dataclass

from . import config

TRANSPORT_CMDS = frozenset({
    'ssh', 'sshpass', 'plink', 'putty', 'pscp', 'psftp', 'scp', 'sftp', 'curl', 'wget', 'nc', 'ncat',
    'socat', 'telnet', 'openssl', 'invoke-webrequest', 'invoke-restmethod', 'iwr', 'irm',
    'new-pssession', 'enter-pssession'})
WRAPPERS = frozenset({'sudo', 'env', 'exec', 'time', 'nohup', 'command', 'xargs', 'timeout', '&'})
INTERPRETERS = frozenset({'python', 'python3', 'py', 'node', 'perl', 'ruby', 'pwsh', 'powershell'})
LIBRARY_RE = re.compile(r'(?<![\w.-])(?:paramiko|netmiko|requests|urllib|http\.client|socket|'
                        r'Net\.WebClient|Net\.Sockets)(?![\w-])', re.I)
HOME_OVERRIDE_RE = re.compile(r'(?i)(?:^|[\s;&|(`$:])CREDVEIL_HOME\s*=|setx\s+CREDVEIL_HOME')
HEREDOC_RE = re.compile(r'<<-?\s*([\'"]?)(\w+)\1[^\n]*\n.*?(?:\n\s*\2\s*(?=\n|$)|\Z)', re.S)
QUOTED_RE = re.compile(r'"(?:[^"\\]|\\.)*"|\'[^\']*\'')
INLINE_ARG_RE = re.compile(r'(?:^|\s)(?:-c|-Command|/c)\s+("(?:[^"\\]|\\.)*"|\'[^\']*\')', re.I)
SEGMENT_SPLIT_RE = re.compile(r'\|\||&&|(?<![&>])&(?![&>])|[|;\n`]|\$\(|\(|\)|\{|\}')


@dataclass
class Rules:
    home: str
    protect: list       # normalized credential paths (files and creds/)
    hosts: list


def load(base=None):
    inv = config.load(base, required=False)
    if inv is None:
        return None
    return Rules(home=norm(inv.home), protect=[norm(p) for p in inv.credential_files()], hosts=inv.hosts())


def norm(p):
    p = os.path.expanduser(p).replace('\\', '/')
    m = re.match(r'^/([a-zA-Z])/(.*)$', p)               # Git Bash /c/Users -> c:/Users
    if m and os.name == 'nt':
        p = f'{m.group(1)}:/{m.group(2)}'
    p = os.path.realpath(p).replace('\\', '/') if p else p
    return p.lower() if os.name == 'nt' else p


# ---------------------------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------------------------
def _within(p, q):
    return p == q or p.startswith(q + '/')


def check_read(path, rules):
    p = norm(path)
    if any(_within(p, q) for q in rules.protect):
        return f'{path} is a protected credential path'
    return None


def check_search(path, rules):
    """A search root at or above a credential path would read it."""
    p = norm(path) if path else ''
    for q in rules.protect:
        if not p or _within(p, q) or _within(q, p):
            return f'searching {path or "."} would read the protected credential path {q}'
    return None


def check_write(path, rules):
    if _within(norm(path), rules.home):
        return f'{path} is inside the credveil configuration ({rules.home}); the operator edits it'
    return None


# ---------------------------------------------------------------------------------------------
# Shell commands
# ---------------------------------------------------------------------------------------------
def _forms(p):
    """Spellings of a protected path likely to appear in a command line."""
    forms = {p}
    user_home = norm('~')
    if p.startswith(user_home + '/'):
        forms.add(p[len(user_home) + 1:])               # .config/credveil/... after ~/ or $HOME/
    base = p.rsplit('/', 1)[-1]
    if '.' in base and len(base) >= 6:                  # a distinctive file name on its own
        forms.add(base)
    return forms


def check_shell(cmd, rules, scope='full'):
    if HOME_OVERRIDE_RE.search(cmd):
        return 'it sets CREDVEIL_HOME, which would point credveil at another inventory'
    c = re.sub(r'/+', '/', cmd.replace('\\', '/'))
    cl = c.lower() if os.name == 'nt' else c
    for p in rules.protect + [rules.home]:
        for f in _forms(p):
            if f in cl:
                return f'it references the protected credveil path {f!r}'
    if scope == 'full' and opens_transport(cmd):
        for h in rules.hosts:
            if re.search(r'(?<![\w.-])' + re.escape(h) + r'(?![\w-]|\.\w)', cmd, re.I):
                return f'it opens a direct connection to inventory device {h}'
    return None


def _word(tok):
    w = tok.replace('\\', '/').rsplit('/', 1)[-1].lower()
    return w[:-4] if w.endswith('.exe') else w


def command_words(cmd, depth=0):
    """First word of every command segment; -c / -Command strings are checked recursively.

    Quoted text and heredoc bodies are dropped first, so prose naming a device never counts.
    """
    words = []
    if depth < 3:
        for m in INLINE_ARG_RE.finditer(cmd):
            words += command_words(m.group(1)[1:-1], depth + 1)
    body = HEREDOC_RE.sub('<<HEREDOC\n', cmd)
    # a quoted program path (PowerShell `& "C:/PuTTY/plink.exe"`) stays visible; other quoted text goes
    body = QUOTED_RE.sub(lambda m: m.group(0)[1:-1].replace(' ', '_')
                         if _word(m.group(0)[1:-1]) in TRANSPORT_CMDS else '""', body)
    for seg in SEGMENT_SPLIT_RE.split(body):
        toks = seg.split()
        while toks:
            if len(toks) >= 2 and toks[1] == '=' and toks[0].startswith('$'):
                del toks[:2]                       # PowerShell `$r = Invoke-RestMethod …`
            elif (re.match(r'^\$?\w+=', toks[0]) or _word(toks[0]) in WRAPPERS
                  or toks[0].startswith('-') or toks[0].isdigit()):
                toks.pop(0)
            else:
                break
        if toks:
            words.append(_word(toks[0]))
    return words


def opens_transport(cmd):
    words = command_words(cmd)
    if any(w in TRANSPORT_CMDS for w in words):
        return True
    return any(w in INTERPRETERS for w in words) and bool(LIBRARY_RE.search(cmd))
