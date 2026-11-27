#!/usr/bin/env python3
"""PreToolUse guard: keep agents on the credveil path to devices and away from credential files.

Blocks (exit 2, reason on stderr - the Claude Code PreToolUse contract):
  Bash / PowerShell  a command naming a protected credential path, or naming an inventory
                     device's host together with a transport (ssh, plink, curl, Invoke-WebRequest…)
  Read / Grep        a path inside, equal to, or (Grep) above a protected credential path

Protected: $CREDVEIL_HOME/creds/, every password_file / token_file / key_file in the inventory,
and `[guard] protect = [...]`. Device hosts: every `host`, plus `[guard] hosts = [...]` for
names that reach the same boxes (FQDNs, HA peers).

A seatbelt against an agent's mistake, not a sandbox: a determined workaround (an encoded
command, a script file) gets past string matching. No inventory, unreadable input or any
internal error: allow (fail open), so a broken guard never blocks unrelated work.
"""
import json
import os
import re
import sys
import tomllib

# A transport counts only in command position (FP-2, 2026-11-27): the first word of a command
# segment, after env assignments and wrappers. Prose in quotes, heredoc bodies and commit
# messages never trigger. Client libraries count only when the command runs an interpreter.
TRANSPORT_CMDS = frozenset({
    'ssh', 'plink', 'putty', 'pscp', 'psftp', 'scp', 'sftp', 'curl', 'wget', 'nc', 'ncat', 'socat',
    'telnet', 'openssl', 'invoke-webrequest', 'invoke-restmethod', 'iwr', 'irm', 'new-pssession',
    'enter-pssession'})
WRAPPERS = frozenset({'sudo', 'env', 'exec', 'time', 'nohup', 'command', 'xargs', 'timeout', '&'})
INTERPRETERS = frozenset({'python', 'python3', 'py', 'node', 'perl', 'ruby', 'pwsh', 'powershell'})
LIBRARY_RE = re.compile(r'(?<![\w.-])(?:paramiko|netmiko|requests|urllib|http\.client|socket|'
                        r'Net\.WebClient|Net\.Sockets)(?![\w-])', re.I)
HEREDOC_RE = re.compile(r'<<-?\s*([\'"]?)(\w+)\1[^\n]*\n.*?(?:\n\s*\2\s*(?=\n|$)|\Z)', re.S)
QUOTED_RE = re.compile(r'"(?:[^"\\]|\\.)*"|\'[^\']*\'')
INLINE_ARG_RE = re.compile(r'(?:^|\s)(?:-c|-Command|/c)\s+("(?:[^"\\]|\\.)*"|\'[^\']*\')', re.I)
SEGMENT_SPLIT_RE = re.compile(r'\|\||&&|(?<![&>])&(?![&>])|[|;\n`]|\$\(|\(|\)|\{|\}')


def _word(tok):
    w = tok.replace('\\', '/').rsplit('/', 1)[-1].lower()
    return w[:-4] if w.endswith('.exe') else w


def command_words(cmd, depth=0):
    """First word of every command segment, with -c / -Command strings checked recursively."""
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


def norm(p):
    p = os.path.expanduser(p).replace('\\', '/')
    m = re.match(r'^/([a-zA-Z])/(.*)$', p)  # Git Bash /c/Users -> c:/Users
    if m and os.name == 'nt':
        p = f'{m.group(1)}:/{m.group(2)}'
    p = re.sub(r'/+', '/', p).rstrip('/')
    return p.lower() if os.name == 'nt' else p


def load():
    home = os.path.expanduser(os.environ.get('CREDVEIL_HOME') or '~/.config/credveil')
    path = os.path.join(home, 'inventory.toml')
    if not os.path.exists(path):
        return None
    with open(path, 'rb') as fh:
        inv = tomllib.load(fh)
    guard = inv.get('guard', {})
    protect = [os.path.join(home, 'creds')] + list(guard.get('protect', []))
    hosts = list(guard.get('hosts', []))
    for d in inv.get('device', {}).values():
        hosts.append(d.get('host', ''))
        for k in ('password_file', 'token_file', 'key_file'):
            if d.get(k):
                p = os.path.expanduser(d[k])
                protect.append(p if os.path.isabs(p) else os.path.join(home, p))
    return [norm(p) for p in protect], [h for h in hosts if h]


def path_forms(p):
    """Spellings of a protected path likely to appear in a command line."""
    forms = {p}
    user_home = norm('~')
    if p.startswith(user_home + '/'):
        forms.add(p[len(user_home) + 1:])          # .config/credveil/creds/x.pw (after ~/ or $HOME/)
    base = p.rsplit('/', 1)[-1]
    if '.' in base and len(base) >= 6:             # a distinctive file name on its own
        forms.add(base)
    return forms


def check_command(cmd, protect, hosts):
    c = cmd.replace('\\', '/')
    c = re.sub(r'/+', '/', c)
    cl = c.lower() if os.name == 'nt' else c
    for p in protect:
        for f in path_forms(p):
            if f in cl:
                return f'it references the protected credential path {f!r}'
    if opens_transport(cmd):
        for h in hosts:
            if re.search(r'(?<![\w.-])' + re.escape(h) + r'(?![\w-]|\.\w)', cmd, re.I):
                return f'it opens a direct connection to inventory device {h}'
    return None


def check_path(path, protect, ancestor_too):
    p = norm(path)
    for q in protect:
        if p == q or p.startswith(q + '/'):
            return f'{path} is a protected credential path'
        if ancestor_too and (q.startswith(p + '/') or not p):
            return f'{path} contains the protected credential path {q}'
    return None


def main():
    try:
        data = json.load(sys.stdin)
        cfg = load()
        if not cfg:
            return 0
        protect, hosts = cfg
        tool = data.get('tool_name') or ''
        ti = data.get('tool_input') or {}
        why = None
        if tool in ('Bash', 'PowerShell'):
            why = check_command(ti.get('command') or '', protect, hosts)
        elif tool == 'Read':
            why = check_path(ti.get('file_path') or '', protect, False)
        elif tool == 'Grep':
            why = check_path(ti.get('path') or data.get('cwd') or '', protect, True)
    except Exception:  # noqa: BLE001 - fail open
        return 0
    if why:
        print(f'Blocked by the credveil guard: {why}. Device access goes through credveil '
              f'(~/.claude/skills/credveil, `credveil run|get <alias>`), which masks secrets and keeps '
              f'credentials out of the session. Do not work around this; tell the user if credveil '
              f'cannot do what is needed.', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
