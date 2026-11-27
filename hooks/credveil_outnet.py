#!/usr/bin/env python3
"""PostToolUse safety net (Claude Code only): mask unambiguous secrets in Bash, PowerShell, Grep and
Read output before the model sees it, via `hookSpecificOutput.updatedToolOutput`.

The second layer behind credveil: it catches what reaches the session by another path - an export
read with Read, a `cat` of a log dump. Only secretmask.net_mask's high-precision rules apply
(private-key PEM blocks, FortiOS ENC blobs, crypt/$9$ hashes, `key=N <hex>` session keys, and
the literal credentials from the credveil inventory), so source code and ordinary output pass
unchanged.

Limits, verified 2026-11-27 (Claude Code 2.x, headless run):
  - Bash and Read output is replaced; the tool already ran - this only changes what Claude sees.
  - A command that exits non-zero goes to PostToolUseFailure, whose error text cannot be
    replaced: that path is NOT covered.
  - Read of files inside the credveil skill itself is skipped (its tests plant fake secrets).
On an internal error with a Bash/PowerShell-shaped response the output is withheld; otherwise
the hook does nothing (fail open).
"""
import json
import os
import sys
import tomllib

HERE = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', 'scripts'))
SKILL_DIR = os.path.normcase(os.path.realpath(os.path.join(HERE, '..')))


def known_secrets():
    home = os.path.expanduser(os.environ.get('CREDVEIL_HOME') or '~/.config/credveil')
    path = os.path.join(home, 'inventory.toml')
    if not os.path.exists(path):
        return []
    with open(path, 'rb') as fh:
        inv = tomllib.load(fh)
    out = []
    for d in inv.get('device', {}).values():
        for k in ('password_file', 'token_file'):
            if d.get(k):
                p = os.path.expanduser(d[k])
                p = p if os.path.isabs(p) else os.path.join(home, p)
                try:
                    with open(p, encoding='utf-8') as fh:
                        out.append(fh.read().strip())
                except OSError:
                    pass
    return [s for s in out if s]


def walk(obj, fn):
    if isinstance(obj, dict):
        return {k: walk(v, fn) for k, v in obj.items()}
    if isinstance(obj, list):
        return [walk(v, fn) for v in obj]
    if isinstance(obj, str):
        return fn(obj)
    return obj


def main():
    try:
        data = json.load(sys.stdin)
    except Exception:  # noqa: BLE001
        return 0
    resp = data.get('tool_response')
    if not isinstance(resp, (dict, list, str)):
        return 0
    try:
        if data.get('tool_name') == 'Read':
            fp = (data.get('tool_input') or {}).get('file_path') or ''
            if os.path.normcase(os.path.realpath(fp)).startswith(SKILL_DIR + os.sep):
                return 0
        import secretmask as sm
        known = known_secrets()
        new = walk(resp, lambda s: sm.net_mask(s, known))
        if new == resp:
            return 0
    except Exception:  # noqa: BLE001 - withhold what we can recognise, else fail open
        if isinstance(resp, dict) and 'stdout' in resp:
            new = dict(resp, stdout='[credveil output net failed; output withheld]', stderr='')
        else:
            return 0
    print(json.dumps({'hookSpecificOutput': {'hookEventName': data.get('hook_event_name', 'PostToolUse'),
                                             'updatedToolOutput': new}}))
    return 0


if __name__ == '__main__':
    sys.exit(main())
