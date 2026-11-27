"""Claude Code hooks. Usage (stdin: the hook JSON):

    python -m credveil.adapters.claude_code pre home    PreToolUse, always on: $CREDVEIL_HOME only
    python -m credveil.adapters.claude_code pre full    PreToolUse, skill-scoped: also direct device access
    python -m credveil.adapters.claude_code post        PostToolUse output net (skill-scoped)

pre: exit 2 with the reason on stderr blocks the call (Claude Code's contract).
post: prints `hookSpecificOutput.updatedToolOutput`. The output of a Bash command that exits
non-zero goes to PostToolUseFailure, which cannot be rewritten: that path is not covered.
Any internal error fails open, except that a Bash-shaped output is withheld.
"""
import json
import os
import sys

from .. import config, policy
from ..mask import mask_any

SHELL, READ, SEARCH = ('Bash', 'PowerShell'), ('Read',), ('Grep',)
WRITE = ('Edit', 'Write', 'MultiEdit', 'NotebookEdit')
PACKAGE_DIR = os.path.normcase(os.path.realpath(os.path.join(os.path.dirname(__file__), '..', '..')))
BLOCK_HINT = ('Device access goes through credveil (`credveil run|get <alias>`), which masks secrets '
              'and keeps credentials out of the session. Do not work around this; tell the user if '
              'credveil cannot do what is needed.')


def decide(data, rules, scope):
    tool = data.get('tool_name') or ''
    ti = data.get('tool_input') or {}
    if tool in SHELL:
        return policy.check_shell(ti.get('command') or '', rules, scope)
    if tool in READ:
        return policy.check_read(ti.get('file_path') or '', rules)
    if tool in SEARCH:
        return policy.check_search(ti.get('path') or data.get('cwd') or '', rules)
    if tool in WRITE:
        return policy.check_write(ti.get('file_path') or ti.get('notebook_path') or '', rules)
    return None


def pre(scope):
    try:
        data = json.load(sys.stdin)
        rules = policy.load()
        why = decide(data, rules, scope) if rules else None
    except Exception:  # noqa: BLE001 - fail open: a broken guard must not block unrelated work
        return 0
    if why:
        print(f'Blocked by the credveil guard: {why}. {BLOCK_HINT}', file=sys.stderr)
        return 2
    return 0


def _walk(obj, fn):
    if isinstance(obj, dict):
        return {k: _walk(v, fn) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_walk(v, fn) for v in obj]
    return fn(obj) if isinstance(obj, str) else obj


def post():
    try:
        data = json.load(sys.stdin)
    except Exception:  # noqa: BLE001
        return 0
    resp = data.get('tool_response')
    if not isinstance(resp, (dict, list, str)):
        return 0
    try:
        if data.get('tool_name') in READ:
            fp = (data.get('tool_input') or {}).get('file_path') or ''
            if os.path.normcase(os.path.realpath(fp)).startswith(PACKAGE_DIR + os.sep):
                return 0                       # credveil's own sources and test fixtures
        inv = config.load(required=False)
        known = inv.known_secrets() if inv else []
        new = _walk(resp, lambda s: mask_any(s, known))
        if new == resp:
            return 0
    except Exception:  # noqa: BLE001 - withhold what we can recognise, else fail open
        if not (isinstance(resp, dict) and 'stdout' in resp):
            return 0
        new = dict(resp, stdout='[credveil output net failed; output withheld]', stderr='')
    print(json.dumps({'hookSpecificOutput': {'hookEventName': data.get('hook_event_name', 'PostToolUse'),
                                             'updatedToolOutput': new}}))
    return 0


def main(argv):
    if argv[:1] == ['pre'] and argv[1:2] in (['home'], ['full']):
        return pre(argv[1])
    if argv[:1] == ['post']:
        return post()
    print(__doc__, file=sys.stderr)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
