#!/bin/sh
# Run one of the credveil hook scripts with a Python that works on this machine.
#   bash run-py.sh credveil_guard.py     (PreToolUse)
#   bash run-py.sh credveil_outnet.py    (PostToolUse)
# Windows (Git Bash): `python` - `python3` there is the Microsoft Store stub.
# No usable Python: exit 0 (fail open), so a missing Python never blocks unrelated work.
script="$(dirname "$0")/$1"
shift
if [ "$OS" = "Windows_NT" ]; then
    command -v python >/dev/null 2>&1 && exec python -I "$script" "$@"
else
    command -v python3 >/dev/null 2>&1 && exec python3 -I "$script" "$@"
fi
exit 0
