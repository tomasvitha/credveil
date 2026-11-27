#!/usr/bin/env python3
"""Claude Code hook entry point: `claude_code.py pre home|full` or `claude_code.py post`."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
from credveil.adapters.claude_code import main  # noqa: E402

sys.exit(main(sys.argv[1:]))
