#!/usr/bin/env python3
"""`python scripts/credveil.py …` without installing the package (the skill's documented entry)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
from credveil.cli import main  # noqa: E402

sys.exit(main())
