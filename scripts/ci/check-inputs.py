#!/usr/bin/env python3
"""Keep required checks reporting while docs-only changes skip heavy steps."""
import subprocess
import sys


def changed_checks(base, head):
    if not base or set(base) == {"0"}:
        return True
    try:
        paths = subprocess.check_output(
            ["git", "diff", "--name-only", "--no-renames", base, head], text=True
        ).splitlines()
        return checks_required(paths)
    except subprocess.CalledProcessError:
        return True  # Unknown history must never skip checks.


def checks_required(paths):
    return any(not (path.startswith("docs/") or path.endswith(".md")) for path in paths)


if __name__ == "__main__":
    base, head = sys.argv[1:]
    print(f"checks={str(changed_checks(base, head)).lower()}")
