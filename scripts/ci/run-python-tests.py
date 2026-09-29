#!/usr/bin/env python3
"""Run the repository's Python unittest suites, one test per process, in parallel.

Each SUITE argument is DIRECTORY[:PATTERN] (default pattern test_*.py). Every
discovered test method runs in its own `python3 -m unittest` process from the
suite directory, so slow subprocess-driven tests (the offline image builder
fixtures) overlap instead of queueing. The run fails if any test fails, errors,
or if a suite discovers no tests.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import os
import subprocess
import sys
import time
from pathlib import Path


DISCOVER = """
import sys, unittest

def ids(suite):
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            yield from ids(test)
        elif type(test).__name__ in ("_FailedTest", "ModuleImportFailure"):
            raise SystemExit(f"cannot import test module: {test.id()}")
        else:
            yield test.id()

print("\\n".join(ids(unittest.TestLoader().discover(".", pattern=sys.argv[1], top_level_dir="."))))
"""


def discover(directory: Path, pattern: str) -> list[str]:
    # Suites reuse module names (several test_qualify.py), so each discovery
    # runs in its own interpreter, from the directory its tests later run in.
    result = subprocess.run([sys.executable, "-c", DISCOVER, pattern], cwd=directory,
                            capture_output=True, text=True, check=False)
    if result.returncode:
        raise SystemExit(f"test discovery failed in {directory}:\n{result.stderr}")
    return result.stdout.split()


def run(directory: Path, test_id: str) -> tuple[str, int, float, str]:
    started = time.monotonic()
    result = subprocess.run(
        [sys.executable, "-m", "unittest", test_id], cwd=directory,
        capture_output=True, text=True, check=False,
    )
    return test_id, result.returncode, time.monotonic() - started, result.stdout + result.stderr


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("suites", nargs="+", metavar="DIRECTORY[:PATTERN]")
    parser.add_argument("--jobs", type=int, default=os.cpu_count() or 4)
    args = parser.parse_args()

    work = []
    for suite in args.suites:
        directory, _, pattern = suite.partition(":")
        root = Path(directory).resolve()
        ids = discover(root, pattern or "test_*.py")
        if not ids:
            raise SystemExit(f"no tests discovered in {suite}")
        work.extend((root, test_id) for test_id in ids)

    started = time.monotonic()
    failures = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        for test_id, status, elapsed, output in pool.map(lambda item: run(*item), work):
            if status:
                failures.append((test_id, output))
            print(f"{'FAIL' if status else 'ok  '} {elapsed:6.1f}s {test_id}", flush=True)
    for test_id, output in failures:
        print(f"\n===== {test_id}\n{output}", file=sys.stderr)
    print(f"{len(work) - len(failures)}/{len(work)} Python tests passed in {time.monotonic() - started:.1f}s")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
