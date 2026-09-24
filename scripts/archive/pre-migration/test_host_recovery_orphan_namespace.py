#!/usr/bin/env python3
"""Run the TUnit recovery tests as children of a deliberately non-reaping PID 1.

From the repository root after a Release solution build:
  nice -n 19 unshare --user --map-root-user --pid --fork --mount-proc \
    python3 scripts/test_host_recovery_orphan_namespace.py /tmp/host-recovery.log
The private PID namespace is destroyed on exit, including any remaining orphans.
"""

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


def main() -> int:
    if os.getpid() != 1 or len(sys.argv) != 2:
        raise SystemExit("Run inside the private PID namespace shown in this script's docstring, with a log path.")
    signal.signal(signal.SIGCHLD, signal.SIG_DFL)
    root = Path(__file__).resolve().parent.parent
    executable = root / "tests/TerraScale.Orchestrator.Tests/bin/Release/net11.0/linux-x64/TerraScale.Orchestrator.Tests"
    if not executable.is_file():
        raise SystemExit("Build the Release solution before running this harness.")
    with Path(sys.argv[1]).open("w") as output:
        child = subprocess.Popen(
            [str(executable), "--treenode-filter", "/*/*/HostRecoveryProcessTests/*",
             "--minimum-expected-tests", "2", "--no-ansi", "--no-progress"],
            stdout=output, stderr=subprocess.STDOUT, cwd=root,
        )
        zombies = {}
        started = time.monotonic()
        while child.poll() is None and time.monotonic() - started < 90:
            for process in Path("/proc").iterdir():
                if not process.name.isdigit():
                    continue
                try:
                    stat = (process / "stat").read_text()
                    fields = stat[stat.rfind(")") + 2:].split()
                    if "(sleep)" in stat and fields[0] == "Z":
                        zombies[process.name] = {"state": fields[0], "parent": fields[1], "startTicks": fields[19]}
                except (FileNotFoundError, ProcessLookupError, PermissionError):
                    pass
            time.sleep(0.05)
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)
        print(json.dumps({"exitCode": child.returncode, "observedZombies": zombies}), flush=True)
        return child.returncode if child.returncode != 0 else (0 if zombies else 3)


if __name__ == "__main__":
    sys.exit(main())
