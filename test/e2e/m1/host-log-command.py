#!/usr/bin/python3
import os
import signal
import subprocess
import sys
from pathlib import Path

root = Path("/run/ts-e2e-host-log-commands")
mode = (root / "mode").read_text().strip()
name = Path(sys.argv[0]).name
args = sys.argv[1:]
for variable in ("NOTIFY_SOCKET", "WATCHDOG_USEC", "WATCHDOG_PID"):
    if variable in os.environ:
        (root / "notification-leak").write_text(variable)
        sys.exit(f"child inherited {variable}")
if name == "iptables":
    state = subprocess.check_output(
        [
            "/usr/local/lib/ts-e2e-host-log-commands/real/systemctl",
            "show",
            "ts-orch.service",
            "--property=ActiveState",
            "--value",
        ],
        text=True,
    ).strip()
    with (root / "notification-probes").open("a") as probes:
        probes.write(f"iptables {state}\n")
if name == "systemctl" and any(arg in ("disable", "stop", "mask") for arg in args):
    with (root / "syslog-actions").open("a") as actions:
        actions.write(" ".join(args) + "\n")
if (
    mode == "unreadable-time"
    and name == "systemctl"
    and any("ActiveEnterTimestamp" in arg for arg in args)
):
    sys.exit("injected journal timestamp read failure")
if mode == "absent" and name == "systemctl" and "rsyslog.service" in args:
    print("LoadState=not-found")
    sys.exit(0)
if name == "journalctl" and args == ["--rotate"]:
    if mode == "interrupted-rotate":
        (root / "entered").touch()
        signal.pause()
    with (root / "rotations").open("a") as rotations:
        rotations.write("rotate\n")
restart = name == "systemctl" and args == ["restart", "systemd-journald.service"]
if (
    mode == "syslog"
    and name == "systemctl"
    and args == ["disable", "--now", "rsyslog.service"]
):
    sys.exit("injected syslog failure")
if mode == "rotate" and name == "journalctl":
    sys.exit("injected rotation failure")
if restart:
    with (root / "restarts").open("a") as counts:
        counts.write("restart\n")
    if mode == "completed-timeout":
        subprocess.run(
            [
                "/usr/local/lib/ts-e2e-host-log-commands/real/systemctl",
                "is-active",
                "--quiet",
                "ts-orch.service",
            ],
            check=True,
        )
        serving = subprocess.run(
            ["/usr/local/bin/ts-orch", "service", "ls"], check=True, capture_output=True
        ).stdout
        if b"e2e-whoami" not in serving:
            sys.exit("agent was not supervising before housekeeping")
        (root / "ready").write_bytes(serving)
        subprocess.run(
            ["/usr/local/lib/ts-e2e-host-log-commands/real/systemctl", *args],
            check=True,
        )
        (root / "entered").touch()
        signal.pause()
    if mode == "restart":
        sys.exit("injected journal restart failure")
    if mode == "interrupted-publish":
        (root / "entered").touch()
        signal.pause()
    if mode in ("hung", "pipe"):
        child = os.fork()
        if child == 0:
            signal.pause()
            sys.exit(0)
        (root / "pids").write_text(f"{os.getpid()} {child}\n")
        if mode == "hung":
            signal.pause()
        sys.exit(0)
os.execv(
    str(Path("/usr/local/lib/ts-e2e-host-log-commands/real") / name), [name, *args]
)
