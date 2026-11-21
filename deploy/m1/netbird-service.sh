#!/usr/bin/env bash
set -euo pipefail
binary=$1
expected=$2
echo "$expected  $binary" | sha256sum -c --status
properties=$(systemctl show --property=LoadState --property=MainPID netbird)
load_state=$(sed -n 's/^LoadState=//p' <<< "$properties")
pid=$(sed -n 's/^MainPID=//p' <<< "$properties")
[[ $pid =~ ^[0-9]+$ ]]
unit=missing
process=stopped
if [[ $load_state != not-found ]]; then
	state=$(busctl --json=short get-property org.freedesktop.systemd1 /org/freedesktop/systemd1/unit/netbird_2eservice org.freedesktop.systemd1.Service ExecStart |
		python3 -c '
import json
import os
import sys
from pathlib import Path

commands = json.load(sys.stdin)["data"]
binary, pid = sys.argv[1:]
canonical = len(commands) == 1 and commands[0][0] == binary and commands[0][1][:3] == [binary, "service", "run"]
matches = False
if pid != "0":
    running = [os.fsdecode(arg) for arg in Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")[:-1]]
    matches = len(commands) == 1 and commands[0][1] == running
print("canonical" if canonical else "different", "matches" if matches else "different")
' "$binary" "$pid")
	read -r unit process <<< "$state"
fi
action=start
if [[ $pid != 0 ]]; then
	running=$(sha256sum "/proc/$pid/exe")
	[[ $running == "$expected "* && $process == matches ]] || action=restart
fi
if [[ $unit != canonical ]]; then
	if [[ $load_state == not-found ]]; then
		"$binary" service install
	else
		systemctl stop netbird
		"$binary" service reconfigure
	fi
	action=restart
fi
systemctl enable netbird
systemctl "$action" netbird
