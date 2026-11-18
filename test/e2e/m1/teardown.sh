#!/usr/bin/env bash
set -euo pipefail

lane_dir=$(cd "$(dirname "$0")" && pwd)
group_file=${RUNNER_TEMP:?}/m1-lane-process-group
unit_patterns=('ts-orch*' 'containerd*' 'netbird*' 'terrascale-*' 'ts-e2e-*' 'docker.service' 'docker.socket')
process_pattern='(^|/)(containerd(-shim[^ ]*)?|terrascale-orchestrator|ts-orch|ntp_responder.py)( |$)'

active_units() {
	systemctl list-units --all --plain --no-legend --state=active,activating,deactivating "${unit_patterns[@]}" | awk '{print $1}'
}

kill_processes() {
	sudo python3 - "$@" <<'PYTHON'
import os
import select
import signal
import sys

handles = []
for value in sys.argv[1:]:
    try:
        handle = os.pidfd_open(int(value))
        signal.pidfd_send_signal(handle, signal.SIGKILL)
        handles.append(handle)
    except ProcessLookupError:
        continue
for handle in handles:
    poll = select.poll()
    poll.register(handle, select.POLLIN)
    poll.poll()
    os.close(handle)
PYTHON
}

check_clean() {
	local failed=0 path units processes listeners
	for path in /var/lib/ts-orch /var/lib/ts-data/e2e "$HOME/.ssh/ts-e2e" "$HOME/.ssh/ts-e2e.pub"; do
		if sudo test -e "$path" || sudo test -L "$path"; then
			echo "::error::Lane found leftover path: $path"
			failed=1
		fi
	done
	units=$(active_units)
	if [[ -n $units ]]; then
		echo "::error::Lane found leftover active units: $units"
		failed=1
	fi
	if processes=$(pgrep -l -f "$process_pattern"); then
		echo "::error::Lane found leftover runtime processes: $processes"
		failed=1
	fi
	listeners=$(sudo ss -H -ltnp 'sport = :8443')
	if [[ -n $listeners ]]; then
		echo "::error::Lane found leftover listener on port 8443: $listeners"
		failed=1
	fi
	return "$failed"
}

if [[ ${1:-} == check ]]; then
	check_clean
	exit
fi
[[ $# == 0 ]]

unit_names=$(systemctl list-units --all --plain --no-legend "${unit_patterns[@]}" | awk '$1 !~ /^containerd/ {print $1}')
if [[ -n $unit_names ]]; then
	mapfile -t units <<<"$unit_names"
	sudo systemctl stop "${units[@]}"
fi

if [[ -e $group_file ]]; then
	group=$(cat "$group_file")
	if processes=$(pgrep -g "$group"); then
		mapfile -t pids <<<"$processes"
		kill_processes "${pids[@]}"
	fi
	rm "$group_file"
fi

if sudo test -S /run/containerd/containerd.sock; then
	namespaces=$(sudo ctr namespaces list -q)
	while read -r namespace; do
		[[ -n $namespace ]] || continue
		tasks=$(sudo ctr --namespace "$namespace" tasks list -q)
		while read -r task; do
			[[ -n $task ]] || continue
			sudo ctr --namespace "$namespace" tasks delete --force "$task"
		done <<<"$tasks"
		containers=$(sudo ctr --namespace "$namespace" containers list -q)
		while read -r container; do
			[[ -n $container ]] || continue
			sudo ctr --namespace "$namespace" containers delete "$container"
		done <<<"$containers"
	done <<<"$namespaces"
fi
unit_names=$(systemctl list-units --all --plain --no-legend 'containerd*' | awk '{print $1}')
if [[ -n $unit_names ]]; then
	mapfile -t units <<<"$unit_names"
	sudo systemctl stop "${units[@]}"
fi

if processes=$(pgrep -f "$process_pattern"); then
	mapfile -t pids <<<"$processes"
	kill_processes "${pids[@]}"
fi
if listeners=$(sudo lsof -t -iTCP:8443 -sTCP:LISTEN); then
	mapfile -t pids <<<"$listeners"
	kill_processes "${pids[@]}"
fi
mounts=$(findmnt --raw --noheadings --output TARGET | awk '$0 ~ "^/(run|var/lib)/containerd/"' | sort -r)
while read -r target; do
	[[ -n $target ]] || continue
	sudo umount "$target"
done <<<"$mounts"
if command -v nft >/dev/null; then
	tables=$(sudo nft list tables)
	for family in inet bridge; do
		if grep -Fxq "table $family terrascale_metadata" <<<"$tables"; then
			sudo nft delete table "$family" terrascale_metadata
		fi
	done
fi
if ip link show ntp-ci >/dev/null 2>&1; then sudo ip link delete ntp-ci; fi

sudo find /etc/systemd/system /run/systemd/system \
	\( -name 'ts-orch*' -o -name 'containerd*' -o -name 'netbird-server*' -o -name 'terrascale-*' -o -name 'ts-e2e-*' \) \
	-prune -exec rm -rf {} +
sudo systemctl daemon-reload
sudo rm -rf /var/lib/ts-orch /var/lib/ts-data/e2e /var/lib/containerd /run/containerd \
	/etc/terrascale-orchestrator /usr/local/bin/terrascale-orchestrator \
	/usr/local/bin/terrascale-orchestrator.prev /usr/local/bin/terrascale-orchestrator.next /usr/local/bin/ts-orch
python3 - <<'PYTHON'
from pathlib import Path
import re

ssh = Path.home() / ".ssh"
key = ssh / "ts-e2e.pub"
authorized = ssh / "authorized_keys"
if key.exists() and authorized.exists():
    public = key.read_text().strip()
    authorized.write_text("".join(line for line in authorized.read_text().splitlines(keepends=True) if line.strip() != public))
config = ssh / "config"
if config.exists():
    config.write_text(re.sub(r"(?m)^Host ts-e2e\n(?:[ \t].*\n)*", "", config.read_text()))
for name in ("ts-e2e", "ts-e2e.pub"):
    (ssh / name).unlink(missing_ok=True)
PYTHON
bash "$lane_dir/teardown.sh" check
