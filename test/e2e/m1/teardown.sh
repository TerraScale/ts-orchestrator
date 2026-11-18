#!/usr/bin/env bash
set -euo pipefail

lane_dir=$(cd "$(dirname "$0")" && pwd)
group_file=${RUNNER_TEMP:?}/m1-lane-process-group
baseline=$RUNNER_TEMP/m1-host-baseline
unit_patterns=('ts-orch*' 'containerd*' 'netbird*' 'terrascale-*' 'ts-e2e-*' 'docker.service' 'docker.socket')
process_pattern='(^|/)(containerd(-shim[^ ]*)?|terrascale-orchestrator|ts-orch|netbird[^/ ]*|ntp_responder.py)( |$)'

active_units() {
	systemctl list-units --all --plain --no-legend --state=active,activating,deactivating "${unit_patterns[@]}" | awk '{print $1}'
}

enabled_units() {
	systemctl list-unit-files --plain --no-legend | awk '$2 ~ /^(enabled|enabled-runtime)$/ && $1 ~ /^(ts-orch.*|containerd.*|netbird.*|terrascale-.*|ts-e2e-.*|docker\.(service|socket))$/ {print $1}'
}

volume_mounts() {
	findmnt --raw --noheadings --output TARGET | awk '$0 ~ "^/((run|var/lib)/containerd(/|$)|var/lib/ts-(data|orch)(/|$))"' | sort -r
}

volume_loops() {
	sudo losetup --list --json --output NAME,BACK-FILE | python3 -c 'import json,sys; print("\n".join(loop["name"] for loop in (json.load(sys.stdin)["loopdevices"] or []) if loop["back-file"].removesuffix(" (deleted)").endswith("/data-volume.img")))'
}

lane_links() {
	ip -o link show | awk -F': ' '{split($2, name, "@"); if (name[1] ~ /^(c21-.*|c18|c18[a-z]+-host|fabric-br|veth[0-9]+|metadata-clock|metadata-host|clock-peer|ntp-ci|wt0)$/) print name[1]}'
}

volume_fstab() {
	awk '$1 !~ /^#/ && $2 ~ "^/var/lib/ts-(data|orch)(/|$)"' /etc/fstab
}

lane_namespaces() {
	ip netns list
}

metadata_addresses() {
	ip -o -4 addr show to 169.254.169.254/32
}

firewall_rules() {
	sudo "$1-save" | sed -E -e '/^#/d' -e 's/\[[0-9]+:[0-9]+\]/[0:0]/g'
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
	local failed=0 path units processes listeners resources family current probe
	for path in /var/lib/ts-orch /var/lib/ts-data /var/lib/ts-orch-bootstrap /etc/ts-orch/data-volume-* /usr/local/lib/ts-orch /dev/oracleoci/oraclevdb "$HOME/.ssh/ts-e2e" "$HOME/.ssh/ts-e2e.pub"; do
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
	units=$(enabled_units)
	if [[ -n $units ]]; then
		echo "::error::Lane found leftover enabled units: $units"
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
	for probe in volume_mounts volume_loops volume_fstab lane_namespaces lane_links metadata_addresses; do
		resources=$("$probe")
		if [[ -n $resources ]]; then
			echo "::error::Lane found leftover $probe: $resources"
			failed=1
		fi
	done
	resources=$(ip -4 route show table all | awk '/10\.203\.21\.|169\.254\.169\.254.*192\.0\.2\.1|c21-|metadata-clock|metadata-host/')
	if [[ -n $resources ]]; then
		echo "::error::Lane found leftover routes: $resources"
		failed=1
	fi
	if command -v nft >/dev/null; then
		resources=$(sudo nft list tables | awk '/terrascale_metadata/')
		if [[ -n $resources ]]; then
			echo "::error::Lane found leftover metadata firewall tables: $resources"
			failed=1
		fi
	fi
	for family in iptables ip6tables; do
		if [[ -f $baseline/$family ]]; then
			current=$(firewall_rules "$family")
			if [[ $current != "$(cat "$baseline/$family")" ]]; then
				echo "::error::Lane left $family rules different from the hosted runner baseline: $current"
				failed=1
			fi
		fi
	done
	if [[ -f $baseline/ip-forward && $(sysctl -n net.ipv4.ip_forward) != "$(cat "$baseline/ip-forward")" ]]; then
		echo "::error::Lane left net.ipv4.ip_forward different from the hosted runner baseline"
		failed=1
	fi
	return "$failed"
}

if [[ ${1:-} == check ]]; then
	check_clean
	exit
fi
[[ $# == 0 || ${1:-} == prepare ]]

unit_names=$(systemctl list-units --all --plain --no-legend "${unit_patterns[@]}" | awk '$1 !~ /^containerd/ {print $1}')
if [[ -n $unit_names ]]; then
	mapfile -t units <<<"$unit_names"
	sudo systemctl stop "${units[@]}"
fi
unit_names=$(enabled_units)
if [[ -n $unit_names ]]; then
	mapfile -t units <<<"$unit_names"
	sudo systemctl disable "${units[@]}"
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
mounts=$(volume_mounts)
while read -r target; do
	[[ -n $target ]] || continue
	sudo umount "$target"
done <<<"$mounts"
loops=$(volume_loops)
while read -r device; do
	[[ -n $device ]] || continue
	sudo losetup --detach "$device"
done <<<"$loops"
sudo python3 - <<'PYTHON'
from pathlib import Path
import re

fstab = Path("/etc/fstab")
fstab.write_text("".join(line for line in fstab.read_text().splitlines(keepends=True)
                         if not re.match(r"^\s*[^#\s]\S*\s+/var/lib/ts-(?:data|orch)(?:/|\s)", line)))
PYTHON
if command -v nft >/dev/null; then
	tables=$(sudo nft list tables)
	for family in inet bridge; do
		if grep -Fxq "table $family terrascale_metadata" <<<"$tables"; then
			sudo nft delete table "$family" terrascale_metadata
		fi
	done
fi
namespaces=$(ip netns list | awk '{print $1}')
while read -r namespace; do
	[[ -n $namespace ]] || continue
	processes=$(sudo ip netns pids "$namespace")
	if [[ -n $processes ]]; then
		mapfile -t pids <<<"$processes"
		kill_processes "${pids[@]}"
	fi
	sudo ip netns delete "$namespace"
	sudo rm -rf "/etc/netns/$namespace"
done <<<"$namespaces"
links=$(lane_links)
while read -r link; do
	[[ -n $link ]] || continue
	sudo ip link delete "$link"
done <<<"$links"
addresses=$(ip -o -4 addr show to 169.254.169.254/32 | awk '{print $2}')
while read -r link; do
	[[ -n $link ]] || continue
	sudo ip addr delete 169.254.169.254/32 dev "$link"
done <<<"$addresses"
for family in iptables ip6tables; do
	if [[ -f $baseline/$family ]]; then
		cat "$baseline/$family" | sudo "$family-restore"
	fi
done
if [[ -f $baseline/ip-forward ]]; then
	sudo sysctl -q -w "net.ipv4.ip_forward=$(cat "$baseline/ip-forward")"
fi

sudo find /etc/systemd/system /run/systemd/system \
	\( -name 'ts-orch*' -o -name 'containerd*' -o -name 'netbird-server*' -o -name 'terrascale-*' -o -name 'ts-e2e-*' \) \
	-prune -exec rm -rf {} +
sudo systemctl daemon-reload
sudo rm -rf /var/lib/ts-orch /var/lib/ts-data /var/lib/ts-orch-bootstrap /var/lib/containerd /run/containerd \
	/etc/ts-orch/data-volume-* /usr/local/lib/ts-orch /dev/oracleoci/oraclevdb \
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
if [[ ${1:-} == prepare ]]; then
	mkdir "$baseline"
	for family in iptables ip6tables; do
		firewall_rules "$family" >"$baseline/$family"
	done
	sysctl -n net.ipv4.ip_forward >"$baseline/ip-forward"
fi
