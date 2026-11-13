#!/usr/bin/env bash
work=$1
here=$2
runtime_pins=$3
repo=$(cd "$here/../../.." && pwd)
config=/etc/systemd/journald.conf.d/60-ts-orch.conf

begin "restart ts-orch repairs host log settings on the controlled runner"
sed -n '/^const hostJournalConfig = /,/^`$/{ s/^const hostJournalConfig = `//; /^`$/d; p; }' "$repo/internal/app/host_logs.go" >"$work/journal.conf"
host_logs_supported() {
	local pid
	pid=$(systemctl show ts-orch.service -p MainPID --value)
	sudo nsenter -t "$pid" -m -- test -S /run/systemd/journal/socket &&
		sudo nsenter -t "$pid" -m -- test -w /etc/systemd/journald.conf.d &&
		systemctl is-active --quiet systemd-journald.service
}
require_host_logs() {
	host_logs_supported || { echo "controlled runner cannot apply host log settings" >&2; return 1; }
}
restart_serving() {
	sudo systemctl restart ts-orch
	wait_for 120 edge whoami.e2e.test /health
	wait_for 60 edge data.e2e.test /boots
}
warning_present() {
	local invocation
	invocation=$(systemctl show ts-orch.service -p InvocationID --value)
	sudo journalctl -u ts-orch.service "_SYSTEMD_INVOCATION_ID=$invocation" --no-pager -o cat | grep 'Host log settings skipped' >/dev/null
}
log_skip_once() {
	local invocation
	wait_for 30 warning_present
	invocation=$(systemctl show ts-orch.service -p InvocationID --value)
	test "$(sudo journalctl -u ts-orch.service "_SYSTEMD_INVOCATION_ID=$invocation" --no-pager -o cat | grep -c 'Host log settings skipped')" = 1
}
housekeeping_finished() {
	local invocation
	invocation=$(systemctl show ts-orch.service -p InvocationID --value)
	sudo journalctl -u ts-orch.service "_SYSTEMD_INVOCATION_ID=$invocation" --no-pager -o cat | grep -E 'Host log settings (applied|skipped)' >/dev/null
}
activation_done() {
	housekeeping_finished && sudo cmp "$work/journal.conf" "$config"
}
syslog_masked() {
	test "$(systemctl is-enabled rsyslog.service)" = masked &&
		test "$(systemctl is-active rsyslog.service)" = inactive
}
wait_for 30 activation_done
sudo cmp "$work/journal.conf" "$config"
journal_started=$(systemctl show systemd-journald.service -p InvocationID --value)
require_host_logs
echo "controlled runner writable journal path -> support check passed"
printf '[Journal]\nSystemMaxUse=1G\n' | sudo tee "$config" >/dev/null
sudo systemctl unmask rsyslog.service
sudo systemctl enable --now rsyslog.service
sudo cp "$config" "$work/drift.conf"
syslog_before=$(systemctl show rsyslog.service -p ActiveState -p UnitFileState)
dropin=/run/systemd/system/ts-orch.service.d/90-e2e-host-logs.conf
sudo install -d -m 0755 "$(dirname "$dropin")"
for unsupported in readonly nojournal; do
	if [[ $unsupported == readonly ]]; then
		printf '[Service]\nConfigurationDirectory=\nReadWritePaths=\nReadWritePaths=/usr/local/bin\n'
	else
		printf '[Service]\nBindReadOnlyPaths=/dev/null:/run/systemd/journal/socket\n'
	fi | sudo tee "$dropin" >/dev/null
	sudo systemctl daemon-reload
	restart_serving
	log_skip_once
	if [[ $unsupported == readonly ]]; then
		if (require_host_logs); then
			echo "runner guard accepted the missing writable path" >&2
			exit 1
		fi
		echo "writable path removed -> required runner check failed as expected"
	fi
	sudo cmp "$work/drift.conf" "$config"
	test "$(systemctl show systemd-journald.service -p InvocationID --value)" = "$journal_started"
	test "$(systemctl show rsyslog.service -p ActiveState -p UnitFileState)" = "$syslog_before"
	echo "$unsupported logging environment -> started, skipped once, settings unchanged"
done
sudo rm "$dropin"
sudo systemctl daemon-reload
restart_serving
wait_for 30 activation_done
wait_for 30 syslog_masked
test "$(sudo stat -c %a:%u:%g "$config")" = 644:0:0
systemctl is-active --quiet systemd-journald.service
test "$(systemctl show systemd-journald.service -p InvocationID --value)" != "$journal_started"
journal_started=$(systemctl show systemd-journald.service -p InvocationID --value)
journal_file=$(sudo stat -c %i:%y:%z "$config")
restart_serving
wait_for 30 activation_done
test "$(sudo stat -c %i:%y:%z "$config")" = "$journal_file"
test "$(systemctl show systemd-journald.service -p InvocationID --value)" = "$journal_started"
syslog_masked
printf '[Service]\nConfigurationDirectory=\nReadWritePaths=\nReadWritePaths=/usr/local/bin\n' | sudo tee "$dropin" >/dev/null
sudo systemctl daemon-reload
restart_serving
wait_for 30 housekeeping_finished
if warning_present; then
	echo "matching settings were skipped on a read-only configuration directory" >&2
	exit 1
fi
test "$(sudo stat -c %i:%y:%z "$config")" = "$journal_file"
test "$(systemctl show systemd-journald.service -p InvocationID --value)" = "$journal_started"
syslog_masked
echo "matching settings on a read-only configuration directory -> checked, nothing changed"
sudo rm "$dropin"
sudo systemctl daemon-reload
restart_serving
wait_for 30 housekeeping_finished
end "ts-orch restarts -> logs repaired, deliberate unsupported cases untouched, both served"

begin "current host state drives one housekeeping attempt per start"
commands=/run/ts-e2e-host-log-commands
binaries=/usr/local/lib/ts-e2e-host-log-commands
sudo install -d -m 0755 "$commands" "$binaries/real"
for command in systemctl journalctl iptables; do
	sudo cp "$(command -v "$command")" "$binaries/real/$command"
	sudo install -m 0755 "$here/host-log-command.py" "$binaries/$command"
done
printf '[Service]\nEnvironment=WATCHDOG_USEC=0 WATCHDOG_PID=1\nBindReadOnlyPaths=%s/systemctl:/usr/bin/systemctl %s/journalctl:/usr/bin/journalctl %s/iptables:/usr/sbin/iptables\n' "$binaries" "$binaries" "$binaries" | sudo tee "$dropin" >/dev/null
sudo systemctl daemon-reload
set_mode() { printf '%s\n' "$1" | sudo tee "$commands/mode" >/dev/null; }
reset_counts() { sudo rm -f "$commands/entered" "$commands/pids" "$commands/restarts" "$commands/rotations" "$commands/syslog-actions"; }
count_is() {
	local count=0
	if sudo test -f "$commands/$1"; then
		count=$(sudo cat "$commands/$1" | wc -l)
	fi
	test "$count" = "$2"
}
unchanged_config() { test "$(sudo stat -c %i:%y:%z "$config")" = "$journal_file"; }
next_run_finished() {
	test "$(systemctl show ts-orch.service -p InvocationID --value)" != "$agent_before" && activation_done
}
set_mode success
reset_counts
sudo cp "$work/journal.conf" "$config"
journal_file=$(sudo stat -c %i:%y:%z "$config")
for start in 1 2 3; do
	restart_serving
	wait_for 30 activation_done
	count_is restarts 1
	count_is rotations 1
	unchanged_config
done
sudo grep -q '^iptables activating$' "$commands/notification-probes"
sudo test ! -e "$commands/notification-leak"
echo "published but not activated -> one restart, one rotation, no write across three starts; pre-ready child environment clean"
for configured in hand-configured rebooted; do
	reset_counts
	if [[ $configured == hand-configured ]]; then
		sudo cp "$work/journal.conf" "$config"
		sudo systemctl restart systemd-journald.service
	else
		sudo python3 - "$config" <<'BOOT'
import os
import sys
from pathlib import Path
boot = next(int(line.split()[1]) for line in Path("/proc/stat").read_text().splitlines() if line.startswith("btime "))
os.utime(sys.argv[1], (boot - 1, boot - 1))
BOOT
	fi
	journal_file=$(sudo stat -c %i:%y:%z "$config")
	restart_serving
	wait_for 30 activation_done
	count_is restarts 0
	count_is rotations 0
	unchanged_config
	echo "$configured ordering -> no restart, rotation or write"
done
reset_counts
sudo cp "$work/journal.conf" "$config"
journal_file=$(sudo stat -c %i:%y:%z "$config")
set_mode restart
for start in 1 2 3; do
	restart_serving
	log_skip_once
	count_is restarts "$start"
	count_is rotations 0
	unchanged_config
done
echo "restart always fails -> exactly one attempt at each of three starts, no write"
for uncertain in future unreadable-time; do
	reset_counts
	sudo cp "$work/journal.conf" "$config"
	if [[ $uncertain == future ]]; then
		sudo touch -d '+1 hour' "$config"
		set_mode success
	else
		set_mode unreadable-time
	fi
	journal_file=$(sudo stat -c %i:%y:%z "$config")
	restart_serving
	log_skip_once
	if [[ $uncertain == future ]]; then
		count_is restarts 1
	else
		count_is restarts 0
	fi
	count_is rotations 0
	unchanged_config
	if [[ $uncertain == future ]]; then
		echo "future timestamp -> one restart, one warning, no loop or rewrite"
	else
		echo "unreadable-time timestamp -> no restart, one warning, no rewrite"
	fi
done
set_mode success
for failure in interrupted-publish interrupted-rotate; do
	reset_counts
	printf '[Journal]\nSystemMaxUse=1G\n' | sudo tee "$config" >/dev/null
	set_mode "$failure"
	restart_serving
	wait_for 30 test -e "$commands/entered"
	sudo cmp "$work/journal.conf" "$config"
	journal_file=$(sudo stat -c %i:%y:%z "$config")
	agent_before=$(systemctl show ts-orch.service -p InvocationID --value)
	set_mode success
	sudo systemctl kill --signal=SIGKILL --kill-whom=main ts-orch
	wait_for 120 next_run_finished
	wait_for 120 edge whoami.e2e.test /health
	wait_for 60 edge data.e2e.test /boots
	unchanged_config
	if [[ $failure == interrupted-publish ]]; then
		count_is restarts 2
		count_is rotations 1
	else
		count_is restarts 1
		count_is rotations 0
	fi
	restart_serving
	wait_for 30 activation_done
	unchanged_config
	if [[ $failure == interrupted-publish ]]; then
		count_is restarts 2
		count_is rotations 1
	else
		count_is restarts 1
		count_is rotations 0
	fi
	echo "$failure -> next start reads current state, never rewrites, no replay of rotation"
done
for failure in syslog rotate hung pipe; do
	reset_counts
	printf '[Journal]\nSystemMaxUse=1G\n' | sudo tee "$config" >/dev/null
	if [[ $failure == syslog ]]; then
		sudo systemctl unmask rsyslog.service
		sudo systemctl enable --now rsyslog.service
	fi
	set_mode "$failure"
	activation_started=$(date +%s%N)
	restart_serving
	log_skip_once
	if [[ $failure == hung || $failure == pipe ]]; then
		test "$((($(date +%s%N) - activation_started) / 1000000))" -lt 30000
		for child in $(sudo cat "$commands/pids"); do
			if sudo test -e "/proc/$child/stat"; then
				test "$(sudo awk '{print $3}' "/proc/$child/stat")" = Z
			fi
		done
	fi
	count_is restarts 1
	journal_file=$(sudo stat -c %i:%y:%z "$config")
	set_mode success
	restart_serving
	wait_for 30 activation_done
	unchanged_config
	if [[ $failure == hung || $failure == pipe ]]; then
		count_is restarts 2
	else
		count_is restarts 1
	fi
	syslog_masked
	echo "$failure -> serving, one warning; next run completes only current-state work"
done
reset_counts
set_mode absent
restart_serving
wait_for 30 activation_done
count_is syslog-actions 0
count_is restarts 0
echo "absent syslog -> no action"
end "state checks converge without a progress record; child environment is clean before readiness"

begin "readiness and supervision precede a timed-out housekeeping restart"
printf '[Journal]\nSystemMaxUse=1G\n' | sudo tee "$config" >/dev/null
reset_counts
sudo rm -f "$commands/ready"
set_mode completed-timeout
restart_serving
wait_for 30 test -e "$commands/entered"
test "$(systemctl show ts-orch.service -p ActiveState --value)" = active
sudo grep -q e2e-whoami "$commands/ready"
orch service ls | grep -q e2e-whoami
edge whoami.e2e.test /health
wait_for 30 activation_done
count_is restarts 1
count_is rotations 1
journal_file=$(sudo stat -c %i:%y:%z "$config")
set_mode success
for start in 2 3; do
	restart_serving
	wait_for 30 activation_done
	count_is restarts 1
	count_is rotations 1
	unchanged_config
done
python3 - "$repo/internal/app/single_host.go" <<'RECOVERY'
import re
import sys
from pathlib import Path
source = Path(sys.argv[1]).read_text()
assert re.search(r'go func\(\) \{\s*defer func\(\) \{\s*if value := recover\(\); value != nil \{\s*slog.Warn\("Host log settings skipped", "panic", fmt.Sprint\(value\)\)\s*\}\s*\}\(\)\s*if err := ensureHostLogs\(ctx\);', source)
print("panic boundary verified by reading: deferred recovery logs the panic and ends only housekeeping; no injectable panic seam")
RECOVERY
sudo rm "$dropin"
sudo systemctl daemon-reload
sudo rm -rf "$commands" "$binaries"
end "ready while restart client hung; timestamp confirms completion once; panic boundary read"

begin "enabled syslog requirement preserves the daemon and still activates the journal"
required=/run/systemd/system/ts-e2e-syslog-required@.service
printf '[Unit]\nRequires=rsyslog.service\n[Service]\nType=oneshot\nExecStart=/usr/bin/true\nRemainAfterExit=yes\n[Install]\nWantedBy=multi-user.target\n' | sudo tee "$required" >/dev/null
sudo systemctl daemon-reload
sudo systemctl unmask rsyslog.service
sudo systemctl enable --now rsyslog.service
sudo systemctl enable ts-e2e-syslog-required@proof.service
printf '[Journal]\nSystemMaxUse=1G\n' | sudo tee "$config" >/dev/null
journal_started=$(systemctl show systemd-journald.service -p InvocationID --value)
restart_serving
log_skip_once
wait_for 30 activation_done
test "$(systemctl show systemd-journald.service -p InvocationID --value)" != "$journal_started"
systemctl is-active --quiet rsyslog.service
test "$(systemctl is-enabled rsyslog.service)" = enabled
sudo bash "$runtime_pins"
systemctl is-active --quiet rsyslog.service
test "$(systemctl is-enabled rsyslog.service)" = enabled
sudo systemctl disable --now ts-e2e-syslog-required@proof.service
sudo rm "$required"
sudo systemctl daemon-reload
restart_serving
wait_for 30 syslog_masked
orch service logs e2e-whoami >"$work/task-logs.txt"
test -s "$work/task-logs.txt"
end "required syslog -> installer untouched, one warning, journal activated, tasks still log"
