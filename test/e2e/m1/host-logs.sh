#!/usr/bin/env bash
work=$1
state=$2
here=$3
runtime_pins=$4
intent=$state/host-logs-activation-pending
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
	housekeeping_finished && sudo cmp "$work/journal.conf" "$config" && sudo test ! -e "$intent"
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
end "ts-orch restarts -> logs repaired, deliberate unsupported cases untouched, both served"

begin "failed and interrupted host log activation resumes at the next start"
commands=/run/ts-e2e-host-log-commands
binaries=/usr/local/lib/ts-e2e-host-log-commands
sudo install -d -m 0755 "$commands" "$binaries/real"
sudo cp "$(command -v systemctl)" "$binaries/real/systemctl"
sudo cp "$(command -v journalctl)" "$binaries/real/journalctl"
sudo install -m 0755 "$here/host-log-command.py" "$binaries/systemctl"
sudo install -m 0755 "$here/host-log-command.py" "$binaries/journalctl"
printf '[Service]\nBindReadOnlyPaths=%s/systemctl:/usr/bin/systemctl %s/journalctl:/usr/bin/journalctl\n' "$binaries" "$binaries" | sudo tee "$dropin" >/dev/null
sudo systemctl daemon-reload
for failure in syslog restart rotate interrupted hung pipe; do
	sudo rm -f "$commands/entered" "$commands/pids" "$commands/restarts"
	printf '[Journal]\nSystemMaxUse=1G\n' | sudo tee "$config" >/dev/null
	sudo systemctl unmask rsyslog.service
	sudo systemctl enable --now rsyslog.service
	printf '%s\n' "$failure" | sudo tee "$commands/mode" >/dev/null
	journal_started=$(systemctl show systemd-journald.service -p InvocationID --value)
	if [[ $failure == interrupted ]]; then
		sudo systemctl restart ts-orch
		wait_for 30 test -e "$commands/entered"
		sudo systemctl kill --signal=SIGKILL --kill-whom=main ts-orch
		printf 'restart\n' | sudo tee "$commands/mode" >/dev/null
	fi
	activation_started=$(date +%s%N)
	restart_serving
	log_skip_once
	activation_ms=$((($(date +%s%N) - activation_started) / 1000000))
	if [[ $failure == hung || $failure == pipe ]]; then
		test "$activation_ms" -lt 30000
		for child in $(sudo cat "$commands/pids"); do
			if sudo test -e "/proc/$child/stat"; then
				test "$(sudo awk '{print $3}' "/proc/$child/stat")" = Z
			fi
		done
	fi
	sudo test -f "$intent"
	sudo cmp "$work/journal.conf" "$config"
	if [[ $failure != rotate ]]; then
		test "$(systemctl show systemd-journald.service -p InvocationID --value)" = "$journal_started"
	fi
	journal_started=$(systemctl show systemd-journald.service -p InvocationID --value)
	journal_file=$(sudo stat -c %i:%y:%z "$config")
	if [[ $failure == rotate ]]; then
		sudo cp "$intent" "$work/replay.json"
		for start in 2 3; do
			restart_serving
			log_skip_once
			test "$(systemctl show systemd-journald.service -p InvocationID --value)" = "$journal_started"
			test "$(sudo cat "$commands/restarts" | wc -l)" = 1
		done
	fi
	echo "$failure activation -> serving, one warning, step intent retained"
	printf 'success\n' | sudo tee "$commands/mode" >/dev/null
	restart_serving
	wait_for 30 activation_done
	test "$(sudo stat -c %i:%y:%z "$config")" = "$journal_file"
	if [[ $failure == rotate ]]; then
		test "$(systemctl show systemd-journald.service -p InvocationID --value)" = "$journal_started"
		test "$(sudo cat "$commands/restarts" | wc -l)" = 1
		sudo python3 - "$work/replay.json" "$intent" <<'REPLAY'
import json
import sys
from pathlib import Path
intent = json.loads(Path(sys.argv[1]).read_text())
intent["Rotated"] = True
intent["Done"] = True
Path(sys.argv[2]).write_text(json.dumps(intent))
REPLAY
		restart_serving
		wait_for 30 activation_done
		test "$(sudo cat "$commands/restarts" | wc -l)" = 1
	else
		test "$(systemctl show systemd-journald.service -p InvocationID --value)" != "$journal_started"
	fi
	syslog_masked
	echo "$failure activation -> next start resumed recorded steps without rewriting config"
done
end "activation failures and interruption -> completed steps never repeated; hung helpers bounded"

begin "readiness and supervision precede a hung housekeeping restart"
printf '[Journal]\nSystemMaxUse=1G\n' | sudo tee "$config" >/dev/null
sudo rm -f "$commands/entered" "$commands/restarts" "$commands/ready"
printf 'completed-timeout\n' | sudo tee "$commands/mode" >/dev/null
restart_serving
wait_for 30 test -e "$commands/entered"
test "$(systemctl show ts-orch.service -p ActiveState --value)" = active
sudo grep -q e2e-whoami "$commands/ready"
orch service ls | grep -q e2e-whoami
edge whoami.e2e.test /health
wait_for 30 activation_done
test "$(sudo cat "$commands/restarts" | wc -l)" = 1
journal_started=$(systemctl show systemd-journald.service -p InvocationID --value)
printf 'success\n' | sudo tee "$commands/mode" >/dev/null
restart_serving
wait_for 30 activation_done
test "$(sudo cat "$commands/restarts" | wc -l)" = 1
test "$(systemctl show systemd-journald.service -p InvocationID --value)" = "$journal_started"
sudo rm "$dropin"
sudo systemctl daemon-reload
sudo rm -rf "$commands" "$binaries"
end "ready while restart client hung; completed restart recorded once"

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
