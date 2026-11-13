#!/usr/bin/env bash
work=$1
state=$2
here=$3
runtime_pins=$4

begin "restart ts-orch repairs host log settings on the controlled runner"
sed -n '/^\[Journal\]/,/^JOURNAL$/{ /^JOURNAL$/d; p; }' "$runtime_pins" >"$work/journal.conf"
sudo cmp "$work/journal.conf" /etc/systemd/journald.conf.d/60-ts-orch.conf
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
log_skip_once() {
	local invocation
	invocation=$(systemctl show ts-orch.service -p InvocationID --value)
	test "$(sudo journalctl -u ts-orch.service "_SYSTEMD_INVOCATION_ID=$invocation" --no-pager -o cat | grep -c 'Host log settings skipped')" = 1
}
journal_started=$(systemctl show systemd-journald.service -p InvocationID --value)
require_host_logs
echo "controlled runner writable journal path -> support check passed"
printf '[Journal]\nSystemMaxUse=1G\n' | sudo tee /etc/systemd/journald.conf.d/60-ts-orch.conf >/dev/null
sudo systemctl unmask rsyslog.service
sudo systemctl enable --now rsyslog.service
sudo cp /etc/systemd/journald.conf.d/60-ts-orch.conf "$work/drift.conf"
syslog_before=$(systemctl show rsyslog.service -p ActiveState -p UnitFileState)
dropin=/run/systemd/system/ts-orch.service.d/90-e2e-host-logs.conf
sudo install -d -m 0755 "$(dirname "$dropin")"
for unsupported in readonly nojournal; do
	if [[ $unsupported == readonly ]]; then
		printf '[Service]\nReadWritePaths=\nReadWritePaths=/usr/local/bin\n'
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
	sudo cmp "$work/drift.conf" /etc/systemd/journald.conf.d/60-ts-orch.conf
	test "$(systemctl show systemd-journald.service -p InvocationID --value)" = "$journal_started"
	test "$(systemctl show rsyslog.service -p ActiveState -p UnitFileState)" = "$syslog_before"
	echo "$unsupported logging environment -> started, skipped once, settings unchanged"
done
sudo rm "$dropin"
sudo systemctl daemon-reload
restart_serving
sudo cmp "$work/journal.conf" /etc/systemd/journald.conf.d/60-ts-orch.conf
test "$(systemctl is-enabled rsyslog.service)" = masked
test "$(systemctl is-active rsyslog.service)" = inactive
systemctl is-active --quiet systemd-journald.service
test "$(systemctl show systemd-journald.service -p InvocationID --value)" != "$journal_started"
journal_started=$(systemctl show systemd-journald.service -p InvocationID --value)
journal_file=$(sudo stat -c %i:%y:%z /etc/systemd/journald.conf.d/60-ts-orch.conf)
restart_serving
sudo cmp "$work/journal.conf" /etc/systemd/journald.conf.d/60-ts-orch.conf
test "$(sudo stat -c %i:%y:%z /etc/systemd/journald.conf.d/60-ts-orch.conf)" = "$journal_file"
test "$(systemctl show systemd-journald.service -p InvocationID --value)" = "$journal_started"
test "$(systemctl is-enabled rsyslog.service)" = masked
test "$(systemctl is-active rsyslog.service)" = inactive
sudo test ! -e "$state/host-logs-activation-pending"
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
	printf '[Journal]\nSystemMaxUse=1G\n' | sudo tee /etc/systemd/journald.conf.d/60-ts-orch.conf >/dev/null
	sudo systemctl unmask rsyslog.service
	sudo systemctl enable --now rsyslog.service
	printf '%s\n' "$failure" | sudo tee "$commands/mode" >/dev/null
	journal_started=$(systemctl show systemd-journald.service -p InvocationID --value)
	if [[ $failure == interrupted ]]; then
		sudo systemctl restart --no-block ts-orch
		wait_for 30 test -e "$commands/entered"
		sudo systemctl kill --signal=SIGKILL --kill-whom=main ts-orch
		printf 'restart\n' | sudo tee "$commands/mode" >/dev/null
	fi
	activation_started=$(date +%s%N)
	restart_serving
	activation_ms=$((($(date +%s%N) - activation_started) / 1000000))
	if [[ $failure == hung || $failure == pipe ]]; then
		test "$activation_ms" -lt 30000
		for child in $(sudo cat "$commands/pids"); do
			if sudo test -e "/proc/$child/stat"; then
				test "$(sudo awk '{print $3}' "/proc/$child/stat")" = Z
			fi
		done
	fi
	log_skip_once
	sudo test -f "$state/host-logs-activation-pending"
	sudo cmp "$work/journal.conf" /etc/systemd/journald.conf.d/60-ts-orch.conf
	if [[ $failure != rotate ]]; then
		test "$(systemctl show systemd-journald.service -p InvocationID --value)" = "$journal_started"
	fi
	journal_started=$(systemctl show systemd-journald.service -p InvocationID --value)
	journal_file=$(sudo stat -c %i:%y:%z /etc/systemd/journald.conf.d/60-ts-orch.conf)
	echo "$failure activation -> serving, one warning, pending marker ($activation_ms ms)"
	printf 'success\n' | sudo tee "$commands/mode" >/dev/null
	restart_serving
	sudo test ! -e "$state/host-logs-activation-pending"
	test "$(sudo stat -c %i:%y:%z /etc/systemd/journald.conf.d/60-ts-orch.conf)" = "$journal_file"
	test "$(systemctl show systemd-journald.service -p InvocationID --value)" != "$journal_started"
	test "$(systemctl is-enabled rsyslog.service)" = masked
	test "$(systemctl is-active rsyslog.service)" = inactive
	echo "$failure activation -> next start completed activation without rewriting config"
done
sudo rm "$dropin"
sudo systemctl daemon-reload
sudo rm -rf "$commands" "$binaries"
end "activation failures and interruption -> next start activates matching bytes; hung helpers bounded"

begin "enabled syslog requirement preserves the daemon and still activates the journal"
required=/run/systemd/system/ts-e2e-syslog-required@.service
printf '[Unit]\nRequires=rsyslog.service\n[Service]\nType=oneshot\nExecStart=/usr/bin/true\nRemainAfterExit=yes\n[Install]\nWantedBy=multi-user.target\n' | sudo tee "$required" >/dev/null
sudo systemctl daemon-reload
sudo systemctl unmask rsyslog.service
sudo systemctl enable --now rsyslog.service
sudo systemctl enable ts-e2e-syslog-required@proof.service
printf '[Journal]\nSystemMaxUse=1G\n' | sudo tee /etc/systemd/journald.conf.d/60-ts-orch.conf >/dev/null
journal_started=$(systemctl show systemd-journald.service -p InvocationID --value)
restart_serving
log_skip_once
sudo cmp "$work/journal.conf" /etc/systemd/journald.conf.d/60-ts-orch.conf
test "$(systemctl show systemd-journald.service -p InvocationID --value)" != "$journal_started"
systemctl is-active --quiet rsyslog.service
test "$(systemctl is-enabled rsyslog.service)" = enabled
sudo test ! -e "$state/host-logs-activation-pending"
sudo systemctl disable --now ts-e2e-syslog-required@proof.service
sudo rm "$required"
sudo systemctl daemon-reload
restart_serving
test "$(systemctl is-enabled rsyslog.service)" = masked
test "$(systemctl is-active rsyslog.service)" = inactive
orch service logs e2e-whoami >"$work/task-logs.txt"
test -s "$work/task-logs.txt"
end "required syslog -> left running with one warning, journal activated, tasks still log"
