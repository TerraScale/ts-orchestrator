package firecracker

import "context"

var contextDeadline = context.DeadlineExceeded

const failureDiagnosticScript = `
set +e
printf '\n=== host service ===\n'
systemctl status ts-orch.service --no-pager --full
printf '\n=== host service journal ===\n'
journalctl -u ts-orch.service -b --no-pager -o short-iso-precise
printf '\n=== native process inventory ===\n'
ps -eo pid,ppid,stat,etime,cmd,cgroup
printf '\n=== runner inventory ===\n'
inventory=/var/lib/ts-orch/host/lab/host-a/inventory.json
if [ -f "$inventory" ]; then cat "$inventory"; else echo 'inventory missing'; fi
printf '\n=== cgroup mount and state ===\n'
findmnt -T /sys/fs/cgroup
service_cgroup=$(systemctl show ts-orch.service -p ControlGroup --value)
for root in /sys/fs/cgroup"$service_cgroup"/terrascale-host-*; do
    [ -d "$root" ] || continue
    for group in "$root" "$root"/*; do
        [ -d "$group" ] || continue
        printf '\n%s\n' "$group"
        for item in cgroup.events cgroup.procs memory.events; do
            if [ -f "$group/$item" ]; then
                printf '%s: ' "$item"
                cat "$group/$item"
            fi
        done
    done
done
printf '\n=== workload marker and process ===\n'
ls -l /run/ts-orch-workload/
for item in /run/ts-orch-workload/marker /run/ts-orch-workload/pid; do
    if [ -f "$item" ]; then printf '%s: ' "$item"; cat "$item"; fi
done
marker_pid=$(cat /run/ts-orch-workload/pid 2>/dev/null)
inventory_pid=$(sed -n 's/.*"pid":[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$inventory" 2>/dev/null | head -n 1)
for pid in "$marker_pid" "$inventory_pid"; do
    case "$pid" in ''|*[!0-9]*) continue ;; esac
    printf '\n/proc/%s\n' "$pid"
    for item in stat status cgroup; do
        if [ -f "/proc/$pid/$item" ]; then
            printf '%s: ' "$item"
            cat "/proc/$pid/$item"
        fi
    done
done
printf '\n=== installed workload artifacts ===\n'
find /var/lib/ts-orch-install -type f -print -exec stat -c '%a %u:%g %s %n' {} \; -exec sha256sum {} \;
`

const clockDiagnosticScript = `set +e
printf '\n=== timesyncd status ===\n'
systemctl status systemd-timesyncd.service --no-pager --full
printf '\n=== timedatectl ===\n'
timedatectl show -p NTPSynchronized -p NTP
timedatectl timesync-status --no-pager
printf '\n=== timesyncd journal ===\n'
journalctl -u systemd-timesyncd.service -b -n 80 --no-pager -o short-iso-precise
printf '\n=== private NTP config and route ===\n'
cat /etc/systemd/timesyncd.conf.d/ts-orch-fc.conf
ip -4 route show
printf '\n=== kernel clock predicate ===\n'
/usr/local/bin/ts-orch-clockprobe
`
