#!/usr/bin/env bash
set -euo pipefail
bin=$(realpath "$1")
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
lane_pid=""
finish() {
 if [[ -n $lane_pid ]]; then
  sudo kill -TERM "$lane_pid" 2>/dev/null || true
  wait "$lane_pid" || true
 fi
 sudo rm -rf "$work"
}
trap finish EXIT
nspawn=$(command -v systemd-nspawn || true)
nspawn_library_dir=""
if [[ -z $nspawn ]]; then
 mkdir -p "$work/nspawn"
 (cd "$work/nspawn" && apt-get download systemd-container libsystemd-shared > "$work/packages.log" 2>&1)
 for package in "$work"/nspawn/*.deb; do
  dpkg-deb -x "$package" "$work/nspawn/root"
 done
 nspawn="$work/nspawn/root/usr/bin/systemd-nspawn"
 nspawn_library=$(find "$work/nspawn/root/usr/lib" -regextype posix-extended -regex '.*/libsystemd-shared[^/]+\.so')
 nspawn_library_dir=$(dirname "$nspawn_library")
fi
nice -n 19 go build -p 2 -o "$work/recovery-e2e" "$here/updater-preflight"
root=$work/root
mkdir -p "$root"/{etc/systemd/system,var/lib/ts-orch/nats,var/log/journal,usr/local/bin,opt,run,proc,sys,dev,tmp,result}
binds=()
for directory in /usr/bin /usr/sbin /usr/lib /usr/lib64 /bin /sbin /lib /lib64 /nix/store /run/current-system; do
 if [[ $directory == /usr/bin && -d /nix/store ]]; then continue; fi
 if [[ -d $directory ]]; then
  mkdir -p "$root$directory"
  binds+=("--bind-ro=$directory")
 fi
done
systemctl=$(readlink -f "$(command -v systemctl)")
systemd_root=$(dirname "$(dirname "$systemctl")")
if [[ -d $systemd_root/example/systemd/system ]]; then
 mkdir -p "$root/usr/lib/systemd" "$root/usr/bin"
 ln -s "$systemd_root/example/systemd/system" "$root/usr/lib/systemd/system"
 for tool in systemctl systemd-analyze journalctl ip bash nice cat dbus-daemon; do
  ln -s "$(command -v "$tool")" "$root/usr/bin/$tool"
 done
 ln -s "$(dirname "$(readlink -f "$(command -v nsenter)")")/mount" "$root/usr/bin/mount"
 mkdir -p "$root/sbin"
 ln -s "$systemd_root/lib/systemd/systemd" "$root/sbin/init"
fi
cp /etc/os-release "$root/etc/os-release"
tr -d '-' < /proc/sys/kernel/random/uuid > "$root/etc/machine-id"
printf 'root:x:0:0:root:/root:/bin/sh\n' > "$root/etc/passwd"
printf 'root:x:0:\n' > "$root/etc/group"
for target in basic sysinit; do
 printf '[Unit]\nDescription=Private release lane prerequisites\nDefaultDependencies=no\n' > "$root/etc/systemd/system/$target.target"
done
ln -s /dev/null "$root/etc/systemd/system/systemd-firstboot.service"
ln -s /dev/null "$root/etc/systemd/system/systemd-oomd.service"
cp "$bin" "$root/usr/local/bin/terrascale-orchestrator"
chmod 755 "$root/usr/local/bin/terrascale-orchestrator"
cp "$work/recovery-e2e" "$root/opt/recovery-e2e"
cp "$bin" "$root/opt/agent"
cat > "$root/etc/systemd/system/ts-orch.service" <<'UNIT'
[Unit]
Description=Private updater recovery journey
StartLimitIntervalSec=0
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/terrascale-orchestrator single-host
TimeoutStartSec=5s
TimeoutStopSec=5s
UNIT
cat > "$root/opt/dbus.conf" <<'BUS'
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN" "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
<type>system</type>
<listen>unix:path=/run/dbus/system_bus_socket</listen>
<auth>EXTERNAL</auth>
<policy user="root"><allow own="*"/><allow send_destination="*"/><allow receive_sender="*"/></policy>
</busconfig>
BUS
mkdir -p "$root/run/dbus"
cat > "$root/etc/systemd/system/dbus.socket" <<'BUS'
[Unit]
Description=Private release lane system bus socket
DefaultDependencies=no
[Socket]
ListenStream=/run/dbus/system_bus_socket
BUS
cat > "$root/etc/systemd/system/dbus.service" <<'BUS'
[Unit]
Description=Private release lane system bus
DefaultDependencies=no
Before=release-lane.service
Requires=dbus.socket
After=dbus.socket
[Service]
Type=notify
ExecStart=/usr/bin/dbus-daemon --address=systemd: --nofork --nopidfile --systemd-activation --config-file=/opt/dbus.conf
RuntimeDirectory=dbus
BUS
cat > "$root/etc/systemd/system/release-lane.service" <<'UNIT'
[Unit]
Description=Private release lane
After=systemd-journald.service dbus.service
Wants=systemd-journald.service dbus.service
[Service]
Type=oneshot
ExecStart=/bin/sh /opt/run-lane
StandardOutput=journal+console
StandardError=journal+console
TimeoutStartSec=infinity
UNIT
cat > "$root/opt/run-lane" <<'INNER'
export PATH=/usr/local/bin:/usr/bin:/usr/sbin:/bin:/sbin
if ip link set lo up; then
 /opt/recovery-e2e recovery-case /opt/recovery-e2e > /result/lane.log 2>&1
 status=$?
else
 status=$?
fi
cat /result/lane.log
printf '%s\n' "$status" > /result/status
systemctl poweroff --no-block
INNER
cat > "$root/etc/systemd/system/release-lane.target" <<'UNIT'
[Unit]
Description=Private release lane boot
DefaultDependencies=no
Wants=release-lane.service
UNIT
ln -s release-lane.target "$root/etc/systemd/system/default.target"
{ sudo env LD_LIBRARY_PATH="$nspawn_library_dir" "$nspawn" --quiet --boot --directory="$root" --machine="release-e2e-$$" --register=no --private-network --link-journal=no --settings=no --capability=CAP_SYS_ADMIN --system-call-filter='fanotify_init fanotify_mark' "${binds[@]}"; } > "$work/boot.log" 2>&1 &
lane_pid=$!
lane_status=0
wait "$lane_pid" || lane_status=$?
lane_pid=""
sudo cat "$root/result/lane.log" 2>/dev/null || true
if [[ $lane_status != 0 ]] || [[ ! -f $root/result/status ]] || [[ $(sudo cat "$root/result/status") != 0 ]]; then
 tail -60 "$work/boot.log"
 exit 1
fi
