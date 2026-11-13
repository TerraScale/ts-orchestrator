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
 nspawn_library=$(rg --files "$work/nspawn/root/usr/lib" | rg '/libsystemd-shared[^/]+\.so$')
 nspawn_library_dir=$(dirname "$nspawn_library")
fi
nice -n 19 go build -p 2 -o "$work/release-e2e" "$here/release"
version=$(sed -n 's/^containerd_version=//p' "$here/../../../deploy/m1/host-runtime.sh")
arch=$(uname -m)
case $arch in
 x86_64) arch=amd64 ;;
 aarch64) arch=arm64 ;;
esac
curl -fsSL "https://github.com/containerd/containerd/releases/download/v$version/containerd-$version-linux-$arch.tar.gz" -o "$work/runtime.tar.gz"
tar -C "$work" -xzf "$work/runtime.tar.gz" bin/containerd
root=$work/root
mkdir -p "$root"/{etc/systemd/system,var/lib/ts-orch/nats,var/log/journal,usr/local/bin,opt,run,proc,sys,dev,tmp,result}
mkdir -p "$root/opt/sys-class/dmi/id"
ln -s sys-class/dmi/id "$root/opt/firmware"
printf 'Local\n' > "$root/opt/firmware/chassis_asset_tag"
for field in board_asset_tag product_serial product_uuid; do
 printf 'unknown\n' > "$root/opt/firmware/$field"
done
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
 for tool in systemctl systemd-run systemd-analyze journalctl ip mount bash nice cat dbus-daemon; do
  ln -s "$(command -v "$tool")" "$root/usr/bin/$tool"
 done
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
printf 'nameserver 1.1.1.1\n' > "$root/etc/resolv.conf"
cp "$bin" "$root/usr/local/bin/terrascale-orchestrator"
chmod 755 "$root/usr/local/bin/terrascale-orchestrator"
cp "$work/release-e2e" "$root/opt/release-e2e"
cp "$work/bin/containerd" "$root/opt/containerd"
"$bin" release unit > "$root/etc/systemd/system/ts-orch.service"
cat > "$root/etc/systemd/system/containerd.service" <<'UNIT'
[Unit]
Description=Private release lane runtime
[Service]
ExecStart=/opt/containerd --root /var/lib/containerd --state /run/containerd
Delegate=yes
KillMode=process
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
ip link set lo up
mount --bind /opt/sys-class /sys/class
/opt/release-e2e > /result/lane.log 2>&1
status=$?
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
sudo env LD_LIBRARY_PATH="$nspawn_library_dir" "$nspawn" --quiet --boot --directory="$root" --machine="release-e2e-$$" --register=no --private-network --link-journal=no --settings=no --capability=CAP_SYS_ADMIN --system-call-filter='fanotify_init fanotify_mark' "${binds[@]}" > "$work/boot.log" 2>&1 &
lane_pid=$!
wait "$lane_pid" || status=$?
lane_pid=""
sudo cat "$root/result/lane.log" 2>/dev/null || true
if [[ ! -f $root/result/status ]] || [[ $(sudo cat "$root/result/status") != 0 ]]; then
 tail -60 "$work/boot.log"
 exit 1
fi
