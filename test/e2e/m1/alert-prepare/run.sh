set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
nice -n 19 go build -p 1 -o "$work/lane" "$here"
cp /etc/passwd "$work/passwd"
if ! getent passwd ts-alerts >/dev/null; then
 printf 'ts-alerts:x:32123:32123:Alert relay:/nonexistent:/usr/sbin/nologin\n' >> "$work/passwd"
fi
sudo -n unshare --mount --net bash -s -- "$work" <<'INNER'
set -euo pipefail
work=$1
mount --make-rprivate /
ip link set lo up
mount --bind "$work/passwd" /etc/passwd
mkdir "$work/run"
mount -t tmpfs -o mode=0755 tmpfs "$work/run"
mkdir -p "$work/run/ts-alert-delivery"
chmod 750 "$work/run/ts-alert-delivery"
current_system=$(readlink /run/current-system 2>/dev/null || true)
if [[ -n $current_system ]]; then
 ln -s "$current_system" "$work/run/current-system"
fi
mount --bind "$work/run" /run
nice -n 19 "$work/lane"
INNER
