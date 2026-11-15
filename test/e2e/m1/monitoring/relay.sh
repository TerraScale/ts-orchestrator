#!/usr/bin/env bash
set -euo pipefail
mount --make-rprivate /
mount -t tmpfs tmpfs /var/lib
mkdir -m 0700 /var/lib/ts-alerts
printf '{broken\n' > /var/lib/ts-alerts/journey.json
ip link set lo up
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cp /etc/passwd "$work/passwd"
if ! getent passwd ts-alerts >/dev/null; then
 printf 'ts-alerts:x:32123:32123:Alert relay:/nonexistent:/usr/sbin/nologin\n' >> "$work/passwd"
fi
mkdir -p "$work/etc-upper" "$work/etc-work"
mount -t overlay -o "lowerdir=/etc,upperdir=$work/etc-upper,workdir=$work/etc-work" overlay /etc
mount --bind "$work/passwd" /etc/passwd
mkdir -p /etc/ts-monitoring/production
script=$(realpath "$(dirname "$0")/relay.py")
mkdir -p /run/ts-alert-delivery
mount -t tmpfs -o mode=0750 tmpfs /run/ts-alert-delivery
python3 "$script" "$1" "$2"
