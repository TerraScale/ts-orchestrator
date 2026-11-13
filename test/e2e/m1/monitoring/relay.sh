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
mount --bind "$work/passwd" /etc/passwd
mount -t tmpfs -o mode=0755 tmpfs /run
python3 "$(dirname "$0")/relay.py" "$1"
