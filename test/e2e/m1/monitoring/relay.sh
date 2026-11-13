#!/usr/bin/env bash
set -euo pipefail
mount --make-rprivate /
mount -t tmpfs tmpfs /var/lib
mkdir -m 0700 /var/lib/ts-alerts
printf '{broken\n' > /var/lib/ts-alerts/journey.json
ip link set lo up
python3 "$(dirname "$0")/relay.py" "$1"
