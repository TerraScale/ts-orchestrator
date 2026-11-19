#!/usr/bin/env bash
set -euo pipefail

minutes=150
deadline=$((SECONDS + minutes * 60))
until curl -fsS --connect-timeout 2 --max-time 8 -o /dev/null -H 'Authorization: Bearer Oracle' \
	http://169.254.169.254/opc/v2/instance/metadata/terrascale-data-volume; do
	if ((SECONDS >= deadline)); then
		echo "no data volume binding after $minutes minutes (instance metadata terrascale-data-volume); ts-orch does not start" >&2
		exit 1
	fi
	echo "waiting for the pool to bind this instance's data volume (instance metadata terrascale-data-volume)"
	sleep 5
done
echo "instance metadata binds a data volume"
