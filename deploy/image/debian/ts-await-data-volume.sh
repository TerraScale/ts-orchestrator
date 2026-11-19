#!/usr/bin/env bash
set -euo pipefail

trap 'echo "stopped before the pool bound a data volume to this instance; ts-orch does not start" >&2; exit 1' TERM
polls=0
until curl -fs --connect-timeout 2 --max-time 8 -o /dev/null -H 'Authorization: Bearer Oracle' \
	http://169.254.169.254/opc/v2/instance/metadata/terrascale-data-volume; do
	if ((polls % 12 == 0)); then
		echo "waiting for the pool to bind this instance's data volume (instance metadata terrascale-data-volume)"
	fi
	polls=$((polls + 1))
	sleep 5 &
	wait $!
done
echo "instance metadata binds a data volume"
