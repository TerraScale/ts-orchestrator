#!/usr/bin/env bash
set -euo pipefail

until curl -fsS --connect-timeout 2 --max-time 8 -o /dev/null -H 'Authorization: Bearer Oracle' \
	http://169.254.169.254/opc/v2/instance/metadata/terrascale-data-volume; do
	echo "waiting for the pool to bind this instance's data volume (instance metadata terrascale-data-volume)"
	sleep 5
done
echo "instance metadata binds a data volume"
