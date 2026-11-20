#!/usr/bin/env bash
set -euo pipefail
usage='Usage: NB=COMMAND scripts/netbird-pool-ssh-check.sh NODE_A NODE_B'
nb=${NB:-netbird}
if [[ $# -ne 2 ]]; then
	printf '%s\n' "$usage" >&2
	exit 2
fi
node_a=$1 node_b=$2

for node in "$node_a" "$node_b"; do
	answer=$($nb ssh "root@$node" hostname)
	if [[ $answer != "$node" ]]; then
		printf 'FAIL ops -> %s: answered %q\n' "$node" "$answer" >&2
		exit 1
	fi
	printf 'ok   ops peer -> %s: NetBird SSH as root\n' "$node"
done

ip_b=$($nb status --json | jq -r --arg node "$node_b" '.peers.details[] | select(.fqdn | startswith($node + ".")) | .netbirdIp | split("/")[0]')
if [[ -z $ip_b ]]; then
	printf 'FAIL %s is not in this NetBird client'"'"'s peer list\n' "$node_b" >&2
	exit 1
fi

probe="for port in 22 22022; do if timeout 5 bash -c 'exec 3<>/dev/tcp/$ip_b/'\$port 2>/dev/null; then echo open \$port; exit 1; fi; echo denied \$port; done"
if ! result=$($nb ssh "root@$node_a" "$probe"); then
	printf 'FAIL non-ops peer %s -> %s (%s): %s\n' "$node_a" "$node_b" "$ip_b" "$result" >&2
	exit 1
fi
printf 'ok   non-ops peer %s -> %s (%s): %s\n' "$node_a" "$node_b" "$ip_b" "$(tr '\n' ' ' <<<"$result")"
