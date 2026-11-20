#!/usr/bin/env bash
set -euo pipefail
usage='Usage: NB=COMMAND scripts/netbird-pool-ssh-check.sh --inventory FILE NODE_A NODE_B'
nb=${NB:-netbird}
if [[ $# -ne 4 || $1 != --inventory ]]; then
	printf '%s\n' "$usage" >&2
	exit 2
fi
inventory=$2 node_a=$3 node_b=$4

fail() {
	printf 'FAIL %s\n' "$*" >&2
	exit 1
}

groups_of() {
	jq -r --arg peer "$1" '[.peers[] | select(.name == $peer)] | if length == 1 then .[0].groups | join(",") else error("peer \($peer) appears \(length) times") end' "$inventory"
}

connected() {
	jq -e --arg peer "$1" '.peers[] | select(.name == $peer) | .connected' "$inventory" >/dev/null
}

self=$($nb status --json | jq -r '.fqdn | split(".")[0]')
self_groups=$(groups_of "$self")
[[ ,$self_groups, == *,operators,* || ,$self_groups, == *,ops-automation,* ]] || fail "this peer $self is in $self_groups, not an ops group"
printf 'ok   %s is an ops peer: %s\n' "$self" "$self_groups"

a_groups=$(groups_of "$node_a")
[[ ,$a_groups, == *,gru-servers,* ]] || fail "$node_a is in $a_groups, not gru-servers"
[[ ,$a_groups, != *,operators,* && ,$a_groups, != *,ops-automation,* ]] || fail "$node_a is in an ops group: $a_groups"
if ! connected "$node_a" || ! connected "$node_b"; then
	fail "$node_a and $node_b must both be connected"
fi
printf 'ok   %s is a non-ops server peer: %s\n' "$node_a" "$a_groups"

for node in "$node_a" "$node_b"; do
	output=$($nb ssh "root@$node" "printf 'pool-ssh %s\n' \"\$(hostname)\"") || fail "ops -> $node: netbird ssh exited $?"
	grep -Fxq "pool-ssh $node" <<<"$output" || fail "ops -> $node: no 'pool-ssh $node' line in: $output"
	printf 'ok   ops peer %s -> %s: root session ran (pool-ssh %s)\n' "$self" "$node" "$node"
done

ip_b=$($nb status --json | jq -r --arg node "$node_b" '.peers.details[] | select(.fqdn | startswith($node + ".")) | .netbirdIp | split("/")[0]')
[[ -n $ip_b ]] || fail "$node_b is not in this NetBird client's peer list"

probe="ping -c 1 -W 3 $ip_b >/dev/null && echo 'icmp reached'; for port in 22 22022; do timeout 5 bash -c 'exec 3<>/dev/tcp/$ip_b/'\$port 2>/dev/null; echo \"tcp \$port exit \$?\"; done"
output=$($nb ssh "root@$node_a" "$probe") || fail "ops -> $node_a probe session exited $?"
for line in 'icmp reached' 'tcp 22 exit 124' 'tcp 22022 exit 124'; do
	grep -Fxq "$line" <<<"$output" || fail "non-ops $node_a -> $node_b ($ip_b): expected '$line' in: $output"
done
printf 'ok   non-ops peer %s -> %s (%s): ICMP reached, TCP 22 and 22022 dropped (timeout exit 124)\n' "$node_a" "$node_b" "$ip_b"
