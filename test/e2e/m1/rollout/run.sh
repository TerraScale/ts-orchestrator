#!/usr/bin/env bash
set -euo pipefail
bin=$(realpath "$1")
work=$(realpath "$2")
spec=$(realpath "$3")
here=$(cd "$(dirname "$0")" && pwd)
forward=$(sysctl -n net.ipv4.ip_forward)
daemons=()
cleanup() {
 set +e
 if ((${#daemons[@]})); then
  kill -TERM "${daemons[@]}"
  wait "${daemons[@]}"
 fi
 for ns in c21-first c21-second; do
  ip netns pids "$ns" | xargs -r kill -KILL
  ip netns delete "$ns"
 rm -rf "/etc/netns/$ns"
 done
 iptables -t nat -D POSTROUTING -s 10.203.21.0/24 ! -o c21-bridge -j MASQUERADE
 iptables -D FORWARD -i c21-bridge -j ACCEPT
 iptables -D FORWARD -o c21-bridge -j ACCEPT
 ip link delete c21-bridge
 sysctl -q -w "net.ipv4.ip_forward=$forward"
}
trap cleanup EXIT
mkdir -p "$work/first/run" "$work/second/run" /run/nri
ip link add c21-bridge type bridge
ip addr add 10.203.21.1/24 dev c21-bridge
ip link set c21-bridge up
sysctl -q -w net.ipv4.ip_forward=1
iptables -t nat -A POSTROUTING -s 10.203.21.0/24 ! -o c21-bridge -j MASQUERADE
iptables -I FORWARD -i c21-bridge -j ACCEPT
iptables -I FORWARD -o c21-bridge -j ACCEPT
for seat in first second; do
 ip netns add "c21-$seat"
 ip link add "c21-$seat" type veth peer name eth0 netns "c21-$seat"
 ip link set "c21-$seat" master c21-bridge
 ip link set "c21-$seat" up
 address=10.203.21.2
 [[ $seat == first ]] || address=10.203.21.3
 ip -n "c21-$seat" addr add "$address/24" dev eth0
 ip -n "c21-$seat" link set eth0 up
 ip -n "c21-$seat" link set lo up
 ip -n "c21-$seat" route add default via 10.203.21.1
 mkdir -p "/etc/netns/c21-$seat"
 printf 'nameserver 1.1.1.1\n' >"/etc/netns/c21-$seat/resolv.conf"
 ip netns exec "c21-$seat" unshare --mount --uts --propagation private bash "$here/launch.sh" "$work/$seat" "$(command -v containerd)" containerd >"$work/$seat/containerd.log" 2>&1 &
 daemons+=("$!")
 done
"$bin" journey "$work" "$here/launch.sh" "$spec"
