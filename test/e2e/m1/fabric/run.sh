set -euo pipefail
bin=$(realpath "$1")
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../../.." && pwd)
work=$(mktemp -d)
finish() {
  result=$?
  if [ "$result" -ne 0 ]; then
    for log in "$work"/*.log; do
      sudo tail -20 "$log"
    done
  fi
  sudo rm -rf "$work"
}
trap finish EXIT
"$bin" help > "$work/artifact-help"
helper="$(dirname "$bin")/fabric"
if [ -x "$helper" ]; then
  cp "$helper" "$work/fabric"
else
  go -C "$repo" build -o "$work/fabric" ./test/e2e/m1/fabric
fi
sudo unshare --mount --net bash -s -- "$work" <<'INNER'
set -euo pipefail
work=$1
mount --make-rprivate /
mkdir -p /run/netns
mount -t tmpfs tmpfs /run/netns
ip link set lo up
ip link add fabric-br type bridge
ip addr add 10.79.0.1/24 dev fabric-br
ip link set fabric-br up
for n in 1 2 3; do
  ip netns add "fabric$n"
  ip link add "veth$n" type veth peer name peer
  ip link set "veth$n" master fabric-br
  ip link set "veth$n" up
  ip link set peer netns "fabric$n"
  ip -n "fabric$n" addr add "10.79.0.$((n+1))/24" dev peer
  ip -n "fabric$n" link set peer up
  ip -n "fabric$n" link set lo up
done
"$work/fabric" "$work"
INNER
