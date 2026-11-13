set -euo pipefail
bin=$(realpath "$1")
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'sudo rm -rf "$work"' EXIT
nice -n 19 go build -p 1 -o "$work/host-credentials" "$here"
sudo unshare --mount --net bash -s -- "$bin" "$work" <<'SH_CREDENTIALS'
set -euo pipefail
bin=$1
work=$2
mount --make-rprivate /
ip link set lo up
"$work/host-credentials" "$bin" "$work"
SH_CREDENTIALS
