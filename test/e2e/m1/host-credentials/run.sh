set -euo pipefail
bin=$(realpath "$1")
work=$(mktemp -d)
trap 'sudo rm -rf "$work"' EXIT
sudo unshare --mount --net bash -s -- "$bin" "$work" <<'SH_CREDENTIALS'
set -euo pipefail
bin=$1
work=$2
mount --make-rprivate /
ip link set lo up
mkdir "$work/varlib"
mount --bind "$work/varlib" /var/lib
"$(dirname "$bin")/host-credentials" "$bin" "$work"
SH_CREDENTIALS
