set -euo pipefail
bin=$(realpath "$1")
work=$(mktemp -d)
trap 'sudo rm -rf "$work"' EXIT
mkdir "$work/varlib"
sudo -n unshare --mount --net bash -s -- "$bin" "$work" <<'INNER'
set -euo pipefail
bin=$1
work=$2
mount --make-rprivate /
mount --bind "$work/varlib" /var/lib
ip link set lo up
"$(dirname "$bin")/revision-gate" "$bin"
INNER
