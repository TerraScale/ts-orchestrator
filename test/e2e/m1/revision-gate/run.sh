set -euo pipefail
bin=$(realpath "$1")
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'sudo rm -rf "$work"' EXIT
go build -p 1 -o "$work/lane" "$here"
mkdir "$work/varlib"
sudo -n unshare --mount --net bash -s -- "$bin" "$work" <<'INNER'
set -euo pipefail
bin=$1
work=$2
mount --make-rprivate /
mount --bind "$work/varlib" /var/lib
ip link set lo up
"$work/lane" "$bin"
INNER
