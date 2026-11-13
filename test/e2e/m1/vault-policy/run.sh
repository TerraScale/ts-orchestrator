set -euo pipefail
bin=$(realpath "$1")
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
go build -p 1 -o "$work/lane" "$here"
"$work/lane" "$bin"
