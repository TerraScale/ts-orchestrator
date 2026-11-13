set -euo pipefail
bin=$(realpath "$1")
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
nice -n 19 go build -ldflags="-s -w" -p 1 -o "$work/updater-preflight" "$here"
previous=8bc71eb416af482823ec9165a4e799acd95330df
repo=$(git -C "$here" rev-parse --show-toplevel)
git -C "$repo" cat-file -e "$previous^{commit}" 2>/dev/null || git -C "$repo" fetch -q --depth 1 origin "$previous"
mkdir "$work/previous-src"
git -C "$repo" archive "$previous" | tar -x -C "$work/previous-src"
cp -r "$here/previous" "$work/previous-src/updater-previous"
git -C "$work/previous-src" init -q
git -C "$work/previous-src" add -A
git -C "$work/previous-src" -c user.name=lane -c user.email=lane@localhost commit -qm "main's build"
(cd "$work/previous-src" && nice -n 19 go build -trimpath -ldflags="-s -w" -o "$work/previous-updater" ./updater-previous)
"$work/updater-preflight" "$bin" "$work/previous-updater"
