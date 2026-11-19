#!/usr/bin/env bash
set -euo pipefail
umask 077

[[ $# -eq 1 ]] || { echo "usage: $0 <out-dir>" >&2; exit 2; }
out=$(realpath "$1")
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
case $(uname -m) in
	aarch64) host_arch=arm64 ;;
	x86_64) host_arch=amd64 ;;
	*) echo "unsupported build host architecture" >&2; exit 1 ;;
esac
work=$(mktemp -d /tmp/ts-image-preload.XXXXXX)
unit="ts-image-preload-${work##*.}"
started=
cleanup() {
	if [[ -n $started ]]; then
		sudo -n systemctl stop "$unit"
	fi
	sudo -n chown --no-dereference -R "$(id -u):$(id -g)" "$work"
	rm -rf "$work"
}
trap cleanup EXIT
curl -fsSL "https://github.com/containerd/containerd/releases/download/v2.4.2/containerd-2.4.2-linux-$host_arch.tar.gz" -o "$work/containerd.tar.gz"
echo "$(jq -r --arg arch "$host_arch" '.containerd_sha256[$arch]' "$here/base.json")  $work/containerd.tar.gz" | sha256sum -c --quiet
tar --no-same-owner -xzf "$work/containerd.tar.gz" -C "$work"
sudo -n systemd-run --quiet --collect --unit="$unit" --property=Type=notify --property=Delegate=yes \
	"$work/bin/containerd" --config /dev/null --root "$work/root" --state "$work/state" --address "$work/containerd.sock"
started=yes
ctr=(sudo -n "$work/bin/ctr" --address "$work/containerd.sock" --namespace terrascale)
install -d "$work/hosts/ghcr.io"
jq -er '.image | if test("^ghcr.io/terrascale/[^/@]+@sha256:[0-9a-f]{64}$") then . else error("boot images require exact GHCR sha256 pins") end' \
	"$repo"/deploy/m1/services/{app-canary,terrabase,ts-auth,ts-dashboard}.json > "$out/boot-images.txt"
while IFS= read -r image; do
	python3 - "$image" "$work/hosts/ghcr.io/hosts.toml" <<'PYTHON'
import base64
import json
import os
from pathlib import Path
import sys
import urllib.parse
import urllib.request

repository = sys.argv[1].removeprefix("ghcr.io/").split("@")[0]
query = urllib.parse.urlencode({"service": "ghcr.io", "scope": f"repository:{repository}:pull"})
request = urllib.request.Request(f"https://ghcr.io/token?{query}")
if token := os.environ.get("GH_TOKEN"):
    credential = base64.b64encode(f"MarioGK:{token}".encode()).decode()
    request.add_header("Authorization", f"Basic {credential}")
with urllib.request.urlopen(request) as response:
    bearer = json.load(response)["token"]
Path(sys.argv[2]).write_text(
    'server = "https://ghcr.io"\n'
    '[host."https://ghcr.io"]\n'
    'capabilities = ["pull", "resolve"]\n'
    '[host."https://ghcr.io".header]\n'
    f'authorization = [{json.dumps("Bearer " + bearer)}]\n'
)
PYTHON
	"${ctr[@]}" images pull --local --hosts-dir "$work/hosts" --platform linux/arm64 --skip-metadata --snapshotter overlayfs "$image" > "$work/pull.log" 2>&1 || {
		tail -10 "$work/pull.log" >&2
		exit 1
	}
	"${ctr[@]}" images list "name==$image" | tee "$work/image.txt" | awk -v image="$image" -v digest="${image##*@}" '
		NR == 2 && $1 == image && $3 == digest && $6 == "linux/arm64" { found = 1 }
		END { exit !found }
	'
	cat "$work/image.txt"
done < "$out/boot-images.txt"
"${ctr[@]}" images check --quiet --snapshotter overlayfs | sort > "$work/ready.txt"
sort "$out/boot-images.txt" | cmp - "$work/ready.txt"
"${ctr[@]}" images list > "$out/boot-images-check.txt"
"${ctr[@]}" images check --snapshotter overlayfs >> "$out/boot-images-check.txt"
sudo -n systemctl stop "$unit"
started=
sudo -n find "$work/root/io.containerd.content.v1.content/blobs/sha256" -type f -exec sha256sum {} + \
	| awk '{ count = split($2, parts, "/"); if ($1 != parts[count]) exit 1; print $1 }' > "$out/boot-images-content.txt"
sudo -n tar --numeric-owner --xattrs --xattrs-include='*' --acls -C "$work/root" -cf "$out/boot-images-store.tar" .
sudo -n chmod 0644 "$out/boot-images-store.tar"
cat "$out/boot-images-check.txt"
