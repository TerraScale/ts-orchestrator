#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
	echo "usage: $0 <arm64|amd64> <out-dir> <binary-url> <binary-sha256>" >&2
	exit 2
fi
arch=$1 out=$2 binary_url=$3 binary_sha256=$4
[[ $arch == arm64 || $arch == amd64 ]] || { echo "arch must be arm64 or amd64" >&2; exit 2; }
[[ $binary_sha256 =~ ^[0-9a-f]{64}$ ]] || { echo "binary sha256 must be 64 lowercase hex characters" >&2; exit 2; }
[[ $binary_url =~ ^https://[A-Za-z0-9./_:%-]+$ ]] || { echo "binary URL must be a plain https URL" >&2; exit 2; }
for tool in curl jq virt-customize virt-sparsify; do
	command -v "$tool" >/dev/null || { echo "$tool is required to build the image" >&2; exit 1; }
done

here=$(cd "$(dirname "$0")" && pwd)
base_url=$(jq -r --arg arch "$arch" '.base[$arch].url' "$here/base.json")
base_sha512=$(jq -r --arg arch "$arch" '.base[$arch].sha512' "$here/base.json")
snapshot=$(jq -r '.snapshot' "$here/base.json")
repo=$(cd "$here/../../.." && pwd)
units=("$repo/deploy/m1/ts-orch.service" "$repo"/deploy/m1/services/*.service)

install -d "$out"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
printf 'TS_ARCH=%q\nTS_SNAPSHOT=%q\nTS_BINARY_URL=%q\nTS_BINARY_SHA256=%q\nTS_NETBIRD_TARBALL_URL=%q\n' \
	"$arch" "$snapshot" "$binary_url" "$binary_sha256" \
	"$(jq -r --arg arch "$arch" '.netbird.url | sub("<arch>"; $arch)' "$here/base.json")" > "$work/image-env"
printf 'TS_CONTAINERD_SHA256=%q\nTS_RUNC_SHA256=%q\nTS_NETBIRD_SHA256=%q\n' \
	"$(jq -r --arg arch "$arch" '.containerd_sha256[$arch]' "$here/base.json")" \
	"$(jq -r --arg arch "$arch" '.runc_sha256[$arch]' "$here/base.json")" \
	"$(jq -r --arg arch "$arch" '.netbird.sha256[$arch]' "$here/base.json")" >> "$work/image-env"
curl -fsSL "$base_url" -o "$work/base.qcow2"
echo "$base_sha512  $work/base.qcow2" | sha512sum -c --quiet

uploads=(
	--upload "$work/image-env:/run/ts-image-env"
	--upload "$here/provision.sh:/run/ts-image-provision.sh"
	--upload "$here/ts-node-init.service:/etc/systemd/system/ts-node-init.service"
	--upload "$here/ts-ssh-keys.service:/etc/systemd/system/ts-ssh-keys.service"
	--upload "$here/ts-ssh-keys.sh:/usr/local/sbin/ts-ssh-keys"
	--upload "$here/fstab-growroot.sh:/usr/local/sbin/fstab-growroot"
	--mkdir /etc/systemd/system/ts-orch.service.d
	--upload "$here/ts-orch-node-init.conf:/etc/systemd/system/ts-orch.service.d/10-node-init.conf"
)
for unit in "${units[@]}"; do
	uploads+=(--upload "$unit:/etc/systemd/system/${unit##*/}" --run-command "chown root:root /etc/systemd/system/${unit##*/}")
done

LIBGUESTFS_BACKEND=direct virt-customize \
	-a "$work/base.qcow2" \
	--network \
	"${uploads[@]}" \
	--run-command 'chown root:root /usr/local/sbin/ts-ssh-keys /usr/local/sbin/fstab-growroot /etc/systemd/system/ts-node-init.service /etc/systemd/system/ts-ssh-keys.service /etc/systemd/system/ts-orch.service.d/10-node-init.conf' \
	--run-command 'chmod 0755 /usr/local/sbin/ts-ssh-keys /usr/local/sbin/fstab-growroot' \
	--run-command 'bash /run/ts-image-provision.sh'

image="$out/ts-host-debian13-$arch.qcow2"
LIBGUESTFS_BACKEND=direct virt-sparsify --compress "$work/base.qcow2" "$image"
(cd "$out" && sha256sum "ts-host-debian13-$arch.qcow2" > "ts-host-debian13-$arch.qcow2.sha256")
