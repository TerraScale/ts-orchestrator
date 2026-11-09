#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
pins=$root/internal/qualification/firecracker/generic.go
pin() { sed -n "s/^[[:space:]]*$1[[:space:]]*= \"\([0-9a-f]\{64\}\)\"$/\1/p" "$pins"; }
kernel_sha=$(pin KernelSHA)
rootfs_sha=$(pin RootfsSHA)
[[ -n $kernel_sha && -n $rootfs_sha ]] || { echo "pins not found in $pins" >&2; exit 1; }
kernel_url=https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/20260923-6f82ac4cf331-0/x86_64/vmlinux-6.1.186
image_url=https://cloud-images.ubuntu.com/releases/noble/release-20260911/ubuntu-24.04-server-cloudimg-amd64.img
dest=${XDG_CACHE_HOME:-$HOME/.cache}/ts-orch/firecracker-qualification
kernel=$dest/vmlinux-6.1.186
rootfs=$dest/rootfs-noble-20260911.ext4
for tool in curl qemu-img sfdisk dd sha256sum; do
  command -v "$tool" >/dev/null || { echo "missing required command: $tool" >&2; exit 1; }
done
mkdir -p "$dest"
work=$(mktemp -d "$dest/.fetch.XXXXXX")
trap 'rm -rf "$work"' EXIT
digest() { sha256sum "$1" | cut -d' ' -f1; }
present() { [[ -f $1 && $(digest "$1") == "$2" ]]; }
store() {
  local got
  got=$(digest "$1")
  [[ $got == "$3" ]] || { echo "$2: SHA-256 $got does not match pinned $3" >&2; exit 1; }
  chmod 0444 "$1"
  mv -f "$1" "$2"
  echo "$2: stored (sha256 $3)"
}
if present "$kernel" "$kernel_sha"; then
  echo "$kernel: already present"
else
  curl -fsSL -o "$work/vmlinux" "$kernel_url"
  store "$work/vmlinux" "$kernel" "$kernel_sha"
fi
if present "$rootfs" "$rootfs_sha"; then
  echo "$rootfs: already present"
else
  curl -fsSL -o "$work/image.qcow2" "$image_url"
  qemu-img convert -f qcow2 -O raw "$work/image.qcow2" "$work/image.raw"
  read -r start size < <(sfdisk -d "$work/image.raw" | awk -v part="$work/image.raw1" '$1 == part { gsub(",", ""); print $4, $6 }')
  dd if="$work/image.raw" of="$work/rootfs.ext4" bs=512 skip="$start" count="$size" status=none
  store "$work/rootfs.ext4" "$rootfs" "$rootfs_sha"
fi
echo "kernel=$kernel"
echo "rootfs=$rootfs"
