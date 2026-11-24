#!/usr/bin/env bash
set -euo pipefail

device="$1"

refuse() {
  printf 'Refusing to format %s: %s\n' "$device" "$1" >&2
  exit 1
}

if ! block_device="$(readlink -e -- "$device")" || [[ ! -b "$block_device" ]]; then
  refuse 'not a block device'
fi
device="$block_device"
exec {device_fd}<"$device"
flock --exclusive "$device_fd"

if signature="$(blkid --probe --match-tag TYPE --match-tag PTTYPE --output value -- "$device")"; then
  [[ "$signature" == ext4 ]] || refuse "unexpected filesystem or partition signature ($signature)"
  exit 0
else
  status=$?
  [[ "$status" == 2 ]] || refuse "blkid probe failed (exit $status)"
fi

if ! size="$(blockdev --getsize64 "$device")" || [[ ! "$size" =~ ^[1-9][0-9]*$ ]]; then
  refuse 'cannot determine the device size'
fi

printf 'Checking that all %s bytes of %s are zero before formatting.\n' "$size" "$device"
cmp --bytes="$size" -- "$device" /dev/zero || refuse 'device contains data or could not be read completely'
mkfs.ext4 -F "$device"
