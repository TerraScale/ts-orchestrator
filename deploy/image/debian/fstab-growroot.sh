#!/usr/bin/env bash
set -euo pipefail

fstab=/etc/fstab
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
awk '$2 == "/" && $3 ~ /ext[234]/ { nf = $4; sub(/(^|,)x-systemd\.growfs(,|$)/, ",", nf); gsub(/,{2,}/, ",", nf); sub(/^,|,$/, "", nf); $4 = (nf == "" ? "x-systemd.growfs" : nf ",x-systemd.growfs") } { print }' "$fstab" > "$tmp"
cmp -s "$tmp" "$fstab" || cp "$tmp" "$fstab"
