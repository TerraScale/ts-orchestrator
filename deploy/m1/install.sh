#!/usr/bin/env bash
# Install or upgrade ts-orch on a milestone 1 host over ssh: pinned containerd
# and runc (host-runtime.sh), the NetBird client, the binary and the units.
# Re-running with a newer release is the upgrade path.
#   deploy/m1/install.sh <ssh-host> <binary-url> <sha256>
# Example binary URL: the terrascale-orchestrator-linux-arm64 asset of a CI
# release ci-<sha>-run-<id>.
set -euo pipefail

if [[ $# -ne 3 ]]; then
	echo "usage: $0 <ssh-host> <binary-url> <sha256>" >&2
	exit 2
fi
host=$1 url=$2 sum=$3
[[ $sum =~ ^[0-9a-f]{64}$ ]] || { echo "sha256 must be 64 lowercase hex characters" >&2; exit 2; }
[[ $url =~ ^https://[A-Za-z0-9./_:%-]+$ ]] || { echo "binary URL must be a plain https URL" >&2; exit 2; }

# Every unit beside this script and under services/ is installed, enabled and
# restarted; ts-orch.service comes first because the others order after it.
dir=$(dirname "$0")
ssh "$host" sudo bash -s < "$dir/host-runtime.sh"
units=""
for unit in "$dir"/ts-orch.service "$dir"/services/*.service; do
	[[ -e $unit ]] || continue
	units+="echo '$(base64 -w0 "$unit")' | base64 -d > /etc/systemd/system/$(basename "$unit")
names+=($(basename "$unit"))
"
done
# shellcheck disable=SC2087 # url, sum and units expand locally on purpose; all are validated or base64.
ssh "$host" sudo bash -s <<REMOTE
set -euo pipefail
# The NetBird client (netbird-server.service enrolls this host with it).
if ! command -v netbird >/dev/null; then
	curl -fsSL https://pkgs.netbird.io/debian/public.key | gpg --dearmor --yes -o /usr/share/keyrings/netbird-archive-keyring.gpg
	echo 'deb [signed-by=/usr/share/keyrings/netbird-archive-keyring.gpg] https://pkgs.netbird.io/debian stable main' > /etc/apt/sources.list.d/netbird.list
	apt-get update -qq
	DEBIAN_FRONTEND=noninteractive apt-get install -y -qq netbird
fi
systemctl is-enabled --quiet netbird || netbird service install
systemctl enable --now netbird
tmp=\$(mktemp)
trap 'rm -f "\$tmp"' EXIT
curl -fsSL --retry 3 -o "\$tmp" '$url'
echo '$sum  '"\$tmp" | sha256sum -c --quiet
install -m 0755 "\$tmp" /usr/local/bin/terrascale-orchestrator
ln -sfn terrascale-orchestrator /usr/local/bin/ts-orch
install -d -m 0700 /var/lib/ts-orch
install -d -m 0755 /var/lib/ts-data /var/lib/ts-data/terrabase
names=()
$units
chmod 0644 "\${names[@]/#//etc/systemd/system/}"
systemctl daemon-reload
systemctl enable "\${names[@]}"
systemctl restart "\${names[@]}"
systemctl is-active "\${names[@]}"
REMOTE
