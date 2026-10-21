#!/usr/bin/env bash
# Install or upgrade ts-orch on a milestone 1 host over ssh. Re-running with a
# newer release is the upgrade path.
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

unit=$(base64 -w0 "$(dirname "$0")/ts-orch.service")
# shellcheck disable=SC2087 # url, sum and unit expand locally on purpose; all are validated or base64.
ssh "$host" sudo bash -s <<REMOTE
set -euo pipefail
tmp=\$(mktemp)
trap 'rm -f "\$tmp"' EXIT
curl -fsSL --retry 3 -o "\$tmp" '$url'
echo '$sum  '"\$tmp" | sha256sum -c --quiet
install -m 0755 "\$tmp" /usr/local/bin/terrascale-orchestrator
ln -sfn terrascale-orchestrator /usr/local/bin/ts-orch
install -d -m 0700 /var/lib/ts-orch
install -d -m 0755 /var/lib/ts-data /var/lib/ts-data/terrabase
echo '$unit' | base64 -d > /etc/systemd/system/ts-orch.service
chmod 0644 /etc/systemd/system/ts-orch.service
systemctl daemon-reload
systemctl enable ts-orch.service
systemctl restart ts-orch.service
systemctl is-active ts-orch.service
REMOTE
