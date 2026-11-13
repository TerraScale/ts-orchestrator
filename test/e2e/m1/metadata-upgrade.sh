#!/usr/bin/env bash
set -euo pipefail
sudo install -d -m 0755 /etc/terrascale-orchestrator
"$1" ts-auth metadata-rules | sudo tee /etc/terrascale-orchestrator/ts-auth-metadata.nft >/dev/null
source "$(dirname "$0")/setup.sh"

source "$here/metadata-clock.sh"

begin "metadata rules survive an installer upgrade and unit restart"
metadata_rules=/etc/terrascale-orchestrator/ts-auth-metadata.nft
sudo test -s "$metadata_rules"
sudo cp "$metadata_rules" "$work/metadata-base.nft"
if ! id -u ts-alerts >/dev/null 2>&1; then
 sudo useradd --system --no-create-home --shell /usr/sbin/nologin ts-alerts
fi
relay_uid=$(id -u ts-alerts)
printf '\ninsert rule inet terrascale_metadata output ip daddr 169.254.169.254 meta skuid %s accept\nadd rule inet terrascale_metadata output ip daddr 192.0.2.1 counter accept\n' "$relay_uid" | sudo tee -a "$metadata_rules" >/dev/null
metadata_before=$(sudo sha256sum "$metadata_rules")
"$repo/deploy/m1/install.sh" ts-e2e https://localhost:8443/terrascale-orchestrator-linux-arm64 "$(sha256sum "$bin" | cut -d' ' -f1)"
test "$(sudo sha256sum "$metadata_rules")" = "$metadata_before"
sudo systemctl restart terrascale-ts-auth-metadata.service
test "$(sudo sha256sum "$metadata_rules")" = "$metadata_before"
sudo nft -n list chain inet terrascale_metadata output | grep -q "ip daddr 169.254.169.254 meta skuid $relay_uid accept"
sudo nft -n list chain inet terrascale_metadata output | grep -q 'ip daddr 192.0.2.1 counter.*accept'
sudo install -m 0644 "$work/metadata-base.nft" "$metadata_rules"
sudo systemctl restart terrascale-ts-auth-metadata.service
end "metadata fresh rules, upgrade exception and additions, actual unit restart"
