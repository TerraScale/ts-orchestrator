package regionhost

import (
	"encoding/base64"
	"fmt"
	"io/fs"
	"regexp"
)

var (
	sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)
	plainURL  = regexp.MustCompile(`^https://[A-Za-z0-9./_:%-]+$`)
)

// userData is the cloud-init script that installs ts-orch on first boot, the
// same steps deploy/m1/install.sh runs over ssh: host-runtime.sh, the NetBird
// client, the release binary (sha256 verified) and ts-orch.service.
func userData(files fs.FS, binaryURL, sum string) (string, error) {
	if !sha256Hex.MatchString(sum) || !plainURL.MatchString(binaryURL) {
		return "", fmt.Errorf("release asset needs a plain https URL and a lowercase sha256")
	}
	runtime, err := fs.ReadFile(files, "host-runtime.sh")
	if err != nil {
		return "", err
	}
	// Only ts-orch.service: services/*.service (netbird-server.service is
	// gru's one NetBird server) must not run twice; a region's other services
	// ship as mesh services.
	unit, err := fs.ReadFile(files, "ts-orch.service")
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(`#!/bin/bash
# ts-orch region add: milestone 1 host install (mirrors deploy/m1/install.sh).
set -euo pipefail
echo '%s' | base64 -d | bash
if ! command -v netbird >/dev/null; then
	curl -fsSL https://pkgs.netbird.io/debian/public.key | gpg --dearmor --yes -o /usr/share/keyrings/netbird-archive-keyring.gpg
	echo 'deb [signed-by=/usr/share/keyrings/netbird-archive-keyring.gpg] https://pkgs.netbird.io/debian stable main' > /etc/apt/sources.list.d/netbird.list
	apt-get update -qq
	DEBIAN_FRONTEND=noninteractive apt-get install -y -qq netbird
fi
systemctl is-enabled --quiet netbird || netbird service install
systemctl enable --now netbird
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
curl -fsSL --retry 3 -o "$tmp" '%s'
echo '%s  '"$tmp" | sha256sum -c --quiet
install -m 0755 "$tmp" /usr/local/bin/terrascale-orchestrator
ln -sfn terrascale-orchestrator /usr/local/bin/ts-orch
install -d -m 0700 /var/lib/ts-orch
install -d -m 0755 /var/lib/ts-data /var/lib/ts-data/terrabase
echo '%s' | base64 -d > /etc/systemd/system/ts-orch.service
chmod 0644 /etc/systemd/system/ts-orch.service
systemctl daemon-reload
systemctl enable ts-orch.service
systemctl restart ts-orch.service
`, base64.StdEncoding.EncodeToString(runtime), binaryURL, sum, base64.StdEncoding.EncodeToString(unit)), nil
}
