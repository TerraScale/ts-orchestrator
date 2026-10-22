package regionhost

import (
	"encoding/base64"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"strings"
)

var (
	sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)
	plainURL  = regexp.MustCompile(`^https://[A-Za-z0-9./_:%-]+$`)
)

// userData is the cloud-init script that installs ts-orch on first boot, the
// same steps deploy/m1/install.sh runs over ssh: host-runtime.sh, the NetBird
// client, the release binary (sha256 verified) and every unit.
func userData(files fs.FS, binaryURL, sum string) (string, error) {
	if !sha256Hex.MatchString(sum) || !plainURL.MatchString(binaryURL) {
		return "", fmt.Errorf("release asset needs a plain https URL and a lowercase sha256")
	}
	runtime, err := fs.ReadFile(files, "host-runtime.sh")
	if err != nil {
		return "", err
	}
	units, err := fs.Glob(files, "services/*.service")
	if err != nil {
		return "", err
	}
	// ts-orch.service comes first because the others order after it.
	units = append([]string{"ts-orch.service"}, units...)
	var b strings.Builder
	fmt.Fprintf(&b, `#!/bin/bash
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
`, base64.StdEncoding.EncodeToString(runtime), binaryURL, sum)
	names := make([]string, 0, len(units))
	for _, unit := range units {
		data, err := fs.ReadFile(files, unit)
		if err != nil {
			return "", err
		}
		name := path.Base(unit)
		names = append(names, name)
		fmt.Fprintf(&b, "echo '%s' | base64 -d > /etc/systemd/system/%s\nchmod 0644 /etc/systemd/system/%[2]s\n",
			base64.StdEncoding.EncodeToString(data), name)
	}
	list := strings.Join(names, " ")
	fmt.Fprintf(&b, "systemctl daemon-reload\nsystemctl enable %s\nsystemctl restart %[1]s\n", list)
	return b.String(), nil
}
