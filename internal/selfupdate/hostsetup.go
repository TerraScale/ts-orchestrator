package selfupdate

import (
	"errors"
	"os"
	"path/filepath"
)

// HostSetupUnit enrolls a host before its host agent starts.
const HostSetupUnit = "terrascale-orchestrator-host-setup.service"

// HostSetupDropin makes host-setup run the current release, the one the host
// agent runs, so an enrollment change ships with a rollout (TS-632); the
// image-baked binary runs it until prepare seeds a current release. It is
// deploy/systemd/selfupdate's copy byte for byte.
const HostSetupDropin = `# Binary-only A/B self-update (docs/continuous-delivery.md), installed by the
# image and by selfupdate prepare on a host whose image predates it.
[Service]
# host-setup runs the current release, the one the host agent runs, so an
# enrollment change ships with a rollout; the image-baked binary runs it
# until prepare seeds a current release.
ExecStart=
ExecStart=/bin/sh -c 'b=/var/lib/terrascale-orchestrator/current/terrascale-orchestrator; [ -x "$$b" ] || b=/usr/local/bin/terrascale-orchestrator; exec "$$b" host-setup --public-config /etc/terrascale-orchestrator/host-enrollment-public.json --output-root /etc/terrascale-orchestrator'
`

// InstallHostSetupDropin writes HostSetupDropin below systemdDir on a host,
// one with the host-setup unit, and reports whether it changed it. systemd
// reads it from the next boot.
func InstallHostSetupDropin(systemdDir string) (bool, error) {
	if _, err := os.Stat(filepath.Join(systemdDir, HostSetupUnit)); errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	dir := filepath.Join(systemdDir, HostSetupUnit+".d")
	path := filepath.Join(dir, "60-selfupdate.conf")
	if current, err := os.ReadFile(path); err == nil && string(current) == HostSetupDropin {
		return false, nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false, err
	}
	return true, writeFileAtomic(path, []byte(HostSetupDropin), 0o644)
}
