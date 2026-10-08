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
# First enrollment shares the private NetBird transaction lock with the worker.
StateDirectory=terrascale-orchestrator/netbird-managed
StateDirectoryMode=0700
# host-setup runs the current release, the one the host agent runs, so an
# enrollment change ships with a rollout; the image-baked binary runs it
# until prepare seeds a current release.
ExecStart=
ExecStart=/bin/sh -c 'b=/var/lib/terrascale-orchestrator/current/terrascale-orchestrator; [ -x "$$b" ] || b=/usr/local/bin/terrascale-orchestrator; exec "$$b" host-setup --public-config /etc/terrascale-orchestrator/host-enrollment-public.json --output-root /etc/terrascale-orchestrator'
`

// BootstrapUnit admits a controller install before the controller starts.
const BootstrapUnit = "terrascale-orchestrator-bootstrap.service"

// BootstrapDropin makes bootstrap admission run the current release, the one
// the controller runs, so a controller.json a newer release installed (a
// material generation, TS-668) is admitted at boot: the image-baked binary may
// refuse its members. The baked binary runs it until prepare seeds a current
// release. Only prepare installs it; the image does not carry it.
const BootstrapDropin = `# Binary-only A/B self-update (docs/continuous-delivery.md), installed by
# selfupdate prepare.
[Service]
# Bootstrap admission runs the current release, the one the controller runs,
# so a config a newer release installed is admitted at boot; the image-baked
# binary runs it until prepare seeds a current release.
ExecStart=
ExecStart=/bin/sh -c 'b=/var/lib/terrascale-orchestrator/current/terrascale-orchestrator; [ -x "$$b" ] || b=/usr/local/bin/terrascale-orchestrator; exec "$$b" bootstrap-controller --config /etc/terrascale-orchestrator/controller.json'
`

// InstallHostSetupDropin writes HostSetupDropin below systemdDir on a host,
// one with the host-setup unit, and reports whether it changed it. systemd
// reads it from the next boot.
func InstallHostSetupDropin(systemdDir string) (bool, error) {
	return installDropin(systemdDir, HostSetupUnit, HostSetupDropin)
}

// InstallBootstrapDropin writes BootstrapDropin below systemdDir on a
// controller, one with the bootstrap unit, and reports whether it changed it.
// systemd reads it from the next boot.
func InstallBootstrapDropin(systemdDir string) (bool, error) {
	return installDropin(systemdDir, BootstrapUnit, BootstrapDropin)
}

func installDropin(systemdDir, unit, dropin string) (bool, error) {
	if _, err := os.Stat(filepath.Join(systemdDir, unit)); errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	dir := filepath.Join(systemdDir, unit+".d")
	path := filepath.Join(dir, "60-selfupdate.conf")
	if current, err := os.ReadFile(path); err == nil && string(current) == dropin {
		return false, nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false, err
	}
	return true, writeFileAtomic(path, []byte(dropin), 0o644)
}
