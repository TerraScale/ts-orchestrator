package selfupdate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

// HostSetupUnit enrolls a host before its host agent starts.
const HostSetupUnit = "terrascale-orchestrator-host-setup.service"

// MemoryPrepareMarker is written by every prepare that mounts the host's
// runtime secret directories, before it tries: its absence is the evidence
// that the prepare before a host start predates the mounts (TS-745).
const MemoryPrepareMarker = "/run/terrascale-orchestrator-memory-prepare"

// hostMountsEnv marks a command RunInHostMounts already moved, so a failed
// move never loops.
const hostMountsEnv = "TERRASCALE_HOST_MOUNTS"

// RunInHostMounts runs this command again in PID 1's mount namespace when it
// runs in another one, and reports whether it did. systemd runs a unit's
// ExecStartPre=+ steps in the unit's private mount namespace, where a tmpfs
// they mount ends up hidden beneath the main process's sandbox and goes with
// the unit. The runtime secret mounts belong to the host, whose mounts every
// unit sees (TS-745).
func RunInHostMounts(ctx context.Context, stdout, stderr io.Writer) (bool, error) {
	self, selfErr := os.Readlink("/proc/self/ns/mnt")
	host, hostErr := os.Readlink("/proc/1/ns/mnt")
	if selfErr != nil || hostErr != nil {
		return false, fmt.Errorf("compare mount namespaces: %w", errors.Join(selfErr, hostErr))
	}
	if self == host {
		return false, nil
	}
	if os.Getenv(hostMountsEnv) != "" {
		return true, errors.New("nsenter left the command outside the host mount namespace")
	}
	executable, err := os.Executable()
	if err != nil {
		return true, err
	}
	command := exec.CommandContext(ctx, "nsenter", append([]string{"--mount=/proc/1/ns/mnt", "--", executable}, os.Args[1:]...)...)
	command.Env = append(os.Environ(), hostMountsEnv+"=1")
	command.Stdin, command.Stdout, command.Stderr = os.Stdin, stdout, stderr
	return true, command.Run()
}

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
# The enrollment identity and credentials live in memory and outlive this
# oneshot for the host agent; host-setup restores the identity from Vault
# after a reboot (TS-745).
RuntimeDirectory=terrascale-orchestrator-host-credentials
RuntimeDirectoryMode=0700
RuntimeDirectoryPreserve=yes
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
# The credential directory is memory only: the same release rebuilds it from
# Vault first (TS-745), and admission waits until it can. Only a rolled-back
# release that lacks the command skips it.
ExecStartPre=
ExecStartPre=+/bin/sh -c 'b=/var/lib/terrascale-orchestrator/current/terrascale-orchestrator; [ -x "$$b" ] || b=/usr/local/bin/terrascale-orchestrator; "$$b" --help 2>/dev/null | grep -q restore-controller-material || exit 0; exec "$$b" restore-controller-material'
`

// ControllerInstallUnit installs the root-signed controller configuration before admission.
const ControllerInstallUnit = "terrascale-orchestrator-controller-install.service"

// ControllerInstallDropin makes controller config installation run the current
// release, the one the controller runs, so an identity or config a newer
// release installed survives a reboot: the image-baked binary may refuse it.
// The baked binary runs it until prepare seeds a current release. Only prepare
// installs it; the image does not carry it.
const ControllerInstallDropin = `# Binary-only A/B self-update (docs/continuous-delivery.md), installed by
# selfupdate prepare.
[Service]
# Config installation runs the current release, the one the controller runs,
# so an identity or config a newer release installed survives a reboot; the
# image-baked binary runs it until prepare seeds a current release.
ExecStart=
ExecStart=/bin/sh -c 'b=/var/lib/terrascale-orchestrator/current/terrascale-orchestrator; [ -x "$$b" ] || b=/usr/local/bin/terrascale-orchestrator; exec "$$b" install-controller-config'
`

// InstallHostSetupDropin writes HostSetupDropin below systemdDir on a host,
// one with the host-setup unit, and reports whether it changed it. systemd
// reads it from the next boot.
func InstallHostSetupDropin(systemdDir string) (bool, error) {
	return installDropin(systemdDir, HostSetupUnit, "60-selfupdate.conf", HostSetupDropin)
}

// InstallBootstrapDropin writes BootstrapDropin below systemdDir on a
// controller, one with the bootstrap unit, and reports whether it changed it.
// systemd reads it from the next boot.
func InstallBootstrapDropin(systemdDir string) (bool, error) {
	return installDropin(systemdDir, BootstrapUnit, "60-selfupdate.conf", BootstrapDropin)
}

// InstallControllerInstallDropin writes ControllerInstallDropin below systemdDir
// on a controller, one with the controller-install unit, and reports whether it
// changed it. systemd reads it from the next boot.
func InstallControllerInstallDropin(systemdDir string) (bool, error) {
	return installDropin(systemdDir, ControllerInstallUnit, "60-selfupdate.conf", ControllerInstallDropin)
}

func installDropin(systemdDir, unit, file, dropin string) (bool, error) {
	if _, err := os.Stat(filepath.Join(systemdDir, unit)); errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	dir := filepath.Join(systemdDir, unit+".d")
	path := filepath.Join(dir, file)
	if current, err := os.ReadFile(path); err == nil && string(current) == dropin {
		return false, nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false, err
	}
	return true, writeFileAtomic(path, []byte(dropin), 0o644)
}

// ManagedRuntimeUnit is an image-installed alias of the canonical host cgroup.
const ManagedRuntimeUnit = "terrascale-orchestrator-managed-runtime.service"

// ManagedRuntimeService matches the image's installed systemd file byte for byte.
const ManagedRuntimeService = `[Unit]
Description=TerraScale admitted regional Swarm runtime
Wants=network-online.target
Requires=containerd.service terrascale-orchestrator-managed-host-start.service
After=network-online.target containerd.service terrascale-orchestrator-managed-host-start.service
Before=terrascale-orchestrator-controller.service
PartOf=terrascale-orchestrator-controller.service
StartLimitIntervalSec=0

[Service]
Type=notify
NotifyAccess=main
ExecStart=/usr/local/bin/terrascale-orchestrator managed-runtime-start
Restart=on-failure
RestartSec=10s
TimeoutStartSec=10min
TimeoutStopSec=90s
KillMode=process
LimitNOFILE=65536
LimitCORE=0
UMask=0077
SupplementaryGroups=
StateDirectory=terrascale-orchestrator-host
StateDirectoryMode=0755
RuntimeDirectory=terrascale-orchestrator-host-credentials
RuntimeDirectoryMode=0700
RuntimeDirectoryPreserve=yes
Delegate=yes

[Install]
WantedBy=multi-user.target
RequiredBy=terrascale-orchestrator-controller.service
Alias=terrascale-orchestrator-managed-runtime.service
`

// ManagedRuntimeHostDropin matches the image's installed systemd file byte for byte.
const ManagedRuntimeHostDropin = `# The image installs the admitted runtime as host.service, preserving its
# signed update owner and the native volume initializer's cgroup fence.
[Service]
# The native host's earlier 60 file must not restore its Agent command.
ExecStartPre=
ExecStartPre=+/usr/local/bin/terrascale-orchestrator selfupdate prepare --root /var/lib/terrascale-orchestrator --unit terrascale-orchestrator-host.service
ExecStart=
ExecStart=/var/lib/terrascale-orchestrator/current/terrascale-orchestrator managed-runtime-start
KillMode=process
InaccessiblePaths=
`

// ManagedRuntimeControllerDropin matches the image's installed systemd file byte for byte.
const ManagedRuntimeControllerDropin = `# The required runtime prepares the shared release before either process starts.
# A controller restart restarts that runtime through PartOf=controller.service.
[Service]
ExecStartPre=
`

// ManagedRuntimeWatchdogDropin matches the image's installed systemd file byte for byte.
const ManagedRuntimeWatchdogDropin = `# An accepted controller's shared release belongs only to controller.service.
[Unit]
ConditionPathExists=!/var/lib/terrascale-orchestrator-bootstrap/accepted-install.json
`

// ManagedRuntimeInstalled recognizes only the image's fixed, exclusively owned
// alias and complete service contract. A standalone native install stays native.
func ManagedRuntimeInstalled(systemdDir string, owner int) (bool, error) {
	layout := Layout{Root: systemdDir, Owner: owner}
	if err := layout.validate(); err != nil {
		return false, err
	}
	alias := filepath.Join(systemdDir, ManagedRuntimeUnit)
	info, err := os.Lstat(alias)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.Mode().IsRegular() {
		return false, nil
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeSymlink == 0 || int(stat.Uid) != owner || owner == 0 && stat.Gid != 0 {
		return false, fmt.Errorf("%w: managed runtime alias", ErrUnsafe)
	}
	target, err := os.Readlink(alias)
	if err != nil {
		return false, err
	}
	if target != HostUnit && target != filepath.Join(systemdDir, HostUnit) {
		return false, fmt.Errorf("%w: managed runtime alias target", ErrUnsafe)
	}
	// Native ordering waits for enrollment through the controller behind this runtime.
	if _, err := os.Lstat(filepath.Join(systemdDir, HostUnit+".d/65-netbird-agent.conf")); !errors.Is(err, os.ErrNotExist) {
		return false, errors.Join(fmt.Errorf("%w: native host dependency on managed runtime", ErrUnsafe), err)
	}
	// Parent directories must not let another principal replace the alias.
	for directory := systemdDir; ; directory = filepath.Dir(directory) {
		info, err := os.Lstat(directory)
		if err != nil {
			return false, err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || int(stat.Uid) != owner && stat.Uid != 0 ||
			info.Mode().Perm()&0o022 != 0 && !(stat.Uid == 0 && info.Mode()&os.ModeSticky != 0) {
			return false, fmt.Errorf("%w: managed runtime directory %s", ErrUnsafe, directory)
		}
		if directory == "/" {
			break
		}
	}
	for relative, contents := range map[string]string{
		HostUnit:                                ManagedRuntimeService,
		HostUnit + ".d/90-managed-runtime.conf": ManagedRuntimeHostDropin,
		ControllerUnit + ".d/90-managed-runtime.conf":                                        ManagedRuntimeControllerDropin,
		"terrascale-orchestrator-selfupdate-watchdog@host.service.d/90-managed-runtime.conf": ManagedRuntimeWatchdogDropin,
	} {
		file := filepath.Join(systemdDir, relative)
		if err := layout.checkOwned(filepath.Dir(file), true); err != nil {
			return false, err
		}
		if err := layout.checkOwned(file, false); err != nil {
			return false, err
		}
		wire, err := readBounded(file, 16<<10)
		if err != nil {
			return false, err
		}
		if string(wire) != contents {
			return false, fmt.Errorf("%w: managed runtime service contract %s", ErrUnsafe, relative)
		}
	}
	return true, nil
}
