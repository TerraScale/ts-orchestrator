// Package tsnodebootstrap owns the production systemd unit contract for the
// ts-node host agent. It renders a unit file only. Cloud-init, image assembly,
// and provider-specific transport belong to callers.
package tsnodebootstrap

import (
	"errors"
	"path"
	"strings"
)

const (
	// UnitName is the one production systemd unit that runs ts-node.
	UnitName = "terrascale-ts-node.service"

	productionUser           = "root"
	productionGroup          = "root"
	productionExecutablePath = "/opt/terrascale/ts-node/current/ts-node"
	productionInstallRoot    = "/opt/terrascale"
	productionUnitDirectory  = "/etc/systemd/system"
	productionDataVolumeRoot = "/var/lib/terrascale"
	productionConfigRoot     = "/etc/terrascale"
	maximumPathBytes         = 4096
)

// Config names the identity and paths that the production unit exposes to
// ts-node. User and Group must both be root. The host agent rejects any other
// effective identity and its live work updates the system account databases,
// owns component data directories, writes system units, and controls systemd.
type Config struct {
	User           string
	Group          string
	ExecutablePath string
	InstallRoot    string
	UnitDirectory  string
	DataVolumeRoot string
}

// ProductionConfig returns the canonical ts-node layout used by images and
// provider bootstrap.
func ProductionConfig() Config {
	return Config{
		User:           productionUser,
		Group:          productionGroup,
		ExecutablePath: productionExecutablePath,
		InstallRoot:    productionInstallRoot,
		UnitDirectory:  productionUnitDirectory,
		DataVolumeRoot: productionDataVolumeRoot,
	}
}

// ValidateConfig checks the systemd rendering trust boundary. Paths must be
// the canonical production layout and safe to emit without systemd escaping.
// The executable is pinned below <installRoot>/ts-node/current so an update is
// an atomic symlink flip, not a unit rewrite.
func ValidateConfig(config Config) error {
	if config.User != productionUser || config.Group != productionGroup {
		return errors.New("tsnodebootstrap: ts-node must run as root:root")
	}
	paths := []struct {
		name  string
		value string
	}{
		{"executable path", config.ExecutablePath},
		{"install root", config.InstallRoot},
		{"unit directory", config.UnitDirectory},
		{"data volume root", config.DataVolumeRoot},
	}
	for _, candidate := range paths {
		if !safeSystemdPath(candidate.value) {
			return errors.New("tsnodebootstrap: " + candidate.name + " is not a safe canonical absolute path")
		}
	}
	if config.InstallRoot == "/" || config.UnitDirectory == "/" || config.DataVolumeRoot == "/" {
		return errors.New("tsnodebootstrap: writable roots must not expose the filesystem root")
	}
	wantExecutable := path.Join(config.InstallRoot, "ts-node", "current", "ts-node")
	if config.ExecutablePath != wantExecutable {
		return errors.New("tsnodebootstrap: executable path must be <installRoot>/ts-node/current/ts-node")
	}
	if config.UnitDirectory != productionUnitDirectory {
		return errors.New("tsnodebootstrap: production units must live in /etc/systemd/system")
	}
	if config.InstallRoot != productionInstallRoot {
		return errors.New("tsnodebootstrap: production installs must live in /opt/terrascale")
	}
	if config.DataVolumeRoot != productionDataVolumeRoot {
		return errors.New("tsnodebootstrap: production data must live in /var/lib/terrascale")
	}
	return nil
}

// RenderSystemdUnit returns the deterministic raw systemd unit. It does not
// quote a shell command or wrap the result in cloud-init.
//
// The unit deliberately has no CAP_DAC_OVERRIDE. Bootstrap must leave the
// install root, data root, unit directory, account databases, and their
// writable parents owned by root and owner-writable. Component validation
// confines every DataVolume below the data root. User provisioning uses
// --no-log-init, so it does not need to mutate lastlog or faillog. Those rules
// let the root process update its files through normal DAC checks. CAP_CHOWN
// allows hostagent.UseraddProvisioner.OwnDirectory to assign a component's
// data directory to its dedicated uid and gid. CAP_FOWNER permits subsequent
// mode repair on that service-owned directory without granting DAC override.
// SecureBits=noroot-locked stops uid 0 from regaining omitted capabilities on
// exec, while the ambient set preserves only those two capabilities across
// the direct useradd and systemctl child execs.
//
// @system-service includes the file-system, chown, network I/O, process, and
// signal syscall groups used by downloads, statfs, file replacement, child
// exec/wait, and systemctl. ProtectProc=invisible does not hide this service's
// own children, and PrivateDevices does not mask mounted filesystems from
// statfs; ts-node never opens a raw device. The image qualification lane must
// still exercise the rendered unit under the target guest's systemd, kernel,
// shadow-utils, NSS, and chrony versions because a unit-file test cannot prove
// those external implementations stay within the documented contract.
func RenderSystemdUnit(config Config) (string, error) {
	if err := ValidateConfig(config); err != nil {
		return "", err
	}
	var unit strings.Builder
	unit.WriteString("[Unit]\n")
	unit.WriteString("Description=TerraScale ts-node host agent\n")
	unit.WriteString("After=network-online.target\n")
	unit.WriteString("Wants=network-online.target\n")
	unit.WriteString("\n[Service]\n")
	unit.WriteString("Type=exec\n")
	unit.WriteString("User=" + config.User + "\n")
	unit.WriteString("Group=" + config.Group + "\n")
	unit.WriteString("Environment=PATH=/usr/sbin:/usr/bin:/sbin:/bin\n")
	unit.WriteString("ExecStart=" + config.ExecutablePath + "\n")
	unit.WriteString("Restart=on-failure\n")
	unit.WriteString("RestartSec=2s\n")
	unit.WriteString("UMask=0022\n")
	unit.WriteString("NoNewPrivileges=yes\n")
	unit.WriteString("CapabilityBoundingSet=CAP_CHOWN CAP_FOWNER\n")
	unit.WriteString("AmbientCapabilities=CAP_CHOWN CAP_FOWNER\n")
	unit.WriteString("SecureBits=noroot-locked\n")
	unit.WriteString("ProtectSystem=strict\n")
	unit.WriteString("ProtectHome=yes\n")
	unit.WriteString("PrivateTmp=yes\n")
	unit.WriteString("PrivateDevices=yes\n")
	unit.WriteString("ProtectClock=yes\n")
	unit.WriteString("ProtectHostname=yes\n")
	unit.WriteString("ProtectKernelLogs=yes\n")
	unit.WriteString("ProtectKernelTunables=yes\n")
	unit.WriteString("ProtectKernelModules=yes\n")
	unit.WriteString("ProtectControlGroups=yes\n")
	unit.WriteString("ProtectProc=invisible\n")
	unit.WriteString("ProcSubset=pid\n")
	unit.WriteString("RestrictNamespaces=yes\n")
	unit.WriteString("RestrictRealtime=yes\n")
	unit.WriteString("RestrictSUIDSGID=yes\n")
	unit.WriteString("LockPersonality=yes\n")
	unit.WriteString("MemoryDenyWriteExecute=yes\n")
	unit.WriteString("SystemCallArchitectures=native\n")
	unit.WriteString("SystemCallFilter=@system-service\n")
	unit.WriteString("SystemCallErrorNumber=EPERM\n")
	unit.WriteString("RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n")
	unit.WriteString("ReadWritePaths=" + config.InstallRoot + "\n")
	unit.WriteString("ReadWritePaths=" + config.DataVolumeRoot + "\n")
	// useradd creates distribution-specific lock, backup, and account files
	// beside /etc/passwd. The parent must therefore be writable. Re-protect
	// the more specific TerraScale configuration tree after that exception.
	unit.WriteString("ReadWritePaths=/etc\n")
	unit.WriteString("ReadOnlyPaths=" + productionConfigRoot + "\n")
	unit.WriteString("CPUWeight=100\n")
	unit.WriteString("MemoryMax=536870912\n")
	unit.WriteString("IOWeight=100\n")
	unit.WriteString("\n[Install]\n")
	unit.WriteString("WantedBy=multi-user.target\n")
	return unit.String(), nil
}

func safeSystemdPath(value string) bool {
	if value == "" || len(value) > maximumPathBytes || !strings.HasPrefix(value, "/") || path.Clean(value) != value {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			strings.ContainsRune("/._-", character) {
			continue
		}
		return false
	}
	return true
}
