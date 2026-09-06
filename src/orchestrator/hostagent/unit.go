// This file renders the hardened systemd SYSTEM unit of one component,
// pinned to the exact directive list of decision D-69: a dedicated user per
// component, ProtectSystem=strict, ReadWritePaths limited to the data volume,
// NoNewPrivileges, an empty CapabilityBoundingSet, SystemCallFilter=
// @system-service, RestrictAddressFamilies without AF_NETLINK unless a
// component declares it, and the cgroup v2 CPUWeight/MemoryMax/IOWeight
// envelope from the component spec. No container runtime is ever involved.
package hostagent

import (
	"fmt"
	"strings"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/serviceidentity"
	"terrascale.tech/orchestrator/src/orchestrator/systemdlimits"
)

// UnitName returns the systemd unit name of one component.
func UnitName(component string) string { return "terrascale-" + component + ".service" }

// InstallDir returns /<installRoot>/<component> that holds every installed
// version directory plus the current and previous symlinks.
func InstallDir(installRoot, component string) string {
	return strings.TrimSuffix(installRoot, "/") + "/" + component
}

// VersionDir returns the directory one installed version lives in:
// /<installRoot>/<component>/<version>/<component>.
func VersionDir(installRoot, component, version string) string {
	return InstallDir(installRoot, component) + "/" + version
}

// ExecStartPath returns the current-symlink-relative ExecStart binary path of
// one component: flipping the symlink is the whole version switch.
func ExecStartPath(installRoot, component string) string {
	return InstallDir(installRoot, component) + "/current/" + component
}

// RenderSystemdUnit renders the D-69 hardened unit file of one validated
// component spec. The D-69 sandbox is extended with explicit locked-memory
// budgets and disabled core files for native key handling.
//
// AF_NETLINK is omitted unless the spec declares NeedsNetlink. No component
// of the launch estate declares it: terrabase, the orchestrator control
// node, and the Grafana agent all speak AF_UNIX/AF_INET/AF_INET6 only. The
// switch exists for a future rtnetlink consumer; granting it to every unit
// would widen the sandbox of components that never need it.
func RenderSystemdUnit(installRoot string, spec hostmanifest.ComponentSpec) (string, error) {
	if !hostmanifest.SafeAbsolutePath(installRoot) {
		return "", &InvalidOperationError{Message: "The install root must be an absolute safe path."}
	}
	if _, err := hostmanifest.NewComponentSpec(spec); err != nil {
		return "", err
	}
	restrictAddressFamilies := "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6"
	if spec.NeedsNetlink {
		restrictAddressFamilies = "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK"
	}
	var b strings.Builder
	b.WriteString("[Unit]\n")
	b.WriteString("Description=TerraScale " + spec.Name + " " + spec.Version + "\n")
	b.WriteString("After=network-online.target\n")
	b.WriteString("Wants=network-online.target\n")
	b.WriteString("\n[Service]\n")
	b.WriteString("Type=exec\n")
	b.WriteString("User=" + spec.User + "\n")
	b.WriteString("Group=" + spec.User + "\n")
	for _, property := range serviceidentity.UnitProperties(spec.User) {
		b.WriteString(property + "\n")
	}
	b.WriteString("ExecStart=" + componentExecStart(installRoot, spec) + "\n")
	b.WriteString("Restart=on-failure\n")
	b.WriteString("RestartSec=2s\n")
	b.WriteString(systemdlimits.Core + "\n" + systemdlimits.MemoryLock(spec.Name) + "\n")
	// The exact D-69 hardening block. CapabilityBoundingSet= (empty) strips
	// every capability; ProtectSystem=strict makes the whole filesystem
	// read-only except ReadWritePaths, which names the data volume only.
	b.WriteString("NoNewPrivileges=true\n")
	b.WriteString("ProtectSystem=strict\n")
	b.WriteString("ReadWritePaths=" + spec.DataVolume + "\n")
	b.WriteString("CapabilityBoundingSet=\n")
	b.WriteString("SystemCallFilter=@system-service\n")
	b.WriteString(restrictAddressFamilies + "\n")
	b.WriteString(fmt.Sprintf("CPUWeight=%d\n", spec.CPUWeight))
	b.WriteString(fmt.Sprintf("MemoryMax=%d\n", spec.MemoryMaxBytes))
	b.WriteString(fmt.Sprintf("IOWeight=%d\n", spec.IOWeight))
	b.WriteString("\n[Install]\n")
	b.WriteString("WantedBy=multi-user.target\n")
	return b.String(), nil
}

// ValidateSystemdUnit checks that a rendered unit is exactly the hardened
// unit for its validated spec. Keeping this separate makes callers validate
// staged bytes before committing a symlink or unit-file transition.
func ValidateSystemdUnit(installRoot string, spec hostmanifest.ComponentSpec, rendered string) error {
	expected, err := RenderSystemdUnit(installRoot, spec)
	if err != nil {
		return err
	}
	if rendered != expected {
		return &InvalidDataError{Message: "The rendered systemd unit is not the canonical hardened unit."}
	}
	return nil
}
