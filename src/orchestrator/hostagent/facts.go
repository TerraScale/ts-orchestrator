// This file assembles the host facts of the D-69 heartbeat: the chrony
// clock offset and write-health flag, the data-volume disk figures, the
// installed versions of every manifest component, and the agent's own
// version. The heartbeat is the single channel these facts travel on; the
// orchestrator's monitoring and rollout gates consume it.
package hostagent

import (
	"context"
	"golang.org/x/sys/unix"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/hostplatform"
)

// TsNodeVersion is stamped at build time by ts-deploy
// (-ldflags -X ...hostagent.TsNodeVersion=<version>); dev builds report dev.
var TsNodeVersion = "dev"

// DiskFacts is the usage of one filesystem.
type DiskFacts struct {
	// Path is the measured mount point.
	Path string `json:"path"`
	// TotalBytes is the filesystem size.
	TotalBytes int64 `json:"totalBytes"`
	// AvailableBytes is the space available to unprivileged writers.
	AvailableBytes int64 `json:"availableBytes"`
}

// ComponentFact is one component's serving state in the heartbeat.
type ComponentFact struct {
	// Name is the component token.
	Name string `json:"name"`
	// Version is the current-symlink version of the component.
	Version string `json:"version"`
	// Desired is the manifest's desired version.
	Desired string `json:"desired"`
	// Installed reports whether the desired version directory exists.
	Installed bool `json:"installed"`
	// UnitActive reports whether the unit is active.
	UnitActive bool `json:"unitActive"`
}

// HostFacts is the payload of one heartbeat.
type HostFacts struct {
	Engine EngineFacts `json:"engine"`
	// State is the node lifecycle state: serving, draining, or quiesced.
	State string `json:"state"`
	// ClockOffsetMillis is the signed chrony system-time offset.
	ClockOffsetMillis int64 `json:"clockOffsetMillis"`
	// ClockMeasured is false when chrony was unreadable.
	ClockMeasured bool `json:"clockMeasured"`
	// ClockUnhealthy marks the host beyond the D-69 write-refusal threshold;
	// the engine refuses new writes while it is set.
	ClockUnhealthy bool `json:"clockUnhealthy"`
	// Disk is the data-volume usage.
	Disk DiskFacts `json:"disk"`
	// TsNodeVersion is the running agent's own release version.
	TsNodeVersion string `json:"tsNodeVersion"`
	// ManifestSha256 is the digest of the currently hydrated canonical
	// desired manifest.
	ManifestSha256 string `json:"manifestSha256"`
	// Components are the facts of every manifest component, ordered by name.
	Components []ComponentFact `json:"components"`
}

// Node lifecycle states of the heartbeat.
const (
	// NodeStateServing is the normal state: units may run and serve.
	NodeStateServing = "serving"
	// NodeStateDraining is the drain-in-progress state: units are stopping.
	NodeStateDraining = "draining"
	// NodeStateQuiesced is the fully drained state: every unit is stopped.
	NodeStateQuiesced = "quiesced"
)

// StatfsPath measures one path; injectable for tests.
type StatfsPath func(path string) (totalBytes int64, availableBytes int64, err error)

// OsStatfs is the live statfs spelling.
func OsStatfs(path string) (int64, int64, error) {
	var statistics unix.Statfs_t
	if err := unix.Statfs(path, &statistics); err != nil {
		return 0, 0, err
	}
	return int64(statistics.Blocks) * int64(statistics.Bsize),
		int64(statistics.Bavail) * int64(statistics.Bsize), nil
}

// HostFactsSourceConfig is the fully explicit facts-source configuration.
type HostFactsSourceConfig struct {
	Engine func(context.Context) (EngineFacts, error)
	// Clock reads the chrony offset.
	Clock hostplatform.ClockSource
	// Statfs measures the data volume.
	Statfs StatfsPath
	// DataVolumeRoot is the mount point disk facts report; the component
	// data volumes live under it.
	DataVolumeRoot string
	// Systemd reports unit activity.
	Systemd SystemdController
	// InstallRoot is /opt/terrascale.
	InstallRoot string
	// Installer authenticates desired release slots before Installed is
	// advertised to rollout gates.
	Installer *Installer
}

// HostFactsSource samples every heartbeat dimension on demand.
type HostFactsSource struct {
	engine         func(context.Context) (EngineFacts, error)
	clock          hostplatform.ClockSource
	statfs         StatfsPath
	dataVolumeRoot string
	systemd        SystemdController
	installRoot    string
	installer      *Installer
}

// NewHostFactsSource validates the configuration and composes the source.
func NewHostFactsSource(config HostFactsSourceConfig) (*HostFactsSource, error) {
	if config.Clock == nil {
		return nil, &InvalidOperationError{Message: "A clock source is required."}
	}
	if config.Statfs == nil {
		return nil, &InvalidOperationError{Message: "A statfs function is required."}
	}
	if !hostmanifest.SafeAbsolutePath(config.DataVolumeRoot) {
		return nil, &InvalidOperationError{Message: "The data volume root must be an absolute safe path."}
	}
	if config.Systemd == nil {
		return nil, &InvalidOperationError{Message: "A systemd controller is required."}
	}
	if !hostmanifest.SafeAbsolutePath(config.InstallRoot) {
		return nil, &InvalidOperationError{Message: "The install root must be an absolute safe path."}
	}
	if config.Installer == nil {
		return nil, &InvalidOperationError{Message: "An installer is required for authenticated host facts."}
	}
	return &HostFactsSource{
		engine:         config.Engine,
		clock:          config.Clock,
		statfs:         config.Statfs,
		dataVolumeRoot: config.DataVolumeRoot,
		systemd:        config.Systemd,
		installRoot:    config.InstallRoot,
		installer:      config.Installer,
	}, nil
}

// Sample collects one full heartbeat payload: lifecycle state, clock facts,
// disk facts, the agent version, and the per-component facts of one desired
// manifest snapshot. A failing statfs reports zero disk figures rather than
// failing the heartbeat; a failing unit probe reports the unit inactive.
func (s *HostFactsSource) Sample(
	ctx context.Context,
	state string,
	desired []hostmanifest.ComponentSpec,
) (HostFacts, error) {
	if ctx == nil {
		return HostFacts{}, &InvalidOperationError{Message: "The facts context must not be nil."}
	}
	offset, clockErr := s.clock.Offset(ctx)
	clock := hostplatform.SampleClock(offset, clockErr)
	disk := DiskFacts{Path: s.dataVolumeRoot}
	if total, available, err := s.statfs(s.dataVolumeRoot); err == nil {
		disk.TotalBytes, disk.AvailableBytes = total, available
	}
	components := make([]ComponentFact, 0, len(desired))
	manifestSha256, err := hostmanifest.HostManifestSha256(hostmanifest.HostManifest{Components: desired})
	if err != nil {
		return HostFacts{}, err
	}
	for _, spec := range desired {
		current, _ := CurrentVersion(s.installRoot, spec.Name)
		installed := s.installer.withVerifiedTransition(ctx, spec.Name, spec.Version, spec.Sha256, func(context.Context) error { return nil }) == nil
		active := false
		if unitProbe, err := s.systemd.UnitActive(ctx, UnitName(spec.Name)); err == nil {
			active = unitProbe
		}
		components = append(components, ComponentFact{
			Name:       spec.Name,
			Version:    current,
			Desired:    spec.Version,
			Installed:  installed,
			UnitActive: active,
		})
	}
	engine := EngineFacts{Databases: []DatabaseCatchUpFacts{}}
	if s.engine != nil {
		if sample, err := s.engine(ctx); err == nil {
			engine = sample
		}
	}
	return HostFacts{
		Engine:            engine,
		State:             state,
		ClockOffsetMillis: clock.OffsetMillis,
		ClockMeasured:     clock.Measured,
		ClockUnhealthy:    clock.Unhealthy,
		Disk:              disk,
		TsNodeVersion:     TsNodeVersion,
		ManifestSha256:    manifestSha256,
		Components:        components,
	}, nil
}
