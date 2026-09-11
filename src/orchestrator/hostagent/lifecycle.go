// This file implements the D-69 host lifecycle: the drain state machine
// (serving → draining → quiesced), the drain-coordinated version deploy
// (flip the current symlink, restart under the drain), the emergency
// rollback (symlink back plus restart), and the ts-node self-update that
// restarts the agent's own cloud-init unit through the current symlink.
package hostagent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/tsnodebootstrap"
)

const hostAgentTransitionRecoveryTimeout = 2 * time.Minute
const hostAgentMaximumUnitBytes = 64 << 10

// LifecycleConfig is the fully explicit lifecycle configuration.
type LifecycleConfig struct {
	// InstallRoot is /opt/terrascale on production hosts.
	InstallRoot string
	// UnitDir is the systemd unit directory unit files are written to.
	UnitDir string
	// DataVolumeRoot is the only root beneath which component writable
	// directories may be created and owned.
	DataVolumeRoot string
	// Installer lands verified release artifacts.
	Installer *Installer
	// Systemd drives units.
	Systemd SystemdController
	// SystemctlBinary is the executable used for the detached self-restart.
	SystemctlBinary string
	// Users provisions the dedicated component accounts.
	Users UserProvisioner
}

// Lifecycle owns the drain state machine and every host mutation of the
// agent. All operations serialize under one mutex: a host is mutated by one
// goroutine at a time by construction.
type Lifecycle struct {
	installRoot     string
	unitDir         string
	dataRoot        string
	installer       *Installer
	systemd         SystemdController
	users           UserProvisioner
	systemctlBinary string

	reconcileProgress atomic.Pointer[reconcileProgress]
	mutex             sync.Mutex
	state             string
	desired           []hostmanifest.ComponentSpec
	stale             []string
	enabledUnits      map[string]bool
}

// transitionPlan freezes every input needed to finish a deploy or rollback
// after a process restart. In particular, a rollback records the previous
// version once; recovery never reads the possibly-swapped previous link and
// accidentally rolls forward again.
type transitionPlan struct {
	Spec           hostmanifest.ComponentSpec `json:"spec"`
	ExpectedSha256 string                     `json:"expectedSha256"`
}

// NewLifecycle validates the configuration and composes the lifecycle in
// the serving state with an empty desired manifest.
func NewLifecycle(config LifecycleConfig) (*Lifecycle, error) {
	if !hostmanifest.SafeAbsolutePath(config.InstallRoot) {
		return nil, &InvalidOperationError{Message: "The install root must be an absolute path."}
	}
	if !hostmanifest.SafeAbsolutePath(config.UnitDir) {
		return nil, &InvalidOperationError{Message: "The unit directory must be an absolute path."}
	}
	if !hostmanifest.SafeAbsolutePath(config.DataVolumeRoot) {
		return nil, &InvalidOperationError{Message: "The data volume root must be an absolute path."}
	}
	if config.Installer == nil {
		return nil, &InvalidOperationError{Message: "An installer is required."}
	}
	if config.Systemd == nil {
		return nil, &InvalidOperationError{Message: "A systemd controller is required."}
	}
	if config.Users == nil {
		return nil, &InvalidOperationError{Message: "A user provisioner is required."}
	}
	systemctlBinary := config.SystemctlBinary
	if systemctlBinary == "" {
		systemctlBinary = "systemctl"
	}
	if systemctlBinary != "systemctl" && !hostmanifest.SafeAbsolutePath(systemctlBinary) {
		return nil, &InvalidOperationError{Message: "The systemctl binary must be an absolute safe path."}
	}
	return &Lifecycle{
		installRoot:     config.InstallRoot,
		unitDir:         config.UnitDir,
		dataRoot:        config.DataVolumeRoot,
		installer:       config.Installer,
		systemd:         config.Systemd,
		users:           config.Users,
		systemctlBinary: systemctlBinary,
		state:           NodeStateServing,
		enabledUnits:    map[string]bool{},
	}, nil
}

// State reports the current lifecycle state.
func (l *Lifecycle) State() string {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	return l.state
}

// Desired returns the current desired manifest snapshot.
func (l *Lifecycle) Desired() []hostmanifest.ComponentSpec {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	return slices.Clone(l.desired)
}

// BeginDrain moves the node from serving to draining and stops every
// component unit gracefully, in manifest order. The agent's own unit is
// never stopped: it must keep answering the drain-status polls that gate
// the restart. Draining twice is idempotent.
func (l *Lifecycle) BeginDrain(ctx context.Context) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	for _, spec := range l.desired {
		if spec.Name == hostmanifest.TsNodeComponentName {
			continue
		}
		if err := l.systemd.StopUnit(ctx, UnitName(spec.Name)); err != nil {
			l.state = NodeStateDraining
			return err
		}
	}
	for _, component := range l.stale {
		if component == hostmanifest.TsNodeComponentName {
			// The agent's own unit must keep answering the drain-status
			// polls even when a foreign manifest retired it.
			continue
		}
		retired, err := l.retirementRecorded(component)
		if err != nil {
			l.state = NodeStateDraining
			return err
		}
		if retired {
			continue
		}
		if err := l.systemd.StopUnit(ctx, UnitName(component)); err != nil {
			l.state = NodeStateDraining
			return err
		}
	}
	l.state = NodeStateDraining
	return nil
}

// ReleaseDrain moves the node back to serving and starts every component
// unit that is not active, restoring normal service after a deploy or an
// aborted rollout.
func (l *Lifecycle) ReleaseDrain(ctx context.Context) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	if err := l.startUnitsLocked(ctx); err != nil {
		return err
	}
	l.state = NodeStateServing
	return nil
}

func (l *Lifecycle) startUnitsLocked(ctx context.Context) error {
	for _, spec := range l.desired {
		if spec.Name == hostmanifest.TsNodeComponentName {
			continue
		}
		active, err := l.systemd.UnitActive(ctx, UnitName(spec.Name))
		if err != nil {
			return err
		}
		if active {
			continue
		}
		if err := l.installer.withVerifiedCurrentTransition(ctx, spec, func(ctx context.Context, _ string) error {
			return l.systemd.StartUnit(ctx, UnitName(spec.Name))
		}); err != nil {
			return err
		}
	}
	return nil
}

// Quiesced reports whether the node is draining and every component unit
// has stopped: the drain gate the orchestrator waits on before a deploy.
// The agent's own unit is excluded — it is the thing answering.
func (l *Lifecycle) Quiesced(ctx context.Context) bool {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	return l.quiescedObservationLocked(ctx)
}

func (l *Lifecycle) quiescedObservationLocked(ctx context.Context) bool {
	if l.state != NodeStateDraining {
		return false
	}
	for _, spec := range l.desired {
		if spec.Name == hostmanifest.TsNodeComponentName {
			continue
		}
		if active, err := l.systemd.UnitActive(ctx, UnitName(spec.Name)); err != nil || active {
			return false
		}
	}
	for _, component := range l.stale {
		if component == hostmanifest.TsNodeComponentName {
			continue
		}
		retired, err := l.retirementRecorded(component)
		if err != nil {
			return false
		}
		if retired {
			continue
		}
		if active, err := l.systemd.UnitActive(ctx, UnitName(component)); err != nil || active {
			return false
		}
	}
	return true
}

// Deploy performs the drain-coordinated version switch of one component:
// the node must be quiesced (fail closed otherwise), the desired version
// must be installed, and the flip is the current symlink followed by the
// unit restart. The node stays draining; the orchestrator releases the
// drain after its health gate passes.
func (l *Lifecycle) Deploy(ctx context.Context, component, version string) error {
	if _, err := hostmanifest.RequireName(component, "component",
		"The component must be a canonical token."); err != nil {
		return err
	}
	l.mutex.Lock()
	defer l.mutex.Unlock()
	plan, err := l.prepareDeployLocked(ctx, component, version)
	if err != nil {
		return err
	}
	return l.applyTransitionLocked(ctx, plan)
}

// prepareDeploy freezes and validates the deploy authorization before the
// transport commits its durable intent record.
func (l *Lifecycle) prepareDeploy(ctx context.Context, component, version string) (transitionPlan, error) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	return l.prepareDeployLocked(ctx, component, version)
}

func (l *Lifecycle) prepareDeployLocked(ctx context.Context, component, version string) (transitionPlan, error) {
	if _, err := hostmanifest.RequireName(component, "component",
		"The component must be a canonical token."); err != nil {
		return transitionPlan{}, err
	}
	spec, known := l.specLocked(component)
	if !known {
		return transitionPlan{}, &InvalidOperationError{Message: fmt.Sprintf(
			"Component %s is not in the desired manifest.", component)}
	}
	if version != spec.Version {
		return transitionPlan{}, &InvalidOperationError{Message: fmt.Sprintf(
			"Component %s deploy version %s is not the desired version %s.", component, version, spec.Version)}
	}
	if l.state != NodeStateDraining || !l.quiescedLocked(ctx) {
		return transitionPlan{}, &InvalidOperationError{Message: fmt.Sprintf(
			"Component %s deploy refused: drain the node first.", component)}
	}
	if err := l.installer.withVerifiedTransition(ctx, spec.Name, spec.Version, spec.Sha256, func(context.Context) error { return nil }); err != nil {
		return transitionPlan{}, err
	}
	return transitionPlan{Spec: spec, ExpectedSha256: spec.Sha256}, nil
}

// prepareRollback freezes the rollback target before the transport records
// intent. Reading previous again after a crash would toggle back to the bad
// release.
func (l *Lifecycle) prepareRollback(component string) (transitionPlan, error) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	if _, err := hostmanifest.RequireName(component, "component",
		"The component must be a canonical token."); err != nil {
		return transitionPlan{}, err
	}
	spec, known := l.specLocked(component)
	if !known {
		return transitionPlan{}, &InvalidOperationError{Message: fmt.Sprintf(
			"Component %s is not in the desired manifest.", component)}
	}
	previous, err := PreviousVersion(l.installRoot, component)
	if err != nil {
		return transitionPlan{}, err
	}
	if previous == "" {
		return transitionPlan{}, &InvalidOperationError{Message: fmt.Sprintf(
			"Component %s has no previous version to roll back to.", component)}
	}
	spec.Version = previous
	spec, err = installedLaunchForSpec(l.installRoot, spec)
	if err != nil {
		return transitionPlan{}, err
	}
	return transitionPlan{Spec: spec}, nil
}

// applyTransition completes a previously authorized transition. The plan is
// self-contained so a pending journal entry can finish after ts-node restarts.
func (l *Lifecycle) applyTransition(ctx context.Context, plan transitionPlan) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	return l.applyTransitionLocked(ctx, plan)
}

func (l *Lifecycle) applyTransitionLocked(ctx context.Context, plan transitionPlan) error {
	if _, err := hostmanifest.NewComponentSpec(plan.Spec); err != nil {
		return err
	}
	if _, err := validateDirectoryWithin(l.dataRoot, plan.Spec.DataVolume); err != nil {
		return err
	}
	if plan.ExpectedSha256 != "" && plan.ExpectedSha256 != plan.Spec.Sha256 {
		return &InvalidDataError{Message: "The transition release digest does not match its component spec."}
	}
	return l.installer.withVerifiedTransition(ctx, plan.Spec.Name, plan.Spec.Version, plan.ExpectedSha256, func(ctx context.Context) error {
		if err := verifyExpectedLaunch(VersionDir(l.installRoot, plan.Spec.Name, plan.Spec.Version), plan.Spec); err != nil {
			return err
		}
		if plan.Spec.Name == hostmanifest.TsNodeComponentName {
			current, err := CurrentVersion(l.installRoot, plan.Spec.Name)
			if err != nil {
				return err
			}
			// A recovered self-transition is already running through current;
			// scheduling another restart would loop before the receipt can commit.
			if current == plan.Spec.Version {
				return nil
			}
			return l.selfDeployLocked(ctx, plan.Spec.Version)
		}
		return l.applyComponentTransitionLocked(ctx, plan.Spec)
	})
}

func (l *Lifecycle) restoreDrainMode(draining bool) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	if draining {
		l.state = NodeStateDraining
		return
	}
	l.state = NodeStateServing
}

func (l *Lifecycle) applyComponentTransitionLocked(ctx context.Context, deployed hostmanifest.ComponentSpec) error {
	rendered, err := RenderSystemdUnit(l.installRoot, deployed)
	if err != nil {
		return err
	}
	if err := ValidateSystemdUnit(l.installRoot, deployed, rendered); err != nil {
		return err
	}
	component := deployed.Name
	version := deployed.Version
	links, err := captureSymlinkState(l.installRoot, component)
	if err != nil {
		return err
	}
	unit, unitPresent, err := readUnitState(l.unitDir, component)
	if err != nil {
		return err
	}
	staged, err := stageUnitFile(l.unitDir, UnitName(component), []byte(rendered))
	if err != nil {
		return err
	}
	rollback := func(cause error) error {
		_ = os.Remove(staged)
		recoveryContext, cancel := context.WithTimeout(context.Background(), hostAgentTransitionRecoveryTimeout)
		defer cancel()
		recoveryErr := errors.Join(
			restoreSymlinkState(l.installRoot, component, links),
			restoreUnitState(l.unitDir, component, unit, unitPresent),
		)
		if reloadErr := l.systemd.DaemonReload(recoveryContext); reloadErr != nil {
			recoveryErr = errors.Join(recoveryErr, reloadErr)
		}
		if recoveryErr == nil && links.hasCurrent {
			expectedSha256 := ""
			if desired, known := l.specLocked(component); known && desired.Version == links.current {
				expectedSha256 = desired.Sha256
			}
			installed, complete, verifyErr := l.installer.inspectInstalledRelease(
				VersionDir(l.installRoot, component, links.current), component, expectedSha256)
			if verifyErr != nil || !installed || !complete {
				if verifyErr == nil {
					verifyErr = &InvalidOperationError{Message: fmt.Sprintf(
						"The restored component %s version %s is not fully authenticated.", component, links.current)}
				}
				recoveryErr = errors.Join(recoveryErr, verifyErr)
			} else if restartErr := l.systemd.RestartUnit(recoveryContext, UnitName(component)); restartErr != nil {
				recoveryErr = errors.Join(recoveryErr, restartErr)
			}
		}
		return errors.Join(cause, recoveryErr)
	}
	if err := FlipCurrent(l.installRoot, component, version); err != nil {
		return rollback(err)
	}
	if err := commitUnitFile(staged, filepath.Join(l.unitDir, UnitName(component))); err != nil {
		return rollback(err)
	}
	if err := l.systemd.DaemonReload(ctx); err != nil {
		return rollback(err)
	}
	if err := l.systemd.RestartUnit(ctx, UnitName(component)); err != nil {
		return rollback(err)
	}
	return nil
}

// selfDeployLocked flips the agent's own current symlink and schedules a
// detached restart of its cloud-init unit: the restart would kill this
// process mid-call, so it runs in its own process group and is never
// waited on. The new binary boots, reconciles from the manifest, and the
// orchestrator's health gate watches the heartbeat return.
func (l *Lifecycle) selfDeployLocked(ctx context.Context, version string) error {
	links, err := captureSymlinkState(l.installRoot, hostmanifest.TsNodeComponentName)
	if err != nil {
		return err
	}
	if err := FlipCurrent(l.installRoot, hostmanifest.TsNodeComponentName, version); err != nil {
		return err
	}
	command := detachedCommand(context.Background(), l.systemctlBinary, "restart", tsnodebootstrap.UnitName)
	if err := command.Start(); err != nil {
		return errors.Join(fmt.Errorf("the ts-node self-restart could not be scheduled: %w", err), restoreSymlinkState(l.installRoot, hostmanifest.TsNodeComponentName, links))
	}
	go func() { _ = command.Wait() }()
	return nil
}

// Rollback performs the emergency version switch of one component: the
// current symlink back to previous plus the unit restart. Unlike a deploy
// it needs no drain — it is the action an orchestrator takes when a deploy
// failed its health gate and every second of writes through the bad version
// is harm.
func (l *Lifecycle) Rollback(ctx context.Context, component string) error {
	if _, err := hostmanifest.RequireName(component, "component",
		"The component must be a canonical token."); err != nil {
		return err
	}
	l.mutex.Lock()
	defer l.mutex.Unlock()
	plan, err := l.prepareRollbackLocked(component)
	if err != nil {
		return err
	}
	return l.applyTransitionLocked(ctx, plan)
}

func (l *Lifecycle) prepareRollbackLocked(component string) (transitionPlan, error) {
	if _, err := hostmanifest.RequireName(component, "component",
		"The component must be a canonical token."); err != nil {
		return transitionPlan{}, err
	}
	spec, known := l.specLocked(component)
	if !known {
		return transitionPlan{}, &InvalidOperationError{Message: fmt.Sprintf(
			"Component %s is not in the desired manifest.", component)}
	}
	previous, err := PreviousVersion(l.installRoot, component)
	if err != nil {
		return transitionPlan{}, err
	}
	if previous == "" {
		return transitionPlan{}, &InvalidOperationError{Message: fmt.Sprintf(
			"Component %s has no previous version to roll back to.", component)}
	}
	spec.Version = previous
	spec, err = installedLaunchForSpec(l.installRoot, spec)
	if err != nil {
		return transitionPlan{}, err
	}
	return transitionPlan{Spec: spec}, nil
}

// writeUnitLocked renders the D-69 unit file of one spec and writes it when
// the on-disk content differs, followed by one daemon-reload.
func (l *Lifecycle) writeUnitLocked(ctx context.Context, spec hostmanifest.ComponentSpec) error {
	rendered, err := RenderSystemdUnit(l.installRoot, spec)
	if err != nil {
		return err
	}
	if err := ValidateSystemdUnit(l.installRoot, spec, rendered); err != nil {
		return err
	}
	path := filepath.Join(l.unitDir, UnitName(spec.Name))
	existing, present, readErr := readUnitState(l.unitDir, spec.Name)
	if readErr != nil {
		return readErr
	}
	if present && string(existing) == rendered {
		return nil
	}
	staged, err := stageUnitFile(l.unitDir, UnitName(spec.Name), []byte(rendered))
	if err != nil {
		return err
	}
	if err := commitUnitFile(staged, path); err != nil {
		return err
	}
	if err := l.systemd.DaemonReload(ctx); err != nil {
		return errors.Join(err, restoreUnitState(l.unitDir, spec.Name, existing, present), l.systemd.DaemonReload(ctx))
	}
	return nil
}

func stageUnitFile(dir, unit string, contents []byte) (string, error) {
	if len(contents) == 0 || len(contents) > hostAgentMaximumUnitBytes {
		return "", &InvalidDataError{Message: "The systemd unit exceeds its size bound."}
	}
	if err := ensureDirectory(dir, 0o755); err != nil {
		return "", err
	}
	directory, err := os.Lstat(dir)
	if err != nil {
		return "", err
	}
	if err := requireOwnedDirectory(directory, "systemd unit directory"); err != nil {
		return "", err
	}
	if err := removeAbandonedUnitStages(dir, unit); err != nil {
		return "", err
	}
	file, err := os.CreateTemp(dir, "."+unit+".staging-")
	if err != nil {
		return "", err
	}
	path := file.Name()
	cleanup := func(cause error) (string, error) { _ = file.Close(); _ = os.Remove(path); return "", cause }
	if err := file.Chmod(0o644); err != nil {
		return cleanup(err)
	}
	if _, err := file.Write(contents); err != nil {
		return cleanup(err)
	}
	if err := file.Sync(); err != nil {
		return cleanup(err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	return path, nil
}

func removeAbandonedUnitStages(dir, unit string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	prefix := "." + unit + ".staging-"
	removed := false
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if err := requireOwnedRegular(info, false, "abandoned unit stage"); err != nil {
			return err
		}
		if err := os.Remove(path); err != nil {
			return err
		}
		removed = true
	}
	if removed {
		return syncDir(dir)
	}
	return nil
}

func commitUnitFile(staged, destination string) error {
	if err := os.Rename(staged, destination); err != nil {
		_ = os.Remove(staged)
		return err
	}
	return syncDir(filepath.Dir(destination))
}

func readUnitState(dir, component string) ([]byte, bool, error) {
	path := filepath.Join(dir, UnitName(component))
	data, info, err := readRegularFileBoundedInfo(path, hostAgentMaximumUnitBytes)
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if err := requireOwnedRegular(info, false, "systemd unit"); err != nil {
		return nil, false, err
	}
	if info.Mode().Perm() != 0o644 {
		return nil, false, &InvalidDataError{Message: "The systemd unit must have mode 0644."}
	}
	return data, true, nil
}

func restoreUnitState(dir, component string, data []byte, present bool) error {
	path := filepath.Join(dir, UnitName(component))
	if !present {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return syncDir(dir)
	}
	staged, err := stageUnitFile(dir, UnitName(component), data)
	if err != nil {
		return err
	}
	return commitUnitFile(staged, path)
}

// specLocked returns the desired spec of one component.
func (l *Lifecycle) specLocked(component string) (hostmanifest.ComponentSpec, bool) {
	for _, spec := range l.desired {
		if spec.Name == component {
			return spec, true
		}
	}
	return hostmanifest.ComponentSpec{}, false
}

// quiescedLocked is Quiesced without relocking. A retired-but-unretired
// stale component is still draining, exactly as the drain-status observation
// reports it; the deploy gate must enforce the same predicate.
func (l *Lifecycle) quiescedLocked(ctx context.Context) bool {
	if l.state != NodeStateDraining {
		return false
	}
	for _, spec := range l.desired {
		if spec.Name == hostmanifest.TsNodeComponentName {
			continue
		}
		if active, err := l.systemd.UnitActive(ctx, UnitName(spec.Name)); err != nil || active {
			return false
		}
	}
	for _, component := range l.stale {
		if component == hostmanifest.TsNodeComponentName {
			continue
		}
		retired, err := l.retirementRecorded(component)
		if err != nil {
			return false
		}
		if retired {
			continue
		}
		if active, err := l.systemd.UnitActive(ctx, UnitName(component)); err != nil || active {
			return false
		}
	}
	return true
}
