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
	"sync"
)

// LifecycleConfig is the fully explicit lifecycle configuration.
type LifecycleConfig struct {
	// InstallRoot is /opt/terrascale on production hosts.
	InstallRoot string
	// UnitDir is the systemd unit directory unit files are written to.
	UnitDir string
	// Installer lands verified release artifacts.
	Installer *Installer
	// Systemd drives units.
	Systemd SystemdController
	// Users provisions the dedicated component accounts.
	Users UserProvisioner
}

// Lifecycle owns the drain state machine and every host mutation of the
// agent. All operations serialize under one mutex: a host is mutated by one
// goroutine at a time by construction.
type Lifecycle struct {
	installRoot string
	unitDir     string
	installer   *Installer
	systemd     SystemdController
	users       UserProvisioner

	mutex        sync.Mutex
	state        string
	desired      []ComponentSpec
	enabledUnits map[string]bool
}

// NewLifecycle validates the configuration and composes the lifecycle in
// the serving state with an empty desired manifest.
func NewLifecycle(config LifecycleConfig) (*Lifecycle, error) {
	if !safeAbsolutePath(config.InstallRoot) {
		return nil, &InvalidOperationError{Message: "The install root must be an absolute path."}
	}
	if !safeAbsolutePath(config.UnitDir) {
		return nil, &InvalidOperationError{Message: "The unit directory must be an absolute path."}
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
	return &Lifecycle{
		installRoot:  config.InstallRoot,
		unitDir:      config.UnitDir,
		installer:    config.Installer,
		systemd:      config.Systemd,
		users:        config.Users,
		state:        NodeStateServing,
		enabledUnits: map[string]bool{},
	}, nil
}

// State reports the current lifecycle state.
func (l *Lifecycle) State() string {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	return l.state
}

// Desired returns the current desired manifest snapshot.
func (l *Lifecycle) Desired() []ComponentSpec {
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
		if spec.Name == TsNodeComponentName {
			continue
		}
		if err := l.systemd.StopUnit(ctx, UnitName(spec.Name)); err != nil {
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
		if spec.Name == TsNodeComponentName {
			continue
		}
		active, err := l.systemd.UnitActive(ctx, UnitName(spec.Name))
		if err != nil {
			return err
		}
		if active {
			continue
		}
		if err := l.systemd.StartUnit(ctx, UnitName(spec.Name)); err != nil {
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
	if l.state != NodeStateDraining {
		return false
	}
	for _, spec := range l.desired {
		if spec.Name == TsNodeComponentName {
			continue
		}
		if active, err := l.systemd.UnitActive(ctx, UnitName(spec.Name)); err != nil || active {
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
	if _, err := requireHostAgentName(component, "component",
		"The component must be a canonical token."); err != nil {
		return err
	}
	l.mutex.Lock()
	defer l.mutex.Unlock()
	spec, known := l.specLocked(component)
	if !known {
		return &InvalidOperationError{Message: fmt.Sprintf(
			"Component %s is not in the desired manifest.", component)}
	}
	if l.state != NodeStateDraining || !l.quiescedLocked(ctx) {
		return &InvalidOperationError{Message: fmt.Sprintf(
			"Component %s deploy refused: drain the node first.", component)}
	}
	if !InstalledVersion(l.installRoot, component, version) {
		return &InvalidOperationError{Message: fmt.Sprintf(
			"Component %s version %s is not installed.", component, version)}
	}
	if component == TsNodeComponentName {
		return l.selfDeployLocked(ctx, version)
	}
	deployed := spec
	deployed.Version = version
	rendered, err := RenderSystemdUnit(l.installRoot, deployed)
	if err != nil {
		return err
	}
	if err := ValidateSystemdUnit(l.installRoot, deployed, rendered); err != nil {
		return err
	}
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
		return errors.Join(cause, restoreSymlinkState(l.installRoot, component, links), restoreUnitState(l.unitDir, component, unit, unitPresent), l.systemd.DaemonReload(ctx))
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
	links, err := captureSymlinkState(l.installRoot, TsNodeComponentName)
	if err != nil {
		return err
	}
	if err := FlipCurrent(l.installRoot, TsNodeComponentName, version); err != nil {
		return err
	}
	command := detachedCommand(context.Background(), "systemctl", "restart", UnitName(TsNodeComponentName))
	if err := command.Start(); err != nil {
		return errors.Join(fmt.Errorf("the ts-node self-restart could not be scheduled: %w", err), restoreSymlinkState(l.installRoot, TsNodeComponentName, links))
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
	if _, err := requireHostAgentName(component, "component",
		"The component must be a canonical token."); err != nil {
		return err
	}
	l.mutex.Lock()
	defer l.mutex.Unlock()
	if _, known := l.specLocked(component); !known {
		return &InvalidOperationError{Message: fmt.Sprintf(
			"Component %s is not in the desired manifest.", component)}
	}
	if component == TsNodeComponentName {
		previous, err := PreviousVersion(l.installRoot, component)
		if err != nil {
			return err
		}
		return l.selfDeployLocked(ctx, previous)
	}
	links, err := captureSymlinkState(l.installRoot, component)
	if err != nil {
		return err
	}
	unit, unitPresent, err := readUnitState(l.unitDir, component)
	if err != nil {
		return err
	}
	previous, err := PreviousVersion(l.installRoot, component)
	if err != nil {
		return err
	}
	if previous == "" {
		return &InvalidOperationError{Message: fmt.Sprintf("Component %s has no previous version to roll back to.", component)}
	}
	spec, _ := l.specLocked(component)
	spec.Version = previous
	rendered, err := RenderSystemdUnit(l.installRoot, spec)
	if err != nil {
		return err
	}
	if err := ValidateSystemdUnit(l.installRoot, spec, rendered); err != nil {
		return err
	}
	staged, err := stageUnitFile(l.unitDir, UnitName(component), []byte(rendered))
	if err != nil {
		return err
	}
	rollback := func(cause error) error {
		_ = os.Remove(staged)
		return errors.Join(cause, restoreSymlinkState(l.installRoot, component, links), restoreUnitState(l.unitDir, component, unit, unitPresent), l.systemd.DaemonReload(ctx))
	}
	if err := RollbackCurrent(l.installRoot, component); err != nil {
		_ = os.Remove(staged)
		return err
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

// writeUnitLocked renders the D-69 unit file of one spec and writes it when
// the on-disk content differs, followed by one daemon-reload.
func (l *Lifecycle) writeUnitLocked(ctx context.Context, spec ComponentSpec) error {
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
	if err := ensureDirectory(dir, 0o755); err != nil {
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

func commitUnitFile(staged, destination string) error {
	if err := os.Rename(staged, destination); err != nil {
		_ = os.Remove(staged)
		return err
	}
	return syncDir(filepath.Dir(destination))
}

func readUnitState(dir, component string) ([]byte, bool, error) {
	path := filepath.Join(dir, UnitName(component))
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, false, &InvalidOperationError{Message: "The systemd unit path must be a regular file."}
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
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
func (l *Lifecycle) specLocked(component string) (ComponentSpec, bool) {
	for _, spec := range l.desired {
		if spec.Name == component {
			return spec, true
		}
	}
	return ComponentSpec{}, false
}

// quiescedLocked is Quiesced without relocking.
func (l *Lifecycle) quiescedLocked(ctx context.Context) bool {
	if l.state != NodeStateDraining {
		return false
	}
	for _, spec := range l.desired {
		if spec.Name == TsNodeComponentName {
			continue
		}
		if active, err := l.systemd.UnitActive(ctx, UnitName(spec.Name)); err != nil || active {
			return false
		}
	}
	return true
}
