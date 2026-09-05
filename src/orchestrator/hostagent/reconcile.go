// This file implements the manifest reconciliation of the D-69 host agent:
// ts-node watches its local manifest file, installs the desired release of
// every component, provisions the dedicated user, keeps the rendered unit
// file current, enables and (while serving) starts the units, and retires
// components that left the manifest. Installs never flip the current
// symlink: the flip is the orchestrator-coordinated deploy of lifecycle.go.
package hostagent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// ManifestWatcherConfig is the fully explicit watcher configuration.
type ManifestWatcherConfig struct {
	// ManifestPath is the local manifest file watched for desired state.
	ManifestPath string
	// Interval is the poll period of the watch.
	Interval time.Duration
	// Lifecycle applies the desired state to the host.
	Lifecycle *Lifecycle
}

// ManifestWatcher polls the manifest file and reconciles the host toward it.
// Polling, not inotify: a 30-second cadence is the contract the delivery
// lane plans around and a poll survives manifest writes by any writer.
type ManifestWatcher struct {
	manifestPath string
	interval     time.Duration
	lifecycle    *Lifecycle
}

// NewManifestWatcher validates the configuration and composes the watcher.
func NewManifestWatcher(config ManifestWatcherConfig) (*ManifestWatcher, error) {
	if !safeAbsolutePath(config.ManifestPath) {
		return nil, &InvalidOperationError{Message: "The manifest path must be an absolute safe path."}
	}
	if config.Interval <= 0 {
		return nil, &InvalidOperationError{Message: "The watch interval must be positive."}
	}
	if config.Lifecycle == nil {
		return nil, &InvalidOperationError{Message: "A lifecycle is required."}
	}
	return &ManifestWatcher{
		manifestPath: config.ManifestPath,
		interval:     config.Interval,
		lifecycle:    config.Lifecycle,
	}, nil
}

// Run reconciles once immediately and then on every tick until the context
// is cancelled. One failed pass never stops the watch: the next tick
// retries, and the heartbeat keeps reporting the gap between desired and
// current.
func (w *ManifestWatcher) Run(ctx context.Context) {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	w.ReconcileOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.ReconcileOnce(ctx)
		}
	}
}

// ReconcileOnce reads the manifest and applies it. A missing or invalid
// manifest changes nothing: the last valid desired state stays applied, so a
// truncated write can never retire a serving component.
func (w *ManifestWatcher) ReconcileOnce(ctx context.Context) error {
	manifest, err := w.readManifest()
	if err != nil {
		return err
	}
	return w.lifecycle.ApplyDesired(ctx, manifest.Components)
}

// HydrateOnce loads validated desired state without installing, starting, or
// retiring anything. HostAgent uses it before journal recovery so commands
// are available even when the first convergence pass later fails.
func (w *ManifestWatcher) HydrateOnce() error {
	manifest, err := w.readManifest()
	if err != nil {
		return err
	}
	return w.lifecycle.HydrateDesired(manifest.Components)
}

func (w *ManifestWatcher) readManifest() (HostManifest, error) {
	data, err := readRegularFileBounded(w.manifestPath, hostAgentMaximumManifestBytes)
	if err != nil {
		return HostManifest{}, fmt.Errorf("the manifest could not be read: %w", err)
	}
	manifest, err := ParseHostManifest(data)
	if err != nil {
		return HostManifest{}, err
	}
	return manifest, nil
}

// HydrateDesired records a validated manifest and discovers older managed
// units without performing host mutations.
func (l *Lifecycle) HydrateDesired(desired []ComponentSpec) error {
	validated, err := l.validateDesiredSet(desired)
	if err != nil {
		return err
	}
	discovered, err := l.discoverManagedComponents()
	if err != nil {
		return err
	}
	wanted := make(map[string]struct{}, len(validated))
	for _, spec := range validated {
		wanted[spec.Name] = struct{}{}
	}
	stale := make([]string, 0, len(discovered))
	for _, component := range discovered {
		if _, present := wanted[component]; !present {
			stale = append(stale, component)
		}
	}
	l.mutex.Lock()
	l.desired = validated
	l.stale = stale
	l.mutex.Unlock()
	return nil
}

// ApplyDesired converges the host on one desired component set: install,
// provision, unit-file, enable, start, and retire. Per-component failures
// are joined and reported; every other component still converges.
func (l *Lifecycle) ApplyDesired(ctx context.Context, desired []ComponentSpec) error {
	validated, err := l.validateDesiredSet(desired)
	if err != nil {
		return err
	}
	discovered, err := l.discoverManagedComponents()
	if err != nil {
		return err
	}
	l.mutex.Lock()
	defer l.mutex.Unlock()
	var failures []error
	desiredNames := make(map[string]struct{}, len(validated))
	for _, spec := range validated {
		desiredNames[spec.Name] = struct{}{}
		if err := l.ensureComponentLocked(ctx, spec); err != nil {
			failures = append(failures, fmt.Errorf(
				"component %s did not converge: %w", spec.Name, err))
		}
	}
	retire := make(map[string]struct{}, len(l.desired)+len(l.stale)+len(discovered))
	for _, spec := range l.desired {
		if _, present := desiredNames[spec.Name]; present {
			continue
		}
		retire[spec.Name] = struct{}{}
	}
	for _, component := range l.stale {
		if _, present := desiredNames[component]; !present {
			retire[component] = struct{}{}
		}
	}
	for _, component := range discovered {
		if _, present := desiredNames[component]; !present {
			retire[component] = struct{}{}
		}
	}
	retainedStale := make([]string, 0, len(retire))
	for component := range retire {
		if err := l.retireComponentLocked(ctx, component); err != nil {
			failures = append(failures, fmt.Errorf(
				"component %s did not retire: %w", component, err))
			// Keep a failed retirement separate from desired state. The next manifest
			// tick must retry the stop/disable/delete sequence; dropping it
			// here would make the host forget that the old unit still exists.
			retainedStale = append(retainedStale, component)
		}
	}
	l.desired = append([]ComponentSpec(nil), validated...)
	l.stale = retainedStale
	return errors.Join(failures...)
}

func (l *Lifecycle) validateDesiredSet(desired []ComponentSpec) ([]ComponentSpec, error) {
	validated, err := validateComponentSet(desired)
	if err != nil {
		return nil, err
	}
	stateRoot := filepath.Join(l.dataRoot, TsNodeComponentName)
	for _, spec := range validated {
		if _, err := validateDirectoryWithin(l.dataRoot, spec.DataVolume); err != nil {
			return nil, err
		}
		if spec.Name != TsNodeComponentName && pathsOverlap(spec.DataVolume, stateRoot) {
			return nil, &InvalidOperationError{Message: "Component data volumes must not overlap the root-owned ts-node state directory."}
		}
	}
	return validated, nil
}

func (l *Lifecycle) discoverManagedComponents() ([]string, error) {
	entries, err := os.ReadDir(l.unitDir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var managed []string
	for _, entry := range entries {
		name := entry.Name()
		retiring := strings.HasSuffix(name, ".service.retiring")
		if retiring {
			name = strings.TrimSuffix(name, ".retiring")
		}
		if !strings.HasPrefix(name, "terrascale-") || !strings.HasSuffix(name, ".service") {
			continue
		}
		component := strings.TrimSuffix(strings.TrimPrefix(name, "terrascale-"), ".service")
		if component == TsNodeComponentName {
			continue
		}
		if _, err := requireHostAgentName(component, "component", "The discovered component name is invalid."); err != nil {
			continue
		}
		unit, present, err := readUnitState(l.unitDir, component)
		if retiring {
			var info os.FileInfo
			unit, info, err = readRegularFileBoundedInfo(filepath.Join(l.unitDir, entry.Name()), hostAgentMaximumUnitBytes)
			if err == nil {
				err = requireOwnedRegular(info, false, "retirement marker")
			}
			present = err == nil
		}
		if err != nil {
			return nil, err
		}
		if !present || !managedExecStart(string(unit), ExecStartPath(l.installRoot, component)) {
			continue
		}
		componentDir := strings.TrimSuffix(InstallDir(l.installRoot, component), "/")
		info, err := os.Lstat(componentDir)
		if retiring && os.IsNotExist(err) {
			managed = append(managed, component)
			continue
		}
		if err != nil {
			return nil, err
		}
		if err := requireOwnedDirectory(info, "discovered component install directory"); err != nil {
			return nil, err
		}
		if err := requireSameMount(l.installRoot, componentDir); err != nil {
			return nil, err
		}
		managed = append(managed, component)
	}
	slices.Sort(managed)
	return managed, nil
}

// ensureComponentLocked converges one component: install the desired
// version when missing, provision the dedicated user and data volume, keep
// the unit file rendered, enable the unit, and start it while serving. The
// ts-node self-component installs but never writes a unit or account — its
// unit is the shared bootstrap unit, exactly one, and the flip is a deploy.
func (l *Lifecycle) ensureComponentLocked(ctx context.Context, spec ComponentSpec) error {
	if _, err := validateDirectoryWithin(l.dataRoot, spec.DataVolume); err != nil {
		return err
	}
	// Install is itself a cheap verified no-op when the immutable version
	// slot already contains the exact requested digest. Do not decide from
	// mere path presence here: a corrupt or substituted slot must fail closed.
	if _, err := l.installer.InstallContext(ctx, spec); err != nil {
		return err
	}
	if spec.Name != TsNodeComponentName {
		if err := l.users.EnsureUser(ctx, spec.User); err != nil {
			return err
		}
		if err := ensureDirectoryWithin(l.dataRoot, spec.DataVolume, 0o750); err != nil {
			return err
		}
		if err := l.users.OwnDirectory(ctx, spec.User, spec.DataVolume); err != nil {
			return err
		}
		unitSpec := spec
		current, err := CurrentVersion(l.installRoot, spec.Name)
		if err != nil {
			return err
		}
		if current != "" {
			unitSpec.Version = current
		}
		unitSpec, err = installedLaunchForSpec(l.installRoot, unitSpec)
		if err != nil {
			return err
		}
		unitSpec.Version = spec.Version
		if err := l.writeUnitLocked(ctx, unitSpec); err != nil {
			return err
		}
		if err := os.Remove(filepath.Join(l.unitDir, UnitName(spec.Name)+".retiring")); err == nil {
			if err := syncDir(l.unitDir); err != nil {
				return err
			}
		} else if !os.IsNotExist(err) {
			return err
		}
		// systemctl enable resolves the unit name, so the unit must already be
		// durably committed and daemon-reloaded before it is enabled.
		if !l.enabledUnits[UnitName(spec.Name)] {
			if err := l.systemd.EnableUnit(ctx, UnitName(spec.Name)); err != nil {
				return err
			}
			l.enabledUnits[UnitName(spec.Name)] = true
		}
		if l.state == NodeStateServing {
			active, err := l.systemd.UnitActive(ctx, UnitName(spec.Name))
			if err != nil {
				return err
			}
			if !active {
				return l.installer.withVerifiedCurrentTransition(ctx, spec, func(string) error {
					return l.systemd.StartUnit(ctx, UnitName(spec.Name))
				})
			}
		}
	}
	return nil
}

// retirementRecorded proves stop and disable completed before the owned unit
// was renamed. This also lets drain recovery handle a unit systemd forgot.
func (l *Lifecycle) retirementRecorded(component string) (bool, error) {
	unitPath := filepath.Join(l.unitDir, UnitName(component))
	markerPath := unitPath + ".retiring"
	_, unitErr := os.Lstat(unitPath)
	if unitErr != nil && !os.IsNotExist(unitErr) {
		return false, unitErr
	}
	retirementRecorded := false
	if os.IsNotExist(unitErr) {
		_, info, markerErr := readRegularFileBoundedInfo(markerPath, hostAgentMaximumUnitBytes)
		if markerErr == nil {
			if err := requireOwnedRegular(info, false, "retirement marker"); err != nil {
				return false, err
			}
			retirementRecorded = true
		} else if !os.IsNotExist(markerErr) {
			return false, markerErr
		}
	}
	return retirementRecorded, nil
}

// retireComponentLocked removes one component that left the manifest: stop
// and disable the unit, delete the unit file and the installed versions.
// The data volume is deliberately kept — deleting a database's files is a
// human decision (D-70 crypto-shred), never a reconcile side effect.
func (l *Lifecycle) retireComponentLocked(ctx context.Context, component string) error {
	if component == TsNodeComponentName {
		return &InvalidOperationError{Message: "ts-node cannot retire itself."}
	}
	unit := UnitName(component)
	unitPath := filepath.Join(l.unitDir, unit)
	markerPath := unitPath + ".retiring"
	retirementRecorded, err := l.retirementRecorded(component)
	if err != nil {
		return err
	}
	if !retirementRecorded {
		if err := l.systemd.StopUnit(ctx, unit); err != nil {
			// A failed stop means the immutable version may still be serving. Do
			// not remove its unit or executable and let the next reconcile retry.
			return fmt.Errorf("stop %s: %w", unit, err)
		}
	}
	componentDir := strings.TrimSuffix(InstallDir(l.installRoot, component), "/")
	componentInfo, err := os.Lstat(componentDir)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil {
		if err := requireOwnedDirectory(componentInfo, "retired component install directory"); err != nil {
			return err
		}
		if err := requireSameMount(l.installRoot, componentDir); err != nil {
			return err
		}
		lock, err := lockInstallDirectory(ctx, componentDir)
		if err != nil {
			return err
		}
		defer unlockInstallDirectory(lock)
	}
	if !retirementRecorded {
		if err := l.systemd.DisableUnit(ctx, unit); err != nil {
			return fmt.Errorf("disable %s: %w", unit, err)
		}
	}
	delete(l.enabledUnits, unit)
	// Preserve the owned unit as a durable retirement marker until its
	// executable removal is synced. A restart can resume even after systemd
	// has forgotten the unit or the component directory has been removed.
	if err := os.Rename(unitPath, markerPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := syncDir(l.unitDir); err != nil {
		return err
	}
	if err := l.systemd.DaemonReload(ctx); err != nil {
		return err
	}
	if err := os.RemoveAll(componentDir); err != nil {
		return err
	}
	if err := syncDir(l.installRoot); err != nil {
		return err
	}
	if err := os.Remove(markerPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return syncDir(l.unitDir)
}

// Match only an exact executable token, never a path prefix or another directive.
func managedExecStart(unit, executable string) bool {
	for _, line := range strings.Split(unit, "\n") {
		if line == "ExecStart="+executable || strings.HasPrefix(line, "ExecStart="+executable+" ") {
			return true
		}
	}
	return false
}
