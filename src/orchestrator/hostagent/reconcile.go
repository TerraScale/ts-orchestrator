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
	if config.ManifestPath == "" || config.ManifestPath[0] != '/' {
		return nil, &InvalidOperationError{Message: "The manifest path must be an absolute path."}
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
	data, err := os.ReadFile(w.manifestPath)
	if err != nil {
		return fmt.Errorf("the manifest could not be read: %w", err)
	}
	manifest, err := ParseHostManifest(data)
	if err != nil {
		return err
	}
	return w.lifecycle.ApplyDesired(ctx, manifest.Components)
}

// ApplyDesired converges the host on one desired component set: install,
// provision, unit-file, enable, start, and retire. Per-component failures
// are joined and reported; every other component still converges.
func (l *Lifecycle) ApplyDesired(ctx context.Context, desired []ComponentSpec) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	var failures []error
	desiredNames := make(map[string]struct{}, len(desired))
	for _, spec := range desired {
		validated, err := NewComponentSpec(spec)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		desiredNames[validated.Name] = struct{}{}
		if err := l.ensureComponentLocked(ctx, validated); err != nil {
			failures = append(failures, fmt.Errorf(
				"component %s did not converge: %w", validated.Name, err))
		}
	}
	retained := append([]ComponentSpec(nil), desired...)
	for _, spec := range l.desired {
		if _, present := desiredNames[spec.Name]; present {
			continue
		}
		if err := l.retireComponentLocked(ctx, spec); err != nil {
			failures = append(failures, fmt.Errorf(
				"component %s did not retire: %w", spec.Name, err))
			// Keep a failed retirement in desired state. The next manifest
			// tick must retry the stop/disable/delete sequence; dropping it
			// here would make the host forget that the old unit still exists.
			retained = append(retained, spec)
		}
	}
	l.desired = retained
	return errors.Join(failures...)
}

// ensureComponentLocked converges one component: install the desired
// version when missing, provision the dedicated user and data volume, keep
// the unit file rendered, enable the unit, and start it while serving. The
// ts-node self-component installs but never writes a unit or account — its
// unit is cloud-init's, exactly one, and the flip is a deploy.
func (l *Lifecycle) ensureComponentLocked(ctx context.Context, spec ComponentSpec) error {
	if !InstalledVersion(l.installRoot, spec.Name, spec.Version) {
		if _, err := l.installer.Install(spec); err != nil {
			return err
		}
	}
	if spec.Name != TsNodeComponentName {
		if err := l.users.EnsureUser(ctx, spec.User); err != nil {
			return err
		}
		if !l.enabledUnits[UnitName(spec.Name)] {
			if err := l.systemd.EnableUnit(ctx, UnitName(spec.Name)); err != nil {
				return err
			}
			l.enabledUnits[UnitName(spec.Name)] = true
		}
		if err := os.MkdirAll(spec.DataVolume, 0o750); err != nil {
			return err
		}
		if err := l.users.OwnDirectory(ctx, spec.User, spec.DataVolume); err != nil {
			return err
		}
		if err := l.writeUnitLocked(ctx, spec); err != nil {
			return err
		}
		if l.state == NodeStateServing {
			active, err := l.systemd.UnitActive(ctx, UnitName(spec.Name))
			if err == nil && !active {
				return l.systemd.StartUnit(ctx, UnitName(spec.Name))
			}
			return nil
		}
	}
	return nil
}

// retireComponentLocked removes one component that left the manifest: stop
// and disable the unit, delete the unit file and the installed versions.
// The data volume is deliberately kept — deleting a database's files is a
// human decision (D-70 crypto-shred), never a reconcile side effect.
func (l *Lifecycle) retireComponentLocked(ctx context.Context, spec ComponentSpec) error {
	if spec.Name == TsNodeComponentName {
		return &InvalidOperationError{Message: "ts-node cannot retire itself."}
	}
	unit := UnitName(spec.Name)
	var failures []error
	if err := l.systemd.StopUnit(ctx, unit); err != nil {
		failures = append(failures, fmt.Errorf("stop %s: %w", unit, err))
	}
	if l.enabledUnits[unit] {
		if err := l.systemd.DisableUnit(ctx, unit); err != nil {
			failures = append(failures, fmt.Errorf("disable %s: %w", unit, err))
		} else {
			delete(l.enabledUnits, unit)
		}
	}
	if err := os.Remove(filepath.Join(l.unitDir, unit)); err != nil && !os.IsNotExist(err) {
		failures = append(failures, err)
	}
	if err := l.systemd.DaemonReload(ctx); err != nil {
		failures = append(failures, err)
	}
	if err := os.RemoveAll(strings.TrimSuffix(InstallDir(l.installRoot, spec.Name), "/")); err != nil {
		failures = append(failures, err)
	}
	return errors.Join(failures...)
}
