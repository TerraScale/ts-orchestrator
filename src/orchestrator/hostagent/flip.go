// This file implements the D-69 version flip: the current symlink of a
// component points at its serving version directory, a flip moves it to the
// new version through an atomic rename, and the previous symlink always
// records the version the last flip replaced so rollback is the symlink
// back. The running binary keeps its inode under the old directory, so a
// flip never disturbs a live process; only the restart switches versions.
package hostagent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
)

var flipMutex sync.Mutex

// CurrentVersion resolves the component's current symlink to its version
// token; the empty string means nothing is current yet.
func CurrentVersion(installRoot, component string) (string, error) {
	if err := validateInstallLocation(installRoot, component); err != nil {
		return "", err
	}
	link := InstallDir(installRoot, component) + "/current"
	target, err := os.Readlink(link)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return validatedLinkTarget(target, componentDir(link), component)
}

// PreviousVersion resolves the component's previous symlink to its version
// token; the empty string means no rollback target exists.
func PreviousVersion(installRoot, component string) (string, error) {
	if err := validateInstallLocation(installRoot, component); err != nil {
		return "", err
	}
	link := InstallDir(installRoot, component) + "/previous"
	target, err := os.Readlink(link)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return validatedLinkTarget(target, componentDir(link), component)
}

// FlipCurrent atomically repoints the current symlink of one component at an
// installed version directory, recording the displaced version in the
// previous symlink. The replacement is one rename(2) over a staged symlink,
// so readers see either the old or the new target, never a missing link.
func FlipCurrent(installRoot, component, version string) error {
	flipMutex.Lock()
	defer flipMutex.Unlock()
	if err := validateInstallLocation(installRoot, component); err != nil {
		return err
	}
	if _, err := hostmanifest.RequireName(version, "version",
		"The version must be a canonical token."); err != nil {
		return err
	}
	if !InstalledVersion(installRoot, component, version) {
		return &InvalidOperationError{Message: fmt.Sprintf(
			"Component %s version %s is not installed; refusing to flip.", component, version)}
	}
	before, err := captureSymlinkState(installRoot, component)
	if err != nil {
		return err
	}
	return flipCurrentUnlocked(installRoot, component, version, before)
}

func flipCurrentUnlocked(installRoot, component, version string, before symlinkState) error {
	componentDir := InstallDir(installRoot, component)
	previous, err := CurrentVersion(installRoot, component)
	if err != nil {
		return err
	}
	if previous != "" && previous != version {
		if err := stageSymlink(componentDir, "previous", previous); err != nil {
			return err
		}
	} else if previous == version {
		// Flipping to the already-current version is a no-op that keeps the
		// previous target intact.
		return nil
	}
	if err := stageSymlink(componentDir, "current", version); err != nil {
		return errors.Join(err, restoreSymlinkStateUnlocked(installRoot, component, before))
	}
	return nil
}

// RollbackCurrent repoints current at the previous symlink's target and
// swaps previous to what current named, so a rollback of a rollback returns
// to the rolled-forward version. It fails closed when no previous target
// exists.
func RollbackCurrent(installRoot, component string) error {
	flipMutex.Lock()
	defer flipMutex.Unlock()
	if err := validateInstallLocation(installRoot, component); err != nil {
		return err
	}
	before, err := captureSymlinkState(installRoot, component)
	if err != nil {
		return err
	}
	return rollbackCurrentUnlocked(installRoot, component, before)
}

func rollbackCurrentUnlocked(installRoot, component string, before symlinkState) error {
	previous, err := PreviousVersion(installRoot, component)
	if err != nil {
		return err
	}
	if previous == "" {
		return &InvalidOperationError{Message: fmt.Sprintf(
			"Component %s has no previous version to roll back to.", component)}
	}
	current, err := CurrentVersion(installRoot, component)
	if err != nil {
		return err
	}
	componentDir := InstallDir(installRoot, component)
	if current != "" {
		if err := stageSymlink(componentDir, "previous", current); err != nil {
			return err
		}
	}
	if err := stageSymlink(componentDir, "current", previous); err != nil {
		return errors.Join(err, restoreSymlinkStateUnlocked(installRoot, component, before))
	}
	return nil
}

// stageSymlink points <dir>/<name> at <dir>/<version> through a staged
// temporary symlink renamed over the destination.
func stageSymlink(dir, name, version string) error {
	if _, err := hostmanifest.RequireName(version, "version", "The version must be a canonical token."); err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(dir, version)); err != nil {
		return err
	}
	staged := dir + "/." + name + ".staging"
	_ = os.Remove(staged)
	if err := os.Symlink(version, staged); err != nil {
		return err
	}
	if err := os.Rename(staged, dir+"/"+name); err != nil {
		_ = os.Remove(staged)
		return err
	}
	return syncDir(dir)
}

func validateInstallLocation(installRoot, component string) error {
	if !hostmanifest.SafeAbsolutePath(installRoot) {
		return &InvalidOperationError{Message: "The install root must be an absolute safe path."}
	}
	if _, err := hostmanifest.RequireName(component, "component", "The component must be a canonical token."); err != nil {
		return err
	}
	return nil
}

func componentDir(path string) string { return filepath.Dir(path) }

func validatedLinkTarget(target, dir, component string) (string, error) {
	if filepath.IsAbs(target) || filepath.Dir(target) != "." {
		return "", &InvalidDataError{Message: "The current version link target is unsafe."}
	}
	if _, err := hostmanifest.RequireName(target, "version", "The version must be a canonical token."); err != nil {
		return "", &InvalidDataError{Message: "The current version link target is unsafe."}
	}
	versionInfo, err := os.Lstat(filepath.Join(dir, target))
	if err != nil || !versionInfo.IsDir() || versionInfo.Mode()&os.ModeSymlink != 0 {
		return "", &InvalidDataError{Message: "The current version link target is not an installed directory."}
	}
	info, err := os.Lstat(filepath.Join(dir, target, component))
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", &InvalidDataError{Message: "The current version link target is not installed."}
	}
	return target, nil
}

type symlinkState struct {
	current, previous       string
	hasCurrent, hasPrevious bool
}

func captureSymlinkState(installRoot, component string) (symlinkState, error) {
	if err := validateInstallLocation(installRoot, component); err != nil {
		return symlinkState{}, err
	}
	dir := InstallDir(installRoot, component)
	state := symlinkState{}
	for _, name := range []string{"current", "previous"} {
		target, err := os.Readlink(filepath.Join(dir, name))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return symlinkState{}, err
		}
		validated, err := validatedLinkTarget(target, dir, component)
		if err != nil {
			return symlinkState{}, err
		}
		if name == "current" {
			state.hasCurrent = true
			state.current = validated
		} else {
			state.hasPrevious = true
			state.previous = validated
		}
	}
	return state, nil
}

func restoreSymlinkState(installRoot, component string, state symlinkState) error {
	flipMutex.Lock()
	defer flipMutex.Unlock()
	return restoreSymlinkStateUnlocked(installRoot, component, state)
}

func restoreSymlinkStateUnlocked(installRoot, component string, state symlinkState) error {
	dir := InstallDir(installRoot, component)
	var failures []error
	for _, entry := range []struct {
		name, value string
		present     bool
	}{
		{"current", state.current, state.hasCurrent}, {"previous", state.previous, state.hasPrevious},
	} {
		path := filepath.Join(dir, entry.name)
		if entry.present {
			if err := stageSymlink(dir, entry.name, entry.value); err != nil {
				failures = append(failures, err)
			}
		} else if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			failures = append(failures, err)
		}
	}
	if err := syncDir(dir); err != nil {
		failures = append(failures, err)
	}
	return errors.Join(failures...)
}
