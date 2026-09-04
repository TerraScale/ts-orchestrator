// This file implements the D-69 version flip: the current symlink of a
// component points at its serving version directory, a flip moves it to the
// new version through an atomic rename, and the previous symlink always
// records the version the last flip replaced so rollback is the symlink
// back. The running binary keeps its inode under the old directory, so a
// flip never disturbs a live process; only the restart switches versions.
package hostagent

import (
	"fmt"
	"os"
	"path/filepath"
)

// CurrentVersion resolves the component's current symlink to its version
// token; the empty string means nothing is current yet.
func CurrentVersion(installRoot, component string) (string, error) {
	link := InstallDir(installRoot, component) + "/current"
	target, err := os.Readlink(link)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return filepath.Base(target), nil
}

// PreviousVersion resolves the component's previous symlink to its version
// token; the empty string means no rollback target exists.
func PreviousVersion(installRoot, component string) (string, error) {
	link := InstallDir(installRoot, component) + "/previous"
	target, err := os.Readlink(link)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return filepath.Base(target), nil
}

// FlipCurrent atomically repoints the current symlink of one component at an
// installed version directory, recording the displaced version in the
// previous symlink. The replacement is one rename(2) over a staged symlink,
// so readers see either the old or the new target, never a missing link.
func FlipCurrent(installRoot, component, version string) error {
	if _, err := requireHostAgentName(version, "version",
		"The version must be a canonical token."); err != nil {
		return err
	}
	componentDir := InstallDir(installRoot, component)
	versionDir := componentDir + "/" + version
	if info, err := os.Stat(versionDir); err != nil || !info.IsDir() {
		return &InvalidOperationError{Message: fmt.Sprintf(
			"Component %s version %s is not installed; refusing to flip.", component, version)}
	}
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
	return stageSymlink(componentDir, "current", version)
}

// RollbackCurrent repoints current at the previous symlink's target and
// swaps previous to what current named, so a rollback of a rollback returns
// to the rolled-forward version. It fails closed when no previous target
// exists.
func RollbackCurrent(installRoot, component string) error {
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
	return stageSymlink(componentDir, "current", previous)
}

// stageSymlink points <dir>/<name> at <dir>/<version> through a staged
// temporary symlink renamed over the destination.
func stageSymlink(dir, name, version string) error {
	staged := dir + "/." + name + ".staging"
	_ = os.Remove(staged)
	if err := os.Symlink(version, staged); err != nil {
		return err
	}
	return os.Rename(staged, dir+"/"+name)
}
