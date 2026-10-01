package fixturegen

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// These complete package and deployment directories are the source boundary
// consumed by the production restart recipe. Inventory is discovered from the
// tree, so a new runtime Go file cannot silently escape packet source pins.
var completedRecipeSourceDirs = []string{
	"cmd/terrascale-orchestrator",
	"deploy/image",
	"deploy/systemd",
	"internal/app",
	"internal/bootstrap",
	"internal/bootstrapstart",
	"internal/cli",
	"internal/commandio",
	"internal/release",
	"internal/trust",
	"tests/firecracker/production",
}

// CurrentCompletedSourcePins computes a sorted SHA-256 inventory from the
// current source tree. The packet writer verifies these pins again before
// publication, so a source edit between preparation and emission fails closed.
func CurrentCompletedSourcePins(sourceRoot string) ([]SourcePin, error) {
	root, err := completedSourceRoot(sourceRoot)
	if err != nil {
		return nil, err
	}
	paths, err := completedSourcePaths(root)
	if err != nil {
		return nil, err
	}
	pins := make([]SourcePin, 0, len(paths))
	for _, path := range paths {
		name := filepath.Join(root, filepath.FromSlash(path))
		file, err := os.Open(name)
		if err != nil {
			return nil, err
		}
		digest := sha256.New()
		_, copyErr := io.Copy(digest, file)
		closeErr := file.Close()
		if err := errors.Join(copyErr, closeErr); err != nil {
			return nil, err
		}
		pins = append(pins, SourcePin{Path: path, SHA256: hex.EncodeToString(digest.Sum(nil))})
	}
	if err := VerifyCompletedSourcePins(root, pins); err != nil {
		return nil, err
	}
	return pins, nil
}

// VerifyCompletedSourcePins checks both hashes and full directory coverage.
// Unlike a fixed required-path list, it rejects a recipe that omits a newly
// added production source file from one of the completed recipe packages.
func VerifyCompletedSourcePins(sourceRoot string, pins []SourcePin) error {
	root, err := completedSourceRoot(sourceRoot)
	if err != nil {
		return err
	}
	paths, err := completedSourcePaths(root)
	if err != nil {
		return err
	}
	for _, path := range paths {
		if !slices.ContainsFunc(pins, func(pin SourcePin) bool { return pin.Path == path }) {
			return fmt.Errorf("completed source pins omit %q", path)
		}
	}
	return VerifySourcePins(root, pins)
}

func completedSourceRoot(sourceRoot string) (string, error) {
	root, err := filepath.Abs(sourceRoot)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("source root must be a real directory")
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil || resolved != root {
		return "", errors.New("source root has a symlink ancestor")
	}
	return root, nil
}

func completedSourcePaths(root string) ([]string, error) {
	var paths []string
	for _, directory := range completedRecipeSourceDirs {
		if !canonicalPath(directory) {
			return nil, fmt.Errorf("invalid completed source directory %q", directory)
		}
		if err := filepath.WalkDir(filepath.Join(root, filepath.FromSlash(directory)),
			func(name string, item fs.DirEntry, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}
				if item.Type()&os.ModeSymlink != 0 {
					return fmt.Errorf("completed source tree contains symlink %q", name)
				}
				if item.IsDir() {
					return nil
				}
				if !item.Type().IsRegular() {
					return fmt.Errorf("completed source tree contains nonregular file %q", name)
				}
				if !strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, ".service") &&
					!strings.HasSuffix(name, ".sh") && !strings.HasSuffix(name, ".sysusers") &&
					!strings.HasSuffix(name, ".py") || strings.HasSuffix(name, "_test.go") ||
					strings.HasPrefix(filepath.Base(name), "test_") {
					return nil
				}
				relative, err := filepath.Rel(root, name)
				if err != nil {
					return err
				}
				path := filepath.ToSlash(relative)
				if !canonicalPath(path) {
					return fmt.Errorf("invalid completed source path %q", path)
				}
				paths = append(paths, path)
				return nil
			}); err != nil {
			return nil, err
		}
	}
	slices.Sort(paths)
	paths = slices.Compact(paths)
	if len(paths) > maxSourcePins {
		return nil, errors.New("completed source inventory exceeds packet pin bound")
	}
	for _, required := range requiredSourcePaths {
		if !slices.Contains(paths, required) {
			return nil, fmt.Errorf("completed source inventory omits baseline %q", required)
		}
	}
	return paths, nil
}
