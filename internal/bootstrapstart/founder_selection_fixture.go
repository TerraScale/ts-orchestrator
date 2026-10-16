//go:build fixturetest

package bootstrapstart

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// NewFounderSelectionFloorStoreFixture relocates only the durable floor files.
func NewFounderSelectionFloorStoreFixture(directory string) (*FounderSelectionFloorStore, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || directory == "/" {
		return nil, ErrFounderSelectionFloor
	}
	store := &FounderSelectionFloorStore{directory: directory, ownerUID: uint32(os.Geteuid()), allowUnsafeAncestors: true}
	dir, err := store.openDirectory()
	if err != nil {
		return nil, err
	}
	unix.Close(dir)
	return store, nil
}
