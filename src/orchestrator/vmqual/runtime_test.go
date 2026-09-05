package vmqual

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAllocatedPathBytesMeasuresSparseAllocation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sparse.img")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	const logicalSize = 64 << 20
	if err := file.Truncate(logicalSize); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if _, err := file.WriteAt([]byte{0xa5}, logicalSize-1); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	allocated, err := allocatedPathBytes(path)
	if err != nil {
		t.Fatal(err)
	}
	if allocated == 0 || allocated >= logicalSize {
		t.Fatalf("allocated bytes = %d for %d-byte sparse file", allocated, logicalSize)
	}
	duplicated, err := allocatedPathBytes(path, path)
	if err != nil {
		t.Fatal(err)
	}
	if duplicated != allocated {
		t.Fatalf("duplicate inode counted twice: %d != %d", duplicated, allocated)
	}
	alias := filepath.Join(filepath.Dir(path), "alias.img")
	if err := os.Link(path, alias); err != nil {
		t.Fatal(err)
	}
	tree, err := allocatedTreeBytes(filepath.Dir(path), filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if tree != allocated {
		t.Fatalf("tree allocation = %d, want %d with hardlink and repeated root deduplicated", tree, allocated)
	}
}
