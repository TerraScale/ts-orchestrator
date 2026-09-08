package hostagent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/controltransition"
)

func TestStoppedCopyRecoversPartialAndPreservesOriginal(t *testing.T) {
	sourceDir, copyDir := t.TempDir(), t.TempDir()
	if err := os.Mkdir(filepath.Join(sourceDir, "account"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "account", "stream.blk"), []byte("original consumer and stream bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	source, err := os.OpenRoot(sourceDir)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	dest, err := os.OpenRoot(copyDir)
	if err != nil {
		t.Fatal(err)
	}
	defer dest.Close()
	limits := controltransition.Limits{MaxStoreFiles: 10, MaxStoreBytes: 1024}
	before, err := inspectCutTree(t.Context(), source, limits)
	if err != nil {
		t.Fatal(err)
	}
	if err := dest.Mkdir("account", 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(copyDir, "account", "stream.blk.storage-copy-partial"), []byte("interrupted"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := copyCutTree(t.Context(), source, dest, limits); err != nil {
		t.Fatal(err)
	}
	after, err := inspectCutTree(t.Context(), source, limits)
	if err != nil || before != after {
		t.Fatalf("original changed: %v", err)
	}
	copyState, err := inspectCutTree(t.Context(), dest, limits)
	if err != nil || copyState.SHA256 != before.SHA256 {
		t.Fatalf("copy differs: %v", err)
	}
	if err := copyCutTree(t.Context(), source, dest, limits); err != nil {
		t.Fatalf("retry failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(copyDir, "account", "stream.blk"), []byte("conflict"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := copyCutTree(t.Context(), source, dest, limits); err == nil {
		t.Fatal("overwrote conflicting existing copy")
	}
	raw, err := os.ReadFile(filepath.Join(copyDir, "account", "stream.blk"))
	if err != nil || string(raw) != "conflict" {
		t.Fatal("changed conflicting retained file")
	}
}

func TestStoppedCopyRefusesUnsafeSourceAndBounds(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "stream"), []byte("four"), 0600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	limits := controltransition.Limits{MaxStoreFiles: 10, MaxStoreBytes: 3}
	if _, err := inspectCutTree(t.Context(), root, limits); err == nil {
		t.Fatal("accepted oversized source")
	}
	limits.MaxStoreBytes = 1024
	if err := os.Link(filepath.Join(dir, "stream"), filepath.Join(dir, "hardlink")); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectCutTree(t.Context(), root, limits); err == nil {
		t.Fatal("accepted hardlink")
	}
	if err := os.Remove(filepath.Join(dir, "hardlink")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectCutTree(t.Context(), root, limits); err == nil {
		t.Fatal("accepted escaping link")
	}
	if err := os.Remove(filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := inspectCutTree(ctx, root, limits); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
}

func TestSourceCutFirstRecordPreservesAbsentLeaf(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "first-seal.json")
	if _, err := readCutRecord(missing, 1024); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("first immutable record cannot be created: %v", err)
	}
	if err := os.Symlink("/etc/passwd", missing); err != nil {
		t.Fatal(err)
	}
	if _, err := readCutRecord(missing, 1024); err == nil || errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unsafe record disguised as absent: %v", err)
	}
}

func TestStoppedCopyBoundsWideDirectoryBeforeHashing(t *testing.T) {
	directory := t.TempDir()
	for _, name := range []string{"a", "b", "c"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err := inspectCutTree(t.Context(), root, controltransition.Limits{MaxStoreFiles: 3, MaxStoreBytes: 100}); err == nil {
		t.Fatal("wide directory exceeded whole-tree bound")
	}
}
