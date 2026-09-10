//go:build sandboxvm

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateRequiresExplicitIntentBeforeWriting(t *testing.T) {
	root := filepath.Join(t.TempDir(), "output")
	if err := generate(root, "", nil); err == nil {
		t.Fatal("missing control/runtime intent accepted")
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("output created before validating input: %v", err)
	}
}
