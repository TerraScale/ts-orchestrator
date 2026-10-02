package image

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

const resumeSource = "5ff44290b67a91c3b27373c6661d778fe6ef8ffc"

func TestReuseReleaseToolRequiresRecordedDigestAndCleanSource(t *testing.T) {
	dir := t.TempDir()
	tool := filepath.Join(dir, "ts-orch")
	if err := os.WriteFile(tool, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	digest, err := fileHash(tool)
	if err != nil {
		t.Fatal(err)
	}
	metadata := "vcs.revision=" + resumeSource + "\nvcs.modified=false\n"
	run := func(_ context.Context, _ string, _ []string, command ...string) (string, error) {
		if !slices.Equal(command, []string{"go", "version", "-m", tool}) {
			t.Fatalf("unexpected command %q", command)
		}
		return metadata, nil
	}
	if _, _, _, ok := reuseReleaseTool(t.Context(), dir, resumeSource, run); ok {
		t.Fatal("tool reused without a record")
	}
	if err := recordReleaseTool(dir, resumeSource, []string{"release"}, map[string]any{"path": tool, "sha256": digest}); err != nil {
		t.Fatal(err)
	}
	path, prefix, record, ok := reuseReleaseTool(t.Context(), dir, resumeSource, run)
	if !ok || path != tool || !slices.Equal(prefix, []string{"release"}) || record["sha256"] != digest || record["reused"] != true {
		t.Fatalf("recorded tool not reused: %q %q %v %t", path, prefix, record, ok)
	}
	if _, _, _, ok := reuseReleaseTool(t.Context(), dir, "0123456789abcdef0123456789abcdef01234567", run); ok {
		t.Fatal("tool reused for another source revision")
	}
	metadata = "vcs.revision=" + resumeSource + "\nvcs.modified=true\n"
	if _, _, _, ok := reuseReleaseTool(t.Context(), dir, resumeSource, run); ok {
		t.Fatal("dirty tool reused")
	}
	metadata = "vcs.revision=" + resumeSource + "\nvcs.modified=false\n"
	if err := os.WriteFile(tool, []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, _, _, ok := reuseReleaseTool(t.Context(), dir, resumeSource, run); ok {
		t.Fatal("changed tool bytes reused")
	}
}
