package image

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// A relative --out must not make the release tool land inside the source
// worktree that go build runs in (#127 12015).
func TestBuildReleaseToolWritesToAnAbsoluteDirectory(t *testing.T) {
	t.Chdir(t.TempDir())
	var output string
	run := func(_ context.Context, dir string, _ []string, command ...string) (string, error) {
		switch {
		case command[0] == "nice":
			output = command[slices.Index(command, "-o")+1]
			if err := os.WriteFile(output, []byte("#!/bin/sh\n"), 0o755); err != nil {
				t.Fatal(err)
			}
		case command[0] == "go":
			return "vcs.revision=" + resumeSource + "\nvcs.modified=false\n", nil
		}
		return "", nil
	}
	if err := os.MkdirAll(filepath.Join("out", "tools", "build-1"), 0o755); err != nil {
		t.Fatal(err)
	}
	tool, _, _, err := BuildReleaseTool(t.Context(), "/repo", filepath.Join("out", "tools", "build-1"), resumeSource, "", run)
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(output) || tool != output {
		t.Fatalf("release tool built to %q (returned %q), want an absolute path", output, tool)
	}
}

// The resume checkpoint is published atomically and an identical one is not
// rewritten, so an interruption can never leave a truncated checkpoint that
// blocks every later --resume (#127 12017).
func TestWriteCheckpointIsAtomicAndIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, promotionStateFile)
	if err := writeCheckpoint(path, []byte(`{"a":1}`)); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeCheckpoint(path, []byte(`{"a":1}`)); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("an identical checkpoint was rewritten")
	}
	if err := writeCheckpoint(path, []byte(`{"a":2}`)); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); string(got) != `{"a":2}` {
		t.Fatalf("checkpoint = %s", got)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o644 {
		t.Fatalf("checkpoint mode = %v", info.Mode())
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("temporary files left behind: %v", entries)
	}
}

// Generated outputs are moved aside on --resume so the non-overwriting
// release commands can regenerate them; without --resume an existing output
// is an error (#127 12014).
func TestFreshOutputMovesAsideOnlyOnResume(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "image-candidate.json")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	var log bytes.Buffer
	p := &promotion{out: &log}
	if err := p.freshOutput(path); err == nil {
		t.Fatal("a fresh promotion reused an existing output")
	}
	p.o.Resume = true
	if err := p.freshOutput(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("output still in place: %v", err)
	}
	matches, _ := filepath.Glob(path + ".superseded-*")
	if len(matches) != 1 || !strings.Contains(log.String(), "regenerating image-candidate.json") {
		t.Fatalf("earlier output not kept aside: %v %q", matches, log.String())
	}
	if err := p.freshOutput(filepath.Join(dir, "missing.json")); err != nil {
		t.Fatal(err)
	}
}
