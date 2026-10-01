package sourcedigest_test

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ci/sourcedigest"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/testutil/script"
)

func TestSourceDigestV1FramingAndBytewisePathOrder(t *testing.T) {
	records := []sourcedigest.Record{{Mode: "120000", Path: []byte("z"), Digest: sha256.Sum256([]byte("a.txt"))}, {Mode: "100644", Path: []byte("a.txt"), Digest: sha256.Sum256([]byte("hello\n"))}}
	got, e := sourcedigest.Digest("commit", "tree", "turso", "prepared", records)
	if e != nil {
		t.Fatal(e)
	}
	const want = "dd6752557c84584777765d39c38da4e29ba06059601631a9e053eaeff43a4fcf"
	if got != want {
		t.Fatalf("v1 identity changed: %s", got)
	}
	if string(records[0].Path) != "z" {
		t.Fatal("digest mutated caller order")
	}
	records = append(records, records[0])
	if _, e = sourcedigest.Digest("commit", "tree", "turso", "prepared", records); e == nil {
		t.Fatal("accepted duplicate tracked source path")
	}
}
func TestSourceDigestReadsTrackedObjectsWithModesAndArbitraryPaths(t *testing.T) {
	repo := t.TempDir()
	git := func(args ...string) string {
		t.Helper()
		r := script.Run(t, repo, nil, "git", args...)
		if r.Code != 0 {
			t.Fatal(args, r.Stderr)
		}
		return strings.TrimSpace(r.Stdout)
	}
	git("init", "--quiet")
	git("config", "user.name", "test")
	git("config", "user.email", "test@example.invalid")
	script.Write(t, filepath.Join(repo, "a\tfile\n.txt"), []byte("committed\x00blob"), 0644)
	script.Write(t, filepath.Join(repo, "exec"), []byte("#!/bin/sh\n"), 0755)
	if e := os.Symlink("a\tfile\n.txt", filepath.Join(repo, "link")); e != nil {
		t.Fatal(e)
	}
	git("add", ".")
	git("commit", "--quiet", "-m", "source")
	source := git("rev-parse", "HEAD")
	script.Write(t, filepath.Join(repo, "a\tfile\n.txt"), []byte("dirty worktree"), 0644)
	entries, e := sourcedigest.Fields(t.Context(), repo, source)
	if e != nil {
		t.Fatal(e)
	}
	records, e := sourcedigest.ContentHashes(t.Context(), repo, entries)
	if e != nil {
		t.Fatal(e)
	}
	if len(records) != 3 {
		t.Fatal(records)
	}
	expected := map[string]struct {
		mode string
		body []byte
	}{"a\tfile\n.txt": {"100644", []byte("committed\x00blob")}, "exec": {"100755", []byte("#!/bin/sh\n")}, "link": {"120000", []byte("a\tfile\n.txt")}}
	for _, r := range records {
		want, ok := expected[string(r.Path)]
		if !ok || r.Mode != want.mode || r.Digest != sha256.Sum256(want.body) {
			t.Fatalf("changed tracked identity: %+v", r)
		}
	}
	if _, e = sourcedigest.ContentHashes(t.Context(), repo, []sourcedigest.Entry{{Kind: "commit", Path: []byte("nested")}}); e == nil {
		t.Fatal("accepted nested unexpanded gitlink")
	}
}
func TestSourceDigestReceiptPublicationRefusesOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "receipt.json")
	if e := sourcedigest.WriteNew(path, map[string]any{"schema": "identity", "count": 2}); e != nil {
		t.Fatal(e)
	}
	before := script.Read(t, path)
	if e := sourcedigest.WriteNew(path, map[string]any{"schema": "replacement"}); e == nil {
		t.Fatal("overwrote retained evidence")
	}
	if !bytes.Equal(before, script.Read(t, path)) {
		t.Fatal("retained receipt changed")
	}
	entries, e := os.ReadDir(filepath.Dir(path))
	if e != nil || len(entries) != 1 {
		t.Fatal(entries, e)
	}
}
