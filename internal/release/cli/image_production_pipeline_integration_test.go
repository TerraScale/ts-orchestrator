package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/json/v2"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestImageProductionEvidenceTransport(t *testing.T) {
	helper, err := filepath.Abs("../../../deploy/image/fetch-production-evidence.sh")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.ReadFile(helper); err != nil {
		t.Fatal(err)
	}
	store, bin := t.TempDir(), t.TempDir()
	tag := "ci-" + strings.Repeat("a", 40) + "-run-1"
	imageDigest := strings.Repeat("b", 64)
	recordName := "image-production-" + imageDigest + "-GRU-arm64.json"
	type asset struct {
		Name string `json:"name"`
		Size int    `json:"size"`
	}
	var assets []asset
	var evidence []map[string]any
	objects := [][]byte{[]byte("runtime evidence"), []byte("workload evidence")}
	var names, digests []string
	for _, object := range objects {
		digest := fmt.Sprintf("%x", sha256.Sum256(object))
		name := "image-production-evidence-" + digest
		names = append(names, name)
		digests = append(digests, digest)
		writeFixtureFile(t, filepath.Join(store, name), object, 0o600)
		assets = append(assets, asset{name, len(object)})
		evidence = append(evidence, map[string]any{"sha256": digest, "bytes": len(object)})
	}
	// Transport checks retained bytes; signed candidate admission has separate CLI tests.
	record, err := json.Marshal(map[string]any{"payload": map[string]any{"evidence": evidence}})
	if err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, filepath.Join(store, recordName), record, 0o600)
	assets = append(assets, asset{recordName, len(record)})
	listing, err := json.Marshal(map[string]any{"assets": assets})
	if err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, filepath.Join(store, "assets.json"), listing, 0o600)
	writeFixtureFile(t, filepath.Join(bin, "gh"), []byte(`#!/usr/bin/env bash
set -euo pipefail
case "$*" in
"release view "*) cat "$PRODUCTION_TEST_STORE/assets.json" ;;
"release download "*)
 [[ $# == 9 && $4 == --repo && $5 == TerraScale/ts-orchestrator &&
    $6 == --pattern && $8 == --output && $7 != */* ]] || exit 2
 cp -- "$PRODUCTION_TEST_STORE/$7" "$9" ;;
*) exit 2 ;;
esac
`), 0o700)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PRODUCTION_TEST_STORE", store)
	fetch := func(destination string, complete bool) {
		t.Helper()
		command := exec.CommandContext(t.Context(), "bash", helper, tag, imageDigest, "GRU", "arm64", destination)
		logs, err := command.CombinedOutput()
		if (err == nil) != complete {
			t.Fatalf("transport complete=%v: %v\n%s", complete, err, logs)
		}
		marker, err := os.ReadFile(filepath.Join(destination, "GRU", "arm64", "production.json"))
		if (err == nil) != complete {
			t.Fatalf("incorrect completion marker: %v", err)
		}
		if complete && !bytes.Equal(marker, record) {
			t.Fatal("completion record bytes differ")
		}
	}
	missingRecord := t.TempDir()
	if err := os.Remove(filepath.Join(store, recordName)); err != nil {
		t.Fatal(err)
	}
	fetch(missingRecord, false)
	writeFixtureFile(t, filepath.Join(store, recordName), record, 0o600)
	resumed := t.TempDir()
	if err := os.Remove(filepath.Join(store, names[1])); err != nil {
		t.Fatal(err)
	}
	fetch(resumed, false)
	// Retry must repair a partially downloaded cache object before completing.
	writeFixtureFile(t, filepath.Join(resumed, "objects", digests[0]), []byte("interrupted"), 0o600)
	writeFixtureFile(t, filepath.Join(store, names[1]), objects[1], 0o600)
	fetch(resumed, true)
	for i, digest := range digests {
		got, err := os.ReadFile(filepath.Join(resumed, "objects", digest))
		if err != nil || !bytes.Equal(got, objects[i]) {
			t.Fatalf("restored object differs: %v", err)
		}
	}
	// Same-size corruption reaches the digest check rather than only the size check.
	corrupt := bytes.Clone(objects[0])
	corrupt[0] ^= 1
	writeFixtureFile(t, filepath.Join(store, names[0]), corrupt, 0o600)
	fetch(t.TempDir(), false)
	// Already verified cached objects remain usable without downloading them again.
	if err := os.Remove(filepath.Join(store, names[0])); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(store, names[1])); err != nil {
		t.Fatal(err)
	}
	fetch(resumed, true)
}
