package cli

import (
	"bytes"
	"encoding/json/v2"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Cross the retained-release CLI/process/filesystem boundary, then use the real
// signature and binary verifier. The release transport is a controlled provider.
func TestProductionEvidenceReleaseTransport(t *testing.T) {
	f := newApplyHTTPFixture(t)
	store := t.TempDir()
	evidence := filepath.Join(f.releaseDir, "production")
	for _, architecture := range []string{"amd64", "arm64"} {
		binary, err := (command{ctx: t.Context()}).inspectBinary(binaryPath(f.releaseDir, architecture), f.binary.GoVersion, f.binary.SourceRevision)
		if err != nil {
			t.Fatal(err)
		}
		binary.QualificationSHA256 = f.binary.QualificationSHA256
		record := writeProductionEvidence(t, evidence, productionCandidate(binary, "GRU"))
		writeProductionRecord(t, filepath.Join(store, "production-GRU-"+architecture+".json"), record,
			f.rootPrivate, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
		data, err := os.ReadFile(filepath.Join(store, "production-GRU-"+architecture+".json"))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(evidence, "GRU", architecture), 0o700); err != nil {
			t.Fatal(err)
		}
		writeFixtureFile(t, filepath.Join(evidence, "GRU", architecture, "production.json"), data, 0o600)
	}
	objects, err := os.ReadDir(filepath.Join(evidence, "objects"))
	if err != nil {
		t.Fatal(err)
	}
	for _, object := range objects {
		data, err := os.ReadFile(filepath.Join(evidence, "objects", object.Name()))
		if err != nil {
			t.Fatal(err)
		}
		writeFixtureFile(t, filepath.Join(store, "production-evidence-"+object.Name()), data, 0o600)
	}
	// Unavailable SJC evidence must not cancel the complete GRU record set.
	writeFixtureFile(t, filepath.Join(store, "production-SJC-amd64.json"), []byte("{}"), 0o600)
	entries, err := os.ReadDir(store)
	if err != nil {
		t.Fatal(err)
	}
	type asset struct {
		Name string `json:"name"`
		Size int64  `json:"size"`
	}
	var assets []asset
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			t.Fatal(err)
		}
		size := info.Size()
		if strings.Contains(entry.Name(), "SJC") {
			size = 1064961
		}
		assets = append(assets, asset{entry.Name(), size})
	}
	wire, err := json.Marshal(struct {
		Assets []asset `json:"assets"`
	}{assets})
	if err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, filepath.Join(store, "assets.json"), wire, 0o600)
	bin := t.TempDir()
	writeFixtureFile(t, filepath.Join(bin, "gh"), []byte(`#!/usr/bin/env bash
set -euo pipefail
[[ $1 == release ]] || exit 2
case $2 in
view) cat "$PRODUCTION_TEST_STORE/assets.json" ;;
upload) cp -- "$4" "$PRODUCTION_TEST_STORE/$(basename "$4")" ;;
download)
    shift 3
    while (($#)); do
        case $1 in
        --repo) shift 2 ;;
        --pattern) name=$2; shift 2 ;;
        --output) output=$2; shift 2 ;;
        *) exit 2 ;;
        esac
    done
    cp -- "$PRODUCTION_TEST_STORE/$name" "$output"
    ;;
*) exit 2 ;;
esac
`), 0o700)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PRODUCTION_TEST_STORE", store)
	// The producer crosses a real CLI process before immutable asset upload/readback.
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PRODUCTION_TEST_EXECUTABLE", executable)
	producer := t.TempDir()
	if err := os.Mkdir(filepath.Join(producer, "dist"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, filepath.Join(producer, "dist", "ts-orch"), []byte(`#!/usr/bin/env bash
exec "$PRODUCTION_TEST_EXECUTABLE" -test.run '^TestProductionEvidenceCLIProcess$' -- "$@"
`), 0o700)
	manifest, err := os.ReadFile(filepath.Join(f.releaseDir, "qualification.json"))
	if err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, filepath.Join(store, "qualification.json"), manifest, 0o600)
	retentionScript, err := filepath.Abs("../../../scripts/ci/retain-production-evidence.sh")
	if err != nil {
		t.Fatal(err)
	}
	// An empty asset listing makes the producer exercise uploads; subsequent
	// repeated evidence objects must be retained once and checked again.
	writeFixtureFile(t, filepath.Join(store, "assets.json"), []byte(`{"assets":[]}`), 0o600)
	retain := func() ([]byte, error) {
		command := exec.CommandContext(t.Context(), "bash", retentionScript, f.releaseDir, f.rootPath, "GRU")
		command.Dir = producer
		return command.CombinedOutput()
	}
	if logs, err := retain(); err != nil {
		t.Fatalf("retain signed production evidence: %v\n%s", err, logs)
	}
	writeFixtureFile(t, filepath.Join(store, "assets.json"), wire, 0o600)
	if logs, err := retain(); err != nil {
		t.Fatalf("read back existing production evidence: %v\n%s", err, logs)
	}
	retainedRecord := filepath.Join(store, "production-GRU-amd64.json")
	writeFixtureFile(t, retainedRecord, []byte("changed retained record"), 0o600)
	if logs, err := retain(); err == nil {
		t.Fatalf("changed retained record overwritten or accepted: %s", logs)
	}
	original, err := os.ReadFile(filepath.Join(evidence, "GRU", "amd64", "production.json"))
	if err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, retainedRecord, original, 0o600)
	destination := t.TempDir()
	cmd := exec.CommandContext(t.Context(), "bash", "../../../scripts/ci/fetch-production-evidence.sh",
		"ci-"+f.binary.SourceRevision+"-run-620", destination)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("fetch retained release: %v\n%s", err, output)
	}
	evidenceDir := filepath.Join(destination, "production")
	if _, err := os.Stat(filepath.Join(evidenceDir, "SJC", "amd64", "production.json")); !os.IsNotExist(err) {
		t.Fatalf("oversized regional record was downloaded: %v", err)
	}
	var output bytes.Buffer
	err = Run(t.Context(), []string{"verify-production", "--dir", f.releaseDir, "--evidence-dir", evidenceDir,
		"--root-key", f.rootPath, "--cell", "GRU", "--cell", "SJC"}, &output)
	if err == nil || !strings.Contains(output.String(), `"cell":"GRU"`) ||
		!strings.Contains(output.String(), `"state":"qualified"`) || !strings.Contains(output.String(), `"state":"refused"`) {
		t.Fatalf("lost independent admission after transport: %v\n%s", err, output.String())
	}
	writeFixtureFile(t, filepath.Join(evidenceDir, "objects", objects[0].Name()), []byte("modified after retention"), 0o600)
	output.Reset()
	err = Run(t.Context(), []string{"verify-production", "--dir", f.releaseDir, "--evidence-dir", evidenceDir,
		"--root-key", f.rootPath, "--cell", "GRU"}, &output)
	if err == nil || strings.Contains(output.String(), `"state":"qualified"`) {
		t.Fatalf("changed retained bytes admitted: %v\n%s", err, output.String())
	}
}

// This subprocess is the actual CLI boundary for the producer scenario above.
func TestProductionEvidenceCLIProcess(t *testing.T) {
	if os.Getenv("PRODUCTION_TEST_EXECUTABLE") == "" {
		return
	}
	for index, arg := range os.Args {
		if arg != "--" {
			continue
		}
		args := os.Args[index+1:]
		if len(args) < 2 || args[0] != "release" {
			os.Exit(2)
		}
		if err := Run(t.Context(), args[1:], io.Discard); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(2)
}
