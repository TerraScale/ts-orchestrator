package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/release"
)

func TestImageProductionPipeline(t *testing.T) {
	f := newApplyHTTPFixture(t)
	store, bin, imageDir := t.TempDir(), t.TempDir(), t.TempDir()
	sourceDir := t.TempDir()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	helperBytes, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(t.TempDir(), "release-cli.test")
	writeFixtureFile(t, helper, helperBytes, 0o700)
	helperDigest := sha256.Sum256(helperBytes)
	// This native fixture binds the real test CLI; it proves only the pipeline boundary.
	adapter := fmt.Sprintf(`package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"syscall"
)

func main() {
	const helper = %q
	data, err := os.ReadFile(helper)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if fmt.Sprintf("%%x", sha256.Sum256(data)) != %q {
		fmt.Fprintln(os.Stderr, "fixture CLI helper digest differs")
		os.Exit(1)
	}
	args := append([]string{helper, "-test.run", "^TestProductionEvidenceCLIProcess$", "--"}, os.Args[1:]...)
	if err := syscall.Exec(helper, args, os.Environ()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
`, helper, hex.EncodeToString(helperDigest[:]))
	module := []byte("module image-pipeline-fixture\n\ngo 1.27.1\n")
	writeFixtureFile(t, filepath.Join(sourceDir, "go.mod"), module, 0o600)
	writeFixtureFile(t, filepath.Join(sourceDir, "go.sum"), nil, 0o600)
	writeFixtureFile(t, filepath.Join(sourceDir, "main.go"), []byte(adapter), 0o600)
	applyFixtureCommand(t, sourceDir, "git", "init", "-q", "--initial-branch=main")
	applyFixtureCommand(t, sourceDir, "git", "add", "go.mod", "go.sum", "main.go")
	applyFixtureCommand(t, sourceDir, "git", "-c", "user.name=Release fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "native image pipeline fixture")
	revision := strings.TrimSpace(applyFixtureCommand(t, sourceDir, "git", "rev-parse", "HEAD"))
	tree := strings.TrimSpace(applyFixtureCommand(t, sourceDir, "git", "rev-parse", "HEAD^{tree}"))
	goVersion := strings.TrimSpace(applyFixtureCommand(t, sourceDir, "go", "env", "GOVERSION"))
	if goVersion != "go1.27.1" {
		t.Fatalf("image pipeline fixture requires go1.27.1, got %s", goVersion)
	}
	c := command{ctx: t.Context(), output: io.Discard}
	var binaries []binaryReceipt
	for _, architecture := range []string{"amd64", "arm64"} {
		path := filepath.Join(store, "terrascale-orchestrator-linux-"+architecture)
		applyFixtureCommand(t, sourceDir, "env", "GOARCH="+architecture, "go", "build", "-buildvcs=true", "-o", path, ".")
		binary, err := c.inspectBinary(path, goVersion, revision)
		if err != nil {
			t.Fatal(err)
		}
		binaries = append(binaries, binary)
	}
	data := []byte("QFI\xfb final guest runtime candidate")
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	writeFixtureFile(t, filepath.Join(imageDir, "terrascale-gru-arm64.qcow2"), data, 0o600)
	qualificationWire, err := os.ReadFile(filepath.Join(f.releaseDir, "qualification.json"))
	if err != nil {
		t.Fatal(err)
	}
	qualification, qualificationDigest, err := release.DecodeQualification(qualificationWire)
	if err != nil {
		t.Fatal(err)
	}
	moduleDigest, sumDigest := sha256.Sum256(module), sha256.Sum256(nil)
	qualification.SourceRevision, qualification.SourceTree = revision, tree
	qualification.GoVersion = goVersion
	qualification.GoModSHA256, qualification.GoSumSHA256 = hex.EncodeToString(moduleDigest[:]), hex.EncodeToString(sumDigest[:])
	qualification.Artifacts = nil
	for _, binary := range binaries {
		qualification.Artifacts = append(qualification.Artifacts, release.QualifiedArtifact{
			Architecture: binary.GOARCH, Name: "terrascale-orchestrator-linux-" + binary.GOARCH,
			Bytes: binary.Bytes, SHA256: binary.SHA256,
		})
	}
	qualificationWire, err = json.Marshal(qualification)
	if err != nil {
		t.Fatal(err)
	}
	qualification, qualificationDigest, err = release.DecodeQualification(qualificationWire)
	if err != nil {
		t.Fatal(err)
	}
	binary := binaries[0]
	binary.QualificationSHA256 = qualificationDigest
	writeFixtureFile(t, filepath.Join(store, "qualification.json"), qualificationWire, 0o600)
	manifest, err := json.Marshal(map[string]any{
		"schema": "terrascale.image.qualification.v2", "source_revision": qualification.SourceRevision,
		"go_candidate": map[string]any{"run_id": qualification.Verification.RunID, "run_number": qualification.Verification.RunNumber, "qualification_sha256": qualificationDigest},
		"image":        map[string]any{"name": "terrascale-gru-arm64.qcow2", "architecture": "arm64", "sha256": digest, "bytes": len(data)},
		"inputs":       map[string]any{"manifest": map[string]any{"region": "GRU"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, filepath.Join(imageDir, "image-qualification.json"), manifest, 0o600)
	inputs, err := json.Marshal(map[string]any{"region": "GRU", "trust_roots": []map[string]string{{"path": f.rootPath}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"deploy/image", "scripts/ci"} {
		if err := os.MkdirAll(filepath.Join(sourceDir, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeFixtureFile(t, filepath.Join(sourceDir, "deploy/image/image-inputs.json"), inputs, 0o600)
	for _, name := range []string{"qualify-image-production.sh", "fetch-image-production-evidence.sh", "qualified_release.py"} {
		script, err := os.ReadFile("../../../scripts/ci/" + name)
		if err != nil {
			t.Fatal(err)
		}
		writeFixtureFile(t, filepath.Join(sourceDir, "scripts/ci", name), script, 0o700)
	}
	candidate := productionCandidate(binary, "GRU")
	candidate.ArtifactSHA256, candidate.Architecture = digest, "arm64"
	evidenceDir := t.TempDir()
	record := writeProductionEvidence(t, evidenceDir, candidate)
	recordPath := filepath.Join(store, "image-production-"+digest+"-GRU-arm64.json")
	writeProductionRecord(t, recordPath, record, f.rootPrivate, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	type asset struct {
		Name string `json:"name"`
		Size int64  `json:"size"`
	}
	var assets []asset
	for _, proof := range record.Evidence {
		object, err := os.ReadFile(filepath.Join(evidenceDir, "objects", proof.SHA256))
		if err != nil {
			t.Fatal(err)
		}
		name := "image-production-evidence-" + proof.SHA256
		writeFixtureFile(t, filepath.Join(store, name), object, 0o600)
		assets = append(assets, asset{name, int64(len(object))})
	}
	info, err := os.Stat(recordPath)
	if err != nil {
		t.Fatal(err)
	}
	assets = append(assets, asset{filepath.Base(recordPath), info.Size()})
	for _, name := range []string{"qualification.json", "terrascale-orchestrator-linux-amd64", "terrascale-orchestrator-linux-arm64"} {
		info, err := os.Stat(filepath.Join(store, name))
		if err != nil {
			t.Fatal(err)
		}
		assets = append(assets, asset{name, info.Size()})
	}
	tag := "ci-" + revision + "-run-" + fmt.Sprint(qualification.Verification.RunID)
	for name, value := range map[string]any{
		"assets.json": map[string]any{"tag_name": tag, "draft": false, "prerelease": true, "assets": assets},
		"commit.json": map[string]any{"sha": revision},
		"run.json": map[string]any{
			"id": qualification.Verification.RunID, "run_number": qualification.Verification.RunNumber,
			"head_sha": revision, "head_branch": "main", "path": ".github/workflows/ci.yml",
			"event": "push", "status": "completed", "conclusion": "success",
			"repository":      map[string]string{"full_name": release.QualificationRepository},
			"head_repository": map[string]string{"full_name": release.QualificationRepository},
		},
		"jobs.json": []any{map[string]any{"jobs": []any{map[string]any{
			"id": 9001, "run_id": qualification.Verification.RunID, "name": release.QualificationJob,
			"status": "completed", "conclusion": "success",
		}}}},
	} {
		wire, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		writeFixtureFile(t, filepath.Join(store, name), wire, 0o600)
	}
	marker := fmt.Sprintf("%s TS_RELEASE_QUALIFICATION_V1 source_sha=%s run_id=%d run_number=%d manifest_sha256=%s\n",
		time.Now().UTC().Format(time.RFC3339), revision, qualification.Verification.RunID, qualification.Verification.RunNumber, qualificationDigest)
	writeFixtureFile(t, filepath.Join(store, "job.log"), []byte(marker), 0o600)
	writeFixtureFile(t, filepath.Join(bin, "gh"), []byte(fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
tag=%q
run=%q
repo=TerraScale/ts-orchestrator
case "$*" in
"api repos/$repo/releases/tags/$tag"|"release view $tag --repo $repo --json assets")
    cat "$PRODUCTION_TEST_STORE/assets.json" ;;
"api repos/$repo/commits/$tag") cat "$PRODUCTION_TEST_STORE/commit.json" ;;
"api repos/$repo/actions/runs/$run") cat "$PRODUCTION_TEST_STORE/run.json" ;;
"api --paginate --slurp repos/$repo/actions/runs/$run/jobs?per_page=100")
    cat "$PRODUCTION_TEST_STORE/jobs.json" ;;
"api repos/$repo/actions/jobs/9001/logs") cat "$PRODUCTION_TEST_STORE/job.log" ;;
"release download "*)
    [[ $# == 9 && $3 == "$tag" && $4 == --repo && $5 == "$repo" &&
        $6 == --pattern && $8 == --output && $7 != */* ]] || exit 2
    cp -- "$PRODUCTION_TEST_STORE/$7" "$9"
    ;;
*) exit 2 ;;
esac
`, tag, fmt.Sprint(qualification.Verification.RunID))), 0o700)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PRODUCTION_TEST_EXECUTABLE", helper)
	t.Setenv("PRODUCTION_TEST_STORE", store)
	t.Setenv("SOURCE_SHA", qualification.SourceRevision)
	t.Setenv("SOURCE_CI_RUN_ID", "")
	t.Setenv("SOURCE_CI_RUN_NUMBER", "")
	t.Setenv("RUNNER_TEMP", t.TempDir())
	run := func(wantQualified bool) string {
		t.Helper()
		command := exec.CommandContext(t.Context(), "bash", "scripts/ci/qualify-image-production.sh", imageDir)
		command.Dir = sourceDir
		logs, err := command.CombinedOutput()
		if (err == nil) != wantQualified {
			t.Fatalf("image admission qualified=%v: %v\n%s", wantQualified, err, logs)
		}
		result, err := os.ReadFile(filepath.Join(imageDir, "image-production-admission.jsonl"))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(result), `"state":"qualified"`) != wantQualified {
			t.Fatalf("incorrect retained admission result: %s", result)
		}
		return string(logs)
	}
	run(true)
	// Same-size corruption must fail the real retained-artifact digest check.
	nativePath := filepath.Join(store, "terrascale-orchestrator-linux-amd64")
	nativeBytes, err := os.ReadFile(nativePath)
	if err != nil {
		t.Fatal(err)
	}
	nativeBytes[len(nativeBytes)-1] ^= 1
	writeFixtureFile(t, nativePath, nativeBytes, 0o600)
	if logs := run(false); !strings.Contains(logs, "retained artifact digest differs: terrascale-orchestrator-linux-amd64") {
		t.Fatalf("corrupt native artifact did not reach retained digest check: %s", logs)
	}
	nativeBytes[len(nativeBytes)-1] ^= 1
	writeFixtureFile(t, nativePath, nativeBytes, 0o600)
	run(true)
	// Reusing the embedded binary's proof cannot qualify changed guest runtime.
	record.Candidate.ArtifactSHA256 = binary.SHA256
	writeProductionRecord(t, recordPath, record, f.rootPrivate, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	if logs := run(false); !strings.Contains(logs, "production qualification is missing or invalid: candidate or required gates") {
		t.Fatalf("embedded binary proof did not reach the real image CLI guard: %s", logs)
	}
	if err := os.Remove(recordPath); err != nil {
		t.Fatal(err)
	}
	run(false)
	// Interrupted provider retrieval cannot expose a completion marker, and a
	// retry repairs a partial object rather than keeping the candidate blocked.
	record.Candidate.ArtifactSHA256 = digest
	writeProductionRecord(t, recordPath, record, f.rootPrivate, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	objectName := "image-production-evidence-" + record.Evidence[0].SHA256
	retainedObject := filepath.Join(store, objectName)
	if err := os.Remove(retainedObject); err != nil {
		t.Fatal(err)
	}
	resumed := t.TempDir()
	fetch := func(wantComplete bool) {
		t.Helper()
		command := exec.CommandContext(t.Context(), "bash", "scripts/ci/fetch-image-production-evidence.sh",
			"ci-"+qualification.SourceRevision+"-run-"+fmt.Sprint(qualification.Verification.RunID), digest, "GRU", "arm64", resumed)
		command.Dir = sourceDir
		logs, err := command.CombinedOutput()
		if (err == nil) != wantComplete {
			t.Fatalf("resumed transport complete=%v: %v\n%s", wantComplete, err, logs)
		}
		_, markerErr := os.Stat(filepath.Join(resumed, "GRU", "arm64", "production.json"))
		if (markerErr == nil) != wantComplete {
			t.Fatalf("incorrect transport completion marker: %v", markerErr)
		}
	}
	fetch(false)
	object, err := os.ReadFile(filepath.Join(evidenceDir, "objects", record.Evidence[0].SHA256))
	if err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, retainedObject, object, 0o600)
	writeFixtureFile(t, filepath.Join(resumed, "objects", record.Evidence[0].SHA256), []byte("interrupted bytes"), 0o600)
	fetch(true)
}
