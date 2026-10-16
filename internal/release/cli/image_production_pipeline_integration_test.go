package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"fmt"
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
		if err := os.MkdirAll(filepath.Join(f.sourceDir, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeFixtureFile(t, filepath.Join(f.sourceDir, "deploy/image/image-inputs.json"), inputs, 0o600)
	for _, name := range []string{"qualify-image-production.sh", "fetch-image-production-evidence.sh"} {
		script, err := os.ReadFile("../../../scripts/ci/" + name)
		if err != nil {
			t.Fatal(err)
		}
		writeFixtureFile(t, filepath.Join(f.sourceDir, "scripts/ci", name), script, 0o700)
	}
	candidate := productionCandidate(f.binary, "GRU")
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
	assetWire, err := json.Marshal(struct {
		Assets []asset `json:"assets"`
	}{assets})
	if err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, filepath.Join(store, "assets.json"), assetWire, 0o600)
	writeFixtureFile(t, filepath.Join(bin, "gh"), []byte(`#!/usr/bin/env bash
set -euo pipefail
[[ $1 == release ]] || exit 2
case $2 in
view) cat "$PRODUCTION_TEST_STORE/assets.json" ;;
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
	// Reuse the real CLI test executable instead of compiling another binary.
	writeFixtureFile(t, filepath.Join(bin, "go"), []byte(`#!/usr/bin/env bash
set -euo pipefail
[[ $1 == build ]] || exit 2
while (($#)); do
    if [[ $1 == -o ]]; then output=$2; break; fi
    shift
done
cat > "$output" <<'WRAPPER'
#!/usr/bin/env bash
exec "$PRODUCTION_TEST_EXECUTABLE" -test.run '^TestProductionEvidenceCLIProcess$' -- "$@"
WRAPPER
chmod 0700 "$output"
`), 0o700)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PRODUCTION_TEST_EXECUTABLE", executable)
	t.Setenv("PRODUCTION_TEST_STORE", store)
	t.Setenv("SOURCE_SHA", qualification.SourceRevision)
	t.Setenv("SOURCE_CI_RUN_ID", "")
	t.Setenv("SOURCE_CI_RUN_NUMBER", "")
	t.Setenv("RUNNER_TEMP", t.TempDir())
	run := func(wantQualified bool) {
		t.Helper()
		command := exec.CommandContext(t.Context(), "bash", "scripts/ci/qualify-image-production.sh", imageDir)
		command.Dir = f.sourceDir
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
	}
	run(true)
	// Reusing the embedded binary's proof cannot qualify changed guest runtime.
	record.Candidate.ArtifactSHA256 = f.binary.SHA256
	writeProductionRecord(t, recordPath, record, f.rootPrivate, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	run(false)
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
		command.Dir = f.sourceDir
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
