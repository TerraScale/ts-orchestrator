package runtimepriority

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	rp "github.com/TerraScale/ts-orchestrator/internal/runtimepriority"
	"github.com/TerraScale/ts-orchestrator/internal/testutil/script"
)

type object = map[string]any

func digest(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
func jsonWire(t *testing.T, value any) []byte {
	t.Helper()
	b, err := json.Marshal(value, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	return append(b, '\n')
}
func decodeObject(t *testing.T, raw []byte) object {
	t.Helper()
	var o object
	if err := json.Unmarshal(raw, &o); err != nil {
		t.Fatalf("decode observation: %v\n%s", err, raw)
	}
	return o
}
func assertEqual(t *testing.T, got, want any) {
	t.Helper()
	if string(jsonWire(t, got)) != string(jsonWire(t, want)) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

const probeAsset = "terrascale-d15-qualify"
const producerJob = "verify/go + artifact/linux-amd64-arm64"

var sourceRevision = strings.Repeat("a", 40)
var probeBytes = []byte("# exact CI-published probe fixture\n")

type admissionFixture struct {
	root                                 string
	descriptor, qualification, runDetail object
	log                                  []byte
}

func newAdmissionFixture(t *testing.T) *admissionFixture {
	t.Helper()
	f := &admissionFixture{root: t.TempDir()}
	f.descriptor = object{"schema": "terrascale.d15.probe-publication/v1", "repository": "TerraScale/ts-orchestrator", "source_revision": sourceRevision, "source_tree": strings.Repeat("b", 40), "verification": object{"workflow": "ci.yml", "job": producerJob, "run_id": 123, "run_number": 7}, "probe": object{"name": probeAsset, "bytes": len(probeBytes), "sha256": digest(probeBytes)}}
	artifacts := []object{}
	for _, arch := range []string{"amd64", "arm64"} {
		artifacts = append(artifacts, object{"architecture": arch, "name": "terrascale-orchestrator-linux-" + arch, "bytes": 100, "sha256": strings.Repeat("e", 64)})
	}
	f.qualification = object{"schema": "terrascale.release.qualification.v1", "repository": "TerraScale/ts-orchestrator", "source_revision": sourceRevision, "source_tree": strings.Repeat("b", 40), "go_version": "go1.27.3", "go_mod_sha256": strings.Repeat("c", 64), "go_sum_sha256": strings.Repeat("d", 64), "verification": object{"workflow": "ci.yml", "job": producerJob, "run_id": 123, "run_number": 7, "conclusion": "success"}, "artifacts": artifacts}
	f.runDetail = object{"run_id": 123, "run_number": 7, "head_sha": sourceRevision, "workflow": "ci.yml", "status": "success", "jobs": []object{{"id": 456, "run_id": 123, "name": producerJob, "status": "success", "attempt": 2}}}
	f.log = fmt.Appendf(nil, "2026-09-28T12:00:00Z TS_D15_PROBE_PUBLICATION_V1 source_sha=%s run_id=123 run_number=7 probe_sha256=%s descriptor_sha256=%s\n2026-09-28T12:00:01Z TS_RELEASE_QUALIFICATION_V1 source_sha=%s run_id=123 run_number=7 manifest_sha256=%s\n", sourceRevision, digest(probeBytes), digest(jsonWire(t, f.descriptor)), sourceRevision, digest(jsonWire(t, f.qualification)))
	script.Write(t, filepath.Join(f.root, probeAsset), probeBytes, 0600)
	return f
}
func (f *admissionFixture) admit(t *testing.T) script.Result {
	t.Helper()
	for name, value := range map[string]any{"publication.json": f.descriptor, "qualification.json": f.qualification, "run-detail.json": f.runDetail} {
		script.Write(t, filepath.Join(f.root, name), jsonWire(t, value), 0600)
	}
	script.Write(t, filepath.Join(f.root, "job.log"), f.log, 0600)
	var out bytes.Buffer
	err := rp.Run(t.Context(), []string{"probe-admission", "--probe", filepath.Join(f.root, probeAsset), "--publication", filepath.Join(f.root, "publication.json"), "--qualification", filepath.Join(f.root, "qualification.json"), "--run-detail", filepath.Join(f.root, "run-detail.json"), "--job-log", filepath.Join(f.root, "job.log"), "--release-tag", "ci-" + sourceRevision + "-run-123", "--out", filepath.Join(f.root, "receipt.json")}, &out)
	result := script.Result{Stdout: out.String()}
	if err != nil {
		result.Code = 1
		result.Stderr = err.Error()
	}
	return result
}
func TestProbeAdmissionExactPublication(t *testing.T) {
	f := newAdmissionFixture(t)
	r := f.admit(t)
	if r.Code != 0 {
		t.Fatalf("admit: %s", r.Stderr)
	}
	receipt := decodeObject(t, script.Read(t, filepath.Join(f.root, "receipt.json")))
	for key, want := range (object{"probe_sha256": digest(probeBytes), "source_revision": sourceRevision, "run_id": 123, "job_id": 456, "attempt": 2}) {
		assertEqual(t, receipt[key], want)
	}
	for key, name := range map[string]string{"publication_sha256": "publication.json", "qualification_sha256": "qualification.json", "run_detail_sha256": "run-detail.json", "job_log_sha256": "job.log"} {
		assertEqual(t, receipt[key], digest(script.Read(t, filepath.Join(f.root, name))))
	}
}
