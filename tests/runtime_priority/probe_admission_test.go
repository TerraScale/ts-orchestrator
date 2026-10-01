package runtimepriority

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/testutil/script"
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
func field(o object, key string) object { return o[key].(map[string]any) }
func assertEqual(t *testing.T, got, want any) {
	t.Helper()
	if string(jsonWire(t, got)) != string(jsonWire(t, want)) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}
func assertContains(t *testing.T, got, want string) {
	t.Helper()
	if !strings.Contains(got, want) {
		t.Fatalf("%q does not contain %q", got, want)
	}
}

const probeAsset = "terrascale-d15-qualify.py"
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
	f.qualification = object{"schema": "terrascale.release.qualification.v1", "repository": "TerraScale/ts-orchestrator", "source_revision": sourceRevision, "source_tree": strings.Repeat("b", 40), "go_version": "go1.27.1", "go_mod_sha256": strings.Repeat("c", 64), "go_sum_sha256": strings.Repeat("d", 64), "verification": object{"workflow": "ci.yml", "job": producerJob, "run_id": 123, "run_number": 7, "conclusion": "success"}, "artifacts": artifacts}
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
	return script.Run(t, script.Root(t), nil, "python3", "tests/runtime_priority/probe_admission.py", "--probe", filepath.Join(f.root, probeAsset), "--publication", filepath.Join(f.root, "publication.json"), "--qualification", filepath.Join(f.root, "qualification.json"), "--run-detail", filepath.Join(f.root, "run-detail.json"), "--job-log", filepath.Join(f.root, "job.log"), "--release-tag", "ci-"+sourceRevision+"-run-123", "--out", filepath.Join(f.root, "receipt.json"))
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
func TestProbeAdmissionRejectsUnboundEvidence(t *testing.T) {
	cases := []struct {
		name, reason string
		change       func(*testing.T, *admissionFixture)
	}{
		{"publication_digest", "differs from the CI publication", func(t *testing.T, f *admissionFixture) {
			field(f.descriptor, "probe")["sha256"] = strings.Repeat("0", 64)
		}},
		{"probe_bytes", "differs from the CI publication", func(t *testing.T, f *admissionFixture) {
			script.Write(t, filepath.Join(f.root, probeAsset), append(append([]byte{}, probeBytes...), []byte("changed")...), 0600)
		}},
		{"qualification_source", "qualification source differs", func(t *testing.T, f *admissionFixture) { f.qualification["source_revision"] = strings.Repeat("c", 40) }},
		{"failed_job", "job is not successful", func(t *testing.T, f *admissionFixture) { f.runDetail["jobs"].([]object)[0]["status"] = "failure" }},
		{"missing_attempt", "D15-producing job attempt", func(t *testing.T, f *admissionFixture) { f.runDetail["jobs"].([]object)[0]["attempt"] = 0 }},
		{"consistent_replacement", "one exact CI publication marker", func(t *testing.T, f *admissionFixture) {
			changed := []byte("replaced probe on mutable release\n")
			script.Write(t, filepath.Join(f.root, probeAsset), changed, 0600)
			field(f.descriptor, "probe")["bytes"] = len(changed)
			field(f.descriptor, "probe")["sha256"] = digest(changed)
		}},
		{"qualification_replacement", "one exact CI publication marker", func(t *testing.T, f *admissionFixture) {
			f.qualification["artifacts"].([]object)[0]["sha256"] = strings.Repeat("f", 64)
		}},
		{"duplicate_markers", "one exact CI publication marker", func(t *testing.T, f *admissionFixture) { f.log = append(f.log, f.log...) }},
		{"missing_binaries", "strict v1 two-binary", func(t *testing.T, f *admissionFixture) { delete(f.qualification, "artifacts") }},
		{"unordered_binaries", "invalid or unordered binary", func(t *testing.T, f *admissionFixture) {
			v := f.qualification["artifacts"].([]object)
			v[0], v[1] = v[1], v[0]
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newAdmissionFixture(t)
			tc.change(t, f)
			r := f.admit(t)
			if r.Code == 0 {
				t.Fatal("unbound evidence admitted")
			}
			assertContains(t, r.Stderr, tc.reason)
			if _, err := os.Stat(filepath.Join(f.root, "receipt.json")); !os.IsNotExist(err) {
				t.Fatalf("failed admission wrote receipt: %v", err)
			}
		})
	}
}

// This adapter extracts the production embedded opener, substitutes ownership
// metadata, and returns the opened bytes or error. All file cases live in Go.
const pinnedProbeObservation = `
import ast, hashlib, os, re, stat, types
from pathlib import Path
from unittest import mock
module = ast.parse(m.REMOTE_ACTIONS)
function = next(node for node in module.body if isinstance(node, ast.FunctionDef) and node.name == "open_pinned_probe")
namespace = {"req": {"probe_source_revision": a["source"]}, "runtime": a["runtime"], "re": re, "Path": Path, "stat": stat, "os": os, "hashlib": hashlib}
exec(compile(ast.Module(body=[function], type_ignores=[]), "<embedded probe opener>", "exec"), namespace)
original = Path.lstat
def root_owned(path):
    meta = original(path)
    return types.SimpleNamespace(st_mode=meta.st_mode, st_uid=0, st_gid=0, st_dev=meta.st_dev, st_ino=meta.st_ino, st_size=meta.st_size, st_nlink=meta.st_nlink)
try:
    with mock.patch.object(Path, "lstat", autospec=True, side_effect=root_owned):
        fd = namespace["open_pinned_probe"](base=Path(a["base"]))
    try:
        result = {"bytes": os.read(fd, a["length"]).decode()}
    finally:
        os.close(fd)
except Exception as error:
    result = {"error": str(error)}
`

func TestRemotePinnedProbe(t *testing.T) {
	for _, tc := range []struct{ name, reason string }{{"exact", ""}, {"mode", "root-owned regular mode-0444"}, {"bytes", "bytes differ from the exact CI digest"}, {"symlink", "root-owned regular mode-0444"}} {
		t.Run(tc.name, func(t *testing.T) {
			base := filepath.Join(t.TempDir(), "terrascale-d15")
			path := filepath.Join(base, "probes", sourceRevision, digest(probeBytes), "qualify.py")
			script.Write(t, path, probeBytes, 0444)
			for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
				if err := os.Chmod(dir, 0700); err != nil {
					t.Fatal(err)
				}
				if dir == base {
					break
				}
			}
			switch tc.name {
			case "mode":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "bytes":
				if err := os.Chmod(path, 0600); err != nil {
					t.Fatal(err)
				}
				script.Write(t, path, []byte("changed probe with same size!!!!!!!\n"), 0444)
			case "symlink":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				replacement := filepath.Join(base, "replacement")
				script.Write(t, replacement, probeBytes, 0600)
				if err := os.Symlink(replacement, path); err != nil {
					t.Fatal(err)
				}
			}
			got := decodeObject(t, script.Python(t, "tests/runtime_priority/alpha_adapter.py", object{"source": sourceRevision, "base": base, "runtime": object{"qualify_path": path, "qualify_sha256": digest(probeBytes)}, "length": len(probeBytes)}, pinnedProbeObservation))
			if tc.reason == "" {
				assertEqual(t, got["bytes"], string(probeBytes))
			} else {
				assertContains(t, fmt.Sprint(got["error"]), tc.reason)
			}
		})
	}
}
