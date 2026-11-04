package deploy_test

import (
	"bytes"

	"path/filepath"
	"strings"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/testutil/script"
)

const inputSource = "470d1f898897d4a0cefc7d638ce8eb72f0ca73b8"

type imageInputsFixture struct {
	t                               *testing.T
	manifest, qualification, detail string
}

func newImageInputs(t *testing.T) *imageInputsFixture {
	t.Helper()
	dir := t.TempDir()
	f := &imageInputsFixture{t, filepath.Join(dir, "image-inputs.json"), filepath.Join(dir, "qualification.json"), filepath.Join(dir, "run-detail.json")}
	write(t, f.manifest, read(t, filepath.Join(deployRoot(t), "deploy/image/image-inputs.json")), 0600)
	write(t, f.qualification, jsonBytes(t, map[string]any{"schema": "terrascale.terrabase.qualification.v2", "repository": "TerraScale/TerraBase", "source_revision": inputSource, "source_tree": strings.Repeat("b", 40), "verification": map[string]any{"workflow": "fast.yml", "job": "fast", "run_id": 11711, "run_number": 1018, "conclusion": "success"}, "artifacts": []any{map[string]any{"name": "tb-server-linux-amd64", "target": "x86_64-unknown-linux-musl", "sha256": strings.Repeat("1", 64)}, map[string]any{"name": "tb-server-linux-arm64", "target": "aarch64-unknown-linux-musl", "sha256": strings.Repeat("2", 64)}}}), 0600)
	f.runDetail("success", "success")
	return f
}
func (f *imageInputsFixture) runDetail(run, fast string) {
	write(f.t, f.detail, jsonBytes(f.t, map[string]any{"run_id": 11711, "run_number": 1018, "head_sha": inputSource, "workflow": "fast.yml", "status": run, "jobs": []any{map[string]any{"id": 1, "run_id": 11711, "name": "fast", "status": fast, "attempt": 1}, map[string]any{"id": 2, "run_id": 11711, "name": "publish", "status": "in_progress", "attempt": 1}}}), 0600)
}
func (f *imageInputsFixture) tool(args ...string) script.Result {
	return runTool(f.t, append([]string{"image", "inputs", "--file", f.manifest}, args...)...)
}
func (f *imageInputsFixture) pin() script.Result {
	return f.tool("pin-terrabase", "--qualification", f.qualification, "--run-detail", f.detail)
}
func (f *imageInputsFixture) replacePin(field string) {
	b := read(f.t, f.manifest)
	v := object(f.t, b)
	var old string
	if field == "timesyncd_config" {
		old = v[field].(map[string]any)["sha256"].(string)
	} else {
		old = v["netbird"].(map[string]any)["enrollment_config"].(map[string]any)["sha256"].(string)
	}
	write(f.t, f.manifest, bytes.Replace(b, []byte(old), []byte(strings.Repeat("0", 64)), 1), 0600)
}

func TestImageInputsAcceptPublishingRun(t *testing.T) {
	f := newImageInputs(t)
	f.runDetail("in_progress", "success")
	successful(t, f.pin())
}
