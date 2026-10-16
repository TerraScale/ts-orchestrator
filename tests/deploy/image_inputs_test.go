package deploy_test

import (
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
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
func TestImageInputsCheckedInManifest(t *testing.T) { successful(t, newImageInputs(t).tool("check")) }
func TestImageInputsRejectMissingVerifierPin(t *testing.T) {
	for _, raw := range []string{"null", "{}"} {
		t.Run(raw, func(t *testing.T) {
			f := newImageInputs(t)
			b := read(t, f.manifest)
			var fields map[string]jsontext.Value
			if err := json.Unmarshal(b, &fields); err != nil {
				t.Fatal(err)
			}
			write(t, f.manifest, bytes.Replace(b, fields["terrabase"], []byte(raw), 1), 0600)
			r := f.tool("check")
			equal(t, r.Code, 1)
			contains(t, r.Stderr, "terrabase has unexpected fields")
		})
	}
}

func TestImageInputsVerifyArchivedVerifier(t *testing.T) {
	for _, name := range []string{"valid", "wrong-binary", "wrong-qualification", "wrong-source", "missing-files"} {
		t.Run(name, func(t *testing.T) {
			f := newImageInputs(t)
			binary := filepath.Join(t.TempDir(), "tb-server-linux-arm64")
			write(t, binary, elf("arm64", "archived native verifier"), 0600)
			b := read(t, f.manifest)
			pin := object(t, b)["terrabase"].(map[string]any)
			archive := pin["archive"].(map[string]any)
			oldBinary, oldQualification := pin["binary_sha256"].(string), archive["qualification_sha256"].(string)
			delete(pin, "archive")
			pin["binary_sha256"] = digest(read(t, binary))
			if name == "wrong-source" {
				pin["source_revision"] = strings.Repeat("a", 40)
			}
			qualification := filepath.Join(t.TempDir(), "image-qualification.json")
			write(t, qualification, jsonBytes(t, map[string]any{"schema": "terrascale.image.qualification.v2", "inputs": map[string]any{"manifest": map[string]any{"terrabase": pin}}}), 0600)
			b = bytes.ReplaceAll(b, []byte(oldBinary), []byte(digest(read(t, binary))))
			b = bytes.ReplaceAll(b, []byte(oldQualification), []byte(digest(read(t, qualification))))
			write(t, f.manifest, b, 0600)
			args := []string{"verify-terrabase-archive", "--qualification", qualification, "--binary", binary}
			switch name {
			case "wrong-binary":
				write(t, binary, elf("arm64", "different verifier"), 0600)
			case "wrong-qualification":
				write(t, qualification, []byte("{}"), 0600)
			case "missing-files":
				args = args[:1]
			}
			r := f.tool(args...)
			if name == "valid" {
				successful(t, r)
			} else {
				equal(t, r.Code, 1)
				contains(t, r.Stderr, "verifier")
			}
		})
	}
}
func TestImageInputsRejectNonCanonicalFormatting(t *testing.T) {
	f := newImageInputs(t)
	write(t, f.manifest, jsonBytes(t, object(t, read(t, f.manifest))), 0600)
	r := f.tool("check")
	equal(t, r.Code, 1)
	contains(t, r.Stderr, "not canonically formatted")
}
func TestImageInputsRequireCheckedInPins(t *testing.T) {
	for _, field := range []string{"timesyncd_config", "netbird"} {
		t.Run(field, func(t *testing.T) {
			f := newImageInputs(t)
			f.replacePin(field)
			r := f.tool("check")
			equal(t, r.Code, 1)
			contains(t, r.Stderr, "checked-in input differs from its pin")
			if field == "netbird" {
				b := read(t, f.manifest)
				v := object(t, b)
				old := v["netbird"].(map[string]any)["archives"].(map[string]any)["arm64"].(map[string]any)["url"].(string)
				write(t, f.manifest, bytes.Replace(b, []byte(old), []byte("https://other.example/netbird.tar.gz"), 1), 0600)
				r = f.tool("check")
				equal(t, r.Code, 1)
				contains(t, r.Stderr, "invalid NetBird arm64 archive source")
			}
		})
	}
}
func TestImageInputsPinOnlyRewritesTerrabase(t *testing.T) {
	f := newImageInputs(t)
	before := object(t, read(t, f.manifest))
	successful(t, f.pin())
	after := object(t, read(t, f.manifest))
	equal(t, after["terrabase"], object(t, jsonBytes(t, map[string]any{"source_revision": inputSource, "source_tree": strings.Repeat("b", 40), "run_id": 11711, "run_number": 1018, "qualification_sha256": digest(read(t, f.qualification)), "binary_sha256": strings.Repeat("2", 64)})))
	delete(before, "terrabase")
	delete(after, "terrabase")
	equal(t, after, before)
	successful(t, f.tool("check"))
}
func TestImageInputsAcceptPublishingRun(t *testing.T) {
	f := newImageInputs(t)
	f.runDetail("in_progress", "success")
	successful(t, f.pin())
}
func TestImageInputsRejectFailedOrMismatchedRunWithoutMutation(t *testing.T) {
	for _, tc := range []struct {
		name, run, fast string
		wrongHead       bool
	}{{"failed-run", "failure", "success", false}, {"failed-fast", "in_progress", "failure", false}, {"wrong-head", "success", "success", true}} {
		t.Run(tc.name, func(t *testing.T) {
			f := newImageInputs(t)
			original := read(t, f.manifest)
			f.runDetail(tc.run, tc.fast)
			if tc.wrongHead {
				b := bytes.Replace(read(t, f.detail), []byte(inputSource), []byte(strings.Repeat("c", 40)), 1)
				write(t, f.detail, b, 0600)
			}
			equal(t, f.pin().Code, 1)
			equal(t, read(t, f.manifest), original)
		})
	}
}
func TestImageInputsRequireOneArm64ServerArtifact(t *testing.T) {
	f := newImageInputs(t)
	q := object(t, read(t, f.qualification))
	q["artifacts"] = q["artifacts"].([]any)[:1]
	write(t, f.qualification, jsonBytes(t, q), 0600)
	r := f.pin()
	equal(t, r.Code, 1)
	contains(t, r.Stderr, "must list one tb-server-linux-arm64")
}

func TestImageInputsPinPreservesExistingBaseAssetOrder(t *testing.T) {
	f := newImageInputs(t)
	var fields map[string]jsontext.Value
	if err := json.Unmarshal(read(t, f.manifest), &fields); err != nil {
		t.Fatal(err)
	}
	var base map[string]jsontext.Value
	if err := json.Unmarshal(fields["base"], &base); err != nil {
		t.Fatal(err)
	}
	var assets map[string]jsontext.Value
	if err := json.Unmarshal(base["assets"], &assets); err != nil {
		t.Fatal(err)
	}
	reordered := []byte(fmt.Sprintf(`{"ubuntu-cloud-image-keyring.gpg":%s,"ubuntu-SHA256SUMS.gpg":%s,"ubuntu-SHA256SUMS":%s,"base-image.qcow2":%s}`, assets["ubuntu-cloud-image-keyring.gpg"], assets["ubuntu-SHA256SUMS.gpg"], assets["ubuntu-SHA256SUMS"], assets["base-image.qcow2"]))
	raw := jsontext.Value(bytes.Replace(read(t, f.manifest), base["assets"], reordered, 1))
	if err := raw.Indent(jsontext.WithIndent("  ")); err != nil {
		t.Fatal(err)
	}
	write(t, f.manifest, append(raw, '\n'), 0600)
	successful(t, f.tool("check"))
	var before map[string]jsontext.Value
	if err := json.Unmarshal(read(t, f.manifest), &before); err != nil {
		t.Fatal(err)
	}
	successful(t, f.pin())
	var after map[string]jsontext.Value
	if err := json.Unmarshal(read(t, f.manifest), &after); err != nil {
		t.Fatal(err)
	}
	equal(t, after["base"], before["base"])
	successful(t, f.tool("check"))
}
