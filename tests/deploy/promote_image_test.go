package deploy_test

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/image"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/testutil/script"
)

const promoteSource = "5ff44290b67a91c3b27373c6661d778fe6ef8ffc"
const imageTag = "image-" + promoteSource + "-run-11738-attempt-1"
const goTag = "ci-" + promoteSource + "-run-11737"
const baseTag = "image-base-noble-arm64-20260926"
const importedOCID = "ocid1.image.oc1.sa-saopaulo-1.aaaaaaaaimported"

// The fake external commands are implemented in Go and use Go-created fixtures.
func TestPromotionCommand(t *testing.T) {
	i := slices.Index(os.Args, "--")
	if i < 0 {
		return
	}
	kind, args := os.Args[i+1], os.Args[i+2:]
	fixture := os.Getenv("PROMOTE_FIXTURE")
	if fixture == "" {
		t.Fatal("missing fixture")
	}
	fail := func(message string) { fmt.Fprintln(os.Stderr, message); os.Exit(1) }
	appendLog := func(name, line string) {
		f, err := os.OpenFile(filepath.Join(fixture, name), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			fail(err.Error())
		}
		fmt.Fprintln(f, line)
		if err := f.Close(); err != nil {
			fail(err.Error())
		}
	}
	reply := func(data any) {
		b, err := json.Marshal(map[string]any{"data": data})
		if err != nil {
			fail(err.Error())
		}
		fmt.Println(string(b))
	}
	switch kind {
	case "fj":
		appendLog("fj-calls.log", strings.Join(args, " "))
		if args[len(args)-1] == "--help" {
			os.Exit(0)
		}
		switch {
		case slices.Equal(args[:3], []string{"release", "asset", "download"}):
			source := filepath.Join(fixture, "releases", strings.ReplaceAll(args[4], "/", "_"), args[5], args[6])
			b, err := os.ReadFile(source)
			if err != nil {
				fail("asset not found: " + args[5] + "/" + args[6])
			}
			if err := os.WriteFile(args[8], b, 0600); err != nil {
				fail(err.Error())
			}
		case slices.Equal(args[:2], []string{"actions", "run-detail"}):
			b, err := os.ReadFile(filepath.Join(fixture, "run-detail", args[2]+".json"))
			if err != nil {
				fail(err.Error())
			}
			fmt.Println(string(b))
		case slices.Equal(args[:2], []string{"actions", "logs"}):
			b, err := os.ReadFile(filepath.Join(fixture, "logs", args[2]+".txt"))
			if err != nil {
				fail(err.Error())
			}
			fmt.Println(string(b))
		default:
			fail(fmt.Sprintf("unexpected fj call: %q", args))
		}
	case "release":
		if args[0] != "release" {
			fail("expected unified release namespace")
		}
		args = args[1:]
		appendLog("release-calls.log", strings.Join(args, "\x00"))
		if os.Getenv("PROMOTE_FAIL_RELEASE") == args[0] {
			fail("fake " + args[0] + " rejected its inputs")
		}
		if j := slices.Index(args, "--out"); j >= 0 {
			if err := os.WriteFile(args[j+1], []byte(`{"fake":"`+args[0]+`"}`+"\n"), 0600); err != nil {
				fail(err.Error())
			}
		}
		if args[0] == "verify-image" {
			fmt.Println("verified OCI image=fake region=GRU")
		}
	case "oci":
		appendLog("oci-calls.log", strings.Join(args, " "))
		command := strings.Join(args[2:5], " ")
		shapes := filepath.Join(fixture, "oci-shapes.json")
		switch {
		case strings.HasPrefix(command, "compute image list"):
			reply([]any{})
		case strings.HasPrefix(command, "os object head"):
			os.Exit(1)
		case strings.HasPrefix(command, "os object put"):
			fmt.Println("{}")
		case strings.HasPrefix(command, "compute image import"):
			reply(map[string]any{"id": importedOCID, "lifecycle-state": "IMPORTING"})
		case strings.HasPrefix(command, "compute image get"):
			reply(map[string]any{"id": importedOCID, "lifecycle-state": "AVAILABLE", "billable-size-in-gbs": 3})
		case strings.HasPrefix(command, "compute image-capability-schema list"):
			reply([]any{})
		case strings.HasPrefix(command, "compute global-image-capability-schema list"):
			reply([]any{map[string]any{"current-version-name": "v1"}})
		case strings.HasPrefix(command, "compute image-capability-schema create"):
			var schema any
			if err := json.Unmarshal([]byte(args[slices.Index(args, "--schema-data")+1]), &schema); err != nil {
				fail(err.Error())
			}
			reply(map[string]any{"id": "ocid1.schema", "schema-data": schema})
		case strings.HasPrefix(command, "compute image-shape-compatibility-entry list"):
			var data any = []any{}
			if b, err := os.ReadFile(shapes); err == nil {
				if err := json.Unmarshal(b, &data); err != nil {
					fail(err.Error())
				}
			}
			reply(data)
		case strings.HasPrefix(command, "compute image-shape-compatibility-entry add"):
			b := []byte(`[{"shape":"VM.Standard.A1.Flex","ocpu-constraints":{"min":1,"max":4},"memory-constraints":{"min-in-gbs":6,"max-in-gbs":24}}]`)
			if err := os.WriteFile(shapes, b, 0600); err != nil {
				fail(err.Error())
			}
			fmt.Println("{}")
		default:
			fail(fmt.Sprintf("unexpected oci call: %q", args))
		}
	default:
		fail("unexpected shim " + kind)
	}
	os.Exit(0)
}

type promotionFixture struct {
	t                                                  *testing.T
	root, fixture, bin, fj, tool, trust, out, imageDir string
	image, kernel                                      []byte
	manifest                                           map[string]any
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
func newPromotion(t *testing.T) *promotionFixture {
	t.Helper()
	dir := t.TempDir()
	f := &promotionFixture{t: t, root: dir, fixture: filepath.Join(dir, "fixture"), bin: filepath.Join(dir, "bin"), fj: filepath.Join(dir, "fj"), tool: filepath.Join(dir, "ts-orch"), trust: filepath.Join(dir, "trust"), out: filepath.Join(dir, "promotion"), image: []byte("final qcow2 bytes"), kernel: []byte("arm64 kernel")}
	exe := fakeToolBinary(t)
	for path, kind := range map[string]string{f.fj: "fj", f.tool: "release", filepath.Join(f.bin, "oci"): "oci"} {
		write(t, path, []byte("#!/bin/sh\nexec "+shellQuote(exe)+" -test.run=^TestPromotionCommand$ -- "+kind+" \"$@\"\n"), 0755)
	}
	write(t, filepath.Join(f.bin, "virt-cat"), []byte("#!/bin/sh\necho 'virt-cat 1.52.3'\n"), 0755)
	for _, name := range []string{"delegation.json", "image-delegation.json", "root.pub", "leaf.pem"} {
		write(t, filepath.Join(f.trust, name), []byte("fake "+name+"\n"), 0600)
	}
	base, binary, qualification := []byte("base qcow2 bytes"), []byte("orchestrator arm64 binary"), []byte(`{"schema": "terrascale.release.qualification.v1"}`)
	f.manifest = map[string]any{"schema": "terrascale.image.qualification.v2", "source_revision": promoteSource, "source_tree": strings.Repeat("0", 40), "builder": map[string]any{"kind": "ci", "workflow": "image.yml", "job": "build/qualified-gru-arm64-image", "run_id": 11738, "run_number": 713, "job_id": 25300, "run_attempt": 1, "required_final_status": "success"}, "inputs": map[string]any{"path": "deploy/image/image-inputs.json", "sha256": strings.Repeat("1", 64), "manifest": map[string]any{"region": "GRU", "base": map[string]any{"release_tag": baseTag, "oci_image_ocid": "ocid1.image.oc1.sa-saopaulo-1.base", "assets": map[string]any{"base-image.qcow2": map[string]any{"bytes": len(base), "sha256": digest(base)}}}}}, "go_candidate": map[string]any{"release_tag": goTag, "run_id": 11737, "run_number": 712, "qualification_sha256": digest(qualification), "binary_sha256": digest(binary), "binary_bytes": len(binary)}, "kernel": map[string]any{"name": "guest-kernel", "release": "6.8.0-142-generic", "sha256": digest(f.kernel)}, "image": map[string]any{"name": "terrascale-gru-arm64.qcow2", "sha256": digest(f.image), "bytes": len(f.image)}}
	f.writeImage()
	f.writeRelease(goTag, map[string][]byte{"qualification.json": qualification, "terrascale-orchestrator-linux-arm64": binary, "canary-linux-arm64.receipt.json": []byte(`{"signed":"binary"}`)})
	f.writeRelease(baseTag, map[string][]byte{"base-image.qcow2": base})
	f.writeRun("success", "success")
	return f
}
func (f *promotionFixture) writeRelease(tag string, assets map[string][]byte) string {
	dir := filepath.Join(f.fixture, "releases", "TerraScale_ts-orchestrator", tag)
	for name, data := range assets {
		write(f.t, filepath.Join(dir, name), data, 0600)
	}
	return dir
}
func (f *promotionFixture) writeImage() {
	manifest := append(jsonBytes(f.t, f.manifest), '\n')
	sums := ""
	for _, asset := range []struct {
		name string
		data []byte
	}{{"terrascale-gru-arm64.qcow2", f.image}, {"guest-kernel", f.kernel}, {"image-qualification.json", manifest}} {
		sums += digest(asset.data) + "  " + asset.name + "\n"
	}
	f.imageDir = f.writeRelease(imageTag, map[string][]byte{"terrascale-gru-arm64.qcow2": f.image, "guest-kernel": f.kernel, "image-qualification.json": manifest, "SHA256SUMS": []byte(sums)})
	marker := fmt.Sprintf("TS_IMAGE_QUALIFICATION_V1 source_sha=%s run_id=11738 run_number=713 job_id=25300 attempt=1 image_sha256=%s kernel_sha256=%s provenance_sha256=%s tag=%s", promoteSource, digest(f.image), digest(f.kernel), digest(manifest), imageTag)
	write(f.t, filepath.Join(f.fixture, "logs/713.txt"), []byte("job_id=25300\n2026-09-29T16:00:00.1234567Z "+marker+"\n"), 0600)
}
func (f *promotionFixture) writeRun(run, job string) {
	write(f.t, filepath.Join(f.fixture, "run-detail/713.json"), jsonBytes(f.t, map[string]any{"run_id": 11738, "run_number": 713, "head_sha": promoteSource, "workflow": "image.yml", "status": run, "jobs": []any{map[string]any{"id": 25300, "run_id": 11738, "attempt": 1, "name": "build/qualified-gru-arm64-image", "status": job}}}), 0600)
}
func (f *promotionFixture) promote(image []string, env map[string]string, extra ...string) script.Result {
	if image == nil {
		image = []string{"--image-release", imageTag}
	}
	args := append([]string{"image", "promote"}, image...)
	args = append(args, "--out", f.out, "--delegation", filepath.Join(f.trust, "delegation.json"), "--root-key", filepath.Join(f.trust, "root.pub"), "--fj", f.fj, "--release-tool", f.tool)
	args = append(args, extra...)
	environment := map[string]string{"PATH": f.bin + string(os.PathListSeparator) + os.Getenv("PATH"), "PROMOTE_FIXTURE": f.fixture, "PROMOTE_IMPORTED_OCID": importedOCID}
	for k, v := range env {
		environment[k] = v
	}
	return script.Run(f.t, deployRoot(f.t), environment, deployTool(f.t), args...)
}
func (f *promotionFixture) importArgs() []string {
	return []string{"--compartment-id", "ocid1.compartment.oc1..c", "--namespace", "ns", "--bucket", "images"}
}
func (f *promotionFixture) realArgs() []string {
	return append(f.importArgs(), "--signing-key", filepath.Join(f.trust, "leaf.pem"), "--image-delegation", filepath.Join(f.trust, "image-delegation.json"))
}
func (f *promotionFixture) lines(name string) []string {
	b, err := os.ReadFile(filepath.Join(f.fixture, name))
	if os.IsNotExist(err) {
		return []string{}
	}
	if err != nil {
		f.t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
}
func (f *promotionFixture) calls() [][]string {
	var out [][]string
	for _, line := range f.lines("release-calls.log") {
		out = append(out, strings.Split(line, "\x00"))
	}
	return out
}
func (f *promotionFixture) commands() []string {
	var names []string
	for _, call := range f.calls() {
		names = append(names, call[0])
	}
	return names
}
func (f *promotionFixture) receipt() map[string]any {
	return object(f.t, read(f.t, filepath.Join(f.out, "promotion-receipt.json")))
}
func flagValue(t *testing.T, args []string, flag string) string {
	t.Helper()
	i := slices.Index(args, flag)
	if i < 0 || i+1 >= len(args) {
		t.Fatalf("missing %s in %q", flag, args)
	}
	return args[i+1]
}
func (f *promotionFixture) rejected(r script.Result, message string) {
	equal(f.t, r.Code, 1)
	contains(f.t, r.Stderr, message)
	equal(f.t, len(f.lines("oci-calls.log")), 0)
	if slices.Contains(f.commands(), "sign-image") {
		f.t.Fatal("signed rejected image")
	}
	absent(f.t, filepath.Join(f.out, "promotion-receipt.json"))
}
func (f *promotionFixture) reset() {
	if err := os.RemoveAll(f.out); err != nil {
		f.t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(f.fixture, "release-calls.log")); err != nil && !os.IsNotExist(err) {
		f.t.Fatal(err)
	}
}

func TestPromotionCIImageImportedSignedVerifiedAndReceipted(t *testing.T) {
	f := newPromotion(t)
	successful(t, f.promote(nil, nil, f.realArgs()...))
	equal(t, f.commands(), []string{"verify-binary", "image-candidate", "sign-image", "verify-image"})
	calls := f.calls()
	equal(t, flagValue(t, calls[1], "--image-ocid"), importedOCID)
	equal(t, flagValue(t, calls[1], "--base-image-ocid"), "ocid1.image.oc1.sa-saopaulo-1.base")
	equal(t, flagValue(t, calls[1], "--kernel-release"), "6.8.0-142-generic")
	equal(t, flagValue(t, calls[2], "--signing-key"), filepath.Join(f.trust, "leaf.pem"))
	for _, call := range calls[2:] {
		equal(t, flagValue(t, call, "--delegation"), filepath.Join(f.trust, "image-delegation.json"))
	}
	for _, call := range calls[:2] {
		equal(t, flagValue(t, call, "--delegation"), filepath.Join(f.trust, "delegation.json"))
	}
	found := false
	for _, call := range f.lines("oci-calls.log") {
		if strings.Contains(call, " image import from-object ") {
			found = true
		}
	}
	equal(t, found, true)
	r := f.receipt()
	equal(t, r["dry_run"], false)
	imp := r["oci_import"].(map[string]any)
	equal(t, imp["image_id"], importedOCID)
	equal(t, imp["shapes"], []any{"VM.Standard.A1.Flex"})
	image := r["image"].(map[string]any)
	equal(t, image["sha256"], digest(f.image))
	equal(t, image["provenance"].(map[string]any)["release_tag"], imageTag)
	equal(t, r["image_receipt"].(map[string]any)["image_ocid"], importedOCID)
	equal(t, r["tools"].(map[string]any)["fj"].(map[string]any)["sha256"], digest(read(t, f.fj)))
	equal(t, r["outcome"], "promotion complete")
}
func TestPromotionFirstRunWaitsForImageDelegation(t *testing.T) {
	f := newPromotion(t)
	r := f.promote(nil, nil, f.importArgs()...)
	successful(t, r)
	equal(t, f.commands(), []string{"verify-binary", "image-candidate"})
	contains(t, r.Stdout, "--image-ocid "+importedOCID)
	receipt := f.receipt()
	equal(t, receipt["image_receipt"], map[string]any{"awaiting": "root-signed image delegation", "image_ocid": importedOCID})
	equal(t, receipt["outcome"], "imported "+importedOCID+"; awaiting the root-signed image delegation")
	f.reset()
	successful(t, f.promote(nil, nil, f.realArgs()...))
	equal(t, f.commands(), []string{"verify-binary", "image-candidate", "sign-image", "verify-image"})
	equal(t, f.receipt()["outcome"], "promotion complete")
}
func TestPromotionDryRunReadOnlyGates(t *testing.T) {
	f := newPromotion(t)
	successful(t, f.promote(nil, nil, "--dry-run"))
	equal(t, len(f.lines("oci-calls.log")), 0)
	equal(t, f.commands(), []string{"verify-binary", "image-candidate"})
	if !strings.HasPrefix(flagValue(t, f.calls()[1], "--image-ocid"), "ocid1.image.oc1.sa-saopaulo-1.dryrun") {
		t.Fatal("candidate did not use dry-run image OCID")
	}
	receipt := f.receipt()
	equal(t, receipt["dry_run"], true)
	equal(t, receipt["oci_import"].(map[string]any)["skipped"], "dry run")
}
func TestPromotionRejectsInvalidEvidenceBeforeEffects(t *testing.T) {
	for _, tc := range []struct {
		name, message string
		prepare       func(*promotionFixture)
		env           map[string]string
	}{
		{"failed-run", "image.yml run did not succeed", func(f *promotionFixture) { f.writeRun("failure", "success") }, nil},
		{"failed-attempt", "image job did not succeed on this attempt", func(f *promotionFixture) { f.writeRun("success", "failure") }, nil},
		{"missing-marker", "lacks one exact TS_IMAGE_QUALIFICATION_V1 marker", func(f *promotionFixture) {
			write(f.t, filepath.Join(f.fixture, "logs/713.txt"), []byte("no marker\n"), 0600)
		}, nil},
		{"tampered-image", "image asset differs from SHA256SUMS: terrascale-gru-arm64.qcow2", func(f *promotionFixture) {
			write(f.t, filepath.Join(f.imageDir, "terrascale-gru-arm64.qcow2"), []byte("tampered"), 0600)
		}, nil},
		{"wrong-binary", "candidate release " + goTag + " differs from the image manifest", func(f *promotionFixture) {
			f.writeRelease(goTag, map[string][]byte{"terrascale-orchestrator-linux-arm64": []byte("other")})
		}, nil},
		{"rejected-receipt", "ts-orch release verify-binary failed", func(*promotionFixture) {}, map[string]string{"PROMOTE_FAIL_RELEASE": "verify-binary"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newPromotion(t)
			tc.prepare(f)
			f.rejected(f.promote(nil, tc.env, f.realArgs()...), tc.message)
		})
	}
}
func TestPromotionUnsignedCandidateRequiresSignBinary(t *testing.T) {
	f := newPromotion(t)
	if err := os.Remove(filepath.Join(f.fixture, "releases/TerraScale_ts-orchestrator", goTag, "canary-linux-arm64.receipt.json")); err != nil {
		t.Fatal(err)
	}
	f.rejected(f.promote(nil, nil, f.realArgs()...), "pass --sign-binary")
	f.reset()
	successful(t, f.promote(nil, nil, "--dry-run"))
	equal(t, f.commands(), []string{"binary-candidate"})
	equal(t, f.receipt()["candidate"].(map[string]any)["binary_receipt"], "missing: sign with --sign-binary")
	f.reset()
	successful(t, f.promote(nil, nil, append(f.realArgs(), "--sign-binary")...))
	equal(t, flagValue(t, f.calls()[1], "--delegation"), filepath.Join(f.trust, "delegation.json"))
	equal(t, f.commands(), []string{"binary-candidate", "sign-binary", "verify-binary", "image-candidate", "sign-image", "verify-image"})
}
func TestPromotionLocalImageWithoutCIEvidence(t *testing.T) {
	f := newPromotion(t)
	f.manifest["builder"] = map[string]any{"kind": "local", "user": "operator", "host": "dev"}
	f.writeImage()
	successful(t, f.promote([]string{"--image-dir", f.imageDir}, nil, "--dry-run"))
	for _, call := range f.lines("fj-calls.log") {
		if strings.Contains(call, "actions run-detail 713") {
			t.Fatal("local image requested CI evidence")
		}
	}
	equal(t, f.receipt()["image"].(map[string]any)["provenance"].(map[string]any)["builder"].(map[string]any)["kind"], "local")
}
func TestPromotionRequiresOCITargetsAndSigning(t *testing.T) {
	f := newPromotion(t)
	r := f.promote(nil, nil)
	equal(t, r.Code, 2)
	contains(t, r.Stderr, "an OCI import needs --compartment-id, --namespace, --bucket")
	r = f.promote(nil, nil, append(f.importArgs(), "--image-delegation", filepath.Join(f.trust, "image-delegation.json"))...)
	equal(t, r.Code, 2)
	contains(t, r.Stderr, "need --signing-key")
}
func TestPromotionRejectsUnpinnedForgejo(t *testing.T) {
	f := newPromotion(t)
	write(t, f.fj, []byte("#!/bin/sh\nexit 1\n"), 0755)
	r := f.promote(nil, nil, "--dry-run")
	equal(t, r.Code, 1)
	contains(t, r.Stderr, "lacks the pinned `fj actions run-detail` extension")
}

func promotionBuild(t *testing.T, unified bool, revision string, modified, failure bool) (string, map[string]any) {
	t.Helper()
	work := t.TempDir()
	calls := []any{}
	marker, contents := "cmd/ts-release/main.go", "#!/bin/sh\n[ \"$1\" = verify-binary ]\n"
	if unified {
		marker = "internal/release/cli/run.go"
		contents = "#!/bin/sh\n[ \"$1\" = release ] && [ \"$2\" = verify-binary ]\n"
	}
	runner := func(ctx context.Context, dir string, env []string, command ...string) (string, error) {
		args := make([]any, len(command))
		for i, a := range command {
			args[i] = a
		}
		calls = append(calls, map[string]any{"command": args, "cwd": dir})
		switch command[0] {
		case "git":
			if command[3] == "worktree" && command[4] == "add" {
				write(t, filepath.Join(work, "source", marker), []byte("pinned source entry point"), 0644)
			} else if command[3] == "worktree" && command[4] == "remove" {
				if err := os.RemoveAll(filepath.Join(work, "source")); err != nil {
					t.Fatal(err)
				}
			}
		case "nice":
			if failure {
				return "", errors.New("build failed")
			}
			path := command[slices.Index(command, "-o")+1]
			write(t, path, []byte(contents), 0755)
		case "go":
			return fmt.Sprintf("vcs.revision=%s\nvcs.modified=%t\n", revision, modified), nil
		default:
			return "", fmt.Errorf("unexpected command %q", command)
		}
		return "", nil
	}
	tool, prefix, record, err := image.BuildReleaseTool(t.Context(), deployRoot(t), work, promoteSource, "", runner)
	p := make([]any, len(prefix))
	for i, a := range prefix {
		p[i] = a
	}
	tools := map[string]any{}
	if record != nil {
		tools["ts_release"] = record
	}
	r := map[string]any{"calls": calls, "tool": tool, "prefix": p, "receipt": map[string]any{"tools": tools}, "error": nil}
	if err != nil {
		r["error"] = map[string]any{"message": err.Error()}
	}
	absent(t, filepath.Join(work, "source"))
	return work, r
}
func TestPromotionAutomaticBuildSelectsPinnedCommands(t *testing.T) {
	for _, unified := range []bool{false, true} {
		t.Run(fmt.Sprintf("unified=%t", unified), func(t *testing.T) {
			work, r := promotionBuild(t, unified, promoteSource, false, false)
			equal(t, r["error"], nil)
			wantTarget, wantName, prefix := "./cmd/ts-release", "ts-release", []any{}
			if unified {
				wantTarget, wantName, prefix = "./cmd/terrascale-orchestrator", "ts-orch", []any{"release"}
			}
			equal(t, r["prefix"], prefix)
			tool := r["tool"].(string)
			equal(t, filepath.Base(tool), wantName)
			var build []any
			var foundWorktree bool
			for _, entry := range r["calls"].([]any) {
				call := entry.(map[string]any)
				cmd := call["command"].([]any)
				if cmd[0] == "nice" {
					build = cmd
					equal(t, call["cwd"], filepath.Join(work, "source"))
				}
				if len(cmd) > 4 && cmd[3] == "worktree" && cmd[4] == "add" {
					equal(t, cmd[len(cmd)-1], promoteSource)
					foundWorktree = true
				}
			}
			equal(t, foundWorktree, true)
			if build == nil {
				t.Fatal("no build command")
			}
			equal(t, build[len(build)-1], wantTarget)
			if !slices.Contains(build, any("-trimpath")) || !slices.Contains(build, any("-buildvcs=true")) {
				t.Fatalf("missing build metadata flags: %q", build)
			}
			args := []string{"verify-binary"}
			if unified {
				args = append([]string{"release"}, args...)
			}
			successful(t, script.Run(t, work, nil, tool, args...))
			equal(t, r["receipt"].(map[string]any)["tools"].(map[string]any)["ts_release"].(map[string]any)["sha256"], digest(read(t, tool)))
		})
	}
}
func TestPromotionAutomaticBuildRejectsDirtyOrWrongRevision(t *testing.T) {
	for _, unified := range []bool{false, true} {
		for _, tc := range []struct {
			revision string
			modified bool
		}{{strings.Repeat("0", 40), false}, {promoteSource, true}} {
			t.Run(fmt.Sprintf("unified=%t/revision=%s/modified=%t", unified, tc.revision, tc.modified), func(t *testing.T) {
				_, r := promotionBuild(t, unified, tc.revision, tc.modified, false)
				e := r["error"].(map[string]any)

				contains(t, e["message"].(string), "clean image source revision")
				equal(t, r["receipt"].(map[string]any)["tools"], map[string]any{})
			})
		}
	}
}
func TestPromotionFailedBuildRemovesSourceWorktree(t *testing.T) {
	_, r := promotionBuild(t, true, promoteSource, false, true)
	contains(t, r["error"].(map[string]any)["message"].(string), "build failed")
}
func (f *promotionFixture) countCalls(log, needle string) int {
	count := 0
	for _, line := range f.lines(log) {
		if strings.Contains(line, needle) {
			count++
		}
	}
	return count
}
func TestPromotionResumeReusesVerifiedWork(t *testing.T) {
	f := newPromotion(t)
	successful(t, f.promote(nil, nil, f.importArgs()...))
	large := []string{" terrascale-gru-arm64.qcow2 ", " base-image.qcow2 ", " terrascale-orchestrator-linux-arm64 "}
	for _, asset := range large {
		equal(t, f.countCalls("fj-calls.log", asset), 1)
	}
	equal(t, f.countCalls("oci-calls.log", " image import from-object "), 1)
	r := f.promote(nil, nil, f.realArgs()...)
	equal(t, r.Code, 2)
	contains(t, r.Stderr, "or pass --resume")

	r = f.promote(nil, nil, append(f.realArgs(), "--resume")...)
	successful(t, r)
	for _, asset := range large {
		equal(t, f.countCalls("fj-calls.log", asset), 1)
	}
	equal(t, f.countCalls("oci-calls.log", " image import from-object "), 1)
	contains(t, r.Stdout, "reusing completed OCI import")
	contains(t, r.Stdout, "reusing verified terrascale-gru-arm64.qcow2")
	equal(t, f.commands(), []string{"verify-binary", "image-candidate", "verify-binary", "image-candidate", "sign-image", "verify-image"})
	receipt := f.receipt()
	equal(t, receipt["resumed"], true)
	equal(t, receipt["outcome"], "promotion complete")
	equal(t, receipt["oci_import"].(map[string]any)["image_id"], importedOCID)
}
func TestPromotionResumeRefetchesChangedAssetsAndRefusesOtherImages(t *testing.T) {
	f := newPromotion(t)
	successful(t, f.promote(nil, nil, f.importArgs()...))
	write(t, filepath.Join(f.out, "base-image.qcow2"), []byte("corrupted"), 0600)
	successful(t, f.promote(nil, nil, append(f.realArgs(), "--resume")...))
	equal(t, f.countCalls("fj-calls.log", " base-image.qcow2 "), 2)
	equal(t, f.countCalls("fj-calls.log", " terrascale-gru-arm64.qcow2 "), 1)

	state := filepath.Join(f.out, "promotion-state.json")
	write(t, state, []byte(`{"image_release":"image-`+strings.Repeat("1", 40)+`-run-1-attempt-1","schema":"terrascale.image.promotion-state.v1"}`), 0600)
	r := f.promote(nil, nil, append(f.realArgs(), "--resume")...)
	equal(t, r.Code, 1)
	contains(t, r.Stderr, "belongs to a different promotion")
}
