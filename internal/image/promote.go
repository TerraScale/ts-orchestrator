package image

import (
	"context"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociregion/imageimport"

	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
)

const repository = "TerraScale/ts-orchestrator"

var imageAssets = []string{"terrascale-gru-arm64.qcow2", "guest-kernel", "image-qualification.json", "SHA256SUMS"}

const orchestratorAsset = "terrascale-orchestrator-linux-arm64"

type PromotionOptions struct {
	ImageRelease, ImageDir, Out, Environment, Delegation, ImageDelegation, RootKey, BinaryReceipt, SigningKey, CompartmentID, Namespace, Bucket, DisplayName, FJ, ReleaseTool string
	SignBinary, DryRun, Resume                                                                                                                                                bool
	// Importer builds the OCI image importer; nil uses the in-binary SDK
	// over the operator's ~/.oci/config. It is not a flag.
	Importer imageimport.ImporterFactory
}

// promotionState pins a resumable --out directory to one image, so a rerun
// can never mix the assets of two promotions.
type promotionState struct {
	Schema       string `json:"schema"`
	ImageRelease string `json:"image_release,omitempty"`
	ImageDir     string `json:"image_dir,omitempty"`
	ImageSHA256  string `json:"image_sha256,omitempty"`
}

const (
	promotionStateFile  = "promotion-state.json"
	promotionStateV1    = "terrascale.image.promotion-state.v1"
	releaseToolDir      = "release-tool"
	releaseToolRecord   = "release-tool.json"
	releaseToolRecordV1 = "terrascale.image.release-tool.v1"
)

type imageManifest struct {
	Schema         string `json:"schema"`
	SourceRevision string `json:"source_revision"`
	SourceTree     string `json:"source_tree"`
	Builder        struct {
		Kind      string `json:"kind"`
		RunID     int64  `json:"run_id"`
		RunNumber int64  `json:"run_number"`
		JobID     int64  `json:"job_id"`
		Attempt   int64  `json:"run_attempt"`
	} `json:"builder"`
	Inputs struct {
		Manifest Inputs `json:"manifest"`
	} `json:"inputs"`
	Candidate struct {
		Tag                 string `json:"release_tag"`
		QualificationSHA256 string `json:"qualification_sha256"`
		BinarySHA256        string `json:"binary_sha256"`
	} `json:"go_candidate"`
	Image struct {
		SHA256 string `json:"sha256"`
	} `json:"image"`
	Kernel struct {
		SHA256  string `json:"sha256"`
		Release string `json:"release"`
	} `json:"kernel"`
}

// BuildReleaseTool builds the source-specific signer and always removes its worktree.
// Historical image revisions keep the command prefix their source implements.
func BuildReleaseTool(ctx context.Context, root, work, source, prebuilt string, run Exec) (tool string, prefix []string, record map[string]any, result error) {
	prefix = []string{"release"}
	if run == nil {
		run = Execute
	}
	if prebuilt != "" {
		tool, result = filepath.Abs(prebuilt)
		if result != nil {
			return
		}
	} else {
		if !gitSHA.MatchString(source) {
			result = errors.New("invalid image source revision")
			return
		}
		// go build runs inside the source worktree: a relative -o would
		// land in (and be removed with) that worktree.
		if work, result = filepath.Abs(work); result != nil {
			return
		}
		checkout := filepath.Join(work, "source")
		if _, result = run(ctx, "", nil, "git", "-C", root, "fetch", "--quiet", "origin", "main"); result != nil {
			return
		}
		if _, result = run(ctx, "", nil, "git", "-C", root, "worktree", "add", "--quiet", "--detach", checkout, source); result != nil {
			return
		}
		func() {
			defer func() {
				cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
				defer cancel()
				_, cleanupErr := run(cleanupCtx, "", nil, "git", "-C", root, "worktree", "remove", "--force", checkout)
				result = errors.Join(result, cleanupErr)
			}()
			target := "./cmd/ts-release"
			name := "ts-release"
			prefix = []string{}
			if s, e := os.Stat(filepath.Join(checkout, "internal/release/cli/run.go")); e == nil && s.Mode().IsRegular() {
				target = "./cmd/terrascale-orchestrator"
				name = "ts-orch"
				prefix = []string{"release"}
			}
			tool = filepath.Join(work, name)
			_, result = run(ctx, checkout, nil, "nice", "-n", "19", "go", "build", "-trimpath", "-buildvcs=true", "-o", tool, target)
		}()
		if result != nil {
			return
		}
		var metadata string
		metadata, result = run(ctx, "", nil, "go", "version", "-m", tool)
		if result != nil {
			return
		}
		if !strings.Contains(metadata, "vcs.revision="+source) || !strings.Contains(metadata, "vcs.modified=false") {
			result = errors.New("release tool was not built from the clean image source revision")
			return
		}
	}
	s, e := os.Stat(tool)
	if e != nil || !s.Mode().IsRegular() || s.Mode().Perm()&0111 == 0 {
		result = fmt.Errorf("release tool is not executable: %s", tool)
		return
	}
	digest, e := fileHash(tool)
	if e != nil {
		result = e
		return
	}
	record = map[string]any{"path": tool, "sha256": digest}
	return
}

type promotion struct {
	ctx           context.Context
	root, work    string
	o             PromotionOptions
	out           io.Writer
	fj            string
	receipt       map[string]any
	manifest      imageManifest
	raw           map[string]any
	releasePrefix []string
}

func (p *promotion) step(message string) { fmt.Fprintln(p.out, "promote-image:", message) }
func (p *promotion) run(capture bool, command ...string) (string, error) {
	env := append(os.Environ(), "PATH="+filepath.Join(p.work, "bin")+string(os.PathListSeparator)+os.Getenv("PATH"))
	out, e := Execute(p.ctx, "", env, command...)
	if e != nil {
		action := ""
		if len(command) > 1 {
			action = command[1]
		}
		if (action == "release" || action == "bootstrap") && len(command) > 2 {
			action += " " + command[2]
		}
		return "", fmt.Errorf("%s %s failed: %w", filepath.Base(command[0]), action, e)
	}
	if !capture && out != "" {
		fmt.Fprintln(p.out, out)
	}
	return out, nil
}

// fetch downloads asset unless a resumed promotion already holds a file
// whose SHA-256 equals the expected pinned digest. Every caller still
// verifies the digest of whatever file it ends up using.
func (p *promotion) fetch(tag, asset, destination, expected string) (string, error) {
	if p.o.Resume && expected != "" {
		if digest, e := fileHash(destination); e == nil && digest == expected {
			p.step("reusing verified " + asset)
			return destination, nil
		}
	}
	return p.download(tag, asset, destination)
}
func (p *promotion) download(tag, asset, destination string) (string, error) {
	if e := os.MkdirAll(filepath.Dir(destination), 0755); e != nil {
		return "", e
	}
	_, e := p.run(true, p.fj, "release", "asset", "download", "-r", repository, tag, asset, "-o", destination)
	return destination, e
}
func (p *promotion) acquireImage() error {
	imageDir := filepath.Join(p.o.Out, "image")
	if p.o.ImageRelease != "" {
		if !regexp.MustCompile(`^image-[0-9a-f]{40}-run-[1-9][0-9]*-attempt-[1-9][0-9]*$`).MatchString(p.o.ImageRelease) {
			return fmt.Errorf("not an image release tag: %s", p.o.ImageRelease)
		}
		// SHA256SUMS is small and always fresh; it pins the large assets a
		// resumed promotion may reuse.
		if _, e := p.download(p.o.ImageRelease, imageAssets[3], filepath.Join(imageDir, imageAssets[3])); e != nil {
			return e
		}
		pinned, e := readImageSums(filepath.Join(imageDir, imageAssets[3]))
		if e != nil {
			return e
		}
		for _, asset := range imageAssets[:3] {
			if _, e := p.fetch(p.o.ImageRelease, asset, filepath.Join(imageDir, asset), pinned[asset]); e != nil {
				return e
			}
		}
	} else {
		mkdir := os.Mkdir
		if p.o.Resume {
			mkdir = os.MkdirAll
		}
		if e := mkdir(imageDir, 0755); e != nil {
			return e
		}
		for _, asset := range imageAssets {
			src := filepath.Join(p.o.ImageDir, asset)
			if s, e := os.Stat(src); e != nil || !s.Mode().IsRegular() {
				return fmt.Errorf("local image directory lacks %s", asset)
			}
			if e := copyFile(src, filepath.Join(imageDir, asset), 0644); e != nil {
				return e
			}
		}
	}
	sums, e := readImageSums(filepath.Join(imageDir, "SHA256SUMS"))
	if e != nil {
		return e
	}
	for _, asset := range imageAssets[:3] {
		digest := sums[asset]
		observed, e := fileHash(filepath.Join(imageDir, asset))
		if e != nil {
			return e
		}
		if observed != digest {
			return fmt.Errorf("image asset differs from SHA256SUMS: %s", asset)
		}
	}
	manifestPath := filepath.Join(imageDir, "image-qualification.json")
	if e = readJSON(manifestPath, &p.manifest); e != nil {
		return e
	}
	if e = readJSON(manifestPath, &p.raw); e != nil {
		return e
	}
	m := p.manifest
	if m.Schema != "terrascale.image.qualification.v2" {
		return errors.New("unsupported image manifest schema")
	}
	if m.Image.SHA256 != sums[imageAssets[0]] || m.Kernel.SHA256 != sums[imageAssets[1]] {
		return errors.New("image manifest digests differ from SHA256SUMS")
	}
	if !gitSHA.MatchString(m.SourceRevision) || !gitSHA.MatchString(m.SourceTree) {
		return errors.New("image manifest source must be a full lowercase Git SHA")
	}
	provenance := map[string]any{"manifest_sha256": sums[imageAssets[2]], "builder": p.raw["builder"]}
	if p.o.ImageRelease != "" {
		builder := m.Builder
		if builder.Kind != "ci" {
			return errors.New("an image release must come from image.yml")
		}
		tag := fmt.Sprintf("image-%s-run-%d-attempt-%d", m.SourceRevision, builder.RunID, builder.Attempt)
		if tag != p.o.ImageRelease {
			return errors.New("image release tag differs from its manifest")
		}
		detail, e := p.run(true, p.fj, "actions", "run-detail", strconv.FormatInt(builder.RunNumber, 10), "-r", repository)
		if e != nil {
			return e
		}
		var run struct {
			RunID            int64 `json:"run_id"`
			Workflow, Status string
			Jobs             []struct {
				ID           int64 `json:"id"`
				Name, Status string
				Attempt      int64 `json:"attempt"`
			}
		}
		if e = json.Unmarshal([]byte(detail), &run, json.MatchCaseInsensitiveNames(true)); e != nil {
			return e
		}
		if run.RunID != builder.RunID || run.Workflow != "image.yml" || run.Status != "success" {
			return errors.New("image.yml run did not succeed")
		}
		jobs := 0
		for _, j := range run.Jobs {
			if j.ID == builder.JobID {
				jobs++
				if j.Name != "build/qualified-gru-arm64-image" || j.Status != "success" || j.Attempt != builder.Attempt {
					return errors.New("image job did not succeed on this attempt")
				}
			}
		}
		if jobs != 1 {
			return errors.New("image job did not succeed on this attempt")
		}
		marker := fmt.Sprintf("TS_IMAGE_QUALIFICATION_V1 source_sha=%s run_id=%d run_number=%d job_id=%d attempt=%d image_sha256=%s kernel_sha256=%s provenance_sha256=%s tag=%s", m.SourceRevision, builder.RunID, builder.RunNumber, builder.JobID, builder.Attempt, m.Image.SHA256, m.Kernel.SHA256, sums[imageAssets[2]], tag)
		logs, e := p.run(true, p.fj, "actions", "logs", strconv.FormatInt(builder.RunNumber, 10), "-r", repository)
		if e != nil {
			return e
		}
		matches := 0
		for line := range strings.SplitSeq(logs, "\n") {
			_, text, ok := strings.Cut(strings.TrimSuffix(line, "\r"), " ")
			if ok && text == marker {
				matches++
			}
		}
		if matches != 1 {
			return errors.New("image job log lacks one exact TS_IMAGE_QUALIFICATION_V1 marker")
		}
		provenance["release_tag"] = tag
		provenance["job_log_marker"] = marker
		p.step(fmt.Sprintf("image release verified tag=%s run=%d attempt=%d", tag, builder.RunID, builder.Attempt))
	} else {
		source, e := filepath.Abs(p.o.ImageDir)
		if e != nil {
			return e
		}
		provenance["image_dir"] = source
		p.step(fmt.Sprintf("local image verified builder=%s source=%s", m.Builder.Kind, m.SourceRevision))
	}
	rawImage, ok := p.raw["image"].(map[string]any)
	if !ok {
		return errors.New("invalid image metadata")
	}
	imageRecord := map[string]any{}
	for k, v := range rawImage {
		imageRecord[k] = v
	}
	imageRecord["kernel"] = p.raw["kernel"]
	imageRecord["source_revision"] = m.SourceRevision
	imageRecord["source_tree"] = m.SourceTree
	imageRecord["provenance"] = provenance
	p.receipt["image"] = imageRecord
	return nil
}

// readImageSums parses SHA256SUMS, which must list exactly the image,
// kernel and manifest.
func readImageSums(path string) (map[string]string, error) {
	invalid := errors.New("SHA256SUMS must list exactly the image, kernel and manifest")
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	sums := map[string]string{}
	for line := range strings.SplitSeq(strings.TrimSuffix(string(b), "\n"), "\n") {
		digest, name, ok := strings.Cut(line, "  ")
		if !ok || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(digest) {
			return nil, invalid
		}
		if _, exists := sums[name]; exists {
			return nil, invalid
		}
		sums[name] = digest
	}
	if len(sums) != 3 {
		return nil, invalid
	}
	for _, asset := range imageAssets[:3] {
		if _, ok := sums[asset]; !ok {
			return nil, invalid
		}
	}
	return sums, nil
}

// checkResumeState refuses to resume an --out directory that belongs to a
// different image release, directory or image digest, then records the pin.
func (p *promotion) checkResumeState(imageSHA256 string) error {
	path := filepath.Join(p.o.Out, promotionStateFile)
	want := promotionState{Schema: promotionStateV1, ImageRelease: p.o.ImageRelease, ImageSHA256: imageSHA256}
	if p.o.ImageDir != "" {
		source, e := filepath.Abs(p.o.ImageDir)
		if e != nil {
			return e
		}
		want.ImageDir = source
	}
	var existing promotionState
	if e := readJSON(path, &existing); e == nil {
		if existing.Schema != promotionStateV1 || existing.ImageRelease != want.ImageRelease || existing.ImageDir != want.ImageDir ||
			imageSHA256 != "" && existing.ImageSHA256 != "" && existing.ImageSHA256 != imageSHA256 {
			return fmt.Errorf("--out %s belongs to a different promotion; use a new directory", p.o.Out)
		}
		if imageSHA256 == "" {
			return nil
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	b, e := canonical(want)
	if e != nil {
		return e
	}
	return writeCheckpoint(path, b)
}

// writeCheckpoint publishes a resume checkpoint through a synced temporary
// file and an atomic rename, so an interruption leaves either the previous
// or the new checkpoint and never a truncated one. An identical checkpoint
// is not rewritten.
func writeCheckpoint(path string, b []byte) error {
	if existing, e := os.ReadFile(path); e == nil && string(existing) == string(b) {
		return nil
	}
	temporary, e := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-")
	if e != nil {
		return e
	}
	defer os.Remove(temporary.Name())
	if _, e = temporary.Write(b); e == nil {
		e = temporary.Sync()
	}
	if e == nil {
		e = temporary.Chmod(0644)
	}
	if closeErr := temporary.Close(); e == nil {
		e = closeErr
	}
	if e != nil {
		return e
	}
	if e = os.Rename(temporary.Name(), path); e != nil {
		return e
	}
	dir, e := os.Open(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer dir.Close()
	return dir.Sync()
}

// freshOutput makes path available to a generating release command, which
// never overwrites its --out. On --resume an output an earlier run left
// behind is moved aside (kept for audit) and regenerated from the verified
// inputs; without --resume --out is new, so an existing file is an error.
func (p *promotion) freshOutput(path string) error {
	s, e := os.Lstat(path)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	if !p.o.Resume || !s.Mode().IsRegular() {
		return fmt.Errorf("promotion output already exists: %s", path)
	}
	aside := fmt.Sprintf("%s.superseded-%d", path, time.Now().UnixNano())
	p.step("regenerating " + filepath.Base(path) + "; the earlier one is kept as " + filepath.Base(aside))
	return os.Rename(path, aside)
}

// reuseReleaseTool returns the signer recorded by an earlier run of a resumed
// promotion when its bytes still match the recorded digest and it was built
// from the clean image source revision.
func reuseReleaseTool(ctx context.Context, dir, source string, run Exec) (string, []string, map[string]any, bool) {
	if run == nil {
		run = Execute
	}
	var recorded struct {
		Schema         string   `json:"schema"`
		Path           string   `json:"path"`
		SHA256         string   `json:"sha256"`
		SourceRevision string   `json:"source_revision"`
		Prefix         []string `json:"prefix"`
	}
	if readJSON(filepath.Join(dir, releaseToolRecord), &recorded) != nil || recorded.Schema != releaseToolRecordV1 ||
		recorded.SourceRevision != source || filepath.Dir(filepath.Dir(recorded.Path)) != dir ||
		!strings.HasPrefix(filepath.Base(filepath.Dir(recorded.Path)), "build-") {
		return "", nil, nil, false
	}
	digest, e := fileHash(recorded.Path)
	if e != nil || digest != recorded.SHA256 {
		return "", nil, nil, false
	}
	metadata, e := run(ctx, "", nil, "go", "version", "-m", recorded.Path)
	if e != nil || !strings.Contains(metadata, "vcs.revision="+source) || !strings.Contains(metadata, "vcs.modified=false") {
		return "", nil, nil, false
	}
	return recorded.Path, recorded.Prefix, map[string]any{"path": recorded.Path, "sha256": digest, "reused": true}, true
}

func recordReleaseTool(dir, source string, prefix []string, record map[string]any) error {
	b, e := canonical(map[string]any{"schema": releaseToolRecordV1, "path": record["path"], "sha256": record["sha256"],
		"source_revision": source, "prefix": prefix})
	if e != nil {
		return e
	}
	return os.WriteFile(filepath.Join(dir, releaseToolRecord), b, 0644)
}

type candidateFiles struct{ qualification, binary, receipt, base string }

func (p *promotion) acquireCandidate() (candidateFiles, error) {
	var files candidateFiles
	c := p.manifest.Candidate
	dir := filepath.Join(p.o.Out, "candidate")
	var e error
	if files.qualification, e = p.fetch(c.Tag, "qualification.json", filepath.Join(dir, "qualification.json"), c.QualificationSHA256); e != nil {
		return files, e
	}
	if files.binary, e = p.fetch(c.Tag, orchestratorAsset, filepath.Join(dir, orchestratorAsset), c.BinarySHA256); e != nil {
		return files, e
	}
	qd, e := fileHash(files.qualification)
	if e != nil {
		return files, e
	}
	bd, e := fileHash(files.binary)
	if e != nil {
		return files, e
	}
	if qd != c.QualificationSHA256 || bd != c.BinarySHA256 {
		return files, fmt.Errorf("candidate release %s differs from the image manifest", c.Tag)
	}
	files.receipt = filepath.Join(dir, "binary.receipt.json")
	if p.o.BinaryReceipt != "" {
		if e = copyFile(p.o.BinaryReceipt, files.receipt, 0644); e != nil {
			return files, e
		}
	} else {
		if _, e = p.download(c.Tag, p.o.Environment+"-linux-arm64.receipt.json", files.receipt); e != nil {
			os.Remove(files.receipt)
			files.receipt = ""
			// A resumed promotion reuses the receipt it signed earlier;
			// verify-binary still checks it against the exact binary.
			signed := filepath.Join(p.o.Out, "binary.receipt.json")
			if s, statErr := os.Stat(signed); p.o.Resume && statErr == nil && s.Mode().IsRegular() {
				files.receipt = signed
				p.step("reusing signed binary receipt")
			}
		}
	}
	base := p.manifest.Inputs.Manifest.Base
	if files.base, e = p.fetch(base.ReleaseTag, "base-image.qcow2", filepath.Join(p.o.Out, "base-image.qcow2"), base.Assets.Base.SHA256); e != nil {
		return files, e
	}
	digest, e := fileHash(files.base)
	if e != nil {
		return files, e
	}
	if digest != base.Assets.Base.SHA256 {
		return files, errors.New("base QCOW2 differs from the image inputs pin")
	}
	p.receipt["candidate"] = p.raw["go_candidate"]
	p.receipt["base"] = map[string]any{"release_tag": base.ReleaseTag, "oci_image_ocid": base.OCIImageOCID, "sha256": base.Assets.Base.SHA256}
	p.step(fmt.Sprintf("candidate verified tag=%s binary_sha256=%s", c.Tag, c.BinarySHA256))
	return files, nil
}
func (p *promotion) finish(outcome string) error {
	p.receipt["outcome"] = outcome
	p.receipt["finished_at"] = time.Now().UTC().Format(time.RFC3339)
	b, e := canonical(p.receipt)
	if e != nil {
		return e
	}
	path := filepath.Join(p.o.Out, "promotion-receipt.json")
	if e = os.WriteFile(path, b, 0644); e != nil {
		return e
	}
	digest, e := fileHash(path)
	if e != nil {
		return e
	}
	p.step(fmt.Sprintf("%s; receipt %s sha256=%s", outcome, path, digest))
	return nil
}
func Promote(ctx context.Context, root string, o PromotionOptions, out io.Writer) error {
	// The release tool is built with its working directory in a source
	// worktree, so every path derived from --out must be absolute.
	absoluteOut, e := filepath.Abs(o.Out)
	if e != nil {
		return e
	}
	o.Out = absoluteOut
	work, e := os.MkdirTemp("", "ts-promote-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(work)
	p := &promotion{ctx: ctx, root: root, work: work, o: o, out: out}
	fj := o.FJ
	if fj == "" {
		fj = os.Getenv("TS_FJ")
	}
	if fj == "" {
		home, e := os.UserHomeDir()
		if e != nil {
			return e
		}
		fj = filepath.Join(home, ".local/share/terrascale-controller-bootstrap-20260927/fj-admission-pinned-7f44ff1a/bin/fj")
	}
	s, e := os.Stat(fj)
	if e != nil || !s.Mode().IsRegular() || s.Mode().Perm()&0111 == 0 {
		return fmt.Errorf("pinned fj not found: %s (--fj)", fj)
	}
	for _, command := range []string{"run-detail", "logs"} {
		if _, e = Execute(ctx, "", nil, fj, "actions", command, "--help"); e != nil {
			return fmt.Errorf("%s lacks the pinned `fj actions %s` extension", fj, command)
		}
	}
	p.fj, e = filepath.Abs(fj)
	if e != nil {
		return e
	}
	digest, e := fileHash(p.fj)
	if e != nil {
		return e
	}
	tools := map[string]any{"fj": map[string]any{"path": p.fj, "sha256": digest}}
	p.receipt = map[string]any{"schema": "terrascale.image.promotion.v1", "dry_run": o.DryRun, "started_at": time.Now().UTC().Format(time.RFC3339), "environment": o.Environment, "tools": tools}
	if o.Resume {
		p.receipt["resumed"] = true
		if e = os.MkdirAll(o.Out, 0755); e != nil {
			return e
		}
		if e = p.checkResumeState(""); e != nil {
			return e
		}
	} else if e = os.Mkdir(o.Out, 0755); e != nil {
		return e
	}
	if e = os.Mkdir(filepath.Join(work, "bin"), 0755); e != nil {
		return e
	}
	if e = os.Symlink(p.fj, filepath.Join(work, "bin/fj")); e != nil {
		return e
	}
	virtCat, e := exec.LookPath("virt-cat")
	if e != nil {
		return errors.New("virt-cat is required; run under deploy/image/tools.sh")
	}
	version, e := p.run(true, virtCat, "--version")
	if e != nil {
		return e
	}
	tools["virt_cat"] = map[string]any{"path": virtCat, "version": version}
	if e = p.acquireImage(); e != nil {
		return e
	}
	if e = p.checkResumeState(p.manifest.Image.SHA256); e != nil {
		return e
	}
	files, e := p.acquireCandidate()
	if e != nil {
		return e
	}
	// Build the signer inside --out so a rerun can reuse it by digest.
	toolDir := filepath.Join(o.Out, releaseToolDir)
	tool, prefix, record, reused := "", []string(nil), map[string]any(nil), false
	if o.ReleaseTool == "" && o.Resume {
		tool, prefix, record, reused = reuseReleaseTool(ctx, toolDir, p.manifest.SourceRevision, nil)
	}
	if !reused {
		buildDir := toolDir
		if o.ReleaseTool == "" {
			if e = os.MkdirAll(toolDir, 0755); e != nil {
				return e
			}
			// A fresh build directory per attempt: an interrupted earlier
			// run may have left its source worktree behind, and git refuses
			// to add a worktree at an existing path.
			if buildDir, e = os.MkdirTemp(toolDir, "build-"); e != nil {
				return e
			}
		}
		if tool, prefix, record, e = BuildReleaseTool(ctx, root, buildDir, p.manifest.SourceRevision, o.ReleaseTool, nil); e != nil {
			return e
		}
		if o.ReleaseTool == "" {
			if e = recordReleaseTool(toolDir, p.manifest.SourceRevision, prefix, record); e != nil {
				return e
			}
		}
	} else {
		p.step("reusing release tool sha256=" + record["sha256"].(string))
	}
	p.releasePrefix = prefix
	tools["ts_release"] = record
	release := func(capture bool, args ...string) (string, error) {
		return p.run(capture, append(append([]string{tool}, prefix...), args...)...)
	}
	image := filepath.Join(o.Out, "image", imageAssets[0])
	kernel := filepath.Join(o.Out, "image", imageAssets[1])
	region := p.manifest.Inputs.Manifest.Region
	if region != "GRU" {
		return errors.New("unsupported image region")
	}
	trust := []string{"--delegation", o.Delegation, "--root-key", o.RootKey, "--environment", o.Environment}
	delegationDigest, e := fileHash(o.Delegation)
	if e != nil {
		return e
	}
	rootDigest, e := fileHash(o.RootKey)
	if e != nil {
		return e
	}
	trustRecord := map[string]any{"delegation_sha256": delegationDigest, "root_key_sha256": rootDigest}
	p.receipt["trust"] = trustRecord
	candidate, ok := p.receipt["candidate"].(map[string]any)
	if !ok {
		return errors.New("invalid candidate metadata")
	}
	if files.receipt == "" {
		unsigned := filepath.Join(o.Out, "binary-candidate.json")
		if e = p.freshOutput(unsigned); e != nil {
			return e
		}
		if _, e = release(false, "binary-candidate", "--binary", files.binary, "--source-revision", p.manifest.SourceRevision, "--qualification", files.qualification, "--out", unsigned); e != nil {
			return e
		}
		if !o.SignBinary {
			if !o.DryRun {
				return errors.New("the candidate has no signed binary receipt; pass --sign-binary with --signing-key, or --binary-receipt")
			}
			candidate["binary_receipt"] = "missing: sign with --sign-binary"
			return p.finish("dry run stopped before the image candidate: the binary is not signed yet")
		}
		files.receipt = filepath.Join(o.Out, "binary.receipt.json")
		if e = p.freshOutput(files.receipt); e != nil {
			return e
		}
		args := []string{"sign-binary", "--candidate", unsigned, "--binary", files.binary, "--qualification", files.qualification, "--signing-key", o.SigningKey}
		args = append(args, trust...)
		args = append(args, "--out", files.receipt)
		if _, e = release(false, args...); e != nil {
			return e
		}
		p.step("binary receipt signed")
	}
	args := append([]string{"verify-binary", "--receipt", files.receipt, "--binary", files.binary, "--qualification", files.qualification}, trust...)
	if _, e = release(false, args...); e != nil {
		return e
	}
	receiptDigest, e := fileHash(files.receipt)
	if e != nil {
		return e
	}
	candidate["binary_receipt_sha256"] = receiptDigest
	p.step("signed binary receipt verified")
	display := o.DisplayName
	if display == "" {
		display = fmt.Sprintf("terrascale-%s-arm64-%s-%s", strings.ToLower(region), p.manifest.SourceRevision[:12], p.manifest.Image.SHA256[:12])
	}
	imageOCID := ""
	if o.DryRun {
		imageOCID = "ocid1.image.oc1.sa-saopaulo-1.dryrun" + p.manifest.Image.SHA256[:32]
		p.receipt["oci_import"] = map[string]any{"skipped": "dry run", "display_name": display}
		p.step(fmt.Sprintf("dry run: would import %s as %s", image, display))
	} else {
		importRecord := filepath.Join(o.Out, "oci-import.json")
		importer := o.Importer
		if importer == nil {
			importer = Services{}.importer()
		}
		var previous map[string]any
		if o.Resume && readJSON(importRecord, &previous) == nil && reusableImport(previous, p.manifest.Image.SHA256,
			o.CompartmentID, o.Namespace, o.Bucket, display) {
			p.step("reusing completed OCI import")
		} else if e = imageimport.RunImporters(ctx, []string{"--qcow2", image, "--sha256", p.manifest.Image.SHA256, "--region", catalog.OCIRegion(catalog.Bootstrap), "--compartment-id", o.CompartmentID, "--namespace", o.Namespace, "--bucket", o.Bucket, "--display-name", display, "--out", importRecord}, out, importer); e != nil {
			return e
		}
		var imported map[string]any
		if e = readJSON(importRecord, &imported); e != nil {
			return e
		}
		if imported["qcow2_sha256"] != p.manifest.Image.SHA256 {
			return errors.New("OCI import record differs from image")
		}
		imageOCID, _ = imported["image_id"].(string)
		if imageOCID == "" {
			return errors.New("OCI import record has no image identity")
		}
		p.receipt["oci_import"] = imported
		p.step("imported image_ocid=" + imageOCID)
	}
	imageCandidate := filepath.Join(o.Out, "image-candidate.json")
	if e = p.freshOutput(imageCandidate); e != nil {
		return e
	}
	args = append([]string{"image-candidate", "--binary-receipt", files.receipt, "--binary", files.binary, "--qualification", files.qualification}, trust...)
	base := p.manifest.Inputs.Manifest.Base
	args = append(args, "--image-file", image, "--base-image-ocid", base.OCIImageOCID, "--base-image-region", region, "--base-image-file", files.base, "--kernel-release", p.manifest.Kernel.Release, "--kernel-file", kernel, "--image-ocid", imageOCID, "--region", region, "--out", imageCandidate)
	if _, e = release(false, args...); e != nil {
		return e
	}
	candidateDigest, e := fileHash(imageCandidate)
	if e != nil {
		return e
	}
	p.receipt["image_candidate_sha256"] = candidateDigest
	p.step("image candidate created")
	if o.DryRun {
		p.receipt["image_receipt"] = map[string]any{"skipped": "dry run"}
		return p.finish("dry run passed every read-only gate")
	}
	if o.ImageDelegation == "" {
		p.receipt["image_receipt"] = map[string]any{"awaiting": "root-signed image delegation", "image_ocid": imageOCID}
		fmt.Fprintf(out, "promote-image: the root owner extends the delegation to this image with:\n  ts-orch release sign-delegation --previous-delegation %s --image-cell %s --image-ocid %s --source-revision %s --arch arm64 --environment %s --subject-public-key LEAF.pub --root-key %s --signing-key ROOT.key --issued-at ... --expires-at ... --out image-delegation.json\nthen rerun this command with --image-delegation image-delegation.json\n", o.Delegation, region, imageOCID, p.manifest.SourceRevision, o.Environment, o.RootKey)
		return p.finish("imported " + imageOCID + "; awaiting the root-signed image delegation")
	}
	imageTrust := []string{"--delegation", o.ImageDelegation, "--root-key", o.RootKey}
	digest, e = fileHash(o.ImageDelegation)
	if e != nil {
		return e
	}
	trustRecord["image_delegation_sha256"] = digest
	signed := filepath.Join(o.Out, "image-receipt.json")
	if e = p.freshOutput(signed); e != nil {
		return e
	}
	args = []string{"sign-image", "--candidate", imageCandidate, "--binary-receipt", files.receipt, "--binary", files.binary, "--qualification", files.qualification, "--image-file", image, "--base-image-file", files.base, "--kernel-file", kernel, "--signing-key", o.SigningKey}
	args = append(args, imageTrust...)
	args = append(args, "--environment", o.Environment, "--out", signed)
	if _, e = release(false, args...); e != nil {
		return e
	}
	args = append([]string{"verify-image", "--receipt", signed}, imageTrust...)
	args = append(args, "--image-file", image, "--base-image-file", files.base, "--kernel-file", kernel, "--region", region, "--environment", o.Environment)
	verified, e := release(true, args...)
	if e != nil {
		return e
	}
	digest, e = fileHash(signed)
	if e != nil {
		return e
	}
	p.receipt["image_receipt"] = map[string]any{"path": signed, "sha256": digest, "image_ocid": imageOCID, "verify_image": verified}
	p.step(verified)
	return p.finish("promotion complete")
}
func runPromotion(ctx context.Context, root string, args []string, out, stderr io.Writer, services Services) (error, int) {
	fs := flag.NewFlagSet("image promote", flag.ContinueOnError)
	fs.SetOutput(stderr)
	o := PromotionOptions{Environment: "canary"}
	for _, f := range []struct {
		p    *string
		name string
	}{{&o.ImageRelease, "image-release"}, {&o.ImageDir, "image-dir"}, {&o.Out, "out"}, {&o.Delegation, "delegation"}, {&o.ImageDelegation, "image-delegation"}, {&o.RootKey, "root-key"}, {&o.BinaryReceipt, "binary-receipt"}, {&o.SigningKey, "signing-key"}, {&o.CompartmentID, "compartment-id"}, {&o.Namespace, "namespace"}, {&o.Bucket, "bucket"}, {&o.DisplayName, "display-name"}, {&o.FJ, "fj"}, {&o.ReleaseTool, "release-tool"}} {
		fs.StringVar(f.p, f.name, "", f.name)
	}
	fs.StringVar(&o.Environment, "environment", "canary", "release environment")
	fs.BoolVar(&o.SignBinary, "sign-binary", false, "sign unsigned binary candidate")
	fs.BoolVar(&o.DryRun, "dry-run", false, "run every read-only gate")
	fs.BoolVar(&o.Resume, "resume", false, "continue in an existing --out of the same image, reusing verified downloads, the recorded release tool and a completed OCI import")
	if e := fs.Parse(args); e != nil {
		if errors.Is(e, flag.ErrHelp) {
			return nil, 0
		}
		return e, 2
	}
	if fs.NArg() != 0 || (o.ImageRelease == "") == (o.ImageDir == "") || o.Out == "" || o.Delegation == "" || o.RootKey == "" {
		return errors.New("promotion needs one of --image-release or --image-dir, --out, --delegation, and --root-key"), 2
	}
	if !slices.Contains([]string{"canary", "production"}, o.Environment) {
		return errors.New("invalid --environment"), 2
	}
	if !o.DryRun {
		var missing []string
		for _, f := range []struct{ name, value string }{{"--compartment-id", o.CompartmentID}, {"--namespace", o.Namespace}, {"--bucket", o.Bucket}} {
			if f.value == "" {
				missing = append(missing, f.name)
			}
		}
		if len(missing) > 0 {
			return fmt.Errorf("an OCI import needs %s (or use --dry-run)", strings.Join(missing, ", ")), 2
		}
	}
	if (o.SignBinary || o.ImageDelegation != "") && o.SigningKey == "" {
		return errors.New("--sign-binary and --image-delegation need --signing-key"), 2
	}
	if o.DryRun && o.ImageDelegation != "" {
		return errors.New("--dry-run never signs the image; drop --image-delegation"), 2
	}
	if s, e := os.Lstat(o.Out); o.Resume {
		if e == nil && !s.IsDir() || e != nil && !os.IsNotExist(e) {
			return fmt.Errorf("--resume needs --out to be a directory: %s", o.Out), 2
		}
	} else if e == nil || !os.IsNotExist(e) {
		return fmt.Errorf("--out must be a new directory (or pass --resume): %s", o.Out), 2
	}
	if _, err := exec.LookPath("virt-cat"); err != nil && os.Getenv("TS_IMAGE_TOOLS_ID") == "" {
		executable, err := os.Executable()
		if err != nil {
			return err, 1
		}
		command := append([]string{"bash", filepath.Join(root, "deploy/image/tools.sh"), executable, "image", "promote"}, args...)
		output, err := Execute(ctx, root, nil, command...)
		if output != "" {
			fmt.Fprintln(out, output)
		}
		return err, 0
	}
	o.Importer = services.importer()
	return Promote(ctx, root, o, out), 0
}

// reusableImport reports whether a recorded OCI import is the one this run
// would perform: the same image bytes into the same compartment, object
// namespace and bucket under the same display name. A resume with any other
// target re-imports instead of reusing an image in the wrong place.
func reusableImport(previous map[string]any, sha256, compartmentID, namespace, bucket, display string) bool {
	id, _ := previous["image_id"].(string)
	object, _ := previous["object"].(string)
	return previous["schema"] == "terrascale.oci.image-import.v1" && id != "" &&
		previous["qcow2_sha256"] == sha256 && previous["compartment_id"] == compartmentID &&
		previous["display_name"] == display && strings.HasPrefix(object, namespace+"/"+bucket+"/")
}
