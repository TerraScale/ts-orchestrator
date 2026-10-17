package image

import (
	"context"
	"crypto/sha256"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/netbird/client"
	"github.com/TerraScale/ts-orchestrator/internal/netbird/foundation"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	releasecli "github.com/TerraScale/ts-orchestrator/internal/release/cli"
)

const managerImageName = "terrascale-netbird-manager-arm64.qcow2"
const managerFoundationUnit = "netbird-foundation.service"

var managerImageUnits = []string{managerFoundationUnit, "containerd.service", "systemd-timesyncd.service", "systemd-time-wait-sync.service", SSHUnit}

// These paths are delivered only after the dedicated host's own signed admission.
var managerDeliveredPaths = []string{"/run/terrascale-netbird/config.yaml", "/var/lib/terrascale/netbird/data"}

type NetBirdManagerImageOptions struct {
	Base, Binary, Qualification, SourceRevision, NetBirdBinary, Out string
}

// NetBirdManagerImage builds a separate native candidate, never controller boot
// authority. Native qualification, import and dedicated signing remain required.
func NetBirdManagerImage(ctx context.Context, repo string, o NetBirdManagerImageOptions, out io.Writer) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !gitSHA.MatchString(o.SourceRevision) || o.Base == "" || o.Binary == "" || o.Qualification == "" || o.NetBirdBinary == "" || o.Out == "" {
		return errors.New("manager image requires exact source, base, binary, qualification, pinned client and new output directory")
	}
	inputsPath := filepath.Join(repo, "deploy/image/image-inputs.json")
	inputs, err := loadManagerInputs(inputsPath)
	if err != nil {
		return err
	}
	architecture, err := inputs.Architecture()
	if err != nil || architecture != "arm64" || inputs.Region != "GRU" {
		return errors.New("dedicated NetBird manager requires the pinned GRU arm64 base")
	}
	if err := managerArtifact(o.Base, inputs.Base.Assets.Base); err != nil {
		return fmt.Errorf("manager base: %w", err)
	}
	if err := client.VerifyBinary(o.NetBirdBinary, inputs.NetBird.Archives.Arm64.BinarySHA256, "arm64"); err != nil {
		return err
	}
	architecture, err = binaryArchitecture(o.Binary)
	if err != nil || architecture != "arm64" {
		return errors.New("dedicated NetBird manager binary must be native Linux arm64")
	}
	wire, err := os.ReadFile(o.Qualification)
	if err != nil {
		return err
	}
	qualification, qualificationDigest, err := release.DecodeQualification(wire)
	if err != nil || qualification.SourceRevision != o.SourceRevision {
		return errors.Join(errors.New("manager binary qualification differs from exact source"), err)
	}
	revision, err := Execute(ctx, repo, nil, "git", "rev-parse", "HEAD")
	if err != nil || revision != o.SourceRevision {
		return errors.Join(errors.New("manager image checkout differs from exact source"), err)
	}
	tree, err := Execute(ctx, repo, nil, "git", "rev-parse", "HEAD^{tree}")
	if err != nil || tree != qualification.SourceTree {
		return errors.Join(errors.New("manager image source tree differs from binary qualification"), err)
	}
	dirty, err := Execute(ctx, repo, nil, "git", "status", "--porcelain=v1", "--untracked-files=all")
	if err != nil || dirty != "" {
		return errors.Join(errors.New("manager image requires a clean source checkout"), err)
	}
	for name, expected := range map[string]string{"go.mod": qualification.GoModSHA256, "go.sum": qualification.GoSumSHA256} {
		digest, err := fileHash(filepath.Join(repo, name))
		if err != nil || digest != expected {
			return errors.Join(fmt.Errorf("manager binary qualification differs from %s", name), err)
		}
	}
	output, err := filepath.Abs(o.Out)
	if err != nil {
		return err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(output))
	if err != nil {
		return err
	}
	output = filepath.Join(parent, filepath.Base(output))
	if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
		return errors.New("manager image output directory must be a new path")
	}
	work, err := os.MkdirTemp(parent, ".netbird-manager-image-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	sourceRepo := filepath.Join(work, "source")
	for _, artifact := range append(managerUploads(sourceRepo, work, inputs), upload{filepath.Join(sourceRepo, "deploy/image/image-inputs.json"), "", 0644}) {
		relative, err := filepath.Rel(sourceRepo, artifact.source)
		if err != nil {
			return err
		}
		if !filepath.IsLocal(relative) {
			continue // Binary artifacts are staged independently below.
		}
		if err := snapshotManagerSource(ctx, repo, sourceRepo, o.SourceRevision, relative); err != nil {
			return err
		}
	}
	if err := managerArtifact(filepath.Join(sourceRepo, "deploy/image/image-inputs.json"), Asset{int64(len(inputs.raw)), fmt.Sprintf("%x", sha256.Sum256(inputs.raw))}); err != nil {
		return fmt.Errorf("manager input pins changed during source snapshot: %w", err)
	}
	configPath := filepath.Join(sourceRepo, inputs.NetBird.EnrollmentConfig.Path)
	if digest, err := fileHash(configPath); err != nil || digest != inputs.NetBird.EnrollmentConfig.SHA256 {
		return errors.Join(errors.New("manager public client configuration differs from image pin"), err)
	}
	if err := managerPublicConfig(configPath); err != nil {
		return err
	}
	// Stage immutable copies before checking or uploading any candidate bytes.
	for _, artifact := range []struct{ source, name string }{{o.Binary, "ts-orch"}, {o.Qualification, "qualification.json"}, {o.NetBirdBinary, "netbird"}} {
		if err := copyFile(artifact.source, filepath.Join(work, artifact.name), 0644); err != nil {
			return err
		}
	}
	binary := filepath.Join(work, "ts-orch")
	netbird := filepath.Join(work, "netbird")
	qualificationPath := filepath.Join(work, "qualification.json")
	if err := releasecli.Run(ctx, []string{"binary-candidate", "--binary", binary, "--source-revision", o.SourceRevision, "--qualification", qualificationPath, "--out", filepath.Join(work, "binary-candidate.json")}, out); err != nil {
		return err
	}
	// Linux /proc retains the executing inode even when the installed path changes.
	builder := filepath.Join(work, "image-builder")
	if err := copyFile("/proc/self/exe", builder, 0644); err != nil {
		return err
	}
	if err := releasecli.Run(ctx, []string{"binary-candidate", "--binary", builder, "--source-revision", o.SourceRevision, "--qualification", qualificationPath, "--out", filepath.Join(work, "image-builder.json")}, out); err != nil {
		return fmt.Errorf("image builder must be the same qualified source artifact: %w", err)
	}
	if err := client.VerifyBinary(netbird, inputs.NetBird.Archives.Arm64.BinarySHA256, "arm64"); err != nil {
		return err
	}
	if digest, err := fileHash(qualificationPath); err != nil || digest != qualificationDigest {
		return errors.Join(errors.New("manager qualification changed during staging"), err)
	}
	for _, root := range inputs.TrustRoots {
		if digest, err := fileHash(filepath.Join(sourceRepo, root.Path)); err != nil || digest != root.SHA256 {
			return errors.Join(errors.New("manager bootstrap root differs from image pin"), err)
		}
	}
	if err := snapshotManagerSource(ctx, repo, sourceRepo, o.SourceRevision, inputs.Timesyncd.Path); err != nil {
		return err
	}
	if digest, err := fileHash(filepath.Join(sourceRepo, inputs.Timesyncd.Path)); err != nil || digest != inputs.Timesyncd.SHA256 {
		return errors.Join(errors.New("manager timesync input differs from image pin"), err)
	}
	timesync, err := os.ReadFile(filepath.Join(sourceRepo, inputs.Timesyncd.Path))
	if err != nil {
		return err
	}
	timesync, err = NormalizeTimesync(timesync)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(work, "timesyncd.conf"), timesync, 0644); err != nil {
		return err
	}
	pin, err := json.Marshal(inputs.NetBird, json.Deterministic(true))
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(work, "netbird-pin.json"), pin, 0644); err != nil {
		return err
	}
	if _, err := Execute(ctx, "", nil, "qemu-img", "check", "--", o.Base); err != nil {
		return err
	}
	info, err := Execute(ctx, "", nil, "qemu-img", "info", "--output=json", "--", o.Base)
	if err != nil {
		return err
	}
	var base struct {
		Format  string `json:"format"`
		Backing string `json:"backing-filename"`
	}
	if err := json.Unmarshal([]byte(info), &base); err != nil || base.Format != "qcow2" || base.Backing != "" {
		return errors.New("manager base must be standalone QCOW2 without a backing file")
	}
	candidate := filepath.Join(work, managerImageName)
	if _, err := Execute(ctx, "", nil, "cp", "--reflink=auto", "--sparse=always", "--", o.Base, candidate); err != nil {
		return err
	}
	if err := managerArtifact(candidate, inputs.Base.Assets.Base); err != nil {
		return fmt.Errorf("manager base changed during staging: %w", err)
	}
	expected, err := buildManagerGuest(ctx, sourceRepo, work, candidate, inputs, out)
	if err != nil {
		return err
	}
	if _, err := Execute(ctx, "", nil, "qemu-img", "check", "--", candidate); err != nil {
		return err
	}
	if err := GuestVerify(ctx, candidate, expected, out); err != nil {
		return err
	}
	artifacts := filepath.Join(work, "artifacts")
	if err := os.Mkdir(artifacts, 0755); err != nil {
		return err
	}
	for _, name := range []string{managerImageName, "guest-kernel"} {
		if err := os.Rename(filepath.Join(work, name), filepath.Join(artifacts, name)); err != nil {
			return err
		}
		if err := os.Chmod(filepath.Join(artifacts, name), 0644); err != nil {
			return err
		}
	}
	if err := managerManifest(sourceRepo, work, artifacts, qualification, qualificationDigest, inputs, expected); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.Rename(artifacts, output); err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "dedicated NetBird manager candidate=%s; native qualification and dedicated signing required\n", output)
	return err
}

func loadManagerInputs(name string) (Inputs, error) {
	var inputs Inputs
	wire, err := os.ReadFile(name)
	if err != nil {
		return inputs, err
	}
	if err := json.Unmarshal(wire, &inputs, json.RejectUnknownMembers(true)); err != nil {
		return inputs, err
	}
	if inputs.Schema != "terrascale.image.inputs.v2" || !kernelRelease.MatchString(inputs.Base.KernelRelease) ||
		inputs.Base.Assets.Base.Bytes <= 0 || !client.SHA256Pattern.MatchString(inputs.Base.Assets.Base.SHA256) ||
		len(inputs.TrustRoots) == 0 || len(inputs.TrustRoots) > 16 {
		return inputs, errors.New("manager image needs exact existing base, kernel and bootstrap root pins")
	}
	if err := client.ValidatePin(inputs.NetBird); err != nil {
		return inputs, err
	}
	for _, pin := range append(append([]client.FilePin{}, inputs.TrustRoots...), inputs.Timesyncd, inputs.NetBird.EnrollmentConfig) {
		if !filepath.IsLocal(pin.Path) || !client.SHA256Pattern.MatchString(pin.SHA256) {
			return inputs, errors.New("manager image public input must be a relative source path with an exact SHA-256")
		}
	}
	inputs.raw = append(inputs.raw, wire...)
	return inputs, nil
}

func managerPublicConfig(name string) error {
	wire, err := os.ReadFile(name)
	if err != nil {
		return err
	}
	var config struct {
		ManagementURL string `json:"management_url"`
		Region        string `json:"region"`
	}
	if err := json.Unmarshal(wire, &config, json.RejectUnknownMembers(true)); err != nil || config.ManagementURL != "https://netbird.terrascale.tech" || config.Region != "sa-saopaulo-1" {
		return errors.Join(errors.New("manager public client configuration must contain only the exact management origin and GRU region"), err)
	}
	return nil
}

// Freeze source bytes before using them; a changing checkout cannot substitute
// deployment assets for the immutable source tree in the binary qualification.
func snapshotManagerSource(ctx context.Context, repo, target, revision, relative string) error {
	if !filepath.IsLocal(relative) {
		return errors.New("manager image source path must stay inside the qualified tree")
	}
	source, destination := filepath.Join(repo, relative), filepath.Join(target, relative)
	stat, err := os.Lstat(source)
	if err != nil || !stat.Mode().IsRegular() {
		return errors.Join(errors.New("manager source asset must be a direct regular file"), err)
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0755); err != nil {
		return err
	}
	if err := copyFile(source, destination, 0644); err != nil {
		return err
	}
	expected, err := Execute(ctx, repo, nil, "git", "rev-parse", revision+":"+filepath.ToSlash(relative))
	if err != nil {
		return err
	}
	actual, err := Execute(ctx, repo, nil, "git", "hash-object", "--no-filters", "--", destination)
	if err != nil || actual != expected {
		return errors.Join(fmt.Errorf("manager source asset differs from qualified tree: %s", relative), err)
	}
	return nil
}

func managerArtifact(name string, expected Asset) error {
	stat, err := os.Lstat(name)
	if err != nil {
		return err
	}
	if !stat.Mode().IsRegular() || stat.Size() <= 0 || stat.Size() != expected.Bytes {
		return errors.New("artifact must be a regular file matching pinned bytes")
	}
	digest, err := fileHash(name)
	if err != nil || digest != expected.SHA256 {
		return errors.Join(errors.New("artifact differs from pinned SHA-256"), err)
	}
	return nil
}

func managerUploads(repo, work string, inputs Inputs) []upload {
	uploads := []upload{
		{filepath.Join(work, "ts-orch"), "/usr/local/bin/ts-orch", 0755},
		{filepath.Join(work, "netbird"), NetBird, 0755},
		{filepath.Join(work, "netbird"), NetBirdFallback, 0755},
		{filepath.Join(work, "netbird-pin.json"), NetBirdPin, 0644},
		{filepath.Join(repo, inputs.NetBird.EnrollmentConfig.Path), NetBirdConfig, 0644},
		{filepath.Join(work, "timesyncd.conf"), TimeConfig, 0644},
		{filepath.Join(repo, "deploy/systemd/netbird.service"), "/etc/systemd/system/netbird.service", 0644},
	}
	for _, name := range []string{"systemd/" + managerFoundationUnit, "systemd/netbird-backup.service", "systemd/netbird-backup.timer", "Caddyfile.netbird", "dashboard.environment", "templates/config.yaml.tmpl"} {
		destination := "/opt/terrascale/netbird/" + name
		if strings.HasPrefix(name, "systemd/") {
			destination = "/etc/systemd/system/" + path.Base(name)
		}
		uploads = append(uploads, upload{filepath.Join(repo, "deploy/netbird/manager", name), destination, 0644})
	}
	for index, root := range inputs.TrustRoots {
		uploads = append(uploads, upload{filepath.Join(repo, root.Path), fmt.Sprintf("%s/trust-roots/%03d.pem", Bootstrap, index+1), 0444})
	}
	return uploads
}

func buildManagerGuest(ctx context.Context, repo, work, candidate string, inputs Inputs, out io.Writer) (expected []string, result error) {
	g, err := NewGuest(ctx, candidate, false, nil)
	if err != nil {
		return nil, err
	}
	defer func() { result = errors.Join(result, g.Close(result != nil)) }()
	if err := auditKernel(g, inputs.Base.KernelRelease, work, filepath.Join(work, "guest-kernel"), "arm64", out); err != nil {
		return nil, err
	}
	kernelDigest, err := fileHash(filepath.Join(work, "guest-kernel"))
	if err != nil {
		return nil, err
	}
	expected = append(expected, "/boot/vmlinuz-"+inputs.Base.KernelRelease+"="+kernelDigest)
	for _, audit := range []func(*Guest, string, io.Writer) error{auditSystemd, auditSSHServer} {
		if err := audit(g, work, out); err != nil {
			return nil, err
		}
	}
	if err := auditTimeConfig(g, work); err != nil {
		return nil, err
	}
	for _, p := range append(append([]string{App, AppLib, "/var/lib/netbird", "/var/lib/terrascale/netbird", "/opt/terrascale/netbird", "/etc/containerd", "/var/lib/containerd", "/run/containerd"}, managerDeliveredPaths...), "/usr/local/bin/ts-orch") {
		if err := g.AssertAbsent(p, "manager image base state"); err != nil {
			return nil, err
		}
	}
	// Ordinary role units and enrollment must never become this host's boot path.
	for _, name := range append(append(append([]string{}, Units...), HostUnitFiles...), "netbird-foundation.service", "netbird-backup.timer") {
		if name == SSHUnit || strings.HasPrefix(name, "systemd-time") {
			continue
		}
		for _, dir := range []string{"/etc/systemd/system", "/usr/lib/systemd/system", "/run/systemd/system", "/usr/local/lib/systemd/system"} {
			if err := g.AssertAbsent(dir+"/"+name, "manager conflicting role unit"); err != nil {
				return nil, err
			}
		}
	}
	uploads := managerUploads(repo, work, inputs)
	if err := os.WriteFile(filepath.Join(work, "containerd.service"), []byte(containerdUnit), 0644); err != nil {
		return nil, err
	}
	uploads = append(uploads, upload{filepath.Join(work, "containerd.service"), "/etc/systemd/system/containerd.service", 0644})
	for _, artifact := range uploads {
		if err := g.Directory(path.Dir(artifact.destination), 0, 0, 0755); err != nil {
			return nil, err
		}
		if err := g.Upload(artifact.source, artifact.destination, artifact.mode); err != nil {
			return nil, err
		}
		digest, err := fileHash(artifact.source)
		if err != nil {
			return nil, err
		}
		expected = append(expected, artifact.destination+"="+digest)
	}
	if err := installRuntimeBinaries(ctx, g, "arm64", work, out); err != nil {
		return nil, err
	}
	for _, name := range []string{"containerd", "containerd-shim-runc-v2", "runc"} {
		digest, err := fileHash(filepath.Join(work, name))
		if err != nil {
			return nil, err
		}
		expected = append(expected, "/usr/local/bin/"+name+"="+digest)
	}
	stage := filepath.Join(work, "systemd-root")
	for _, directory := range []string{"etc/systemd", "usr/lib/systemd"} {
		if err := os.MkdirAll(filepath.Join(stage, directory), 0755); err != nil {
			return nil, err
		}
		if _, err := g.Call("copy-out", "/"+directory+"/system", filepath.Join(stage, directory)); err != nil {
			return nil, err
		}
	}
	if err := os.Symlink("usr/lib", filepath.Join(stage, "lib")); err != nil {
		return nil, err
	}
	if err := enableImageUnits(g, stage, managerImageUnits, out); err != nil {
		return nil, err
	}
	for _, name := range []string{"netbird.service", "terrascale-netbird-enroll.service", "terrascale-netbird-agent.service", "terrascale-orchestrator-controller.service", "terrascale-orchestrator-host.service"} {
		if err := g.AssertAbsent("/etc/systemd/system/multi-user.target.wants/"+name, "manager premature enrollment or ordinary serving"); err != nil {
			return nil, err
		}
	}
	for _, p := range managerDeliveredPaths {
		if err := g.AssertAbsent(p, "manager runtime-only delivery"); err != nil {
			return nil, err
		}
	}
	return expected, nil
}

func managerManifest(repo, work, artifacts string, qualification release.Qualification, qualificationDigest string, inputs Inputs, expected []string) error {
	asset := func(name string) (map[string]any, error) {
		p := filepath.Join(artifacts, name)
		stat, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		digest, err := fileHash(p)
		return map[string]any{"name": name, "architecture": "arm64", "sha256": digest, "bytes": stat.Size()}, err
	}
	image, err := asset(managerImageName)
	if err != nil {
		return err
	}
	image["format"] = "qcow2"
	kernel, err := asset("guest-kernel")
	if err != nil {
		return err
	}
	kernel["release"], kernel["guest_path"] = inputs.Base.KernelRelease, "/boot/vmlinuz-"+inputs.Base.KernelRelease
	inputsDigest, err := fileHash(filepath.Join(repo, "deploy/image/image-inputs.json"))
	if err != nil {
		return err
	}
	binaryDigest, err := fileHash(filepath.Join(work, "ts-orch"))
	if err != nil {
		return err
	}
	binaryStat, err := os.Stat(filepath.Join(work, "ts-orch"))
	if err != nil {
		return err
	}
	components, err := foundation.PinnedComponentImages("arm64")
	if err != nil {
		return err
	}
	builderDigest, err := fileHash(filepath.Join(work, "image-builder"))
	if err != nil {
		return err
	}
	runtimePins := runtimeDigests["arm64"]
	manifest := map[string]any{
		"schema": "terrascale.image.qualification.v2", "source_revision": qualification.SourceRevision, "source_tree": qualification.SourceTree,
		"builder":      map[string]any{"kind": "local"},
		"inputs":       map[string]any{"path": "deploy/image/image-inputs.json", "sha256": inputsDigest, "manifest": inputs},
		"go_candidate": map[string]any{"release_tag": fmt.Sprintf("ci-%s-run-%d", qualification.SourceRevision, qualification.Verification.RunID), "run_id": qualification.Verification.RunID, "run_number": qualification.Verification.RunNumber, "qualification_sha256": qualificationDigest, "binary_sha256": binaryDigest, "binary_bytes": binaryStat.Size()},
		"toolchain":    map[string]any{"go_version": qualification.GoVersion, "ts_release_sha256": builderDigest},
		"image":        image, "kernel": kernel,
		"manager":              map[string]any{"role": "netbird-manager", "runtime": release.NetBirdProductionRuntime, "cell": "GRU", "enabled_units": managerImageUnits, "readback": expected, "delivered_paths": managerDeliveredPaths, "component_images": components, "component_delivery": "admitted immutable digest pulls", "containerd_version": containerdVersion, "containerd_archive_sha256": runtimePins.containerd, "runc_version": runcVersion, "runc_sha256": runtimePins.runc},
		"image_receipt_status": "requires native NetBird production qualification, OCI import and dedicated signing",
	}
	wire, err := canonical(manifest)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(artifacts, "image-qualification.json"), wire, 0644); err != nil {
		return err
	}
	var sums strings.Builder
	for _, name := range []string{managerImageName, "guest-kernel", "image-qualification.json"} {
		digest, err := fileHash(filepath.Join(artifacts, name))
		if err != nil {
			return err
		}
		fmt.Fprintf(&sums, "%s  %s\n", digest, name)
	}
	return os.WriteFile(filepath.Join(artifacts, "SHA256SUMS"), []byte(sums.String()), 0644)
}
