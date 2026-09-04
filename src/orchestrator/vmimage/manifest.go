// Package vmimage contains the test-only guest image contract used by the
// Firecracker qualification stack.  It deliberately has no VMM, OCI, or
// privileged-host dependency: image bytes are ordinary files or HTTP
// responses and all trust decisions are made from the immutable manifest.
package vmimage

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	pathpkg "path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Architecture is the guest CPU architecture. Firecracker does not emulate a
// different architecture, so only native amd64 and arm64 are admitted.
type Architecture string

const (
	ArchitectureAMD64 Architecture = "amd64"
	ArchitectureARM64 Architecture = "arm64"

	// AMD64 and ARM64 are short aliases useful to callers constructing a
	// manifest without string conversions.
	AMD64 = ArchitectureAMD64
	ARM64 = ArchitectureARM64
)

const (
	ManifestSchemaVersion = 1
	defaultArtifactMode   = uint32(0o644)
	maxSourceLength       = 4096
	maxArtifactSize       = int64(16 << 30)
	maxManifestBytes      = int64(64 << 10)

	// The pinned Firecracker kernels do not include CONFIG_EFI_PARTITION, so
	// the Ubuntu GPT image is deterministically reduced to its root ext4
	// partition before it can be attached as /dev/vda.
	UbuntuRootSectorSize  = int64(512)
	UbuntuRootStartSector = int64(2099200)
	UbuntuRootSectorCount = int64(5240799)
	UbuntuRootFSSize      = UbuntuRootSectorSize * UbuntuRootSectorCount
)

var (
	sha256Pattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	namePattern    = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*$`)
	versionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
	ubuntuPattern  = regexp.MustCompile(`^([0-9]{2})\.04(?:\.[0-9]+)?$`)
	versionSegment = regexp.MustCompile(`^(?:v[0-9]+(?:\.[0-9]+){1,2}|release-[0-9]{8})$`)
	amd64Source    = regexp.MustCompile(`(?:^|[/._-])(?:amd64|x86_64)(?:$|[/._-])`)
	arm64Source    = regexp.MustCompile(`(?:^|[/._-])(?:arm64|aarch64)(?:$|[/._-])`)
	kernelSource   = regexp.MustCompile(`^/spec\.ccfc\.min/firecracker-ci/v[0-9]+\.[0-9]+/(?:x86_64|aarch64)/vmlinux-[0-9][0-9._-]*$`)
	ubuntuSource   = regexp.MustCompile(`^/minimal/releases/[a-z0-9-]+/release-[0-9]{8}/ubuntu-[0-9]{2}\.04-minimal-cloudimg-(?:amd64|arm64)\.img$`)
)

// ArtifactManifest identifies one immutable byte stream. Mode is the exact
// Unix permission mask expected for a regular file (special bits are never
// accepted). A zero Mode is interpreted as 0644 for compatibility with older
// manifests; new manifests should always carry Mode explicitly.
type ArtifactManifest struct {
	Name         string       `json:"name"`
	Architecture Architecture `json:"architecture"`
	Version      string       `json:"version"`
	Source       string       `json:"source"`
	SHA256       string       `json:"sha256"`
	Size         int64        `json:"size"`
	Mode         uint32       `json:"mode"`
	InputSHA256  string       `json:"inputSha256,omitempty"`
	InputSize    int64        `json:"inputSize,omitempty"`
	Transform    *Transform   `json:"transform,omitempty"`

	// Sha256 is accepted as a Go spelling alias. It is excluded from JSON so
	// that there remains exactly one wire representation.
	Sha256 string `json:"-"`
}

// Transform defines the one reproducible conversion admitted for a guest
// root filesystem. The source is a pinned QCOW2 disk. The output is the root
// partition copied into a standalone sparse ext4 image for Firecracker.
type Transform struct {
	Type        string `json:"type"`
	SectorSize  int64  `json:"sectorSize"`
	StartSector int64  `json:"startSector"`
	SectorCount int64  `json:"sectorCount"`
}

const TransformQCOW2RootPartition = "qcow2-root-partition"

// GuestImageManifest is the complete boot pair. Kernel and RootFS must have
// the same architecture and version; their bytes remain independently
// addressable so a mismatched pair can never be booted accidentally.
type GuestImageManifest struct {
	SchemaVersion int              `json:"schemaVersion"`
	UbuntuRelease string           `json:"ubuntuRelease"`
	Architecture  Architecture     `json:"architecture"`
	Version       string           `json:"version"`
	Kernel        ArtifactManifest `json:"kernel"`
	RootFS        ArtifactManifest `json:"rootfs"`

	// Rootfs is the Go spelling alias. It is excluded from JSON.
	Rootfs ArtifactManifest `json:"-"`
}

// Common contract aliases keep the package vocabulary convenient for image
// builders while preserving one wire type.
type Manifest = GuestImageManifest
type ImageManifest = GuestImageManifest
type Artifact = ArtifactManifest

// NewManifest validates and returns a copy of manifest. Callers should retain
// the returned value as the immutable snapshot used for an install.
func NewManifest(manifest GuestImageManifest) (GuestImageManifest, error) {
	if err := manifest.Validate(); err != nil {
		return GuestImageManifest{}, err
	}
	manifest.Kernel = canonicalArtifact(manifest.Kernel)
	manifest.RootFS = canonicalArtifact(manifest.rootFS())
	manifest.Rootfs = ArtifactManifest{}
	return manifest, nil
}

// Validate checks all fields at the trust boundary, including the Ubuntu LTS
// release spelling and the architecture/version kernel-rootfs pairing.
func (manifest GuestImageManifest) Validate() error {
	if manifest.SchemaVersion != ManifestSchemaVersion {
		return fmt.Errorf("vmimage: unsupported manifest schema %d", manifest.SchemaVersion)
	}
	if !isUbuntuLTS(manifest.UbuntuRelease) {
		return errors.New("vmimage: ubuntuRelease must be an Ubuntu LTS .04 release")
	}
	if !validArchitecture(manifest.Architecture) {
		return errors.New("vmimage: architecture must be amd64 or arm64")
	}
	if !versionPattern.MatchString(manifest.Version) {
		return errors.New("vmimage: version is not a safe release token")
	}
	kernel, rootfs := manifest.Kernel, manifest.rootFS()
	if err := kernel.validate("kernel", manifest.Architecture, manifest.Version); err != nil {
		return err
	}
	if err := rootfs.validate("rootfs", manifest.Architecture, manifest.Version); err != nil {
		return err
	}
	if kernel.Name == rootfs.Name {
		return errors.New("vmimage: kernel and rootfs names must differ")
	}
	return nil
}

// ValidateManifest applies the complete supply-chain policy used by image
// preparation. Guest-only metadata that needs structural validation can use
// GuestImageManifest.Validate or NewManifest directly.
func ValidateManifest(manifest GuestImageManifest) error {
	_, err := NewPinnedManifest(manifest)
	return err
}

// NewPinnedManifest returns an immutable manifest snapshot after applying the
// stricter boot-artifact policy: versioned HTTPS sources, native source paths,
// fixed 0644 output modes, and the pinned Ubuntu root-partition transform.
func NewPinnedManifest(manifest GuestImageManifest) (GuestImageManifest, error) {
	canonical, err := NewManifest(manifest)
	if err != nil {
		return GuestImageManifest{}, err
	}
	if canonical.Kernel.expectedMode() != 0o644 || canonical.RootFS.expectedMode() != 0o644 {
		return GuestImageManifest{}, errors.New("vmimage: kernel and rootfs modes must be 0644")
	}
	if err := validateImmutableImageSource("kernel", canonical.Kernel.Source, canonical.Architecture, canonical.UbuntuRelease, canonical.Version); err != nil {
		return GuestImageManifest{}, err
	}
	if err := validateImmutableImageSource("rootfs", canonical.RootFS.Source, canonical.Architecture, canonical.UbuntuRelease, canonical.Version); err != nil {
		return GuestImageManifest{}, err
	}
	transform := canonical.RootFS.Transform
	if transform == nil || transform.Type != TransformQCOW2RootPartition ||
		transform.SectorSize != UbuntuRootSectorSize || transform.StartSector != UbuntuRootStartSector ||
		transform.SectorCount != UbuntuRootSectorCount || canonical.RootFS.Size != UbuntuRootFSSize {
		return GuestImageManifest{}, errors.New("vmimage: rootfs must use the pinned Ubuntu root-partition transform")
	}
	return canonical, nil
}

// Validate checks an artifact independently of an image pair. It is useful
// when a guest-channel binary is verified before the image manifest arrives.
func (artifact ArtifactManifest) Validate() error {
	return artifact.validate("artifact", artifact.Architecture, artifact.Version)
}

// Digest returns the canonical manifest digest field. It is empty when both
// Go aliases are present with conflicting values.
func (artifact ArtifactManifest) Digest() string { return artifact.digest() }

// ValidateKernelRootfsPair enforces the pairing invariant independently of a
// complete image manifest.
func ValidateKernelRootfsPair(kernel, rootfs ArtifactManifest) error {
	if err := kernel.Validate(); err != nil {
		return fmt.Errorf("vmimage: kernel: %w", err)
	}
	if err := rootfs.Validate(); err != nil {
		return fmt.Errorf("vmimage: rootfs: %w", err)
	}
	if kernel.Architecture != rootfs.Architecture || kernel.Version != rootfs.Version {
		return errors.New("vmimage: kernel and rootfs must share architecture and version")
	}
	if kernel.Name == rootfs.Name {
		return errors.New("vmimage: kernel and rootfs names must differ")
	}
	return nil
}

// ValidateKernelRootFSPair is the acronym-capitalized spelling of
// ValidateKernelRootfsPair.
func ValidateKernelRootFSPair(kernel, rootfs ArtifactManifest) error {
	return ValidateKernelRootfsPair(kernel, rootfs)
}

func (manifest GuestImageManifest) rootFS() ArtifactManifest {
	if !isZeroArtifact(manifest.RootFS) && !isZeroArtifact(manifest.Rootfs) &&
		!artifactsEqual(manifest.RootFS, manifest.Rootfs) {
		return ArtifactManifest{}
	}
	if isZeroArtifact(manifest.RootFS) {
		return manifest.Rootfs
	}
	return manifest.RootFS
}

func (artifact ArtifactManifest) validate(kind string, arch Architecture, version string) error {
	if !namePattern.MatchString(artifact.Name) || len(artifact.Name) > 128 {
		return fmt.Errorf("vmimage: %s name is not a safe file name", kind)
	}
	if artifact.Architecture != arch {
		return fmt.Errorf("vmimage: %s architecture does not match image", kind)
	}
	if artifact.Version != version {
		return fmt.Errorf("vmimage: %s version does not match image", kind)
	}
	if err := validateSource(artifact.Source); err != nil {
		return fmt.Errorf("vmimage: %s source: %w", kind, err)
	}
	digest := artifact.digest()
	if !validDigest(digest) {
		return fmt.Errorf("vmimage: %s sha256 must be lowercase SHA-256 hex", kind)
	}
	if artifact.Size <= 0 || artifact.Size > maxArtifactSize {
		return fmt.Errorf("vmimage: %s size is outside the permitted range", kind)
	}
	mode := artifact.expectedMode()
	if mode&^uint32(0o777) != 0 || mode == 0 {
		return fmt.Errorf("vmimage: %s mode must contain only non-zero Unix permission bits", kind)
	}
	if artifact.Transform == nil {
		if artifact.InputSHA256 != "" || artifact.InputSize != 0 {
			return fmt.Errorf("vmimage: %s input fields require a transform", kind)
		}
		return nil
	}
	if kind != "rootfs" && kind != "artifact" {
		return fmt.Errorf("vmimage: %s cannot declare a root filesystem transform", kind)
	}
	if !validDigest(artifact.InputSHA256) {
		return fmt.Errorf("vmimage: %s inputSha256 must be non-zero lowercase SHA-256 hex", kind)
	}
	if artifact.InputSize <= 0 || artifact.InputSize > maxArtifactSize {
		return fmt.Errorf("vmimage: %s inputSize is outside the permitted range", kind)
	}
	transform := artifact.Transform
	if transform.Type != TransformQCOW2RootPartition {
		return fmt.Errorf("vmimage: %s transform type is not supported", kind)
	}
	if transform.SectorSize <= 0 || transform.SectorSize > 4096 || transform.SectorSize&(transform.SectorSize-1) != 0 ||
		transform.StartSector <= 0 || transform.StartSector > (1<<63-1)/transform.SectorSize ||
		transform.SectorCount <= 0 || transform.SectorCount > maxArtifactSize/transform.SectorSize ||
		transform.SectorCount*transform.SectorSize != artifact.Size {
		return fmt.Errorf("vmimage: %s root partition geometry is invalid", kind)
	}
	return nil
}

func validDigest(value string) bool {
	return sha256Pattern.MatchString(value) && value != strings.Repeat("0", sha256.Size*2)
}

func (artifact ArtifactManifest) digest() string {
	if artifact.SHA256 != "" && artifact.Sha256 != "" && artifact.SHA256 != artifact.Sha256 {
		return ""
	}
	if artifact.SHA256 != "" {
		return artifact.SHA256
	}
	return artifact.Sha256
}

func (artifact ArtifactManifest) expectedMode() uint32 {
	if artifact.Mode == 0 {
		return defaultArtifactMode
	}
	return artifact.Mode
}

func canonicalArtifact(artifact ArtifactManifest) ArtifactManifest {
	artifact.SHA256 = artifact.digest()
	artifact.Sha256 = ""
	artifact.Mode = artifact.expectedMode()
	if artifact.Transform != nil {
		transform := *artifact.Transform
		artifact.Transform = &transform
	}
	return artifact
}

func validArchitecture(value Architecture) bool {
	return value == ArchitectureAMD64 || value == ArchitectureARM64
}

func isUbuntuLTS(value string) bool {
	match := ubuntuPattern.FindStringSubmatch(value)
	if match == nil {
		return false
	}
	// Ubuntu .04 releases in even-numbered years are LTS releases. This keeps
	// the check future-proof while refusing rolling/development images.
	year, err := strconv.Atoi(match[1])
	return err == nil && year%2 == 0
}

func validateSource(source string) error {
	if source == "" || len(source) > maxSourceLength || strings.IndexByte(source, 0) >= 0 ||
		strings.IndexFunc(source, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return errors.New("source is empty or contains unsafe characters")
	}
	parsed, err := url.Parse(source)
	if err != nil {
		return errors.New("source is not a valid path or URL")
	}
	if parsed.Scheme != "" && parsed.Scheme != "http" && parsed.Scheme != "https" && parsed.Scheme != "file" {
		return errors.New("source URL scheme is not supported")
	}
	if (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Host == "" {
		return errors.New("HTTP source must contain a host")
	}
	if parsed.Scheme == "file" && parsed.Host != "" {
		return errors.New("file source must not contain a host")
	}
	return nil
}

// validateImmutableImageSource is deliberately stricter than validateSource.
// Guest service provenance can name a local test fixture, but the boot pair is
// supply-chain input and may only come from a canonical, versioned HTTPS URL.
func validateImmutableImageSource(kind, source string, architecture Architecture, ubuntuRelease, imageVersion string) error {
	parsed, err := url.Parse(source)
	if err != nil || parsed.Scheme != "https" || parsed.Opaque != "" || parsed.Hostname() == "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawPath != "" {
		return fmt.Errorf("vmimage: %s source must be a canonical versioned HTTPS URL", kind)
	}
	if parsed.Host != parsed.Hostname() || parsed.Host != strings.ToLower(parsed.Host) ||
		parsed.Path == "" || parsed.Path != pathpkg.Clean(parsed.Path) || strings.Contains(parsed.Path, "\\") {
		return fmt.Errorf("vmimage: %s source must not contain a port, escaped path, or traversal", kind)
	}
	versioned := false
	for _, segment := range strings.Split(strings.Trim(parsed.Path, "/"), "/") {
		if versionSegment.MatchString(segment) {
			versioned = true
			break
		}
	}
	if !versioned {
		return fmt.Errorf("vmimage: %s source path is not pinned to a version or immutable release", kind)
	}
	if (kind == "kernel" && (parsed.Host != "s3.amazonaws.com" || !kernelSource.MatchString(parsed.Path))) ||
		(kind == "rootfs" && (parsed.Host != "cloud-images.ubuntu.com" || !ubuntuSource.MatchString(parsed.Path))) {
		return fmt.Errorf("vmimage: %s source is not the fixed upstream artifact path", kind)
	}
	if kind == "rootfs" {
		series := strings.Join(strings.Split(ubuntuRelease, ".")[:2], ".")
		if !strings.HasPrefix(pathpkg.Base(parsed.Path), "ubuntu-"+series+"-minimal-cloudimg-") {
			return errors.New("vmimage: rootfs source Ubuntu series does not match image")
		}
	}
	if kind == "kernel" {
		marker := strings.LastIndex(imageVersion, "-fc")
		if marker < 0 {
			return errors.New("vmimage: image version does not identify its Firecracker release")
		}
		components := strings.Split(imageVersion[marker+3:], ".")
		if len(components) != 3 || !strings.Contains(parsed.Path, "/v"+components[0]+"."+components[1]+"/") {
			return errors.New("vmimage: kernel source Firecracker release does not match image")
		}
	}
	pathValue := strings.ToLower(parsed.Path)
	hasAMD64 := amd64Source.MatchString(pathValue)
	hasARM64 := arm64Source.MatchString(pathValue)
	if hasAMD64 == hasARM64 || (architecture == ArchitectureAMD64 && !hasAMD64) || (architecture == ArchitectureARM64 && !hasARM64) {
		return fmt.Errorf("vmimage: %s source architecture does not match image", kind)
	}
	return nil
}

func isZeroArtifact(artifact ArtifactManifest) bool {
	return artifact.Name == "" && artifact.Architecture == "" && artifact.Version == "" &&
		artifact.Source == "" && artifact.digest() == "" && artifact.Size == 0 && artifact.Mode == 0 &&
		artifact.InputSHA256 == "" && artifact.InputSize == 0 && artifact.Transform == nil
}

func artifactsEqual(left, right ArtifactManifest) bool {
	return left.Name == right.Name && left.Architecture == right.Architecture && left.Version == right.Version &&
		left.Source == right.Source && left.digest() == right.digest() && left.Size == right.Size && left.expectedMode() == right.expectedMode() &&
		left.InputSHA256 == right.InputSHA256 && left.InputSize == right.InputSize && transformsEqual(left.Transform, right.Transform)
}

func transformsEqual(left, right *Transform) bool {
	if left == nil || right == nil {
		return left == right
	}
	return *left == *right
}

// MarshalJSON intentionally emits only canonical fields, even when a caller
// used the Sha256 or Rootfs Go aliases.
func (artifact ArtifactManifest) MarshalJSON() ([]byte, error) {
	type wire ArtifactManifest
	artifact.SHA256 = artifact.digest()
	artifact.Sha256 = ""
	return json.Marshal(wire(artifact))
}

// CanonicalJSON returns deterministic manifest bytes suitable for hashing or
// embedding in a guest seed.
func (manifest GuestImageManifest) CanonicalJSON() ([]byte, error) {
	canonical, err := NewManifest(manifest)
	if err != nil {
		return nil, err
	}
	return json.Marshal(canonical)
}

// Digest returns the SHA-256 of CanonicalJSON.
func (manifest GuestImageManifest) Digest() (string, error) {
	data, err := manifest.CanonicalJSON()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// DecodeManifest strictly decodes one manifest document and validates it.
func DecodeManifest(data []byte) (GuestImageManifest, error) {
	if len(data) == 0 || int64(len(data)) > maxManifestBytes {
		return GuestImageManifest{}, errors.New("vmimage: manifest size is outside the permitted range")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var manifest GuestImageManifest
	if err := decoder.Decode(&manifest); err != nil {
		return GuestImageManifest{}, fmt.Errorf("vmimage: decode manifest: %w", err)
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return GuestImageManifest{}, errors.New("vmimage: manifest contains trailing data")
	}
	return NewPinnedManifest(manifest)
}

// Decode is a concise alias for DecodeManifest.
func Decode(data []byte) (GuestImageManifest, error) { return DecodeManifest(data) }

// VerifyFile verifies that path is a regular, non-symlink file with exactly
// the manifest's mode, byte count, and SHA-256. It never follows a symlink.
func VerifyFile(path string, artifact ArtifactManifest) error {
	if path == "" {
		return errors.New("vmimage: artifact path is empty")
	}
	if err := artifact.validate("artifact", artifact.Architecture, artifact.Version); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("vmimage: stat artifact: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("vmimage: artifact must be a regular file, not a symlink")
	}
	if uint32(info.Mode().Perm()) != artifact.expectedMode() {
		return fmt.Errorf("vmimage: artifact mode %04o does not match manifest mode %04o", info.Mode().Perm(), artifact.expectedMode())
	}
	if info.Size() != artifact.Size {
		return fmt.Errorf("vmimage: artifact size %d does not match manifest size %d", info.Size(), artifact.Size)
	}
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return fmt.Errorf("vmimage: open artifact: %w", err)
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.CopyN(hash, file, artifact.Size+1); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("vmimage: hash artifact: %w", err)
	}
	if hex.EncodeToString(hash.Sum(nil)) != artifact.digest() {
		return errors.New("vmimage: artifact sha256 does not match manifest")
	}
	return nil
}

// VerifyArtifact is a descriptive alias for VerifyFile.
func VerifyArtifact(path string, artifact ArtifactManifest) error { return VerifyFile(path, artifact) }
