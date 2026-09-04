package vmimage

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const (
	ToolchainSchemaVersion = 1
	maxToolchainBytes      = 64 << 10
	maxArchiveEntries      = 1024
	maxArchiveExpandedSize = int64(1 << 30)
)

// RemoteArtifact identifies one immutable HTTPS response.
type RemoteArtifact struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// ArchiveMember identifies one executable inside the pinned Firecracker
// release archive. ArchivePath is exact, not a glob or basename match.
type ArchiveMember struct {
	ArchivePath string `json:"archivePath"`
	Name        string `json:"name"`
	SHA256      string `json:"sha256"`
	Size        int64  `json:"size"`
	Mode        uint32 `json:"mode"`
}

// ToolchainManifest pins the native Firecracker release and the official Go
// SDK. Architecture-specific manifests prevent an amd64 binary from being
// installed for an arm64 qualification run or vice versa.
type ToolchainManifest struct {
	SchemaVersion      int            `json:"schemaVersion"`
	Architecture       Architecture   `json:"architecture"`
	FirecrackerVersion string         `json:"firecrackerVersion"`
	Archive            RemoteArtifact `json:"archive"`
	Firecracker        ArchiveMember  `json:"firecracker"`
	Jailer             ArchiveMember  `json:"jailer"`
	SDKModule          string         `json:"sdkModule"`
	SDKVersion         string         `json:"sdkVersion"`
}

func (manifest ToolchainManifest) Validate() error {
	if manifest.SchemaVersion != ToolchainSchemaVersion {
		return fmt.Errorf("vmimage: unsupported toolchain schema %d", manifest.SchemaVersion)
	}
	if !validArchitecture(manifest.Architecture) {
		return errors.New("vmimage: toolchain architecture must be amd64 or arm64")
	}
	if !versionPattern.MatchString(manifest.FirecrackerVersion) {
		return errors.New("vmimage: Firecracker version is not a safe release token")
	}
	releaseArch := map[Architecture]string{ArchitectureAMD64: "x86_64", ArchitectureARM64: "aarch64"}[manifest.Architecture]
	archiveName := "firecracker-v" + manifest.FirecrackerVersion + "-" + releaseArch + ".tgz"
	expectedURL := "https://github.com/firecracker-microvm/firecracker/releases/download/v" + manifest.FirecrackerVersion + "/" + archiveName
	if err := manifest.Archive.validate(expectedURL); err != nil {
		return fmt.Errorf("vmimage: Firecracker archive: %w", err)
	}
	prefix := "release-v" + manifest.FirecrackerVersion + "-" + releaseArch + "/"
	if err := manifest.Firecracker.validate("firecracker", prefix+"firecracker-v"+manifest.FirecrackerVersion+"-"+releaseArch); err != nil {
		return err
	}
	if err := manifest.Jailer.validate("jailer", prefix+"jailer-v"+manifest.FirecrackerVersion+"-"+releaseArch); err != nil {
		return err
	}
	if manifest.SDKModule != "github.com/firecracker-microvm/firecracker-go-sdk" || !versionPattern.MatchString(manifest.SDKVersion) || !strings.HasPrefix(manifest.SDKVersion, "v") {
		return errors.New("vmimage: official Firecracker Go SDK module and version are required")
	}
	return nil
}

func (artifact RemoteArtifact) validate(expectedURL string) error {
	if err := validateRemoteURL(artifact.URL); err != nil {
		return err
	}
	if artifact.URL != expectedURL {
		return errors.New("source is not the fixed versioned release URL")
	}
	if !validToolchainDigest(artifact.SHA256) {
		return errors.New("sha256 must be a non-zero lowercase SHA-256 digest")
	}
	if artifact.Size <= 0 || artifact.Size > maxArtifactSize {
		return errors.New("size is outside the permitted range")
	}
	return nil
}

func (member ArchiveMember) validate(name, expectedPath string) error {
	if member.Name != name || member.ArchivePath != expectedPath || !safeArchivePath(member.ArchivePath) {
		return fmt.Errorf("vmimage: %s archive identity is invalid", name)
	}
	if !validToolchainDigest(member.SHA256) {
		return fmt.Errorf("vmimage: %s sha256 must be a non-zero lowercase SHA-256 digest", name)
	}
	if member.Size <= 0 || member.Size > maxArtifactSize {
		return fmt.Errorf("vmimage: %s size is outside the permitted range", name)
	}
	if member.Mode != 0o755 {
		return fmt.Errorf("vmimage: %s mode must be 0755", name)
	}
	return nil
}

func validToolchainDigest(value string) bool {
	return sha256Pattern.MatchString(value) && value != strings.Repeat("0", sha256.Size*2)
}

func safeArchivePath(value string) bool {
	return value != "" && !strings.ContainsRune(value, 0) && !strings.Contains(value, "\\") && !strings.HasPrefix(value, "/") && path.Clean(value) == value && value != "." && value != ".." && !strings.HasPrefix(value, "../")
}

func (manifest ToolchainManifest) CanonicalJSON() ([]byte, error) {
	if err := manifest.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(manifest)
}

func (manifest ToolchainManifest) Digest() (string, error) {
	data, err := manifest.CanonicalJSON()
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

func DecodeToolchainManifest(data []byte) (ToolchainManifest, error) {
	if len(data) == 0 || len(data) > maxToolchainBytes {
		return ToolchainManifest{}, errors.New("vmimage: toolchain manifest size is outside the permitted range")
	}
	if err := validateSeedJSONObjectDocument(data, toolchainJSONSchema(), "toolchain manifest"); err != nil {
		return ToolchainManifest{}, fmt.Errorf("vmimage: decode toolchain manifest: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var manifest ToolchainManifest
	if err := decoder.Decode(&manifest); err != nil {
		return ToolchainManifest{}, fmt.Errorf("vmimage: decode toolchain manifest: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return ToolchainManifest{}, errors.New("vmimage: toolchain manifest contains trailing data")
	}
	if err := manifest.Validate(); err != nil {
		return ToolchainManifest{}, err
	}
	return manifest, nil
}

type InstalledToolchain struct {
	Manifest    ToolchainManifest
	Dir         string
	Firecracker string
	Jailer      string
}

type ToolchainInstaller struct {
	Root       string
	Client     *http.Client
	Downloader Downloader
}

// Location returns the immutable destination without reading or writing it.
func (installer *ToolchainInstaller) Location(manifest ToolchainManifest) (InstalledToolchain, error) {
	if installer == nil || installer.Root == "" || !filepath.IsAbs(installer.Root) || strings.ContainsRune(installer.Root, 0) {
		return InstalledToolchain{}, errors.New("vmimage: toolchain root must be an absolute path")
	}
	if err := manifest.Validate(); err != nil {
		return InstalledToolchain{}, err
	}
	digest, err := manifest.Digest()
	if err != nil {
		return InstalledToolchain{}, err
	}
	entry := filepath.Join(filepath.Clean(installer.Root), "toolchain", string(manifest.Architecture), "v"+manifest.FirecrackerVersion, digest)
	return InstalledToolchain{Manifest: manifest, Dir: entry, Firecracker: filepath.Join(entry, manifest.Firecracker.Name), Jailer: filepath.Join(entry, manifest.Jailer.Name)}, nil
}

// Verify checks an installed toolchain against the complete pinned manifest.
func (installer *ToolchainInstaller) Verify(installed InstalledToolchain) error {
	return installer.verify(installed)
}

func (installer *ToolchainInstaller) Install(ctx context.Context, manifest ToolchainManifest) (InstalledToolchain, error) {
	if ctx == nil {
		return InstalledToolchain{}, errors.New("vmimage: toolchain context is nil")
	}
	installed, err := installer.Location(manifest)
	if err != nil {
		return InstalledToolchain{}, err
	}
	entry := installed.Dir
	if installer.verify(installed) == nil {
		if err := syncDir(filepath.Dir(entry)); err != nil {
			return InstalledToolchain{}, fmt.Errorf("vmimage: sync existing toolchain parent: %w", err)
		}
		return installed, nil
	}
	if err := ensurePrivateTree(installer.Root, filepath.Dir(entry)); err != nil {
		return InstalledToolchain{}, fmt.Errorf("vmimage: create toolchain cache: %w", err)
	}
	lock, err := acquireCacheLock(installer.Root)
	if err != nil {
		return InstalledToolchain{}, err
	}
	defer releaseCacheLock(lock)
	if err := recoverStaging(filepath.Dir(entry)); err != nil {
		return InstalledToolchain{}, fmt.Errorf("vmimage: recover toolchain staging: %w", err)
	}
	if installer.verify(installed) == nil {
		if err := syncDir(filepath.Dir(entry)); err != nil {
			return InstalledToolchain{}, fmt.Errorf("vmimage: sync existing toolchain parent: %w", err)
		}
		return installed, nil
	}
	stage, err := createStaging(filepath.Dir(entry))
	if err != nil {
		return InstalledToolchain{}, err
	}
	defer func() { _ = recoverStaging(filepath.Dir(entry)) }()
	archivePath := filepath.Join(stage, "firecracker.tgz")
	if err := installer.fetch(ctx, manifest.Archive, archivePath); err != nil {
		return InstalledToolchain{}, fmt.Errorf("vmimage: fetch Firecracker archive: %w", err)
	}
	if err := extractToolchain(archivePath, stage, manifest); err != nil {
		return InstalledToolchain{}, err
	}
	if err := os.Remove(archivePath); err != nil {
		return InstalledToolchain{}, err
	}
	manifestBytes, err := manifest.CanonicalJSON()
	if err != nil {
		return InstalledToolchain{}, err
	}
	if err := writePrivate(filepath.Join(stage, "manifest.json"), manifestBytes); err != nil {
		return InstalledToolchain{}, err
	}
	for _, file := range []string{manifest.Firecracker.Name, manifest.Jailer.Name, "manifest.json"} {
		if err := syncFile(filepath.Join(stage, file)); err != nil {
			return InstalledToolchain{}, err
		}
	}
	if err := syncDir(stage); err != nil {
		return InstalledToolchain{}, err
	}
	if err := ctx.Err(); err != nil {
		return InstalledToolchain{}, err
	}
	if err := publishDirectory(stage, entry); err != nil {
		if syncErr := syncDir(filepath.Dir(entry)); syncErr != nil {
			return InstalledToolchain{}, fmt.Errorf("vmimage: sync toolchain parent after publication race: %w", syncErr)
		}
		if installer.verify(installed) == nil {
			return installed, nil
		}
		return InstalledToolchain{}, fmt.Errorf("vmimage: publish toolchain cache entry: %w", err)
	}
	if err := syncDir(filepath.Dir(entry)); err != nil {
		return InstalledToolchain{}, err
	}
	if err := installer.verify(installed); err != nil {
		return InstalledToolchain{}, err
	}
	return installed, nil
}

func (installer *ToolchainInstaller) fetch(ctx context.Context, artifact RemoteArtifact, target string) error {
	downloader := installer.Downloader
	if downloader == nil {
		downloader = httpDownloader{client: installer.Client, allowGitHubReleaseRedirect: true}
	}
	return downloadPinned(ctx, downloader, artifact.URL, target, artifact.SHA256, artifact.Size, 0o600)
}

func extractToolchain(archivePath, targetDir string, manifest ToolchainManifest) error {
	file, metadata, err := secureOpenPath(archivePath, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	if !metadata.regular || metadata.special || metadata.uid != uint32(os.Geteuid()) || metadata.links != 1 {
		return errors.New("vmimage: Firecracker archive metadata is unsafe")
	}
	compressed, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("vmimage: open Firecracker archive: %w", err)
	}
	defer compressed.Close()
	reader := tar.NewReader(compressed)
	wanted := map[string]ArchiveMember{manifest.Firecracker.ArchivePath: manifest.Firecracker, manifest.Jailer.ArchivePath: manifest.Jailer}
	found := make(map[string]bool, len(wanted))
	var expandedSize int64
	for count := 0; ; count++ {
		if count >= maxArchiveEntries {
			return errors.New("vmimage: Firecracker archive has too many entries")
		}
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("vmimage: read Firecracker archive: %w", err)
		}
		if !safeArchivePath(header.Name) {
			return errors.New("vmimage: Firecracker archive contains an unsafe path")
		}
		if header.Size < 0 || expandedSize > maxArchiveExpandedSize-header.Size {
			return errors.New("vmimage: Firecracker archive exceeds the expanded-size limit")
		}
		expandedSize += header.Size
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA && header.Typeflag != tar.TypeDir {
			return errors.New("vmimage: Firecracker archive contains a link or unsupported entry")
		}
		member, ok := wanted[header.Name]
		if !ok {
			continue
		}
		if found[header.Name] {
			return fmt.Errorf("vmimage: Firecracker archive repeats %s", header.Name)
		}
		if header.Typeflag == tar.TypeDir || header.Size != member.Size || uint32(header.FileInfo().Mode().Perm()) != member.Mode {
			return fmt.Errorf("vmimage: Firecracker archive member %s has the wrong type or size", header.Name)
		}
		if err := extractMember(reader, filepath.Join(targetDir, member.Name), member); err != nil {
			return err
		}
		found[header.Name] = true
	}
	for member := range wanted {
		if !found[member] {
			return fmt.Errorf("vmimage: Firecracker archive is missing %s", member)
		}
	}
	return nil
}

func extractMember(reader io.Reader, target string, member ArchiveMember) error {
	file, _, err := secureOpenPath(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, os.FileMode(member.Mode))
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = removeFileEntry(target)
		}
	}()
	if err := file.Chmod(os.FileMode(member.Mode)); err != nil {
		return err
	}
	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(file, hash), io.LimitReader(reader, member.Size+1))
	if err != nil {
		return err
	}
	if written != member.Size || hex.EncodeToString(hash.Sum(nil)) != member.SHA256 {
		return fmt.Errorf("vmimage: extracted %s does not match its pin", member.Name)
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}

func (installer *ToolchainInstaller) verify(installed InstalledToolchain) error {
	if installer == nil {
		return errors.New("vmimage: toolchain installer is nil")
	}
	expected, err := installer.Location(installed.Manifest)
	if err != nil {
		return err
	}
	if installed.Dir != expected.Dir || installed.Firecracker != expected.Firecracker || installed.Jailer != expected.Jailer {
		return errors.New("vmimage: installed toolchain paths do not match their derived location")
	}
	directory, directoryMetadata, err := openVerifiedDirectory(installed.Dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	if err := verifyExactDirectoryEntriesAt(directory, installed.Manifest.Firecracker.Name, installed.Manifest.Jailer.Name, "manifest.json"); err != nil {
		return err
	}
	data, err := readRegularFileAt(directory, directoryMetadata, "manifest.json", 0o600, maxToolchainBytes)
	if err != nil {
		return err
	}
	cached, err := DecodeToolchainManifest(data)
	if err != nil {
		return err
	}
	want, _ := installed.Manifest.CanonicalJSON()
	got, _ := cached.CanonicalJSON()
	if !bytes.Equal(want, got) {
		return errors.New("vmimage: cached toolchain manifest differs from requested manifest")
	}
	for _, item := range []struct {
		name   string
		member ArchiveMember
	}{{installed.Manifest.Firecracker.Name, installed.Manifest.Firecracker}, {installed.Manifest.Jailer.Name, installed.Manifest.Jailer}} {
		file, metadata, err := secureOpenAt(directory, item.name, os.O_RDONLY, 0)
		if err != nil {
			return err
		}
		if err := validateCacheFileMetadata(metadata, directoryMetadata, os.FileMode(item.member.Mode), item.member.Size, item.member.Size); err != nil {
			_ = file.Close()
			return err
		}
		hash := sha256.New()
		_, copyErr := io.Copy(hash, file)
		after, statErr := secureMetadata(file)
		closeErr := file.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		if statErr != nil || after != metadata {
			return errors.New("vmimage: cached toolchain executable changed while it was verified")
		}
		if hex.EncodeToString(hash.Sum(nil)) != item.member.SHA256 {
			return errors.New("vmimage: cached toolchain executable digest differs from manifest")
		}
	}
	return nil
}
