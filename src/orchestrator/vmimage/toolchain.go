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
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

const (
	ToolchainSchemaVersion = 1
	maxToolchainBytes      = 64 << 10
	maxArchiveEntries      = 1024
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
	parsed, err := url.Parse(artifact.URL)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" {
		return errors.New("source must be an HTTPS URL without credentials or a fragment")
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
	return value != "" && !strings.ContainsRune(value, 0) && !strings.HasPrefix(value, "/") && path.Clean(value) == value && value != "." && value != ".." && !strings.HasPrefix(value, "../")
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
	Root   string
	Client *http.Client
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
		return installed, nil
	}
	if err := os.MkdirAll(filepath.Dir(entry), 0o700); err != nil {
		return InstalledToolchain{}, fmt.Errorf("vmimage: create toolchain cache: %w", err)
	}
	stage, err := createStaging(filepath.Dir(entry))
	if err != nil {
		return InstalledToolchain{}, err
	}
	defer os.RemoveAll(stage)
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
	if err := os.Rename(stage, entry); err != nil {
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
	client := installer.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Minute}
	} else {
		clone := *client
		client = &clone
	}
	client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if len(via) > 2 || request.URL.Scheme != "https" || request.URL.User != nil || request.URL.Hostname() != "release-assets.githubusercontent.com" {
			return errors.New("Firecracker release redirect is not allowed")
		}
		return nil
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, artifact.URL, nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("source answered HTTP %d", response.StatusCode)
	}
	if response.ContentLength >= 0 && response.ContentLength != artifact.Size {
		return errors.New("source content length does not match manifest")
	}
	file, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(target)
		}
	}()
	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(file, hash), contextReader{ctx: ctx, reader: io.LimitReader(response.Body, artifact.Size+1)})
	if err != nil {
		return err
	}
	if written != artifact.Size || hex.EncodeToString(hash.Sum(nil)) != artifact.SHA256 {
		return errors.New("source bytes do not match pinned size and sha256")
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

func extractToolchain(archivePath, targetDir string, manifest ToolchainManifest) error {
	file, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer file.Close()
	compressed, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("vmimage: open Firecracker archive: %w", err)
	}
	defer compressed.Close()
	reader := tar.NewReader(compressed)
	wanted := map[string]ArchiveMember{manifest.Firecracker.ArchivePath: manifest.Firecracker, manifest.Jailer.ArchivePath: manifest.Jailer}
	found := make(map[string]bool, len(wanted))
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
		if header.Typeflag == tar.TypeDir || header.Size != member.Size {
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
	file, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, os.FileMode(member.Mode))
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(target)
		}
	}()
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
	if installed.Dir == "" || !pathWithin(filepath.Clean(installer.Root), installed.Dir) {
		return errors.New("vmimage: installed toolchain lies outside its root")
	}
	if err := verifyDirectory(installed.Dir); err != nil {
		return err
	}
	data, err := os.ReadFile(filepath.Join(installed.Dir, "manifest.json"))
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
		path   string
		member ArchiveMember
	}{{installed.Firecracker, installed.Manifest.Firecracker}, {installed.Jailer, installed.Manifest.Jailer}} {
		info, err := os.Lstat(item.path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() != item.member.Size || uint32(info.Mode().Perm()) != item.member.Mode {
			return errors.New("vmimage: cached toolchain executable metadata differs from manifest")
		}
		file, err := os.Open(item.path)
		if err != nil {
			return err
		}
		hash := sha256.New()
		_, copyErr := io.Copy(hash, file)
		closeErr := file.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		if hex.EncodeToString(hash.Sum(nil)) != item.member.SHA256 {
			return errors.New("vmimage: cached toolchain executable digest differs from manifest")
		}
	}
	return nil
}
