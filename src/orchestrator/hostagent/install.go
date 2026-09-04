// This file implements the D-69 component installer: download the signed
// release artifact into a private staging directory, verify the pinned
// sha256 and the detached ed25519 signature against the public key pinned in
// ts-node's own configuration, and atomically rename the staged directory
// into /opt/terrascale/<component>/<version>/. Every failure path removes
// the staging directory, so a rejected artifact never leaves a partial
// version directory behind.
package hostagent

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
)

// ArtifactDownloader fetches one bounded release file from its https URL;
// http.Client-based DownloadClient is the live spelling and tests inject an
// in-memory fake.
type ArtifactDownloader interface {
	// Download writes the body of url into target and returns the bytes
	// read. It must refuse non-https URLs.
	Download(url string, target string, limitBytes int64) error
}

// DownloadClient is the live downloader over one shared http.Client.
type DownloadClient struct {
	// Client is the HTTP client; NewInstallClient wires safe timeouts.
	Client *http.Client
	// AllowedHosts is the exact HTTPS host boundary for release downloads.
	// A hostname-only entry permits that host's HTTPS ports; an entry with a
	// port is exact. An empty list leaves host admission to the caller.
	AllowedHosts []string
}

// Download fetches url into target, enforcing https, the redirect budget of
// the client, and the byte limit.
func (d DownloadClient) Download(url string, target string, limitBytes int64) error {
	if d.Client == nil {
		return &InvalidOperationError{Message: "The download client needs an HTTP client."}
	}
	if !safeAbsolutePath(target) {
		return &errs.Argument{Param: "target", Message: "The download target must be an absolute safe path."}
	}
	parent := filepath.Dir(target)
	resolvedParent, resolveErr := filepath.EvalSymlinks(parent)
	if resolveErr != nil || filepath.Clean(resolvedParent) != filepath.Clean(parent) {
		return &errs.Argument{Param: "target", Message: "The download target directory must not contain symlinks."}
	}
	parsed, err := parseReleaseURL(url)
	if err != nil {
		return &errs.Argument{Param: "url", Message: "Release artifacts are fetched over https only."}
	}
	if !releaseHostAllowed(parsed, d.AllowedHosts) {
		return &errs.Argument{Param: "url", Message: "The release URL host is not trusted."}
	}
	if limitBytes < 1 {
		return &errs.ArgumentOutOfRangeError{Param: "limitBytes", Message: "The release response limit must be positive."}
	}
	// Copy the caller-owned client. In particular, redirect policy must not be
	// changed on a client that may be shared by another subsystem.
	client := *d.Client
	client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if len(via) >= 8 {
			return http.ErrUseLastResponse
		}
		redirect, redirectErr := parseReleaseURL(request.URL.String())
		if redirectErr != nil || !releaseHostAllowed(redirect, d.AllowedHosts) {
			return http.ErrUseLastResponse
		}
		return nil
	}
	response, err := client.Get(parsed.String())
	if err != nil {
		// Do not return url.Error verbatim: it may include query credentials
		// from a manifest URL or a redirect Location.
		return errors.New("the release download request failed")
	}
	if response.Body == nil {
		return &InvalidDataError{Message: "The release response has no body."}
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("the release URL answered status %d", response.StatusCode)
	}
	if response.ContentLength > limitBytes {
		return &errs.ArgumentOutOfRangeError{Param: "limitBytes", Message: "The release artifact exceeds its size bound."}
	}
	file, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	cleanup := func(cause error) error { _ = os.Remove(target); return cause }
	readLimit := limitBytes
	if limitBytes < int64(^uint64(0)>>1) {
		readLimit++
	}
	written, err := io.Copy(file, io.LimitReader(response.Body, readLimit))
	closeErr := file.Close()
	if err != nil {
		return cleanup(err)
	}
	if closeErr != nil {
		return cleanup(closeErr)
	}
	if err := syncFile(target); err != nil {
		return cleanup(err)
	}
	if written > limitBytes {
		return cleanup(&errs.ArgumentOutOfRangeError{
			Param:   "limitBytes",
			Message: "The release artifact exceeds its size bound.",
		})
	}
	return nil
}

// InstallClient composes the downloader and timeouts shared by every
// component install.
func InstallClient() DownloadClient {
	return DownloadClient{Client: &http.Client{
		Timeout: 5 * time.Minute,
	}, AllowedHosts: []string{"releases.terrascale.tech"}}
}

func parseReleaseURL(raw string) (*url.URL, error) {
	if raw == "" || len(raw) > hostAgentMaximumUrlLength || strings.ContainsAny(raw, "\r\n\x00") {
		return nil, fmt.Errorf("invalid release URL")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.Fragment != "" || parsed.Hostname() == "" {
		return nil, fmt.Errorf("invalid release URL")
	}
	return parsed, nil
}

func releaseHostAllowed(candidate *url.URL, allowedHosts []string) bool {
	if len(allowedHosts) == 0 {
		return true
	}
	host := strings.ToLower(candidate.Host)
	hostname := strings.TrimSuffix(strings.ToLower(candidate.Hostname()), ".")
	for _, allowed := range allowedHosts {
		allowed = strings.TrimSpace(strings.ToLower(allowed))
		if allowed == "" {
			continue
		}
		if allowed == host {
			return true
		}
		configured, err := url.Parse("https://" + allowed)
		if err == nil && configured.User == nil && configured.Path == "" && configured.RawQuery == "" &&
			configured.Fragment == "" && configured.Port() == "" &&
			strings.TrimSuffix(strings.ToLower(configured.Hostname()), ".") == hostname {
			return true
		}
	}
	return false
}

// InstallerConfig is the fully explicit configuration of one installer.
type InstallerConfig struct {
	// InstallRoot is /opt/terrascale on production hosts.
	InstallRoot string
	// PublicKeyHex is the release-signing ed25519 public key pinned in the
	// agent configuration; it is never fetched from the network.
	PublicKeyHex string
	// Downloader fetches artifacts and signatures.
	Downloader ArtifactDownloader
	// AllowedHosts is the release HTTPS host boundary. Empty uses the
	// production release host, while tests or an explicitly configured mirror
	// may provide their own exact boundary.
	AllowedHosts []string
}

// Installer installs verified release artifacts into version directories.
type Installer struct {
	installRoot  string
	publicKey    ed25519.PublicKey
	downloader   ArtifactDownloader
	allowedHosts []string
	mutex        sync.Mutex
}

func safeAbsolutePath(value string) bool {
	if value == "" || !filepath.IsAbs(value) || strings.ContainsAny(value, "\x00\r\n") {
		return false
	}
	clean := filepath.Clean(value)
	if clean == "." || clean == string(filepath.Separator)+"" {
		return false
	}
	for _, part := range strings.Split(filepath.ToSlash(value), "/") {
		if part == ".." {
			return false
		}
	}
	return true
}

func syncFile(path string) error {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	err = file.Sync()
	closeErr := file.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func syncDir(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	err = directory.Sync()
	closeErr := directory.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func ensureDirectory(path string, mode os.FileMode) error {
	if err := os.MkdirAll(path, mode); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return &InvalidOperationError{Message: "The install directory must be a real directory."}
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || filepath.Clean(resolved) != filepath.Clean(path) {
		return &InvalidOperationError{Message: "The install directory path must not contain symlinks."}
	}
	return nil
}

// NewInstaller validates the configuration and composes the installer.
func NewInstaller(config InstallerConfig) (*Installer, error) {
	if !safeAbsolutePath(config.InstallRoot) {
		return nil, &errs.Argument{
			Param:   "InstallRoot",
			Message: "The install root must be an absolute path.",
		}
	}
	if !hostAgentEd25519PublicKeyPattern.MatchString(config.PublicKeyHex) {
		return nil, &errs.Argument{
			Param:   "PublicKeyHex",
			Message: "The pinned release-signing key must be lowercase hex ed25519.",
		}
	}
	keyBytes, err := hex.DecodeString(config.PublicKeyHex)
	if err != nil {
		return nil, &errs.Argument{
			Param:   "PublicKeyHex",
			Message: "The pinned release-signing key must be lowercase hex ed25519.",
		}
	}
	if config.Downloader == nil {
		return nil, &errs.Argument{Param: "Downloader", Message: "An artifact downloader is required."}
	}
	allowedHosts := append([]string(nil), config.AllowedHosts...)
	if len(allowedHosts) == 0 {
		allowedHosts = []string{"releases.terrascale.tech"}
	}
	return &Installer{
		installRoot:  filepath.Clean(config.InstallRoot),
		publicKey:    ed25519.PublicKey(keyBytes),
		downloader:   config.Downloader,
		allowedHosts: allowedHosts,
	}, nil
}

// Install downloads and verifies one component release and lands it at
// /<installRoot>/<component>/<version>/<component>. The artifact is staged
// in .staging-<version> under the component directory and renamed into
// place only after both the sha256 and the ed25519 signature verify, so an
// existing good version directory is never touched and a bad one never
// exists. The returned path is the installed version directory.
func (i *Installer) Install(spec ComponentSpec) (string, error) {
	if i == nil {
		return "", &InvalidOperationError{Message: "The installer is required."}
	}
	i.mutex.Lock()
	defer i.mutex.Unlock()
	validated, err := NewComponentSpec(spec)
	if err != nil {
		return "", err
	}
	if info, statErr := os.Lstat(i.installRoot); statErr == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", &InvalidOperationError{Message: "The install root must be a real directory."}
		}
	} else if !os.IsNotExist(statErr) {
		return "", statErr
	} else if err := ensureDirectory(i.installRoot, 0o755); err != nil {
		return "", err
	}
	if artifactURL, parseErr := parseReleaseURL(validated.ArtifactURL); parseErr != nil || !releaseHostAllowed(artifactURL, i.allowedHosts) {
		return "", &errs.Argument{Param: "artifactUrl", Message: "The release URL host is not trusted."}
	}
	if signatureURL, parseErr := parseReleaseURL(validated.SignatureURL); parseErr != nil || !releaseHostAllowed(signatureURL, i.allowedHosts) {
		return "", &errs.Argument{Param: "signatureUrl", Message: "The release URL host is not trusted."}
	}
	componentDir := InstallDir(i.installRoot, validated.Name)
	if err := ensureDirectory(componentDir, 0o755); err != nil {
		return "", err
	}
	staging, err := os.MkdirTemp(componentDir, ".staging-"+validated.Version+"-")
	if err != nil {
		return "", err
	}
	failClosed := func(cause error) (string, error) {
		_ = os.RemoveAll(staging)
		return "", cause
	}
	if err := os.MkdirAll(staging, 0o755); err != nil {
		return "", err
	}
	binaryPath := staging + "/" + validated.Name
	signaturePath := staging + "/" + validated.Name + ".sig"
	if err := i.downloader.Download(validated.ArtifactURL, binaryPath, hostAgentMaximumArtifactBytes); err != nil {
		return failClosed(fmt.Errorf("the artifact download failed: %w", err))
	}
	if err := i.downloader.Download(validated.SignatureURL, signaturePath, 1024); err != nil {
		return failClosed(fmt.Errorf("the signature download failed: %w", err))
	}
	artifact, err := os.ReadFile(binaryPath)
	if err != nil {
		return failClosed(err)
	}
	signatureFile, err := os.ReadFile(signaturePath)
	if err != nil {
		return failClosed(err)
	}
	signature, err := decodeEd25519Signature(signatureFile)
	if err != nil {
		return failClosed(err)
	}
	digest := sha256.Sum256(artifact)
	if hex.EncodeToString(digest[:]) != validated.Sha256 {
		return failClosed(&InvalidDataError{Message: fmt.Sprintf(
			"Component %s %s failed its sha256 check.", validated.Name, validated.Version)})
	}
	if !ed25519.Verify(i.publicKey, artifact, signature) {
		return failClosed(&InvalidDataError{Message: fmt.Sprintf(
			"Component %s %s failed its ed25519 signature check.", validated.Name, validated.Version)})
	}
	if err := os.Chmod(binaryPath, 0o755); err != nil {
		return failClosed(err)
	}
	if err := os.Remove(signaturePath); err != nil {
		return failClosed(err)
	}
	if err := syncDir(staging); err != nil {
		return failClosed(err)
	}
	versionDir := VersionDir(i.installRoot, validated.Name, validated.Version)
	if _, err := os.Stat(versionDir); err == nil {
		// An identical version directory already exists; replace it through
		// the staging rename so the verified bytes are always the ones on disk.
		if err := os.RemoveAll(versionDir); err != nil {
			return failClosed(err)
		}
	} else if !os.IsNotExist(err) {
		return failClosed(err)
	}
	if info, statErr := os.Lstat(versionDir); statErr == nil {
		if !info.IsDir() {
			return failClosed(&InvalidOperationError{Message: "The installed version path is not a directory."})
		}
		// Version directories are immutable content-addressed release slots.
		// Never remove a possibly serving directory; an already-present slot is
		// the safe idempotent result and the newly verified stage is discarded.
		_ = os.RemoveAll(staging)
		return versionDir, nil
	} else if !os.IsNotExist(statErr) {
		return failClosed(statErr)
	}
	if err := syncDir(componentDir); err != nil {
		return failClosed(err)
	}
	if err := os.Rename(staging, versionDir); err != nil {
		return failClosed(err)
	}
	if err := syncDir(componentDir); err != nil {
		return versionDir, err
	}
	return versionDir, nil
}

// decodeEd25519Signature accepts the detached signature as raw 64 bytes or
// as 128 hex characters with optional trailing whitespace. The raw spelling
// is length-checked before any trimming: a raw signature byte may itself be
// 0x0a.
func decodeEd25519Signature(signatureFile []byte) ([]byte, error) {
	switch len(signatureFile) {
	case ed25519.SignatureSize:
		return signatureFile, nil
	case 2*ed25519.SignatureSize + 1:
		if signatureFile[len(signatureFile)-1] != '\n' {
			break
		}
		signatureFile = signatureFile[:len(signatureFile)-1]
		fallthrough
	case 2 * ed25519.SignatureSize:
		decoded, err := hex.DecodeString(string(signatureFile))
		if err != nil || len(decoded) != ed25519.SignatureSize {
			return nil, &InvalidDataError{Message: "The release signature is not canonical hex."}
		}
		return decoded, nil
	}
	return nil, &InvalidDataError{Message: "The release signature is not 64 raw or hex-encoded bytes."}
}

// InstalledVersion reports whether one component version directory exists on
// disk with its binary present.
func InstalledVersion(installRoot, component, version string) bool {
	if validateInstallLocation(installRoot, component) != nil || requireVersion(version) != nil {
		return false
	}
	directory, err := os.Lstat(VersionDir(installRoot, component, version))
	if err != nil || !directory.IsDir() || directory.Mode()&os.ModeSymlink != 0 {
		return false
	}
	info, err := os.Lstat(filepath.Join(VersionDir(installRoot, component, version), component))
	return err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0
}

func requireVersion(version string) error {
	_, err := requireHostAgentName(version, "version", "The version must be a canonical token.")
	return err
}
