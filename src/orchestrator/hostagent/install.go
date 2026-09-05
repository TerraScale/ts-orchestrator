// This file implements the D-69 component installer: download the signed
// release artifact into a private staging directory, verify the pinned
// sha256 and the detached ed25519 signature against the public key pinned in
// ts-node's own configuration, and atomically rename the staged directory
// into /opt/terrascale/<component>/<version>/. Every failure path removes
// the staging directory, so a rejected artifact never leaves a partial
// version directory behind.
package hostagent

import (
	"context"
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
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
)

// ArtifactDownloader fetches one bounded release file from its https URL;
// http.Client-based DownloadClient is the live spelling and tests inject an
// in-memory fake.
type ArtifactDownloader interface {
	// Download writes the body of url into target and returns the bytes
	// read. It must refuse non-https URLs.
	Download(ctx context.Context, url string, target string, limitBytes int64) error
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
func (d DownloadClient) Download(ctx context.Context, url string, target string, limitBytes int64) error {
	if ctx == nil {
		return &errs.Argument{Param: "ctx", Message: "The download context is required."}
	}
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
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return errors.New("the release download request is invalid")
	}
	response, err := client.Do(request)
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
}

func safeAbsolutePath(value string) bool {
	if value == "" || !filepath.IsAbs(value) || strings.ContainsAny(value, " \t\x00\r\n\\") {
		return false
	}
	clean := filepath.Clean(value)
	if clean == "." || clean == string(filepath.Separator) || clean != value {
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
	if !safeAbsolutePath(path) {
		return &InvalidOperationError{Message: "The directory path must be absolute and safe."}
	}
	clean := filepath.Clean(path)
	current := string(filepath.Separator)
	for _, part := range strings.Split(strings.TrimPrefix(filepath.ToSlash(clean), "/"), "/") {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			if err := os.Mkdir(current, mode); err != nil && !os.IsExist(err) {
				return err
			}
			info, err = os.Lstat(current)
		}
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return &InvalidOperationError{Message: "The directory path must not contain symlinks."}
		}
	}
	return nil
}

func ensureDirectoryWithin(root, target string, mode os.FileMode) error {
	relative, err := validateDirectoryWithin(root, target)
	if err != nil {
		return err
	}
	cleanRoot := filepath.Clean(root)
	if err := ensureDirectory(cleanRoot, 0o755); err != nil {
		return err
	}
	if err := ensureDirectoryMode(cleanRoot, 0o755); err != nil {
		return err
	}
	current := cleanRoot
	for _, part := range strings.Split(filepath.ToSlash(relative), "/") {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			if err := os.Mkdir(current, mode); err != nil && !os.IsExist(err) {
				return err
			}
			info, err = os.Lstat(current)
		}
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return &InvalidOperationError{Message: "The data volume path must not contain symlinks."}
		}
	}
	return ensureDirectoryMode(current, mode)
}

// Avoid a privileged chmod when the declared mode already matches. Drift still
// requires CAP_FOWNER after the directory has been assigned to its service uid.
func ensureDirectoryMode(path string, mode os.FileMode) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return &InvalidOperationError{Message: "The data volume must be a real directory."}
	}
	if info.Mode().Perm() == mode.Perm() && !hasSpecialMode(info.Mode()) {
		return nil
	}
	return os.Chmod(path, mode)
}

// validateDirectoryWithin is the read-only admission check used before any
// component lifecycle mutation. Existing path elements must be real
// directories, and the target must be a strict descendant of root.
func validateDirectoryWithin(root, target string) (string, error) {
	if !safeAbsolutePath(root) || !safeAbsolutePath(target) {
		return "", &InvalidOperationError{Message: "The data volume path must be absolute and safe."}
	}
	cleanRoot := filepath.Clean(root)
	cleanTarget := filepath.Clean(target)
	relative, err := filepath.Rel(cleanRoot, cleanTarget)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", &InvalidOperationError{Message: "The component data volume must be below the configured data volume root."}
	}
	current := string(filepath.Separator)
	for _, part := range strings.Split(strings.TrimPrefix(filepath.ToSlash(cleanTarget), "/"), "/") {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, statErr := os.Lstat(current)
		if os.IsNotExist(statErr) {
			continue
		}
		if statErr != nil {
			return "", statErr
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", &InvalidOperationError{Message: "The data volume path must not contain symlinks."}
		}
	}
	return relative, nil
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
	return i.InstallContext(context.Background(), spec)
}

// InstallContext is Install with cancellation propagated through lock waits
// and HTTPS downloads so agent shutdown cannot hang behind an install.
func (i *Installer) InstallContext(ctx context.Context, spec ComponentSpec) (installedPath string, result error) {
	phase := "install-filesystem"
	defer func() {
		if result != nil {
			result = &installPhaseFailure{phase: phase, cause: result}
		}
	}()
	if i == nil {
		return "", &InvalidOperationError{Message: "The installer is required."}
	}
	if ctx == nil {
		return "", &errs.Argument{Param: "ctx", Message: "The install context is required."}
	}
	validated, err := NewComponentSpec(spec)
	if err != nil {
		return "", err
	}
	if info, statErr := os.Lstat(i.installRoot); statErr == nil {
		if err := requireOwnedDirectory(info, "install root"); err != nil {
			return "", err
		}
	} else if !os.IsNotExist(statErr) {
		return "", statErr
	} else if err := ensureDirectory(i.installRoot, 0o755); err != nil {
		return "", err
	}
	if err := os.Chmod(i.installRoot, 0o755); err != nil {
		return "", err
	}
	installInfo, err := os.Lstat(i.installRoot)
	if err != nil {
		return "", err
	}
	if err := requireOwnedDirectory(installInfo, "install root"); err != nil {
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
	componentInfo, err := os.Lstat(componentDir)
	if err != nil {
		return "", err
	}
	if err := requireOwnedDirectory(componentInfo, "component install directory"); err != nil {
		return "", err
	}
	if err := os.Chmod(componentDir, 0o755); err != nil {
		return "", err
	}
	if err := requireSameMount(i.installRoot, componentDir); err != nil {
		return "", err
	}
	if err := syncDir(i.installRoot); err != nil {
		return "", err
	}
	if err := syncDir(componentDir); err != nil {
		return "", err
	}
	lock, err := lockInstallDirectory(ctx, componentDir)
	if err != nil {
		return "", err
	}
	defer unlockInstallDirectory(lock)
	if err := removeAbandonedInstallStages(componentDir); err != nil {
		return "", err
	}
	versionDir := VersionDir(i.installRoot, validated.Name, validated.Version)
	phase = "installed-verification"
	installed, complete, err := i.inspectInstalledRelease(versionDir, validated.Name, validated.Sha256)
	if err != nil {
		return "", err
	}
	if installed && complete {
		return versionDir, verifyExpectedLaunch(versionDir, validated)
	}
	if installed {
		return "", &InvalidDataError{Message: "The installed version is missing immutable release metadata."}
	}
	phase = "install-filesystem"
	staging, err := os.MkdirTemp(componentDir, ".staging-"+validated.Version+"-")
	if err != nil {
		return "", err
	}
	failClosed := func(cause error) (string, error) {
		removeErr := os.RemoveAll(staging)
		syncErr := syncDir(componentDir)
		return "", errors.Join(cause, removeErr, syncErr)
	}
	binaryPath := staging + "/" + validated.Name
	signaturePath := staging + "/" + validated.Name + ".sig"
	digestPath := staging + "/" + validated.Name + ".sha256"
	phase = "artifact-download"
	if err := i.downloader.Download(ctx, validated.ArtifactURL, binaryPath, hostAgentMaximumArtifactBytes); err != nil {
		return failClosed(fmt.Errorf("the artifact download failed: %w", err))
	}
	phase = "signature-download"
	if err := i.downloader.Download(ctx, validated.SignatureURL, signaturePath, 1024); err != nil {
		return failClosed(fmt.Errorf("the signature download failed: %w", err))
	}
	phase = "artifact-read"
	artifact, err := readRegularFileBounded(binaryPath, hostAgentMaximumArtifactBytes)
	if err != nil {
		return failClosed(err)
	}
	phase = "signature-read"
	signatureFile, err := readRegularFileBounded(signaturePath, 1024)
	if err != nil {
		return failClosed(err)
	}
	signature, err := decodeEd25519Signature(signatureFile)
	if err != nil {
		return failClosed(err)
	}
	phase = "artifact-digest"
	digest := sha256.Sum256(artifact)
	if hex.EncodeToString(digest[:]) != validated.Sha256 {
		return failClosed(&InvalidDataError{Message: fmt.Sprintf(
			"Component %s %s failed its sha256 check.", validated.Name, validated.Version)})
	}
	phase = "artifact-signature"
	if !ed25519.Verify(i.publicKey, artifact, signature) {
		return failClosed(&InvalidDataError{Message: fmt.Sprintf(
			"Component %s %s failed its ed25519 signature check.", validated.Name, validated.Version)})
	}
	phase = "release-persistence"
	if err := os.Chmod(binaryPath, 0o755); err != nil {
		return failClosed(err)
	}
	if err := syncFile(binaryPath); err != nil {
		return failClosed(err)
	}
	if err := os.Chmod(signaturePath, 0o444); err != nil {
		return failClosed(err)
	}
	if err := syncFile(signaturePath); err != nil {
		return failClosed(err)
	}
	if err := writeReleaseDigest(digestPath, validated.Sha256); err != nil {
		return failClosed(err)
	}
	if err := writeComponentLaunch(staging, validated); err != nil {
		return failClosed(err)
	}
	if err := os.Chmod(staging, 0o755); err != nil {
		return failClosed(err)
	}
	if err := syncDir(staging); err != nil {
		return failClosed(err)
	}
	if err := syncDir(componentDir); err != nil {
		return failClosed(err)
	}
	if err := os.Rename(staging, versionDir); err != nil {
		// Another process following this install contract may have won a
		// same-version race. The slot is an idempotent success only when its
		// immutable artifact has the exact expected identity; it is never
		// deleted or overwritten here.
		installed, complete, verifyErr := i.inspectInstalledRelease(versionDir, validated.Name, validated.Sha256)
		if verifyErr == nil && installed && complete && verifyExpectedLaunch(versionDir, validated) == nil {
			removeErr := os.RemoveAll(staging)
			return versionDir, errors.Join(removeErr, syncDir(componentDir))
		}
		return failClosed(err)
	}
	if err := syncDir(componentDir); err != nil {
		return versionDir, err
	}
	return versionDir, nil
}

func writeReleaseDigest(path, digest string) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0o444)
	if err != nil {
		return err
	}
	cleanup := func(cause error) error {
		_ = file.Close()
		_ = os.Remove(path)
		return cause
	}
	if _, err := io.WriteString(file, digest); err != nil {
		return cleanup(err)
	}
	if err := file.Chmod(0o444); err != nil {
		return cleanup(err)
	}
	if err := file.Sync(); err != nil {
		return cleanup(err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

// lockInstallDirectory serializes installers across processes. A crash
// releases flock automatically, allowing the next installer to remove only
// abandoned staging entries while never touching a version directory.
func lockInstallDirectory(ctx context.Context, componentDir string) (*os.File, error) {
	if ctx == nil {
		return nil, &errs.Argument{Param: "ctx", Message: "The install lock context is required."}
	}
	path := filepath.Join(componentDir, ".install.lock")
	lock, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	info, err := lock.Stat()
	if err != nil {
		_ = lock.Close()
		return nil, err
	}
	if err := requireOwnedRegular(info, false, "component install lock"); err != nil || info.Mode().Perm() != 0o600 {
		_ = lock.Close()
		if err != nil {
			return nil, err
		}
		return nil, &InvalidOperationError{Message: "The component install lock must have mode 0600."}
	}
	if err := requireSameMount(componentDir, path); err != nil {
		_ = lock.Close()
		return nil, err
	}
	for {
		err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return lock, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			_ = lock.Close()
			return nil, err
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			_ = lock.Close()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func unlockInstallDirectory(lock *os.File) {
	if lock == nil {
		return
	}
	_ = unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	_ = lock.Close()
}

func removeAbandonedInstallStages(componentDir string) error {
	entries, err := os.ReadDir(componentDir)
	if err != nil {
		return err
	}
	removed := false
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".staging-") {
			continue
		}
		if err := os.RemoveAll(filepath.Join(componentDir, entry.Name())); err != nil {
			return err
		}
		removed = true
	}
	if removed {
		return syncDir(componentDir)
	}
	return nil
}

// inspectInstalledRelease authenticates an immutable release and its launch
// configuration. Existing incomplete or invalid slots are never repaired or replaced.
func (i *Installer) inspectInstalledRelease(versionDir, component, expectedSha256 string) (bool, bool, error) {
	directory, err := os.Lstat(versionDir)
	if os.IsNotExist(err) {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	if err := requireOwnedDirectory(directory, "installed version"); err != nil {
		return false, false, err
	}
	artifactPath := filepath.Join(versionDir, component)
	if err := requireSameMount(i.installRoot, filepath.Dir(versionDir), versionDir, artifactPath); err != nil {
		return false, false, err
	}
	artifact, info, err := readRegularFileBoundedInfo(artifactPath, hostAgentMaximumArtifactBytes)
	if err != nil {
		return false, false, &InvalidDataError{Message: "The installed version does not contain its immutable artifact."}
	}
	if err := requireOwnedRegular(info, true, "installed version artifact"); err != nil {
		return false, false, err
	}
	digest := sha256.Sum256(artifact)
	digestHex := hex.EncodeToString(digest[:])
	if expectedSha256 != "" && digestHex != expectedSha256 {
		return false, false, &InvalidDataError{Message: fmt.Sprintf(
			"The installed component %s does not match the requested sha256.", component)}
	}

	digestFile, digestInfo, digestPresent, err := readOptionalRegularFileBounded(
		filepath.Join(versionDir, component+".sha256"), 64)
	if err != nil {
		return false, false, err
	}
	if digestPresent {
		if err := requireSameMount(versionDir, filepath.Join(versionDir, component+".sha256")); err != nil {
			return false, false, err
		}
		if err := requireOwnedRegular(digestInfo, false, "release digest"); err != nil {
			return false, false, err
		}
		if len(digestFile) != 64 || !hostAgentSha256Pattern.Match(digestFile) || string(digestFile) != digestHex {
			return false, false, &InvalidDataError{Message: "The installed release digest metadata is invalid."}
		}
	}
	signatureFile, signatureInfo, signaturePresent, err := readOptionalRegularFileBounded(
		filepath.Join(versionDir, component+".sig"), 1024)
	if err != nil {
		return false, false, err
	}
	if signaturePresent {
		if err := requireSameMount(versionDir, filepath.Join(versionDir, component+".sig")); err != nil {
			return false, false, err
		}
		if err := requireOwnedRegular(signatureInfo, false, "release signature"); err != nil {
			return false, false, err
		}
		signature, err := decodeEd25519Signature(signatureFile)
		if err != nil || !ed25519.Verify(i.publicKey, artifact, signature) {
			return false, false, &InvalidDataError{Message: "The installed release signature metadata is invalid."}
		}
	}
	launchPresent, err := hasComponentLaunch(versionDir, component)
	if err != nil {
		return false, false, err
	}
	if launchPresent {
		launch, err := readComponentLaunch(versionDir, component)
		if err != nil {
			return false, false, err
		}
		if launch.Sha256 != digestHex {
			return false, false, &InvalidDataError{Message: "The component launch manifest is bound to a different artifact."}
		}
	}
	return true, digestPresent && signaturePresent && launchPresent, nil
}

func readOptionalRegularFileBounded(path string, maximum int64) ([]byte, os.FileInfo, bool, error) {
	data, info, err := readRegularFileBoundedInfo(path, maximum)
	if os.IsNotExist(err) {
		return nil, nil, false, nil
	}
	return data, info, err == nil, err
}

func readRegularFileBoundedInfo(path string, maximum int64) ([]byte, os.FileInfo, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, nil, &InvalidDataError{Message: "The file must be a regular file."}
	}
	if info.Size() > maximum {
		return nil, nil, &errs.ArgumentOutOfRangeError{Param: "maximum", Message: "The file exceeds its size bound."}
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, nil, err
	}
	if int64(len(data)) > maximum {
		return nil, nil, &errs.ArgumentOutOfRangeError{Param: "maximum", Message: "The file exceeds its size bound."}
	}
	return data, info, nil
}

func readRegularFileBounded(path string, maximum int64) ([]byte, error) {
	data, _, err := readRegularFileBoundedInfo(path, maximum)
	return data, err
}

func requireOwnedDirectory(info os.FileInfo, label string) error {
	if info == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 || hasSpecialMode(info.Mode()) {
		return &InvalidOperationError{Message: "The " + label + " must be an owner-only-writable directory."}
	}
	metadata, ok := info.Sys().(*syscall.Stat_t)
	if !ok || metadata.Uid != uint32(os.Geteuid()) || metadata.Gid != uint32(os.Getegid()) {
		return &InvalidOperationError{Message: "The " + label + " must be owned by the ts-node identity."}
	}
	return nil
}

func requireOwnedRegular(info os.FileInfo, executable bool, label string) error {
	if info == nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 || hasSpecialMode(info.Mode()) {
		return &InvalidDataError{Message: "The " + label + " must be an immutable regular file."}
	}
	if executable && info.Mode().Perm()&0o111 == 0 {
		return &InvalidDataError{Message: "The " + label + " must be executable."}
	}
	metadata, ok := info.Sys().(*syscall.Stat_t)
	if !ok || metadata.Uid != uint32(os.Geteuid()) || metadata.Gid != uint32(os.Getegid()) || metadata.Nlink != 1 {
		return &InvalidDataError{Message: "The " + label + " must have one link and be owned by the ts-node identity."}
	}
	return nil
}

func hasSpecialMode(mode os.FileMode) bool {
	return mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0
}

func requireSameMount(paths ...string) error {
	if len(paths) < 2 {
		return nil
	}
	var reference unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, paths[0], unix.AT_SYMLINK_NOFOLLOW,
		unix.STATX_TYPE|unix.STATX_MNT_ID, &reference); err != nil {
		return err
	}
	for _, path := range paths[1:] {
		var candidate unix.Statx_t
		if err := unix.Statx(unix.AT_FDCWD, path, unix.AT_SYMLINK_NOFOLLOW,
			unix.STATX_TYPE|unix.STATX_MNT_ID, &candidate); err != nil {
			return err
		}
		if reference.Dev_major != candidate.Dev_major || reference.Dev_minor != candidate.Dev_minor ||
			reference.Mnt_id != candidate.Mnt_id {
			return &InvalidOperationError{Message: "The install slot must stay on one filesystem mount."}
		}
	}
	return nil
}

// withVerifiedTransition holds the installer and component locks while it
// authenticates the exact immutable release and performs one serving
// transition. This removes the lifecycle's former verify/use gap.
func (i *Installer) withVerifiedTransition(ctx context.Context, component, version, expectedSha256 string, transition func() error) error {
	if i == nil || transition == nil {
		return &InvalidOperationError{Message: "A verified release transition is required."}
	}
	if ctx == nil {
		return &errs.Argument{Param: "ctx", Message: "The transition context is required."}
	}
	if _, err := requireHostAgentName(component, "component", "The component must be a canonical token."); err != nil {
		return err
	}
	if err := requireVersion(version); err != nil {
		return err
	}
	if expectedSha256 != "" && !hostAgentSha256Pattern.MatchString(expectedSha256) {
		return &InvalidDataError{Message: "The expected release digest is invalid."}
	}
	componentDir := InstallDir(i.installRoot, component)
	installRootInfo, err := os.Lstat(i.installRoot)
	if err != nil {
		return err
	}
	if err := requireOwnedDirectory(installRootInfo, "install root"); err != nil {
		return err
	}
	componentInfo, err := os.Lstat(componentDir)
	if err != nil {
		return err
	}
	if err := requireOwnedDirectory(componentInfo, "component install directory"); err != nil {
		return err
	}
	if err := requireSameMount(i.installRoot, componentDir); err != nil {
		return err
	}
	lock, err := lockInstallDirectory(ctx, componentDir)
	if err != nil {
		return err
	}
	defer unlockInstallDirectory(lock)
	installed, complete, err := i.inspectInstalledRelease(VersionDir(i.installRoot, component, version), component, expectedSha256)
	if err != nil {
		return err
	}
	if !installed || !complete {
		return &InvalidOperationError{Message: fmt.Sprintf("Component %s version %s is not fully authenticated.", component, version)}
	}
	return transition()
}

// withVerifiedCurrentTransition resolves current only after taking the
// component install lock, authenticates that exact version, and keeps the
// lock held until the serving transition completes. A current version that
// differs from the manifest uses its own durable digest/signature metadata.
func (i *Installer) withVerifiedCurrentTransition(ctx context.Context, spec ComponentSpec, transition func(version string) error) error {
	if i == nil || transition == nil {
		return &InvalidOperationError{Message: "A verified current transition is required."}
	}
	if ctx == nil {
		return &errs.Argument{Param: "ctx", Message: "The transition context is required."}
	}
	validated, err := NewComponentSpec(spec)
	if err != nil {
		return err
	}
	componentDir := InstallDir(i.installRoot, validated.Name)
	installRootInfo, err := os.Lstat(i.installRoot)
	if err != nil {
		return err
	}
	if err := requireOwnedDirectory(installRootInfo, "install root"); err != nil {
		return err
	}
	componentInfo, err := os.Lstat(componentDir)
	if err != nil {
		return err
	}
	if err := requireOwnedDirectory(componentInfo, "component install directory"); err != nil {
		return err
	}
	if err := requireSameMount(i.installRoot, componentDir); err != nil {
		return err
	}
	lock, err := lockInstallDirectory(ctx, componentDir)
	if err != nil {
		return err
	}
	defer unlockInstallDirectory(lock)
	version, err := CurrentVersion(i.installRoot, validated.Name)
	if err != nil {
		return err
	}
	if version == "" {
		return &InvalidOperationError{Message: "The component has no activated current release; deploy it before starting the unit."}
	}
	expectedSha256 := ""
	if version == validated.Version {
		expectedSha256 = validated.Sha256
	}
	installed, complete, err := i.inspectInstalledRelease(
		VersionDir(i.installRoot, validated.Name, version), validated.Name, expectedSha256)
	if err != nil {
		return err
	}
	if !installed || !complete {
		return &InvalidOperationError{Message: fmt.Sprintf("Component %s version %s is not fully authenticated.", validated.Name, version)}
	}
	return transition(version)
}

// decodeEd25519Signature admits the exact raw detached signature emitted by
// ts-deploy. No trimming is allowed: every byte, including a newline, is data.
func decodeEd25519Signature(signatureFile []byte) ([]byte, error) {
	if len(signatureFile) != ed25519.SignatureSize {
		return nil, &InvalidDataError{Message: "The release signature must contain exactly 64 raw bytes."}
	}
	return signatureFile, nil
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
