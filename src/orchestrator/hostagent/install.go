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
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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
}

// Download fetches url into target, enforcing https, the redirect budget of
// the client, and the byte limit.
func (d DownloadClient) Download(url string, target string, limitBytes int64) error {
	if d.Client == nil {
		return &InvalidOperationError{Message: "The download client needs an HTTP client."}
	}
	if len(url) < 8 || url[:8] != "https://" {
		return &errs.Argument{Param: "url", Message: "Release artifacts are fetched over https only."}
	}
	response, err := d.Client.Get(url)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("the release URL answered status %d", response.StatusCode)
	}
	file, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	written, err := io.Copy(file, io.LimitReader(response.Body, limitBytes+1))
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if written > limitBytes {
		return &errs.ArgumentOutOfRangeError{
			Param:   "limitBytes",
			Message: "The release artifact exceeds its size bound.",
		}
	}
	return nil
}

// InstallClient composes the downloader and timeouts shared by every
// component install.
func InstallClient() DownloadClient {
	return DownloadClient{Client: &http.Client{
		Timeout: 5 * time.Minute,
	}}
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
}

// Installer installs verified release artifacts into version directories.
type Installer struct {
	installRoot string
	publicKey   ed25519.PublicKey
	downloader  ArtifactDownloader
}

// NewInstaller validates the configuration and composes the installer.
func NewInstaller(config InstallerConfig) (*Installer, error) {
	if !strings.HasPrefix(config.InstallRoot, "/") || strings.Contains(config.InstallRoot, "..") {
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
	return &Installer{
		installRoot: config.InstallRoot,
		publicKey:   ed25519.PublicKey(keyBytes),
		downloader:  config.Downloader,
	}, nil
}

// Install downloads and verifies one component release and lands it at
// /<installRoot>/<component>/<version>/<component>. The artifact is staged
// in .staging-<version> under the component directory and renamed into
// place only after both the sha256 and the ed25519 signature verify, so an
// existing good version directory is never touched and a bad one never
// exists. The returned path is the installed version directory.
func (i *Installer) Install(spec ComponentSpec) (string, error) {
	validated, err := NewComponentSpec(spec)
	if err != nil {
		return "", err
	}
	componentDir := InstallDir(i.installRoot, validated.Name)
	staging := componentDir + "/.staging-" + validated.Version
	if err := os.RemoveAll(staging); err != nil {
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
	if err := os.Rename(staging, versionDir); err != nil {
		return failClosed(err)
	}
	return versionDir, nil
}

// decodeEd25519Signature accepts the detached signature as raw 64 bytes or
// as 128 lowercase/uppercase hex characters.
func decodeEd25519Signature(signatureFile []byte) ([]byte, error) {
	trimmed := signatureFile
	if len(trimmed) > 0 && trimmed[len(trimmed)-1] == '\n' {
		trimmed = trimmed[:len(trimmed)-1]
	}
	switch len(trimmed) {
	case ed25519.SignatureSize:
		return trimmed, nil
	case 2 * ed25519.SignatureSize:
		decoded, err := hex.DecodeString(string(trimmed))
		if err != nil || len(decoded) != ed25519.SignatureSize {
			return nil, &InvalidDataError{Message: "The release signature is not canonical hex."}
		}
		return decoded, nil
	default:
		return nil, &InvalidDataError{Message: "The release signature is not 64 raw or hex-encoded bytes."}
	}
}

// InstalledVersion reports whether one component version directory exists on
// disk with its binary present.
func InstalledVersion(installRoot, component, version string) bool {
	info, err := os.Stat(filepath.Join(VersionDir(installRoot, component, version), component))
	return err == nil && !info.IsDir()
}
