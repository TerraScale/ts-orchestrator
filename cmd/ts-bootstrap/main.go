// Command ts-bootstrap assembles and signs root-authorized bootstrap manifests
// after the final OCI image receipt is available.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/release"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

const maxKeyFileBytes = 16 << 10

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "ts-bootstrap:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	return runAt(args, time.Now().UTC())
}

func runAt(args []string, now time.Time) error {
	if len(args) == 0 {
		return errors.New("usage: ts-bootstrap sign-manifest [flags]")
	}
	switch args[0] {
	case "sign-manifest":
		return signManifestAt(args[1:], now)
	default:
		return errors.New("usage: ts-bootstrap sign-manifest [flags]")
	}
}

func signManifestAt(args []string, now time.Time) error {
	flags := flag.NewFlagSet("sign-manifest", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	candidatePath := flags.String("candidate", "", "reviewed unsigned v2 bootstrap manifest JSON")
	imageReceiptPath := flags.String("image-receipt", "", "canonical signed OCI image receipt envelope")
	releaseDelegationPath := flags.String("release-delegation", "", "canonical root-signed release delegation envelope")
	rootPublicPath := flags.String("root-key", "", "offline root Ed25519 public key PEM")
	rootPrivatePath := flags.String("signing-key", "", "owner-only offline root Ed25519 PKCS#8 private key PEM")
	outputPath := flags.String("out", "", "new canonical signed manifest envelope")
	validFor := flags.Duration("valid-for", bootstrap.DefaultManifestValidity, "manifest validity, bounded by current proof expiries")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *candidatePath == "" || *imageReceiptPath == "" || *releaseDelegationPath == "" ||
		*rootPublicPath == "" || *rootPrivatePath == "" || *outputPath == "" || flags.NArg() != 0 {
		return errors.New("sign-manifest requires --candidate, --image-receipt, --release-delegation, --root-key, --signing-key, and --out")
	}
	policy := bootstrap.ManifestTrustPolicy()
	if *validFor <= 0 || *validFor > policy.MaxLifetime {
		return fmt.Errorf("manifest validity must be positive and no longer than %s", policy.MaxLifetime)
	}
	now = now.Round(0).UTC()
	if now.IsZero() {
		return errors.New("manifest signing time is invalid")
	}

	candidateBytes, err := readBoundedRegular(*candidatePath, bootstrap.MaxManifestBytes)
	if err != nil {
		return err
	}
	var manifest bootstrap.Manifest
	if err := protocol.DecodeStrict(candidateBytes, &manifest, bootstrap.MaxManifestBytes); err != nil {
		return fmt.Errorf("decode candidate manifest: %w", err)
	}
	imageWire, err := readBoundedRegular(*imageReceiptPath, bootstrap.MaxManifestBytes)
	if err != nil {
		return fmt.Errorf("read image receipt: %w", err)
	}
	delegationWire, err := readBoundedRegular(*releaseDelegationPath, bootstrap.MaxManifestBytes)
	if err != nil {
		return fmt.Errorf("read release delegation: %w", err)
	}
	if len(manifest.ReleaseImageReceiptWire) > 0 && !bytes.Equal(manifest.ReleaseImageReceiptWire, imageWire) {
		return errors.New("candidate manifest contains a conflicting image receipt wire")
	}
	if len(manifest.ReleaseDelegationWire) > 0 && !bytes.Equal(manifest.ReleaseDelegationWire, delegationWire) {
		return errors.New("candidate manifest contains a conflicting release delegation wire")
	}
	imageDigest := sha256.Sum256(imageWire)
	imageDigestHex := hex.EncodeToString(imageDigest[:])
	if manifest.ReleaseReceiptSHA256 != imageDigestHex {
		return errors.New("candidate release receipt SHA-256 does not match the exact supplied image envelope wire")
	}
	rootPublic, err := readRootPublicKey(*rootPublicPath)
	if err != nil {
		return err
	}
	roots, err := trust.ParseKeyring(rootPublic)
	if err != nil {
		return fmt.Errorf("parse root trust key: %w", err)
	}
	rootPrivate, err := readRootPrivateKey(*rootPrivatePath)
	if err != nil {
		return err
	}
	defer clear(rootPrivate)
	if !bytes.Equal(rootPrivate.Public().(ed25519.PublicKey), rootPublic) {
		return errors.New("offline root signing key does not match the supplied root public key")
	}
	architecture, err := releaseArchitecture(manifest.ImageArchitecture)
	if err != nil {
		return err
	}
	imageProof, err := release.VerifyImageCurrent(imageWire, delegationWire, roots, release.ImageExpectation{
		Environment: manifest.Environment, LogicalRegion: string(manifest.Cell),
		OCIImageOCID: manifest.ImageOCID, Architecture: architecture,
	}, now)
	if err != nil {
		return fmt.Errorf("verify current release image proof: %w", err)
	}
	if imageProof.EnvelopeSHA256() != imageDigestHex {
		return errors.New("verified image receipt digest differs from the exact supplied wire")
	}
	delegationEnvelope, err := trust.DecodeEnvelope(delegationWire)
	if err != nil {
		return fmt.Errorf("decode release delegation: %w", err)
	}
	manifest.ReleaseImageReceiptWire = bytes.Clone(imageWire)
	manifest.ReleaseDelegationWire = bytes.Clone(delegationWire)
	if err := manifest.Validate(); err != nil {
		return fmt.Errorf("validate candidate manifest: %w", err)
	}

	issuedAt := now
	expiresAt := now.Add(*validFor)
	expiresAt = minTime(minTime(expiresAt, imageProof.ExpiresAt()), delegationEnvelope.ExpiresAt)
	if manifest.PeerReceiptDelegation != nil {
		expiresAt = minTime(expiresAt, manifest.PeerReceiptDelegation.ExpiresAt)
	}
	if expiresAt.Sub(issuedAt) < bootstrap.MinimumManifestWindow {
		return fmt.Errorf("current release or peer proof leaves less than %s of manifest validity", bootstrap.MinimumManifestWindow)
	}
	signed, err := bootstrap.SignManifest(manifest, issuedAt, expiresAt, rootPrivate)
	if err != nil {
		return fmt.Errorf("sign bootstrap manifest: %w", err)
	}
	expected := bootstrap.ManifestExpectation{
		DeploymentID: manifest.DeploymentID, Environment: manifest.Environment, ClusterID: manifest.ClusterID,
		Cell: manifest.Cell, Slot: manifest.Slot, ImageOCID: manifest.ImageOCID,
		StorageDomain: manifest.StorageDomain,
	}
	verified, err := bootstrap.VerifyManifest(signed, roots, expected, now, policy)
	if err != nil {
		return fmt.Errorf("verify newly signed bootstrap manifest: %w", err)
	}
	verifiedManifest := verified.Manifest()
	if !bytes.Equal(verifiedManifest.ReleaseImageReceiptWire, imageWire) ||
		!bytes.Equal(verifiedManifest.ReleaseDelegationWire, delegationWire) || verifiedManifest.ReleaseReceiptSHA256 != imageDigestHex {
		return errors.New("signed manifest changed the verified release proof bytes")
	}
	encoded, err := trust.EncodeEnvelope(signed)
	if err != nil {
		return fmt.Errorf("encode signed manifest: %w", err)
	}
	if len(encoded) > bootstrap.MaxManifestBytes {
		return fmt.Errorf("signed manifest envelope exceeds %d bytes", bootstrap.MaxManifestBytes)
	}
	if err := writeNew(*outputPath, encoded, 0o644); err != nil {
		return err
	}
	fmt.Printf("signed current bootstrap manifest cell=%s slot=%s digest=%s expires=%s\n",
		manifest.Cell, manifest.Slot, verified.Digest(), expiresAt.Format(time.RFC3339))
	return nil
}

func releaseArchitecture(value string) (string, error) {
	switch value {
	case "linux-amd64":
		return "amd64", nil
	case "linux-arm64":
		return "arm64", nil
	default:
		return "", fmt.Errorf("unsupported bootstrap image architecture %q", value)
	}
}

func minTime(left, right time.Time) time.Time {
	if right.Before(left) {
		return right
	}
	return left
}

func readRootPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := readBoundedRegular(path, maxKeyFileBytes)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("root public key must be a PEM Ed25519 SubjectPublicKeyInfo")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse root public key: %w", err)
	}
	public, ok := parsed.(ed25519.PublicKey)
	if !ok || len(public) != ed25519.PublicKeySize {
		return nil, errors.New("root public key must be Ed25519")
	}
	return public, nil
}

func readRootPrivateKey(path string) (ed25519.PrivateKey, error) {
	file, err := openRegular(path)
	if err != nil {
		return nil, fmt.Errorf("open offline root signing key: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat offline root signing key: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("offline root signing key must be an owner-only file")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Uid != uint32(os.Getuid()) {
		return nil, errors.New("offline root signing key must be owned by this process user")
	}
	if info.Size() <= 0 || info.Size() > maxKeyFileBytes {
		return nil, fmt.Errorf("offline root signing key exceeds %d bytes", maxKeyFileBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxKeyFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read offline root signing key: %w", err)
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("offline root signing key must be PEM PKCS#8 Ed25519")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse offline root signing key: %w", err)
	}
	private, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(private) != ed25519.PrivateKeySize {
		return nil, errors.New("offline root signing key must be Ed25519")
	}
	return private, nil
}

func readBoundedRegular(path string, maximum int64) ([]byte, error) {
	file, err := openRegular(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", filepath.Base(path), err)
	}
	if info.Size() < 0 || info.Size() > maximum {
		return nil, fmt.Errorf("%s exceeds the %d-byte limit", filepath.Base(path), maximum)
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", filepath.Base(path), err)
	}
	if int64(len(data)) > maximum {
		return nil, fmt.Errorf("%s exceeds the %d-byte limit", filepath.Base(path), maximum)
	}
	return data, nil
}

func openRegular(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", filepath.Base(path), err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s must be a regular file", filepath.Base(path))
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", filepath.Base(path), err)
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		_ = file.Close()
		return nil, fmt.Errorf("%s changed while opening", filepath.Base(path))
	}
	return file, nil
}

func writeNew(path string, contents []byte, mode os.FileMode) error {
	if path == "" || len(contents) == 0 {
		return errors.New("output path and content are required")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("create output without overwrite: %w", err)
	}
	if _, err := file.Write(contents); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}
