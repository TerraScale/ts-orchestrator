// Command ts-bootstrap signs the public deployment anchor before OCI image
// import, then assembles the per-slot manifest after the image receipt exists.
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
	"strings"
	"syscall"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
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
		return errors.New("usage: ts-bootstrap verify-anchor [flags] | sign-anchor [flags] | sign-manifest [flags]")
	}
	switch args[0] {
	case "verify-anchor":
		return verifyBootstrapAnchorAt(args[1:], now)
	case "sign-anchor":
		return signBootstrapAnchorAt(args[1:], now)
	case "sign-manifest":
		return signManifestAt(args[1:], now)
	default:
		return errors.New("usage: ts-bootstrap verify-anchor [flags] | sign-anchor [flags] | sign-manifest [flags]")
	}
}

type stringListFlag []string

func (values *stringListFlag) String() string { return strings.Join(*values, ",") }

func (values *stringListFlag) Set(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("flag value must not be empty")
	}
	*values = append(*values, value)
	return nil
}

type verifiedBootstrapAnchorOutput struct {
	SchemaVersion                 int                     `json:"schemaVersion"`
	AnchorSHA256                  string                  `json:"anchorSha256"`
	DeploymentID                  string                  `json:"deploymentId"`
	Environment                   string                  `json:"environment"`
	ClusterID                     string                  `json:"clusterId"`
	Cell                          oci.Region              `json:"cell"`
	OCIRegion                     string                  `json:"ociRegion"`
	ControllerSlots               []string                `json:"controllerSlots"`
	StorageDomain                 bootstrap.StorageDomain `json:"storageDomain"`
	InitialRegionIntentGeneration uint64                  `json:"initialRegionIntentGeneration"`
	InitialRegionIntentSHA256     string                  `json:"initialRegionIntentSha256"`
	LedgerDelegationSubjectKeyID  string                  `json:"ledgerDelegationSubjectKeyId"`
	IssuedAt                      time.Time               `json:"issuedAt"`
	ExpiresAt                     time.Time               `json:"expiresAt"`
}

func verifyBootstrapAnchorAt(args []string, now time.Time) error {
	flags := flag.NewFlagSet("verify-anchor", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	anchorPath := flags.String("anchor", "", "canonical root-signed deployment bootstrap anchor envelope")
	identityPath := flags.String("identity", "", "canonical version-1 baked identity JSON")
	var rootPaths stringListFlag
	flags.Var(&rootPaths, "root-key", "trusted root Ed25519 public key PEM (repeatable)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *anchorPath == "" || *identityPath == "" || flags.NArg() != 0 {
		return errors.New("verify-anchor requires --anchor, --identity, and at least one --root-key")
	}
	if len(rootPaths) == 0 || len(rootPaths) > bootstrapstart.MaxRootFiles {
		return fmt.Errorf("verify-anchor requires between 1 and %d --root-key files", bootstrapstart.MaxRootFiles)
	}
	identityWire, err := readBoundedRegular(*identityPath, 4<<10)
	if err != nil {
		return fmt.Errorf("read fixed bootstrap identity: %w", err)
	}
	var identity bootstrapstart.BakedIdentity
	if err := protocol.DecodeStrict(identityWire, &identity, 4<<10); err != nil {
		return fmt.Errorf("decode fixed bootstrap identity: %w", err)
	}
	if identity.SchemaVersion != 1 {
		return errors.New("fixed bootstrap identity schemaVersion must be 1")
	}
	canonical, err := protocol.EncodeJSON(identity)
	if err != nil || !bytes.Equal(identityWire, canonical) {
		return errors.New("fixed bootstrap identity must be canonical JSON")
	}
	expected := identity.AnchorExpectation()
	rootKeys := make([]ed25519.PublicKey, 0, len(rootPaths))
	rootBytes := 0
	for _, path := range rootPaths {
		wire, err := readBoundedRegular(path, bootstrapstart.MaxRootBytes)
		if err != nil {
			return err
		}
		rootBytes += len(wire)
		if rootBytes > bootstrapstart.MaxRootsTotal {
			return fmt.Errorf("verify-anchor root key files exceed %d aggregate bytes", bootstrapstart.MaxRootsTotal)
		}
		publicKey, err := parseRootPublicKey(wire)
		if err != nil {
			return err
		}
		rootKeys = append(rootKeys, publicKey)
	}
	roots, err := trust.ParseKeyring(rootKeys...)
	if err != nil {
		return fmt.Errorf("parse root trust set: %w", err)
	}
	anchorWire, err := readBoundedRegular(*anchorPath, bootstrap.MaxBootstrapAnchorBytes)
	if err != nil {
		return fmt.Errorf("read bootstrap anchor: %w", err)
	}
	envelope, err := trust.DecodeEnvelope(anchorWire)
	if err != nil {
		return fmt.Errorf("decode bootstrap anchor: %w", err)
	}
	now = now.Round(0).UTC()
	verified, err := bootstrap.VerifyBootstrapAnchor(envelope, roots, expected, now, bootstrap.BootstrapAnchorTrustPolicy())
	if err != nil {
		return fmt.Errorf("verify current bootstrap anchor: %w", err)
	}
	anchor := verified.Anchor()
	grant, err := verified.LedgerDelegation()
	if err != nil {
		return err
	}
	output := verifiedBootstrapAnchorOutput{
		SchemaVersion: bootstrap.BootstrapAnchorSchemaVersion, AnchorSHA256: verified.Digest(),
		DeploymentID: anchor.DeploymentID, Environment: anchor.Environment, ClusterID: anchor.ClusterID,
		Cell: anchor.Cell, OCIRegion: anchor.OCIRegion, ControllerSlots: anchor.ControllerSlots,
		StorageDomain: anchor.StorageDomain, InitialRegionIntentGeneration: anchor.InitialRegionIntentGeneration,
		InitialRegionIntentSHA256: anchor.InitialRegionIntentSHA256, LedgerDelegationSubjectKeyID: grant.SubjectKeyID(),
		IssuedAt: verified.IssuedAt(), ExpiresAt: verified.ExpiresAt(),
	}
	encoded, err := trust.EncodePayload(output)
	if err != nil {
		return fmt.Errorf("encode verified bootstrap anchor summary: %w", err)
	}
	if _, err := os.Stdout.Write(append(encoded, '\n')); err != nil {
		return fmt.Errorf("write verified bootstrap anchor summary: %w", err)
	}
	return nil
}

func signBootstrapAnchorAt(args []string, now time.Time) error {
	flags := flag.NewFlagSet("sign-anchor", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	candidatePath := flags.String("candidate", "", "reviewed unsigned deployment bootstrap anchor JSON")
	regionIntentPath := flags.String("region-intent", "", "canonical initial OCI region-intent JSON")
	ledgerDelegationPath := flags.String("ledger-delegation", "", "root-signed one-signer bootstrap ledger capability grant")
	rootPublicPath := flags.String("root-key", "", "offline root Ed25519 public key PEM")
	rootPrivatePath := flags.String("signing-key", "", "owner-only offline root Ed25519 PKCS#8 private key PEM")
	outputPath := flags.String("out", "", "new canonical signed anchor envelope")
	validFor := flags.Duration("valid-for", bootstrap.DefaultBootstrapAnchorValidity, "anchor validity, no longer than one year")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *candidatePath == "" || *regionIntentPath == "" || *ledgerDelegationPath == "" || *rootPublicPath == "" ||
		*rootPrivatePath == "" || *outputPath == "" || flags.NArg() != 0 {
		return errors.New("sign-anchor requires --candidate, --region-intent, --ledger-delegation, --root-key, --signing-key, and --out")
	}
	policy := bootstrap.BootstrapAnchorTrustPolicy()
	if *validFor <= 0 || *validFor > policy.MaxLifetime {
		return fmt.Errorf("anchor validity must be positive and no longer than %s", policy.MaxLifetime)
	}
	now = now.Round(0).UTC()
	if now.IsZero() {
		return errors.New("anchor signing time is invalid")
	}

	candidateBytes, err := readBoundedRegular(*candidatePath, bootstrap.MaxBootstrapAnchorBytes)
	if err != nil {
		return err
	}
	var anchor bootstrap.BootstrapAnchor
	if err := protocol.DecodeStrict(candidateBytes, &anchor, bootstrap.MaxBootstrapAnchorBytes); err != nil {
		return fmt.Errorf("decode candidate anchor: %w", err)
	}
	regionIntentWire, err := readBoundedRegular(*regionIntentPath, bootstrap.MaxInitialRegionIntentBytes)
	if err != nil {
		return fmt.Errorf("read initial region intent: %w", err)
	}
	intent, err := oci.ParseRegionIntent(regionIntentWire)
	if err != nil {
		return fmt.Errorf("parse initial region intent: %w", err)
	}
	canonicalIntentWire, err := trust.EncodePayload(intent)
	if err != nil {
		return fmt.Errorf("encode canonical initial region intent: %w", err)
	}
	if !bytes.Equal(regionIntentWire, canonicalIntentWire) {
		return errors.New("initial region intent must be canonical JSON")
	}
	ledgerDelegationWire, err := readBoundedRegular(*ledgerDelegationPath, bootstrap.MaxBootstrapLedgerGrantBytes)
	if err != nil {
		return fmt.Errorf("read bootstrap ledger delegation: %w", err)
	}
	if len(anchor.LedgerDelegationWire) > 0 && !bytes.Equal(anchor.LedgerDelegationWire, ledgerDelegationWire) {
		return errors.New("candidate anchor contains a conflicting ledger delegation wire")
	}
	anchor.LedgerDelegationWire = bytes.Clone(ledgerDelegationWire)
	intentDigest := sha256.Sum256(regionIntentWire)
	intentDigestHex := hex.EncodeToString(intentDigest[:])
	if anchor.InitialRegionIntentGeneration != 0 && anchor.InitialRegionIntentGeneration != intent.Generation {
		return errors.New("candidate anchor contains a conflicting initial region-intent generation")
	}
	if anchor.InitialRegionIntentSHA256 != "" && anchor.InitialRegionIntentSHA256 != intentDigestHex {
		return errors.New("candidate anchor contains a conflicting initial region-intent digest")
	}
	if len(anchor.InitialRegionIntentWire) > 0 && !bytes.Equal(anchor.InitialRegionIntentWire, regionIntentWire) {
		return errors.New("candidate anchor contains conflicting initial region-intent bytes")
	}
	anchor.InitialRegionIntentGeneration = intent.Generation
	anchor.InitialRegionIntentSHA256 = intentDigestHex
	anchor.InitialRegionIntentWire = bytes.Clone(regionIntentWire)
	rootPublic, err := readRootPublicKey(*rootPublicPath)
	if err != nil {
		return err
	}
	roots, err := trust.ParseKeyring(rootPublic)
	if err != nil {
		return fmt.Errorf("parse root trust key: %w", err)
	}
	ledgerDelegation, err := trust.DecodeEnvelope(ledgerDelegationWire)
	if err != nil {
		return fmt.Errorf("decode bootstrap ledger delegation: %w", err)
	}
	if _, err := trust.VerifyDelegationCurrent(ledgerDelegation, roots, now, policy); err != nil {
		return fmt.Errorf("verify current root-signed bootstrap ledger delegation: %w", err)
	}
	if err := anchor.Validate(); err != nil {
		return fmt.Errorf("validate candidate anchor: %w", err)
	}
	rootPrivate, err := readRootPrivateKey(*rootPrivatePath)
	if err != nil {
		return err
	}
	defer clear(rootPrivate)
	if !bytes.Equal(rootPrivate.Public().(ed25519.PublicKey), rootPublic) {
		return errors.New("offline root signing key does not match the supplied root public key")
	}
	issuedAt := now
	expiresAt := minTime(now.Add(*validFor), ledgerDelegation.ExpiresAt)
	if !expiresAt.After(issuedAt) {
		return errors.New("bootstrap ledger delegation leaves no anchor validity")
	}
	signed, err := bootstrap.SignBootstrapAnchor(anchor, issuedAt, expiresAt, rootPrivate)
	if err != nil {
		return fmt.Errorf("sign bootstrap anchor: %w", err)
	}
	expected := bootstrap.BootstrapAnchorExpectation{
		DeploymentID: anchor.DeploymentID, Environment: anchor.Environment, Cell: anchor.Cell,
	}
	verified, err := bootstrap.VerifyBootstrapAnchor(signed, roots, expected, now, policy)
	if err != nil {
		return fmt.Errorf("verify newly signed bootstrap anchor: %w", err)
	}
	if !bytes.Equal(verified.Anchor().InitialRegionIntentWire, regionIntentWire) ||
		verified.Anchor().InitialRegionIntentSHA256 != intentDigestHex || verified.Anchor().InitialRegionIntentGeneration != intent.Generation {
		return errors.New("signed anchor changed the canonical initial region-intent bytes")
	}
	encoded, err := trust.EncodeEnvelope(signed)
	if err != nil {
		return fmt.Errorf("encode signed bootstrap anchor: %w", err)
	}
	if len(encoded) > bootstrap.MaxBootstrapAnchorBytes {
		return fmt.Errorf("signed anchor envelope exceeds %d bytes", bootstrap.MaxBootstrapAnchorBytes)
	}
	if err := writeNew(*outputPath, encoded, 0o644); err != nil {
		return err
	}
	fmt.Printf("signed bootstrap anchor cell=%s cluster=%s digest=%s expires=%s\n",
		anchor.Cell, anchor.ClusterID, verified.Digest(), verified.ExpiresAt().Format(time.RFC3339))
	return nil
}

func signManifestAt(args []string, now time.Time) error {
	flags := flag.NewFlagSet("sign-manifest", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	candidatePath := flags.String("candidate", "", "reviewed unsigned v2 bootstrap manifest JSON")
	anchorPath := flags.String("anchor", "", "current root-signed deployment bootstrap anchor envelope")
	imageReceiptPath := flags.String("image-receipt", "", "canonical signed OCI image receipt envelope")
	releaseDelegationPath := flags.String("release-delegation", "", "canonical root-signed release delegation envelope")
	rootPublicPath := flags.String("root-key", "", "offline root Ed25519 public key PEM")
	rootPrivatePath := flags.String("signing-key", "", "owner-only offline root Ed25519 PKCS#8 private key PEM")
	outputPath := flags.String("out", "", "new canonical signed manifest envelope")
	validFor := flags.Duration("valid-for", bootstrap.DefaultManifestValidity, "manifest validity, bounded by current proof expiries")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *candidatePath == "" || *anchorPath == "" || *imageReceiptPath == "" || *releaseDelegationPath == "" ||
		*rootPublicPath == "" || *rootPrivatePath == "" || *outputPath == "" || flags.NArg() != 0 {
		return errors.New("sign-manifest requires --candidate, --anchor, --image-receipt, --release-delegation, --root-key, --signing-key, and --out")
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
	anchorWire, err := readBoundedRegular(*anchorPath, bootstrap.MaxBootstrapAnchorBytes)
	if err != nil {
		return fmt.Errorf("read bootstrap anchor: %w", err)
	}
	anchorEnvelope, err := trust.DecodeEnvelope(anchorWire)
	if err != nil {
		return fmt.Errorf("decode bootstrap anchor: %w", err)
	}
	verifiedAnchor, err := bootstrap.VerifyBootstrapAnchor(anchorEnvelope, roots, bootstrap.BootstrapAnchorExpectation{
		DeploymentID: manifest.DeploymentID, Environment: manifest.Environment, Cell: manifest.Cell,
	}, now, bootstrap.BootstrapAnchorTrustPolicy())
	if err != nil {
		return fmt.Errorf("verify current bootstrap anchor: %w", err)
	}
	expected, err := verifiedAnchor.ManifestExpectation(manifest.Slot, manifest.ImageOCID)
	if err != nil {
		return fmt.Errorf("derive bootstrap manifest expectation from anchor: %w", err)
	}
	if manifest.ClusterID != expected.ClusterID || manifest.StorageDomain != expected.StorageDomain ||
		!equalOrderedStrings(manifest.ControllerSlots, expected.ControllerSlots) ||
		manifest.IntentGeneration != expected.IntentGeneration || manifest.IntentSHA256 != expected.IntentSHA256 {
		return errors.New("candidate manifest identity, storage domain, controller slots, or region-intent pin does not match the signed anchor")
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
	expiresAt = minTime(minTime(minTime(expiresAt, imageProof.ExpiresAt()), delegationEnvelope.ExpiresAt), verifiedAnchor.ExpiresAt())
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

func equalOrderedStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func readRootPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := readBoundedRegular(path, maxKeyFileBytes)
	if err != nil {
		return nil, err
	}
	return parseRootPublicKey(data)
}

func parseRootPublicKey(data []byte) (ed25519.PublicKey, error) {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
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
