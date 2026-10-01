package cli

import (
	"bytes"
	"context"
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
	"slices"
	"strings"
	"syscall"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/commandio"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/release"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

const maxKeyFileBytes = 16 << 10

func (c command) run(args []string) error {
	return c.runAt(args, time.Now().UTC())
}

func (c command) runAt(args []string, now time.Time) error {
	if len(args) == 0 {
		return errors.New("usage: ts-orch bootstrap verify-anchor | verify-manifest | sign-ledger-delegation | sign-anchor | render-controller-config | render-operator-config | render-host-enrollment-public | install-operator-material | open-customer-material | open-rotated-customer-material | sign-manifest | generate-controller-material | provision-controller-material | sign-peer-receipt-delegation | sign-founder-plan | sign-initial-founder-selection | publish-initial-founder-selection | sign-external-seed-reservation | publish-external-seed-reservation | observe-external-seed | sign-external-seed-completion | publish-external-seed-completion | render-founder-continuity | sign-founder-continuity | sign-founder-selection | publish-founder-selection [flags]")
	}
	switch args[0] {
	case "verify-anchor":
		return c.verifyBootstrapAnchorAt(args[1:], now)
	case "verify-manifest":
		return c.verifyBootstrapManifestAt(args[1:], now)
	case "sign-ledger-delegation":
		return c.signLedgerDelegationAt(args[1:], now)
	case "sign-anchor":
		return c.signBootstrapAnchorAt(args[1:], now)
	case "sign-manifest":
		return c.signManifestAt(args[1:], now)
	case "render-controller-config":
		return c.renderControllerConfigAt(args[1:], now)
	case "render-operator-config":
		return c.renderOperatorConfigAt(args[1:], now)
	case "render-host-enrollment-public":
		return c.renderHostEnrollmentPublicAt(args[1:], now)
	case "install-operator-material":
		return c.installOperatorMaterialAt(args[1:], now)
	case "open-customer-material":
		return c.openCustomerMaterialAt(args[1:])
	case "open-rotated-customer-material":
		return c.openRotatedCustomerMaterialAt(args[1:])
	case "generate-controller-material":
		return c.runGenerateControllerMaterial(args[1:])
	case "provision-controller-material":
		return c.runProvisionControllerMaterial(args[1:])
	case "sign-peer-receipt-delegation":
		return c.signPeerReceiptDelegationAt(args[1:], now)
	case "render-founder-continuity":
		return c.renderFounderContinuityAt(args[1:])
	case "sign-founder-continuity":
		return c.signFounderContinuityAt(args[1:], now)
	case "sign-founder-plan":
		return c.signFounderPlanAt(args[1:], now)
	case "sign-initial-founder-selection":
		return c.signInitialFounderSelectionAt(args[1:], now)
	case "publish-initial-founder-selection":
		return c.publishInitialFounderSelectionAt(args[1:], now)
	case "sign-external-seed-reservation":
		return c.signSeedReservationAt(args[1:], now)
	case "publish-external-seed-reservation":
		return c.publishSeedReservationAt(args[1:], now)
	case "observe-external-seed":
		return c.observeExternalSeedAt(args[1:], now)
	case "sign-external-seed-completion":
		return c.signSeedCompletionAt(args[1:], now)
	case "publish-external-seed-completion":
		return c.publishSeedCompletionAt(args[1:], now)
	case "sign-founder-selection":
		return c.signFounderSelectionAt(args[1:], now)
	case "publish-founder-selection":
		return c.publishFounderSelectionAt(args[1:], now)
	default:
		return errors.New("usage: ts-orch bootstrap verify-anchor | verify-manifest | sign-ledger-delegation | sign-anchor | render-controller-config | render-operator-config | render-host-enrollment-public | install-operator-material | open-customer-material | open-rotated-customer-material | sign-manifest | generate-controller-material | provision-controller-material | sign-peer-receipt-delegation | sign-founder-plan | sign-initial-founder-selection | publish-initial-founder-selection | sign-external-seed-reservation | publish-external-seed-reservation | observe-external-seed | sign-external-seed-completion | publish-external-seed-completion | render-founder-continuity | sign-founder-continuity | sign-founder-selection | publish-founder-selection [flags]")
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

type verifiedBootstrapManifestOutput struct {
	SchemaVersion        int                     `json:"schemaVersion"`
	AnchorSHA256         string                  `json:"anchorSha256"`
	ManifestSHA256       string                  `json:"manifestSha256"`
	DeploymentID         string                  `json:"deploymentId"`
	Environment          string                  `json:"environment"`
	ClusterID            string                  `json:"clusterId"`
	Cell                 oci.Region              `json:"cell"`
	OCIRegion            string                  `json:"ociRegion"`
	Slot                 string                  `json:"slot"`
	ImageOCID            string                  `json:"imageOcid"`
	ImageArchitecture    string                  `json:"imageArchitecture"`
	ReleaseReceiptSHA256 string                  `json:"releaseReceiptSha256"`
	Profile              bootstrap.LaunchProfile `json:"profile"`
	IssuedAt             time.Time               `json:"issuedAt"`
	ExpiresAt            time.Time               `json:"expiresAt"`
}

func (c command) verifyBootstrapManifestAt(args []string, now time.Time) error {
	flags := flag.NewFlagSet("verify-manifest", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	anchorPath := flags.String("anchor", "", "canonical root-signed deployment bootstrap anchor envelope")
	manifestPath := flags.String("manifest", "", "canonical root-signed per-slot bootstrap manifest envelope")
	identityPath := flags.String("identity", "", "canonical version-1 baked identity JSON")
	slot := flags.String("slot", "", "independently established controller slot")
	imageOCID := flags.String("image-ocid", "", "independently established OCI image OCID")
	var rootPaths stringListFlag
	flags.Var(&rootPaths, "root-key", "trusted root Ed25519 public key PEM (repeatable)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *anchorPath == "" || *manifestPath == "" || *identityPath == "" || *slot == "" || *imageOCID == "" || flags.NArg() != 0 {
		return errors.New("verify-manifest requires --anchor, --manifest, --identity, --slot, --image-ocid, and at least one --root-key")
	}
	if len(rootPaths) == 0 || len(rootPaths) > bootstrapstart.MaxRootFiles {
		return fmt.Errorf("verify-manifest requires between 1 and %d --root-key files", bootstrapstart.MaxRootFiles)
	}
	anchor, roots, err := loadVerifiedBootstrapAnchor(*anchorPath, *identityPath, rootPaths, now)
	if err != nil {
		return err
	}
	expected, err := anchor.ManifestExpectation(*slot, *imageOCID)
	if err != nil {
		return fmt.Errorf("derive manifest expectation from current anchor: %w", err)
	}
	manifestWire, err := c.readBoundedRegular(*manifestPath, bootstrap.MaxManifestBytes)
	if err != nil {
		return fmt.Errorf("read bootstrap manifest: %w", err)
	}
	envelope, err := trust.DecodeEnvelope(manifestWire)
	if err != nil {
		return fmt.Errorf("decode bootstrap manifest: %w", err)
	}
	verified, err := bootstrap.VerifyManifest(envelope, roots, expected, now.Round(0).UTC(), bootstrap.ManifestTrustPolicy())
	if err != nil {
		return fmt.Errorf("verify current bootstrap manifest: %w", err)
	}
	manifest := verified.Manifest()
	profile, found := verified.Profile(*slot)
	if !found {
		return errors.New("verified bootstrap manifest has no launch profile for the requested slot")
	}
	architecture, err := releaseArchitecture(manifest.ImageArchitecture)
	if err != nil {
		return err
	}
	if _, err := release.VerifyImageCurrent(manifest.ReleaseImageReceiptWire, manifest.ReleaseDelegationWire, roots,
		release.ImageExpectation{Environment: manifest.Environment, LogicalRegion: string(manifest.Cell),
			OCIImageOCID: manifest.ImageOCID, Architecture: architecture}, now.Round(0).UTC()); err != nil {
		return fmt.Errorf("verify current manifest release image proof: %w", err)
	}
	output := verifiedBootstrapManifestOutput{
		SchemaVersion: bootstrap.ManifestSchemaVersion, AnchorSHA256: anchor.Digest(), ManifestSHA256: verified.Digest(),
		DeploymentID: manifest.DeploymentID, Environment: manifest.Environment, ClusterID: manifest.ClusterID,
		Cell: manifest.Cell, OCIRegion: manifest.OCIRegion, Slot: manifest.Slot, ImageOCID: manifest.ImageOCID,
		ImageArchitecture: manifest.ImageArchitecture, ReleaseReceiptSHA256: manifest.ReleaseReceiptSHA256,
		Profile: profile, IssuedAt: envelope.IssuedAt, ExpiresAt: envelope.ExpiresAt,
	}
	encoded, err := trust.EncodePayload(output)
	if err != nil {
		return fmt.Errorf("encode verified bootstrap manifest summary: %w", err)
	}
	if _, err := c.output.Write(append(encoded, '\n')); err != nil {
		return fmt.Errorf("write verified bootstrap manifest summary: %w", err)
	}
	return nil
}

func (c command) verifyBootstrapAnchorAt(args []string, now time.Time) error {
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
	verified, _, err := loadVerifiedBootstrapAnchor(*anchorPath, *identityPath, rootPaths, now)
	if err != nil {
		return err
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
	if _, err := c.output.Write(append(encoded, '\n')); err != nil {
		return fmt.Errorf("write verified bootstrap anchor summary: %w", err)
	}
	return nil
}

func loadVerifiedBootstrapAnchor(anchorPath, identityPath string, rootPaths []string, now time.Time) (
	bootstrap.VerifiedBootstrapAnchor, trust.Keyring, error,
) {
	identityWire, err := readBoundedRegular(identityPath, 4<<10)
	if err != nil {
		return bootstrap.VerifiedBootstrapAnchor{}, trust.Keyring{}, fmt.Errorf("read fixed bootstrap identity: %w", err)
	}
	var identity bootstrapstart.BakedIdentity
	if err := protocol.DecodeStrict(identityWire, &identity, 4<<10); err != nil {
		return bootstrap.VerifiedBootstrapAnchor{}, trust.Keyring{}, fmt.Errorf("decode fixed bootstrap identity: %w", err)
	}
	if identity.SchemaVersion != 1 {
		return bootstrap.VerifiedBootstrapAnchor{}, trust.Keyring{}, errors.New("fixed bootstrap identity schemaVersion must be 1")
	}
	canonical, err := protocol.EncodeJSON(identity)
	if err != nil || !bytes.Equal(identityWire, canonical) {
		return bootstrap.VerifiedBootstrapAnchor{}, trust.Keyring{}, errors.New("fixed bootstrap identity must be canonical JSON")
	}
	expected := identity.AnchorExpectation()
	rootKeys := make([]ed25519.PublicKey, 0, len(rootPaths))
	rootBytes := 0
	for _, path := range rootPaths {
		wire, err := readBoundedRegular(path, bootstrapstart.MaxRootBytes)
		if err != nil {
			return bootstrap.VerifiedBootstrapAnchor{}, trust.Keyring{}, err
		}
		rootBytes += len(wire)
		if rootBytes > bootstrapstart.MaxRootsTotal {
			return bootstrap.VerifiedBootstrapAnchor{}, trust.Keyring{}, fmt.Errorf("bootstrap root key files exceed %d aggregate bytes", bootstrapstart.MaxRootsTotal)
		}
		publicKey, err := parseRootPublicKey(wire)
		if err != nil {
			return bootstrap.VerifiedBootstrapAnchor{}, trust.Keyring{}, err
		}
		rootKeys = append(rootKeys, publicKey)
	}
	roots, err := trust.ParseKeyring(rootKeys...)
	if err != nil {
		return bootstrap.VerifiedBootstrapAnchor{}, trust.Keyring{}, fmt.Errorf("parse root trust set: %w", err)
	}
	anchorWire, err := readBoundedRegular(anchorPath, bootstrap.MaxBootstrapAnchorBytes)
	if err != nil {
		return bootstrap.VerifiedBootstrapAnchor{}, trust.Keyring{}, fmt.Errorf("read bootstrap anchor: %w", err)
	}
	envelope, err := trust.DecodeEnvelope(anchorWire)
	if err != nil {
		return bootstrap.VerifiedBootstrapAnchor{}, trust.Keyring{}, fmt.Errorf("decode bootstrap anchor: %w", err)
	}
	now = now.Round(0).UTC()
	verified, err := bootstrap.VerifyBootstrapAnchor(envelope, roots, expected, now, bootstrap.BootstrapAnchorTrustPolicy())
	if err != nil {
		return bootstrap.VerifiedBootstrapAnchor{}, trust.Keyring{}, fmt.Errorf("verify current bootstrap anchor: %w", err)
	}
	return verified, roots, nil
}

// signLedgerDelegationAt issues only the exact current anchor ledger grant.
// It runs on the offline signer; the seed receives this public envelope and
// the separate delegated private key through its version-pinned Vault secret.
func (c command) signLedgerDelegationAt(args []string, now time.Time) error {
	flags := flag.NewFlagSet("sign-ledger-delegation", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	deploymentID := flags.String("deployment", "", "reviewed deployment identity")
	cell := flags.String("cell", "", "reviewed region cell: GRU, SFO, or FRA")
	environment := flags.String("environment", "", "reviewed environment: production or canary")
	var slots stringListFlag
	flags.Var(&slots, "slot", "reviewed controller slot, in ascending order (repeatable)")
	signerPublicPath := flags.String("signer-public-key", "", "delegated ledger signer Ed25519 public key PEM")
	rootPublicPath := flags.String("root-key", "", "offline root Ed25519 public key PEM")
	rootPrivatePath := flags.String("signing-key", "", "owner-only offline root Ed25519 PKCS#8 private key PEM")
	outputPath := flags.String("out", "", "new canonical signed ledger delegation envelope")
	issuedAtText := flags.String("issued-at", "", "explicit UTC RFC3339 grant issue time")
	expiresAtText := flags.String("expires-at", "", "explicit UTC RFC3339 grant expiry time")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *deploymentID == "" || *cell == "" || *environment == "" || len(slots) == 0 ||
		*signerPublicPath == "" || *rootPublicPath == "" || *rootPrivatePath == "" || *outputPath == "" ||
		*issuedAtText == "" || *expiresAtText == "" || flags.NArg() != 0 {
		return errors.New("sign-ledger-delegation requires deployment, cell, environment, ordered slots, signer public key, root public/private keys, issue/expiry times, and output")
	}
	if *environment != "production" && *environment != "canary" ||
		!slices.IsSorted(slots) || len(slots) > bootstrap.MaxBootstrapAnchorSlots {
		return errors.New("ledger grant environment or ordered controller slots are invalid")
	}
	if _, err := oci.Region(*cell).OCIRegion(); err != nil {
		return err
	}
	issuedAt, err := time.Parse(time.RFC3339, *issuedAtText)
	if err != nil || issuedAt.Location() != time.UTC {
		return errors.New("ledger grant issued-at must be UTC RFC3339")
	}
	expiresAt, err := time.Parse(time.RFC3339, *expiresAtText)
	if err != nil || expiresAt.Location() != time.UTC || !expiresAt.After(issuedAt) ||
		expiresAt.Sub(issuedAt) > bootstrap.MaxBootstrapAnchorLifetime || now.Before(issuedAt) || !now.Before(expiresAt) {
		return errors.New("ledger grant must have a current UTC interval no longer than the anchor maximum")
	}
	rootPublic, err := readRootPublicKey(*rootPublicPath)
	if err != nil {
		return err
	}
	signerPublic, err := readRootPublicKey(*signerPublicPath)
	if err != nil {
		return err
	}
	if bytes.Equal(rootPublic, signerPublic) {
		return errors.New("delegated ledger signer must differ from the offline root")
	}
	rootPrivate, err := readRootPrivateKey(*rootPrivatePath)
	if err != nil {
		return err
	}
	defer clear(rootPrivate)
	if !bytes.Equal(rootPrivate.Public().(ed25519.PublicKey), rootPublic) {
		return errors.New("offline root signing key does not match the supplied root public key")
	}
	signerID, err := trust.KeyID(signerPublic)
	if err != nil {
		return err
	}
	signerWire, err := trust.EncodeDelegatedPublicKey(signerPublic)
	if err != nil {
		return err
	}
	domains := bootstrap.BootstrapLedgerCapabilityDomains()
	capabilities := make([]trust.Capability, 0, len(domains))
	for _, domain := range domains {
		capabilities = append(capabilities, trust.Capability{Domain: domain, DeploymentID: *deploymentID,
			Cell: *cell, Environment: *environment, Role: "controller", Slots: slices.Clone(slots), Actions: []string{"sign"}})
	}
	grant := trust.Delegation{SchemaVersion: trust.SchemaVersion, SubjectKeyID: signerID,
		SubjectPublicKey: signerWire, Capabilities: capabilities}
	signed, err := trust.SignDelegation(grant, issuedAt, expiresAt, rootPrivate)
	if err != nil {
		return fmt.Errorf("sign exact ledger delegation: %w", err)
	}
	roots, err := trust.ParseKeyring(rootPublic)
	if err != nil {
		return err
	}
	verified, err := trust.VerifyDelegationCurrent(signed, roots, now, bootstrap.BootstrapAnchorTrustPolicy())
	if err != nil || verified.SubjectKeyID() != signerID || !slices.EqualFunc(verified.Capabilities(), capabilities,
		func(a, b trust.Capability) bool {
			return a.Domain == b.Domain && a.DeploymentID == b.DeploymentID && a.Cell == b.Cell &&
				a.Environment == b.Environment && a.Role == b.Role && slices.Equal(a.Slots, b.Slots) &&
				slices.Equal(a.Actions, b.Actions)
		}) {
		return errors.New("signed ledger delegation failed exact-scope verification")
	}
	encoded, err := trust.EncodeEnvelope(signed)
	if err != nil {
		return err
	}
	if len(encoded) > bootstrap.MaxBootstrapLedgerGrantBytes {
		return errors.New("signed ledger delegation exceeds anchor size limit")
	}
	if err := c.writeNew(*outputPath, encoded, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(c.output, "signed ledger delegation deployment=%s cell=%s signer=%s digest=%x expires=%s\n",
		*deploymentID, *cell, signerID, sha256.Sum256(encoded), expiresAt.Format(time.RFC3339))
	return nil
}

func (c command) signBootstrapAnchorAt(args []string, now time.Time) error {
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

	candidateBytes, err := c.readBoundedRegular(*candidatePath, bootstrap.MaxBootstrapAnchorBytes)
	if err != nil {
		return err
	}
	var anchor bootstrap.BootstrapAnchor
	if err := protocol.DecodeStrict(candidateBytes, &anchor, bootstrap.MaxBootstrapAnchorBytes); err != nil {
		return fmt.Errorf("decode candidate anchor: %w", err)
	}
	regionIntentWire, err := c.readBoundedRegular(*regionIntentPath, bootstrap.MaxInitialRegionIntentBytes)
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
	ledgerDelegationWire, err := c.readBoundedRegular(*ledgerDelegationPath, bootstrap.MaxBootstrapLedgerGrantBytes)
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
	if err := c.writeNew(*outputPath, encoded, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(c.output, "signed bootstrap anchor cell=%s cluster=%s digest=%s expires=%s\n",
		anchor.Cell, anchor.ClusterID, verified.Digest(), verified.ExpiresAt().Format(time.RFC3339))
	return nil
}

func (c command) signManifestAt(args []string, now time.Time) error {
	flags := flag.NewFlagSet("sign-manifest", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	candidatePath := flags.String("candidate", "", "reviewed unsigned bootstrap manifest JSON")
	controllerConfigPath := flags.String("controller-config", "", "reviewed canonical controller role JSON")
	controllerConfigSHA := flags.String("controller-config-sha256", "", "reviewed controller role SHA-256")
	regionIntentPath := flags.String("oci-region-intent", "", "reviewed canonical regional intent JSON")
	regionIntentSHA := flags.String("oci-region-intent-sha256", "", "reviewed regional intent SHA-256")
	regionConfigPath := flags.String("oci-region-config", "", "reviewed canonical regional fleet JSON")
	regionConfigSHA := flags.String("oci-region-config-sha256", "", "reviewed regional fleet SHA-256")
	placementPath := flags.String("placement-config", "", "reviewed canonical placement JSON")
	placementSHA := flags.String("placement-config-sha256", "", "reviewed placement SHA-256")
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
	if *candidatePath == "" || *controllerConfigPath == "" || *controllerConfigSHA == "" ||
		*regionIntentPath == "" || *regionIntentSHA == "" || *regionConfigPath == "" ||
		*regionConfigSHA == "" || *placementPath == "" || *placementSHA == "" ||
		*anchorPath == "" || *imageReceiptPath == "" || *releaseDelegationPath == "" ||
		*rootPublicPath == "" || *rootPrivatePath == "" || *outputPath == "" || flags.NArg() != 0 {
		return errors.New("sign-manifest requires the reviewed controller config and three sidecars with SHA-256 pins, candidate, anchor, release proofs, root keys, and output")
	}
	policy := bootstrap.ManifestTrustPolicy()
	if *validFor <= 0 || *validFor > policy.MaxLifetime {
		return fmt.Errorf("manifest validity must be positive and no longer than %s", policy.MaxLifetime)
	}
	now = now.Round(0).UTC()
	if now.IsZero() {
		return errors.New("manifest signing time is invalid")
	}

	candidateBytes, err := c.readBoundedRegular(*candidatePath, bootstrap.MaxManifestBytes)
	if err != nil {
		return err
	}
	var manifest bootstrap.Manifest
	if err := protocol.DecodeStrict(candidateBytes, &manifest, bootstrap.MaxManifestBytes); err != nil {
		return fmt.Errorf("decode candidate manifest: %w", err)
	}
	if err := attachReviewedControllerConfig(&manifest, *controllerConfigPath, *controllerConfigSHA,
		*regionIntentPath, *regionIntentSHA, *regionConfigPath, *regionConfigSHA,
		*placementPath, *placementSHA); err != nil {
		return err
	}
	imageWire, err := c.readBoundedRegular(*imageReceiptPath, bootstrap.MaxManifestBytes)
	if err != nil {
		return fmt.Errorf("read image receipt: %w", err)
	}
	delegationWire, err := c.readBoundedRegular(*releaseDelegationPath, bootstrap.MaxManifestBytes)
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
	anchorWire, err := c.readBoundedRegular(*anchorPath, bootstrap.MaxBootstrapAnchorBytes)
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
	if len(encoded) > bootstrapstart.MaxControllerManifestMetadataBytes {
		return fmt.Errorf("signed manifest envelope exceeds %d-byte OCI metadata transport", bootstrapstart.MaxControllerManifestMetadataBytes)
	}
	if err := c.writeNew(*outputPath, encoded, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(c.output, "signed current bootstrap manifest cell=%s slot=%s digest=%s expires=%s\n",
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
	return readBoundedRegularContext(context.Background(), path, maximum)
}

func (c command) readBoundedRegular(path string, maximum int64) ([]byte, error) {
	return readBoundedRegularContext(c.ctx, path, maximum)
}

func readBoundedRegularContext(ctx context.Context, path string, maximum int64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
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
	data, err := io.ReadAll(io.LimitReader(commandio.Reader(ctx, file), maximum+1))
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

func (c command) writeNew(path string, contents []byte, mode os.FileMode) error {
	if err := c.ctx.Err(); err != nil {
		return err
	}
	if path == "" || len(contents) == 0 {
		return errors.New("output path and content are required")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("create output without overwrite: %w", err)
	}
	if err := c.ctx.Err(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
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
	if err := c.ctx.Err(); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}
