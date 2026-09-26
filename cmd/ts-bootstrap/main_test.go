package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/release"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

const testRevision = "0123456789abcdef0123456789abcdef01234567"

type manifestFixture struct {
	now                  time.Time
	roots                trust.Keyring
	rootPublic           ed25519.PublicKey
	rootPrivate          ed25519.PrivateKey
	delegatePrivate      ed25519.PrivateKey
	ledgerPublic         ed25519.PublicKey
	ledgerDelegationWire []byte
	ledgerExpiresAt      time.Time
	manifest             bootstrap.Manifest
	anchor               bootstrap.BootstrapAnchor
	image                release.ImageReceipt
	imageWire            []byte
	delegationWire       []byte
	initialIntentWire    []byte
	directory            string
	candidatePath        string
	anchorCandidatePath  string
	anchorPath           string
	intentPath           string
	ledgerDelegationPath string
	imagePath            string
	delegationPath       string
	rootPath             string
	privatePath          string
}

func newManifestFixture(t *testing.T, delegationFor, imageFor time.Duration) *manifestFixture {
	t.Helper()
	now := time.Date(2026, time.September, 25, 12, 0, 0, 0, time.UTC)
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	delegatePublic, delegatePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(rootPublic)
	if err != nil {
		t.Fatal(err)
	}
	delegateKeyID, err := trust.KeyID(delegatePublic)
	if err != nil {
		t.Fatal(err)
	}
	encodedDelegatePublic, err := trust.EncodeDelegatedPublicKey(delegatePublic)
	if err != nil {
		t.Fatal(err)
	}
	image := testImageReceipt()
	delegation, err := trust.SignDelegation(trust.Delegation{
		SchemaVersion: trust.SchemaVersion, SubjectKeyID: delegateKeyID, SubjectPublicKey: encodedDelegatePublic,
		Capabilities: []trust.Capability{{
			Domain: release.ImageDomain, DeploymentID: image.SourceRevision, Cell: "GRU", Environment: "production",
			Role: "oci-image", Slots: []string{image.OCIImageOCID}, Actions: []string{"sign"},
		}},
	}, now.Add(-24*time.Hour), now.Add(delegationFor), rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	imageEnvelope, err := release.SignImageReceipt(image, "production", delegation, roots,
		delegatePrivate, now, imageFor)
	if err != nil {
		t.Fatal(err)
	}
	imageWire := encodeEnvelope(t, imageEnvelope)
	delegationWire := encodeEnvelope(t, delegation)
	imageDigest := sha256.Sum256(imageWire)
	initialIntentWire, err := trust.EncodePayload(oci.RegionIntent{
		SchemaVersion: 1, Generation: 1, BootstrapRegion: oci.RegionGRU,
		Regions: []oci.RegionMapping{{Cell: oci.RegionGRU, OCIRegion: "sa-saopaulo-1"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	manifest := bootstrap.Manifest{
		SchemaVersion: bootstrap.ManifestSchemaVersion, DeploymentID: "deployment-a", Environment: "production",
		ClusterID: "cluster-a", Cell: oci.RegionGRU, OCIRegion: "sa-saopaulo-1", IntentGeneration: 1,
		IntentSHA256: digest(initialIntentWire), ControllerRole: "controller", Slot: "seed-a", SeedSlot: "seed-a",
		ControllerSlots: []string{"seed-a"},
		Profiles: []bootstrap.LaunchProfile{{
			Slot: "seed-a", CompartmentOCID: "ocid1.compartment.oc1..compartment",
			AvailabilityDomain: "SA-SAOPAULO-1-AD-1", FaultDomain: "FAULT-DOMAIN-1",
			SubnetOCID: "ocid1.subnet.oc1.sa-saopaulo-1.subnet", Shape: "VM.Standard.E5.Flex",
		}},
		ImageOCID: image.OCIImageOCID, ImageArchitecture: "linux-amd64",
		ReleaseReceiptSHA256: hex.EncodeToString(imageDigest[:]),
		StorageDomain: bootstrap.StorageDomain{
			Namespace: "namespace", LedgerBucket: "bootstrap-ledger",
			LedgerKMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.ledger", HeadBucket: "bootstrap-head",
			HeadKMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.head", Prefix: "private/bootstrap",
		},
	}
	ledgerPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ledgerPublicWire, err := trust.EncodeDelegatedPublicKey(ledgerPublic)
	if err != nil {
		t.Fatal(err)
	}
	ledgerKeyID, err := trust.KeyID(ledgerPublic)
	if err != nil {
		t.Fatal(err)
	}
	ledgerExpiresAt := now.Add(bootstrap.MaxBootstrapAnchorLifetime - 24*time.Hour)
	ledgerCapabilities := make([]trust.Capability, 0, len(bootstrap.BootstrapLedgerCapabilityDomains()))
	for _, domain := range bootstrap.BootstrapLedgerCapabilityDomains() {
		ledgerCapabilities = append(ledgerCapabilities, trust.Capability{
			Domain: domain, DeploymentID: manifest.DeploymentID, Cell: string(manifest.Cell),
			Environment: manifest.Environment, Role: manifest.ControllerRole,
			Slots: append([]string(nil), manifest.ControllerSlots...), Actions: []string{"sign"},
		})
	}
	ledgerGrant, err := trust.SignDelegation(trust.Delegation{
		SchemaVersion: trust.SchemaVersion, SubjectKeyID: ledgerKeyID, SubjectPublicKey: ledgerPublicWire,
		Capabilities: ledgerCapabilities,
	}, now.Add(-24*time.Hour), ledgerExpiresAt, rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	ledgerDelegationWire := encodeEnvelope(t, ledgerGrant)
	directory := t.TempDir()
	rootDER, err := x509.MarshalPKIXPublicKey(rootPublic)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &manifestFixture{
		now: now, roots: roots, rootPublic: rootPublic, rootPrivate: rootPrivate,
		delegatePrivate: delegatePrivate, ledgerPublic: ledgerPublic,
		ledgerDelegationWire: ledgerDelegationWire, ledgerExpiresAt: ledgerExpiresAt,
		manifest: manifest, image: image,
		imageWire: imageWire, delegationWire: delegationWire, initialIntentWire: initialIntentWire, directory: directory,
		candidatePath:       filepath.Join(directory, "candidate.json"),
		anchorCandidatePath: filepath.Join(directory, "anchor-candidate.json"),
		anchorPath:          filepath.Join(directory, "bootstrap-anchor.json"), intentPath: filepath.Join(directory, "region-intent.json"),
		ledgerDelegationPath: filepath.Join(directory, "ledger-delegation.json"),
		imagePath:            filepath.Join(directory, "image.json"),
		delegationPath:       filepath.Join(directory, "release-delegation.json"), rootPath: filepath.Join(directory, "root.pub"),
		privatePath: filepath.Join(directory, "root.key"),
	}
	writeFixture(t, fixture.imagePath, imageWire, 0o600)
	writeFixture(t, fixture.delegationPath, delegationWire, 0o600)
	writeFixture(t, fixture.rootPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: rootDER}), 0o644)
	writeFixture(t, fixture.privatePath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0o600)
	writeFixture(t, fixture.intentPath, initialIntentWire, 0o600)
	writeFixture(t, fixture.ledgerDelegationPath, ledgerDelegationWire, 0o600)
	fixture.writeAnchor(t, bootstrap.BootstrapAnchor{
		SchemaVersion: bootstrap.BootstrapAnchorSchemaVersion, DeploymentID: manifest.DeploymentID,
		Environment: manifest.Environment, ClusterID: manifest.ClusterID, Cell: manifest.Cell,
		OCIRegion: manifest.OCIRegion, StorageDomain: manifest.StorageDomain,
		ControllerSlots: append([]string(nil), manifest.ControllerSlots...), LedgerDelegationWire: bytes.Clone(ledgerDelegationWire),
		InitialRegionIntentGeneration: 1, InitialRegionIntentSHA256: digest(initialIntentWire),
		InitialRegionIntentWire: bytes.Clone(initialIntentWire),
	})
	return fixture
}

func (fixture *manifestFixture) args(output string, validFor string) []string {
	args := []string{
		"--candidate", fixture.candidatePath,
		"--anchor", fixture.anchorPath,
		"--image-receipt", fixture.imagePath,
		"--release-delegation", fixture.delegationPath,
		"--root-key", fixture.rootPath,
		"--signing-key", fixture.privatePath,
		"--out", output,
	}
	if validFor != "" {
		args = append(args, "--valid-for", validFor)
	}
	return args
}

func (fixture *manifestFixture) anchorArgs(output string, validFor string) []string {
	args := []string{
		"--candidate", fixture.anchorCandidatePath,
		"--region-intent", fixture.intentPath,
		"--ledger-delegation", fixture.ledgerDelegationPath,
		"--root-key", fixture.rootPath,
		"--signing-key", fixture.privatePath,
		"--out", output,
	}
	if validFor != "" {
		args = append(args, "--valid-for", validFor)
	}
	return args
}

func (fixture *manifestFixture) writeCandidate(t *testing.T, manifest bootstrap.Manifest) {
	t.Helper()
	encoded, err := trust.EncodePayload(manifest)
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, fixture.candidatePath, encoded, 0o600)
}

func (fixture *manifestFixture) writeAnchorCandidate(t *testing.T, anchor bootstrap.BootstrapAnchor) {
	t.Helper()
	encoded, err := trust.EncodePayload(anchor)
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, fixture.anchorCandidatePath, encoded, 0o600)
}

func (fixture *manifestFixture) writeAnchor(t *testing.T, anchor bootstrap.BootstrapAnchor) {
	fixture.writeAnchorAt(t, anchor, fixture.now, fixture.ledgerExpiresAt)
}

func (fixture *manifestFixture) writeAnchorFor(t *testing.T, anchor bootstrap.BootstrapAnchor, validFor time.Duration) {
	t.Helper()
	expiresAt := fixture.now.Add(validFor)
	if fixture.ledgerExpiresAt.Before(expiresAt) {
		expiresAt = fixture.ledgerExpiresAt
	}
	fixture.writeAnchorAt(t, anchor, fixture.now, expiresAt)
}

func (fixture *manifestFixture) writeAnchorAt(t *testing.T, anchor bootstrap.BootstrapAnchor, issuedAt, expiresAt time.Time) {
	t.Helper()
	envelope, err := bootstrap.SignBootstrapAnchor(anchor, issuedAt, expiresAt, fixture.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	fixture.anchor = anchor
	writeFixture(t, fixture.anchorPath, encoded, 0o600)
}

func (fixture *manifestFixture) setLedgerGrant(t *testing.T, slots []string) {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicWire, err := trust.EncodeDelegatedPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := trust.KeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	capabilities := make([]trust.Capability, 0, len(bootstrap.BootstrapLedgerCapabilityDomains()))
	for _, domain := range bootstrap.BootstrapLedgerCapabilityDomains() {
		capabilities = append(capabilities, trust.Capability{
			Domain: domain, DeploymentID: fixture.manifest.DeploymentID, Cell: string(fixture.manifest.Cell),
			Environment: fixture.manifest.Environment, Role: fixture.manifest.ControllerRole,
			Slots: append([]string(nil), slots...), Actions: []string{"sign"},
		})
	}
	grant, err := trust.SignDelegation(trust.Delegation{
		SchemaVersion: trust.SchemaVersion, SubjectKeyID: keyID, SubjectPublicKey: publicWire,
		Capabilities: capabilities,
	}, fixture.now.Add(-24*time.Hour), fixture.ledgerExpiresAt, fixture.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	fixture.ledgerDelegationWire = encodeEnvelope(t, grant)
	fixture.ledgerPublic = public
	writeFixture(t, fixture.ledgerDelegationPath, fixture.ledgerDelegationWire, 0o600)
}

func signTestLedgerGrant(t *testing.T, root ed25519.PrivateKey, public ed25519.PublicKey,
	deployment string, cell oci.Region, environment string, slots []string, issuedAt, expiresAt time.Time,
) trust.Envelope {
	t.Helper()
	publicWire, err := trust.EncodeDelegatedPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := trust.KeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	capabilities := make([]trust.Capability, 0, len(bootstrap.BootstrapLedgerCapabilityDomains()))
	for _, domain := range bootstrap.BootstrapLedgerCapabilityDomains() {
		capabilities = append(capabilities, trust.Capability{
			Domain: domain, DeploymentID: deployment, Cell: string(cell), Environment: environment,
			Role: "controller", Slots: append([]string(nil), slots...), Actions: []string{"sign"},
		})
	}
	grant, err := trust.SignDelegation(trust.Delegation{
		SchemaVersion: trust.SchemaVersion, SubjectKeyID: keyID, SubjectPublicKey: publicWire, Capabilities: capabilities,
	}, issuedAt, expiresAt, root)
	if err != nil {
		t.Fatal(err)
	}
	return grant
}

func TestSignLedgerDelegationIssuesExactCurrentGrant(t *testing.T) {
	fixture := newManifestFixture(t, 30*24*time.Hour, 20*24*time.Hour)
	rootDER, err := x509.MarshalPKIXPublicKey(fixture.ledgerPublic)
	if err != nil {
		t.Fatal(err)
	}
	signerPath := filepath.Join(fixture.directory, "ledger-signer.pub")
	writeFixture(t, signerPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: rootDER}), 0o644)
	output := filepath.Join(fixture.directory, "new-ledger-grant.json")
	issuedAt := fixture.now.Add(-time.Minute)
	expiresAt := fixture.now.Add(24 * time.Hour)
	args := []string{"sign-ledger-delegation", "--deployment", fixture.manifest.DeploymentID,
		"--cell", string(fixture.manifest.Cell), "--environment", fixture.manifest.Environment,
		"--signer-public-key", signerPath, "--root-key", fixture.rootPath,
		"--signing-key", fixture.privatePath, "--issued-at", issuedAt.Format(time.RFC3339),
		"--expires-at", expiresAt.Format(time.RFC3339), "--out", output}
	for _, slot := range fixture.manifest.ControllerSlots {
		args = append(args, "--slot", slot)
	}
	if err := runAt(args, fixture.now); err != nil {
		t.Fatalf("sign current ledger grant: %v", err)
	}
	wire, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := trust.DecodeEnvelope(wire)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := trust.VerifyDelegationCurrent(envelope, fixture.roots, fixture.now, bootstrap.BootstrapAnchorTrustPolicy())
	if err != nil {
		t.Fatal(err)
	}
	domains := bootstrap.BootstrapLedgerCapabilityDomains()
	if len(verified.Capabilities()) != len(domains) {
		t.Fatalf("grant capabilities=%d want=%d", len(verified.Capabilities()), len(domains))
	}
	for i, capability := range verified.Capabilities() {
		if capability.Domain != domains[i] || capability.DeploymentID != fixture.manifest.DeploymentID ||
			capability.Cell != string(fixture.manifest.Cell) || capability.Environment != fixture.manifest.Environment ||
			capability.Role != "controller" || !slices.Equal(capability.Slots, fixture.manifest.ControllerSlots) ||
			!slices.Equal(capability.Actions, []string{"sign"}) {
			t.Fatalf("wrong grant capability[%d]: %+v", i, capability)
		}
	}
	if err := runAt(args, fixture.now); !errors.Is(err, os.ErrExist) {
		t.Fatalf("grant output was overwritten: %v", err)
	}
	writeFixture(t, fixture.ledgerDelegationPath, wire, 0o600)
	anchor := fixture.anchor
	anchor.LedgerDelegationWire = nil
	fixture.writeAnchorCandidate(t, anchor)
	anchorOutput := filepath.Join(fixture.directory, "issued-anchor.json")
	if err := runAt(append([]string{"sign-anchor"}, fixture.anchorArgs(anchorOutput, "")...),
		fixture.now.Add(time.Minute)); err != nil {
		t.Fatalf("default sign-anchor could not consume the new grant: %v", err)
	}
	anchorWire, err := os.ReadFile(anchorOutput)
	if err != nil {
		t.Fatal(err)
	}
	anchorEnvelope, err := trust.DecodeEnvelope(anchorWire)
	if err != nil {
		t.Fatal(err)
	}
	if !anchorEnvelope.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("default anchor expiry=%s, want grant bound %s", anchorEnvelope.ExpiresAt, expiresAt)
	}
}

func TestSignLedgerDelegationRejectsWrongScopeAndKey(t *testing.T) {
	fixture := newManifestFixture(t, 30*24*time.Hour, 20*24*time.Hour)
	rootDER, err := x509.MarshalPKIXPublicKey(fixture.ledgerPublic)
	if err != nil {
		t.Fatal(err)
	}
	signerPath := filepath.Join(fixture.directory, "ledger-signer.pub")
	writeFixture(t, signerPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: rootDER}), 0o644)
	base := []string{"sign-ledger-delegation", "--deployment", fixture.manifest.DeploymentID,
		"--cell", string(fixture.manifest.Cell), "--environment", fixture.manifest.Environment,
		"--signer-public-key", signerPath, "--root-key", fixture.rootPath,
		"--signing-key", fixture.privatePath, "--issued-at", fixture.now.Add(-time.Minute).Format(time.RFC3339),
		"--expires-at", fixture.now.Add(time.Hour).Format(time.RFC3339),
		"--out", filepath.Join(fixture.directory, "rejected-grant.json")}
	for _, test := range []struct {
		name string
		args []string
	}{
		{name: "missing slots", args: base},
		{name: "duplicate slots", args: append(append([]string(nil), base...), "--slot", "seed-a", "--slot", "seed-a")},
		{name: "wrong cell", args: append(append([]string(nil), base...), "--cell", "OTHER", "--slot", "seed-a")},
		{name: "root as signer", args: append(append([]string(nil), base...), "--signer-public-key", fixture.rootPath, "--slot", "seed-a")},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := runAt(test.args, fixture.now); err == nil {
				t.Fatal("invalid offline grant request succeeded")
			}
		})
	}
}

func (fixture *manifestFixture) anchorForSlots(t *testing.T, slots []string) bootstrap.BootstrapAnchor {
	t.Helper()
	fixture.setLedgerGrant(t, slots)
	anchor := fixture.anchor
	anchor.ControllerSlots = append([]string(nil), slots...)
	anchor.LedgerDelegationWire = bytes.Clone(fixture.ledgerDelegationWire)
	return anchor
}

func TestSignBootstrapAnchorBindsExactCanonicalIntent(t *testing.T) {
	fixture := newManifestFixture(t, 60*24*time.Hour, 45*24*time.Hour)
	candidate := fixture.anchor
	candidate.InitialRegionIntentGeneration = 0
	candidate.InitialRegionIntentSHA256 = ""
	candidate.InitialRegionIntentWire = nil
	fixture.writeAnchorCandidate(t, candidate)
	output := filepath.Join(fixture.directory, "new-bootstrap-anchor.json")
	if err := runAt(append([]string{"sign-anchor"}, fixture.anchorArgs(output, "")...), fixture.now); err != nil {
		t.Fatalf("sign-anchor: %v", err)
	}
	encoded, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := trust.DecodeEnvelope(encoded)
	if err != nil {
		t.Fatalf("decode signed anchor: %v", err)
	}
	verified, err := bootstrap.VerifyBootstrapAnchor(envelope, fixture.roots, bootstrap.BootstrapAnchorExpectation{
		DeploymentID: fixture.anchor.DeploymentID, Environment: fixture.anchor.Environment, Cell: fixture.anchor.Cell,
	}, fixture.now, bootstrap.BootstrapAnchorTrustPolicy())
	if err != nil {
		t.Fatalf("verify signed anchor: %v", err)
	}
	anchor := verified.Anchor()
	if !bytes.Equal(anchor.InitialRegionIntentWire, fixture.initialIntentWire) ||
		anchor.InitialRegionIntentGeneration != 1 || anchor.InitialRegionIntentSHA256 != digest(fixture.initialIntentWire) {
		t.Fatal("signed anchor did not preserve exact canonical initial region-intent bytes and pins")
	}
	if !bytes.Equal(verified.Wire(), encoded) || verified.Digest() != digest(encoded) {
		t.Fatal("verified anchor did not preserve its exact canonical wire and digest")
	}
	if !verified.ExpiresAt().Equal(fixture.ledgerExpiresAt) {
		t.Fatalf("anchor expiry = %s; want ledger-grant expiry %s", verified.ExpiresAt(), fixture.ledgerExpiresAt)
	}
	expectation, err := verified.ManifestExpectation("seed-a", fixture.image.OCIImageOCID)
	if err != nil {
		t.Fatalf("derive manifest expectation: %v", err)
	}
	if expectation.ClusterID != fixture.anchor.ClusterID || expectation.StorageDomain != fixture.anchor.StorageDomain ||
		!equalOrderedStrings(expectation.ControllerSlots, fixture.anchor.ControllerSlots) ||
		expectation.IntentGeneration != 1 || expectation.IntentSHA256 != digest(fixture.initialIntentWire) ||
		expectation.ImageOCID != fixture.image.OCIImageOCID {
		t.Fatalf("derived manifest expectation = %+v", expectation)
	}
}

func TestVerifyBootstrapAnchorUsesCurrentRootSetAndStrictIdentityFile(t *testing.T) {
	fixture := newManifestFixture(t, 60*24*time.Hour, 45*24*time.Hour)
	identity := bootstrapstart.BakedIdentity{
		SchemaVersion: 1, DeploymentID: fixture.anchor.DeploymentID,
		Environment: fixture.anchor.Environment, Cell: fixture.anchor.Cell,
	}
	identityWire, err := protocol.EncodeJSON(identity)
	if err != nil {
		t.Fatal(err)
	}
	identityPath := filepath.Join(fixture.directory, "identity.json")
	writeFixture(t, identityPath, identityWire, 0o600)
	secondRootPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	secondRootDER, err := x509.MarshalPKIXPublicKey(secondRootPublic)
	if err != nil {
		t.Fatal(err)
	}
	secondRootPath := filepath.Join(fixture.directory, "second-root.pub")
	writeFixture(t, secondRootPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: secondRootDER}), 0o644)
	args := []string{
		"verify-anchor", "--anchor", fixture.anchorPath, "--identity", identityPath,
		"--root-key", fixture.rootPath, "--root-key", secondRootPath,
	}
	output, err := captureStdout(t, func() error { return runAt(args, fixture.now) })
	if err != nil {
		t.Fatalf("verify-anchor with the current root set: %v", err)
	}
	for _, want := range []string{`"clusterId":"cluster-a"`, `"controllerSlots":["seed-a"]`,
		`"initialRegionIntentGeneration":1`, `"ledgerDelegationSubjectKeyId":`} {
		if !strings.Contains(string(output), want) {
			t.Errorf("verify-anchor output %q does not contain %q", output, want)
		}
	}

	unknownIdentity, err := trust.EncodePayload(struct {
		SchemaVersion int        `json:"schemaVersion"`
		DeploymentID  string     `json:"deploymentId"`
		Environment   string     `json:"environment"`
		Cell          oci.Region `json:"cell"`
		Unknown       bool       `json:"unknown"`
	}{
		SchemaVersion: 1, DeploymentID: fixture.anchor.DeploymentID,
		Environment: identity.Environment, Cell: fixture.anchor.Cell, Unknown: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, identityPath, unknownIdentity, 0o600)
	if _, err := captureStdout(t, func() error { return runAt(args, fixture.now) }); err == nil {
		t.Fatal("verify-anchor accepted an identity file with an unknown key")
	}

	for _, test := range []struct {
		name string
		wire []byte
	}{
		{name: "malformed JSON", wire: []byte(`{"schemaVersion":1,`)},
		{name: "missing schema version", wire: []byte(`{"deploymentId":"deployment-a","environment":"production","cell":"GRU"}`)},
		{name: "missing deployment identity", wire: []byte(`{"schemaVersion":1,"environment":"production","cell":"GRU"}`)},
		{name: "wrong schema version", wire: mustEncodePayload(t, bootstrapstart.BakedIdentity{
			SchemaVersion: 2, DeploymentID: identity.DeploymentID, Environment: identity.Environment, Cell: identity.Cell,
		})},
	} {
		t.Run(test.name, func(t *testing.T) {
			writeFixture(t, identityPath, test.wire, 0o600)
			if _, err := captureStdout(t, func() error { return runAt(args, fixture.now) }); err == nil {
				t.Fatalf("verify-anchor accepted invalid identity: %s", test.wire)
			}
		})
	}
	if _, err := captureStdout(t, func() error {
		return runAt([]string{"verify-anchor", "--anchor", fixture.anchorPath, "--root-key", fixture.rootPath}, fixture.now)
	}); err == nil {
		t.Fatal("verify-anchor accepted an invocation without the baked identity file")
	}

	writeFixture(t, identityPath, append(bytes.Clone(identityWire), '\n'), 0o600)
	if _, err := captureStdout(t, func() error { return runAt(args, fixture.now) }); err == nil {
		t.Fatal("verify-anchor accepted noncanonical identity JSON")
	}

	writeFixture(t, identityPath, identityWire, 0o600)
	fixture.writeAnchorAt(t, fixture.anchor, fixture.now.Add(-2*time.Hour), fixture.now.Add(-time.Hour))
	args[2] = fixture.anchorPath
	if _, err := captureStdout(t, func() error { return runAt(args, fixture.now) }); err == nil {
		t.Fatal("verify-anchor accepted an expired anchor")
	}
}

func TestVerifyBootstrapAnchorMatchesBakedRootSetLimits(t *testing.T) {
	fixture := newManifestFixture(t, 60*24*time.Hour, 45*24*time.Hour)
	identityWire, err := protocol.EncodeJSON(bootstrapstart.BakedIdentity{
		SchemaVersion: 1, DeploymentID: fixture.anchor.DeploymentID,
		Environment: fixture.anchor.Environment, Cell: fixture.anchor.Cell,
	})
	if err != nil {
		t.Fatal(err)
	}
	identityPath := filepath.Join(fixture.directory, "baked-identity.json")
	writeFixture(t, identityPath, identityWire, 0o600)
	argsForRoots := func(rootPaths ...string) []string {
		args := []string{"verify-anchor", "--anchor", fixture.anchorPath, "--identity", identityPath}
		for _, path := range rootPaths {
			args = append(args, "--root-key", path)
		}
		return args
	}
	verifyRoots := func(rootPaths ...string) error {
		_, err := captureStdout(t, func() error { return runAt(argsForRoots(rootPaths...), fixture.now) })
		return err
	}
	writePaddedRoot := func(name string, public ed25519.PublicKey, headers map[string]string, size int) string {
		der, err := x509.MarshalPKIXPublicKey(public)
		if err != nil {
			t.Fatal(err)
		}
		wire := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Headers: headers, Bytes: der})
		if size > 0 {
			if len(wire) > size {
				t.Fatalf("un-padded public-key PEM size %d exceeds requested size %d", len(wire), size)
			}
			wire = append(wire, bytes.Repeat([]byte{' '}, size-len(wire))...)
		}
		path := filepath.Join(fixture.directory, name)
		writeFixture(t, path, wire, 0o644)
		return path
	}

	t.Run("aggregate maximum accepted", func(t *testing.T) {
		rootPaths := make([]string, bootstrapstart.MaxRootsTotal/bootstrapstart.MaxRootBytes)
		for index := range rootPaths {
			public := fixture.rootPublic
			if index > 0 {
				var err error
				public, _, err = ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
			}
			rootPaths[index] = writePaddedRoot(fmt.Sprintf("exact-limit-%d.pem", index), public, nil, bootstrapstart.MaxRootBytes)
		}
		if err := verifyRoots(rootPaths...); err != nil {
			t.Fatalf("verify-anchor rejected an exact-limit baked root set: %v", err)
		}
	})

	t.Run("too many files rejected", func(t *testing.T) {
		rootPaths := make([]string, bootstrapstart.MaxRootFiles+1)
		for index := range rootPaths {
			rootPaths[index] = fixture.rootPath
		}
		if err := verifyRoots(rootPaths...); err == nil {
			t.Fatal("verify-anchor accepted more root files than the baked loader")
		}
	})

	t.Run("oversized file rejected", func(t *testing.T) {
		path := writePaddedRoot("oversized-root.pem", fixture.rootPublic, nil, bootstrapstart.MaxRootBytes+1)
		if err := verifyRoots(path); err == nil {
			t.Fatal("verify-anchor accepted a root file larger than the baked loader limit")
		}
	})

	t.Run("aggregate over limit rejected", func(t *testing.T) {
		rootPaths := make([]string, bootstrapstart.MaxRootsTotal/bootstrapstart.MaxRootBytes+1)
		for index := range rootPaths {
			rootPaths[index] = writePaddedRoot(fmt.Sprintf("over-total-%d.pem", index), fixture.rootPublic, nil, bootstrapstart.MaxRootBytes)
		}
		if err := verifyRoots(rootPaths...); err == nil {
			t.Fatal("verify-anchor accepted aggregate root bytes above the baked loader limit")
		}
	})

	t.Run("PEM headers rejected", func(t *testing.T) {
		path := writePaddedRoot("header-root.pem", fixture.rootPublic, map[string]string{"Comment": "not accepted by baked loader"}, 0)
		if err := verifyRoots(path); err == nil {
			t.Fatal("verify-anchor accepted PEM headers rejected by the baked loader")
		}
	})

	t.Run("duplicate root identifiers rejected", func(t *testing.T) {
		if err := verifyRoots(fixture.rootPath, fixture.rootPath); err == nil {
			t.Fatal("verify-anchor accepted duplicate root key identifiers")
		}
	})
}

func captureStdout(t *testing.T, operation func() error) ([]byte, error) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stdout
	os.Stdout = writer
	operationErr := operation()
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	os.Stdout = original
	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	return output, operationErr
}

func TestSignBootstrapAnchorRejectsConflictingOrNoncanonicalIntent(t *testing.T) {
	for _, test := range []struct {
		name         string
		mutateAnchor func(*bootstrap.BootstrapAnchor)
		mutateIntent func([]byte) []byte
	}{
		{name: "conflicting generation", mutateAnchor: func(anchor *bootstrap.BootstrapAnchor) {
			anchor.InitialRegionIntentGeneration = 2
		}},
		{name: "conflicting digest", mutateAnchor: func(anchor *bootstrap.BootstrapAnchor) {
			anchor.InitialRegionIntentSHA256 = strings.Repeat("0", 64)
		}},
		{name: "noncanonical region intent", mutateIntent: func(wire []byte) []byte {
			return append(bytes.Clone(wire), '\n')
		}},
		{name: "wrong anchor cell", mutateAnchor: func(anchor *bootstrap.BootstrapAnchor) {
			anchor.Cell, anchor.OCIRegion = oci.RegionFRA, "eu-frankfurt-1"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newManifestFixture(t, 60*24*time.Hour, 45*24*time.Hour)
			candidate := fixture.anchor
			if test.mutateAnchor != nil {
				test.mutateAnchor(&candidate)
			}
			fixture.writeAnchorCandidate(t, candidate)
			if test.mutateIntent != nil {
				writeFixture(t, fixture.intentPath, test.mutateIntent(fixture.initialIntentWire), 0o600)
			}
			output := filepath.Join(fixture.directory, "rejected-anchor.json")
			if err := runAt(append([]string{"sign-anchor"}, fixture.anchorArgs(output, "")...), fixture.now); err == nil {
				t.Fatal("sign-anchor accepted a conflicting anchor or noncanonical intent")
			}
			if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("rejected anchor created output: stat error = %v", err)
			}
		})
	}
}

func TestSignBootstrapAnchorRejectsUntrustedLedgerGrantBeforeWriting(t *testing.T) {
	fixture := newManifestFixture(t, 60*24*time.Hour, 45*24*time.Hour)
	_, wrongRootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongGrant := signTestLedgerGrant(t, wrongRootPrivate, fixture.ledgerPublic,
		fixture.anchor.DeploymentID, fixture.anchor.Cell, fixture.anchor.Environment,
		fixture.anchor.ControllerSlots, fixture.now.Add(-24*time.Hour), fixture.ledgerExpiresAt)
	writeFixture(t, fixture.ledgerDelegationPath, encodeEnvelope(t, wrongGrant), 0o600)
	candidate := fixture.anchor
	candidate.LedgerDelegationWire = nil
	fixture.writeAnchorCandidate(t, candidate)
	output := filepath.Join(fixture.directory, "wrong-ledger-grant.anchor.json")
	if err := runAt(append([]string{"sign-anchor"}, fixture.anchorArgs(output, "")...), fixture.now); err == nil {
		t.Fatal("sign-anchor accepted a ledger grant absent from the current root set")
	}
	if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("untrusted ledger grant created anchor output: stat error = %v", err)
	}
}

func TestSignBootstrapAnchorRejectsSlotOutsideInstanceDescriptorGrammar(t *testing.T) {
	fixture := newManifestFixture(t, 60*24*time.Hour, 45*24*time.Hour)
	candidate := fixture.anchorForSlots(t, []string{"seed/a"})
	fixture.writeAnchorCandidate(t, candidate)
	output := filepath.Join(fixture.directory, "invalid-slot.anchor.json")
	if err := runAt(append([]string{"sign-anchor"}, fixture.anchorArgs(output, "")...), fixture.now); err == nil {
		t.Fatal("sign-anchor accepted a controller slot the instance descriptor cannot parse")
	}
	if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid descriptor slot created anchor output: stat error = %v", err)
	}
}

func (fixture *manifestFixture) writeProofs(t *testing.T, imageWire, delegationWire []byte) {
	t.Helper()
	writeFixture(t, fixture.imagePath, imageWire, 0o600)
	writeFixture(t, fixture.delegationPath, delegationWire, 0o600)
	fixture.manifest.ReleaseReceiptSHA256 = digest(imageWire)
}

func (fixture *manifestFixture) verifyOutput(t *testing.T, output string, expected bootstrap.Manifest) trust.Envelope {
	t.Helper()
	encoded, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := trust.DecodeEnvelope(encoded)
	if err != nil {
		t.Fatalf("decode signed output: %v", err)
	}
	verified, err := bootstrap.VerifyManifest(envelope, fixture.roots, bootstrap.ManifestExpectation{
		DeploymentID: expected.DeploymentID, Environment: expected.Environment, ClusterID: expected.ClusterID,
		Cell: expected.Cell, Slot: expected.Slot, ImageOCID: expected.ImageOCID, StorageDomain: expected.StorageDomain,
		ControllerSlots:  append([]string(nil), expected.ControllerSlots...),
		IntentGeneration: expected.IntentGeneration, IntentSHA256: expected.IntentSHA256,
	}, fixture.now, bootstrap.ManifestTrustPolicy())
	if err != nil {
		t.Fatalf("verify signed output: %v", err)
	}
	manifest := verified.Manifest()
	if !bytes.Equal(manifest.ReleaseImageReceiptWire, fixture.imageWire) ||
		!bytes.Equal(manifest.ReleaseDelegationWire, fixture.delegationWire) || manifest.ReleaseReceiptSHA256 != digest(fixture.imageWire) {
		t.Fatal("signed manifest did not preserve the exact supplied release proof wires")
	}
	return envelope
}

func TestSignManifestSignsEachSlotWithExactCurrentReleaseProofs(t *testing.T) {
	fixture := newManifestFixture(t, 60*24*time.Hour, 45*24*time.Hour)
	peerPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	peerKeyID, err := trust.KeyID(peerPublic)
	if err != nil {
		t.Fatal(err)
	}
	encodedPeerPublic, err := trust.EncodeDelegatedPublicKey(peerPublic)
	if err != nil {
		t.Fatal(err)
	}
	peerDelegation, err := trust.SignDelegation(trust.Delegation{
		SchemaVersion: trust.SchemaVersion, SubjectKeyID: peerKeyID, SubjectPublicKey: encodedPeerPublic,
		Capabilities: []trust.Capability{{
			Domain: "terrascale.bootstrap.peer-receipt", DeploymentID: fixture.manifest.DeploymentID,
			Cell: string(fixture.manifest.Cell), Environment: fixture.manifest.Environment,
			Role: fixture.manifest.ControllerRole, Slots: []string{"peer-b"}, Actions: []string{"sign"},
		}},
	}, fixture.now.Add(-time.Minute), fixture.now.Add(60*24*time.Hour), fixture.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	var envelopeDigests []string
	for _, slot := range []string{"seed-a", "peer-b"} {
		t.Run(slot, func(t *testing.T) {
			manifest := fixture.manifest
			manifest.Slot, manifest.SeedSlot = slot, "seed-a"
			manifest.ControllerSlots = []string{"peer-b", "seed-a"}
			manifest.Profiles = []bootstrap.LaunchProfile{
				{Slot: "peer-b", CompartmentOCID: "ocid1.compartment.oc1..compartment",
					AvailabilityDomain: "SA-SAOPAULO-1-AD-1", FaultDomain: "FAULT-DOMAIN-2",
					SubnetOCID: "ocid1.subnet.oc1.sa-saopaulo-1.peer", Shape: "VM.Standard.E5.Flex"},
				{Slot: "seed-a", CompartmentOCID: "ocid1.compartment.oc1..compartment",
					AvailabilityDomain: "SA-SAOPAULO-1-AD-1", FaultDomain: "FAULT-DOMAIN-1",
					SubnetOCID: "ocid1.subnet.oc1.sa-saopaulo-1.subnet", Shape: "VM.Standard.E5.Flex"},
			}
			manifest.PeerReceiptDelegation = &peerDelegation
			fixture.writeAnchorFor(t, fixture.anchorForSlots(t, manifest.ControllerSlots), 60*24*time.Hour)
			fixture.writeCandidate(t, manifest)
			output := filepath.Join(fixture.directory, slot+".manifest.json")
			if err := runAt(append([]string{"sign-manifest"}, fixture.args(output, "2160h")...), fixture.now); err != nil {
				t.Fatalf("sign-manifest: %v", err)
			}
			envelope := fixture.verifyOutput(t, output, manifest)
			if !envelope.ExpiresAt.Equal(fixture.now.Add(45 * 24 * time.Hour)) {
				t.Fatalf("manifest expiry = %s, want image receipt expiry %s", envelope.ExpiresAt, fixture.now.Add(45*24*time.Hour))
			}
			envelopeDigests = append(envelopeDigests, digest(mustEncodeEnvelope(t, envelope)))
		})
	}
	if envelopeDigests[0] == envelopeDigests[1] {
		t.Fatal("per-slot manifests unexpectedly have the same signed envelope digest")
	}
}

func TestSignManifestRejectsInvalidCandidatesAndIdentityMismatches(t *testing.T) {
	tests := []struct {
		name      string
		candidate func(*testing.T, *manifestFixture) []byte
	}{
		{name: "missing schema version", candidate: func(t *testing.T, fixture *manifestFixture) []byte {
			manifest := fixture.manifest
			manifest.SchemaVersion = 0
			return mustEncodePayload(t, manifest)
		}},
		{name: "missing cluster id", candidate: func(t *testing.T, fixture *manifestFixture) []byte {
			encoded := mustEncodePayload(t, fixture.manifest)
			withoutCluster := bytes.Replace(encoded, []byte(`"clusterId":"cluster-a",`), nil, 1)
			if bytes.Equal(encoded, withoutCluster) {
				t.Fatal("test failed to remove the clusterId field")
			}
			return withoutCluster
		}},
		{name: "unknown field", candidate: func(t *testing.T, fixture *manifestFixture) []byte {
			encoded := mustEncodePayload(t, fixture.manifest)
			return append(encoded[:len(encoded)-1], []byte(`,"unknown":true}`)...)
		}},
		{name: "conflicting image wire", candidate: func(t *testing.T, fixture *manifestFixture) []byte {
			manifest := fixture.manifest
			manifest.ReleaseImageReceiptWire = []byte("different proof")
			return mustEncodePayload(t, manifest)
		}},
		{name: "wrong image", candidate: func(t *testing.T, fixture *manifestFixture) []byte {
			manifest := fixture.manifest
			manifest.ImageOCID = "ocid1.image.oc1.sa-saopaulo-1.different"
			return mustEncodePayload(t, manifest)
		}},
		{name: "wrong region", candidate: func(t *testing.T, fixture *manifestFixture) []byte {
			manifest := fixture.manifest
			manifest.Cell, manifest.OCIRegion = oci.RegionFRA, "eu-frankfurt-1"
			return mustEncodePayload(t, manifest)
		}},
		{name: "wrong architecture", candidate: func(t *testing.T, fixture *manifestFixture) []byte {
			manifest := fixture.manifest
			manifest.ImageArchitecture = "linux-arm64"
			return mustEncodePayload(t, manifest)
		}},
		{name: "wrong environment", candidate: func(t *testing.T, fixture *manifestFixture) []byte {
			manifest := fixture.manifest
			manifest.Environment = "canary"
			return mustEncodePayload(t, manifest)
		}},
		{name: "wrong cluster", candidate: func(t *testing.T, fixture *manifestFixture) []byte {
			manifest := fixture.manifest
			manifest.ClusterID = "cluster-b"
			return mustEncodePayload(t, manifest)
		}},
		{name: "wrong storage domain", candidate: func(t *testing.T, fixture *manifestFixture) []byte {
			manifest := fixture.manifest
			manifest.StorageDomain.Namespace = "other-namespace"
			return mustEncodePayload(t, manifest)
		}},
		{name: "wrong intent generation", candidate: func(t *testing.T, fixture *manifestFixture) []byte {
			manifest := fixture.manifest
			manifest.IntentGeneration = 2
			return mustEncodePayload(t, manifest)
		}},
		{name: "wrong digest", candidate: func(t *testing.T, fixture *manifestFixture) []byte {
			manifest := fixture.manifest
			manifest.ReleaseReceiptSHA256 = strings.Repeat("0", 64)
			return mustEncodePayload(t, manifest)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newManifestFixture(t, 60*24*time.Hour, 45*24*time.Hour)
			candidate := test.candidate(t, fixture)
			writeFixture(t, fixture.candidatePath, candidate, 0o600)
			output := filepath.Join(fixture.directory, "bad.manifest.json")
			if err := runAt(append([]string{"sign-manifest"}, fixture.args(output, "")...), fixture.now); err == nil {
				t.Fatal("sign-manifest accepted invalid candidate")
			}
			if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("invalid candidate created output: stat error = %v", err)
			}
		})
	}
}

func TestSignManifestRejectsWrongRootKeyAndBadProofWires(t *testing.T) {
	t.Run("mismatched private key", func(t *testing.T) {
		fixture := newManifestFixture(t, 60*24*time.Hour, 45*24*time.Hour)
		_, wrongPrivate, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(wrongPrivate)
		if err != nil {
			t.Fatal(err)
		}
		writeFixture(t, fixture.privatePath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
		fixture.writeCandidate(t, fixture.manifest)
		output := filepath.Join(fixture.directory, "wrong-key.manifest.json")
		if err := runAt(append([]string{"sign-manifest"}, fixture.args(output, "")...), fixture.now); err == nil {
			t.Fatal("sign-manifest accepted a private key that does not match root public key")
		}
	})

	for _, test := range []struct {
		name string
		wire func(*testing.T, *manifestFixture) []byte
	}{
		{name: "tampered image signature", wire: func(t *testing.T, fixture *manifestFixture) []byte {
			envelope, err := trust.DecodeEnvelope(fixture.imageWire)
			if err != nil {
				t.Fatal(err)
			}
			signature := []byte(envelope.Signature)
			if signature[0] == 'A' {
				signature[0] = 'B'
			} else {
				signature[0] = 'A'
			}
			envelope.Signature = string(signature)
			return mustEncodeEnvelope(t, envelope)
		}},
		{name: "noncanonical release delegation", wire: func(_ *testing.T, fixture *manifestFixture) []byte {
			return append(bytes.Clone(fixture.delegationWire), '\n')
		}},
		{name: "expired image receipt", wire: func(t *testing.T, fixture *manifestFixture) []byte {
			payload, err := trust.EncodePayload(fixture.image)
			if err != nil {
				t.Fatal(err)
			}
			envelope, err := trust.Sign(payload, release.ImageScope(fixture.image, "production"),
				fixture.now.Add(-2*time.Hour), fixture.now.Add(-time.Hour), fixture.delegatePrivate)
			if err != nil {
				t.Fatal(err)
			}
			return mustEncodeEnvelope(t, envelope)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newManifestFixture(t, 60*24*time.Hour, 45*24*time.Hour)
			imageWire := test.wire(t, fixture)
			fixture.writeProofs(t, imageWire, fixture.delegationWire)
			fixture.writeCandidate(t, fixture.manifest)
			output := filepath.Join(fixture.directory, "bad-proof.manifest.json")
			if err := runAt(append([]string{"sign-manifest"}, fixture.args(output, "")...), fixture.now); err == nil {
				t.Fatal("sign-manifest accepted invalid release proof")
			}
			if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("invalid proof created output: stat error = %v", err)
			}
		})
	}
}

func TestSignManifestRejectsShortProofWindowAndNeverOverwrites(t *testing.T) {
	t.Run("less than minimum validity", func(t *testing.T) {
		fixture := newManifestFixture(t, 12*time.Hour, 30*24*time.Hour)
		fixture.writeCandidate(t, fixture.manifest)
		output := filepath.Join(fixture.directory, "short-window.manifest.json")
		if err := runAt(append([]string{"sign-manifest"}, fixture.args(output, "48h")...), fixture.now); err == nil {
			t.Fatal("sign-manifest accepted fewer than the minimum 24 hours of remaining proof validity")
		}
		if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("short proof window created output: stat error = %v", err)
		}
	})

	t.Run("existing output is preserved", func(t *testing.T) {
		fixture := newManifestFixture(t, 60*24*time.Hour, 45*24*time.Hour)
		fixture.writeCandidate(t, fixture.manifest)
		output := filepath.Join(fixture.directory, "signed.manifest.json")
		args := append([]string{"sign-manifest"}, fixture.args(output, "720h")...)
		if err := runAt(args, fixture.now); err != nil {
			t.Fatalf("first sign-manifest: %v", err)
		}
		before, err := os.ReadFile(output)
		if err != nil {
			t.Fatal(err)
		}
		if err := runAt(args, fixture.now); err == nil {
			t.Fatal("sign-manifest overwrote an existing output")
		}
		after, err := os.ReadFile(output)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(after, before) {
			t.Fatal("existing output changed after refused overwrite")
		}
	})
}

func TestSignManifestClampsToReleaseAndPeerDelegationExpiries(t *testing.T) {
	t.Run("release delegation", func(t *testing.T) {
		fixture := newManifestFixture(t, 40*24*time.Hour, 90*24*time.Hour)
		fixture.writeCandidate(t, fixture.manifest)
		output := filepath.Join(fixture.directory, "release-clamped.manifest.json")
		if err := runAt(append([]string{"sign-manifest"}, fixture.args(output, "2160h")...), fixture.now); err != nil {
			t.Fatalf("sign-manifest: %v", err)
		}
		envelope := fixture.verifyOutput(t, output, fixture.manifest)
		if !envelope.ExpiresAt.Equal(fixture.now.Add(40 * 24 * time.Hour)) {
			t.Fatalf("manifest expiry = %s, want release delegation expiry %s", envelope.ExpiresAt, fixture.now.Add(40*24*time.Hour))
		}
	})

	t.Run("peer delegation", func(t *testing.T) {
		fixture := newManifestFixture(t, 60*24*time.Hour, 45*24*time.Hour)
		peerPublic, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		peerKeyID, err := trust.KeyID(peerPublic)
		if err != nil {
			t.Fatal(err)
		}
		encodedPeerPublic, err := trust.EncodeDelegatedPublicKey(peerPublic)
		if err != nil {
			t.Fatal(err)
		}
		peerDelegation, err := trust.SignDelegation(trust.Delegation{
			SchemaVersion: trust.SchemaVersion, SubjectKeyID: peerKeyID, SubjectPublicKey: encodedPeerPublic,
			Capabilities: []trust.Capability{{
				Domain: "terrascale.bootstrap.peer-receipt", DeploymentID: fixture.manifest.DeploymentID,
				Cell: string(fixture.manifest.Cell), Environment: fixture.manifest.Environment,
				Role: fixture.manifest.ControllerRole, Slots: []string{"peer-b"}, Actions: []string{"sign"},
			}},
		}, fixture.now.Add(-time.Minute), fixture.now.Add(48*time.Hour), fixture.rootPrivate)
		if err != nil {
			t.Fatal(err)
		}
		manifest := fixture.manifest
		manifest.ControllerSlots = []string{"peer-b", "seed-a"}
		manifest.Profiles = append(manifest.Profiles, bootstrap.LaunchProfile{
			Slot: "peer-b", CompartmentOCID: "ocid1.compartment.oc1..compartment",
			AvailabilityDomain: "SA-SAOPAULO-1-AD-1", FaultDomain: "FAULT-DOMAIN-2",
			SubnetOCID: "ocid1.subnet.oc1.sa-saopaulo-1.peer", Shape: "VM.Standard.E5.Flex",
		})
		manifest.PeerReceiptDelegation = &peerDelegation
		fixture.writeAnchorFor(t, fixture.anchorForSlots(t, manifest.ControllerSlots), 48*time.Hour)
		fixture.writeCandidate(t, manifest)
		output := filepath.Join(fixture.directory, "peer-clamped.manifest.json")
		if err := runAt(append([]string{"sign-manifest"}, fixture.args(output, "720h")...), fixture.now); err != nil {
			t.Fatalf("sign-manifest: %v", err)
		}
		envelope := fixture.verifyOutput(t, output, manifest)
		if !envelope.ExpiresAt.Equal(fixture.now.Add(48 * time.Hour)) {
			t.Fatalf("manifest expiry = %s, want peer delegation expiry %s", envelope.ExpiresAt, fixture.now.Add(48*time.Hour))
		}
	})
}

func TestSignManifestClampsToCurrentAnchorAndRejectsExpiredAnchor(t *testing.T) {
	t.Run("caps manifest expiry at anchor", func(t *testing.T) {
		fixture := newManifestFixture(t, 60*24*time.Hour, 45*24*time.Hour)
		fixture.writeAnchorFor(t, fixture.anchor, 48*time.Hour)
		fixture.writeCandidate(t, fixture.manifest)
		output := filepath.Join(fixture.directory, "anchor-clamped.manifest.json")
		if err := runAt(append([]string{"sign-manifest"}, fixture.args(output, "720h")...), fixture.now); err != nil {
			t.Fatalf("sign-manifest: %v", err)
		}
		envelope := fixture.verifyOutput(t, output, fixture.manifest)
		if !envelope.ExpiresAt.Equal(fixture.now.Add(48 * time.Hour)) {
			t.Fatalf("manifest expiry = %s; want anchor expiry %s", envelope.ExpiresAt, fixture.now.Add(48*time.Hour))
		}
	})

	t.Run("expired anchor cannot authorize signing", func(t *testing.T) {
		fixture := newManifestFixture(t, 60*24*time.Hour, 45*24*time.Hour)
		fixture.writeAnchorAt(t, fixture.anchor, fixture.now.Add(-2*time.Hour), fixture.now.Add(-time.Hour))
		fixture.writeCandidate(t, fixture.manifest)
		output := filepath.Join(fixture.directory, "expired-anchor.manifest.json")
		if err := runAt(append([]string{"sign-manifest"}, fixture.args(output, "720h")...), fixture.now); err == nil {
			t.Fatal("sign-manifest accepted an expired root-signed anchor")
		}
		if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("expired anchor created manifest output: stat error = %v", err)
		}
	})
}

func TestSignManifestRejectsFinalEnvelopeOverSizeLimit(t *testing.T) {
	fixture := newManifestFixture(t, 60*24*time.Hour, 45*24*time.Hour)
	manifest := fixture.manifest
	manifest.ReleaseImageReceiptWire = bytes.Clone(fixture.imageWire)
	manifest.ReleaseDelegationWire = bytes.Clone(fixture.delegationWire)
	manifest.Slot = "s"
	manifest.SeedSlot = manifest.Slot
	manifest.ControllerSlots = []string{manifest.Slot}
	manifest.Profiles[0].Slot = manifest.Slot
	fixture.writeAnchorFor(t, fixture.anchorForSlots(t, manifest.ControllerSlots), 48*time.Hour)
	manifest.StorageDomain.Namespace = strings.Repeat("n", 128)
	manifest.StorageDomain.Prefix = strings.Repeat("p", 128)
	for index := range 128 {
		target := "file-" + strings.Repeat("x", 120) + fmt.Sprintf("%03d", index)
		ocidPrefix := "ocid1.secret.oc1.sa-saopaulo-1."
		suffix := fmt.Sprintf("%03d", index)
		secretOCID := ocidPrefix + strings.Repeat("a", 255-len(ocidPrefix)-len(suffix)) + suffix
		manifest.Secrets = append(manifest.Secrets, bootstrap.SecretReference{
			Purpose: bootstrap.SecretController, Slot: manifest.Slot, SecretOCID: secretOCID,
			VersionNumber: int64(index + 1), SHA256: digest([]byte(fmt.Sprintf("secret-%d", index))),
			MaxBytes: bootstrap.MaxSecretBytes, TargetFile: target,
		})
		payload, err := trust.EncodePayload(manifest)
		if err != nil {
			t.Fatal(err)
		}
		if len(payload) > bootstrap.MaxManifestBytes {
			manifest.Secrets = manifest.Secrets[:len(manifest.Secrets)-1]
			break
		}
	}
	if err := manifest.Validate(); err != nil {
		t.Fatalf("large size-boundary fixture is invalid: %v", err)
	}
	payload, err := trust.EncodePayload(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) < bootstrap.MaxManifestBytes-1024 {
		t.Fatalf("size-boundary payload is too small to exceed the envelope bound: %d bytes", len(payload))
	}
	manifest.ReleaseImageReceiptWire = nil
	manifest.ReleaseDelegationWire = nil
	fixture.writeCandidate(t, manifest)
	output := filepath.Join(fixture.directory, "oversize.manifest.json")
	if err := runAt(append([]string{"sign-manifest"}, fixture.args(output, "720h")...), fixture.now); err == nil {
		encoded, readErr := os.ReadFile(output)
		t.Fatalf("sign-manifest accepted a %d-byte signed envelope exceeding the manifest limit (read error %v)", len(encoded), readErr)
	}
	if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("oversize manifest created output: stat error = %v", err)
	}
}

func testImageReceipt() release.ImageReceipt {
	imageDigest := digest([]byte("image bytes"))
	return release.ImageReceipt{
		Schema: release.ImageSchema, SourceRevision: testRevision, GoVersion: release.DefaultGoVersion,
		Architecture: "amd64", BinaryBytes: 13, BinarySHA256: digest([]byte("binary bytes")),
		BaseImageOCID: "ocid1.image.oc1.sa-saopaulo-1.base", BaseImageRegion: "GRU",
		BaseImageSHA256: imageDigest, KernelRelease: "6.1.0-test+1", KernelSHA256: imageDigest,
		ImageFormat: "qcow2", ImageBytes: 1024, ImageSHA256: imageDigest,
		OCIImageOCID: "ocid1.image.oc1.sa-saopaulo-1.bootstrap", OCIRegion: "GRU",
	}
}

func writeFixture(t *testing.T, path string, contents []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, contents, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func digest(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func encodeEnvelope(t *testing.T, envelope trust.Envelope) []byte {
	t.Helper()
	encoded, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func mustEncodeEnvelope(t *testing.T, envelope trust.Envelope) []byte {
	t.Helper()
	return encodeEnvelope(t, envelope)
}

func mustEncodePayload(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := trust.EncodePayload(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
