package bootstrap

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

func TestHistoricalManifestVerifiesExpiredProofWithoutCurrentAuthority(t *testing.T) {
	authority := newTestBootstrapAuthority(t)
	manifest := authority.manifest
	manifest.Slot = "seed-a"
	issuedAt := authority.now.Add(-90 * time.Minute)
	expiresAt := authority.now.Add(-30 * time.Minute)
	envelope, err := SignManifest(manifest, issuedAt, expiresAt, authority.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	expected := historyExpectation(manifest)
	if _, err := VerifyManifest(envelope, authority.roots, expected, authority.now, authority.policy); !errors.Is(err, trust.ErrExpired) {
		t.Fatalf("expired current manifest error = %v", err)
	}
	historical, err := VerifyHistoricalManifest(envelope, authority.roots, expected, authority.policy)
	if err != nil {
		t.Fatalf("VerifyHistoricalManifest() error = %v", err)
	}
	if historical.Digest() == "" || historical.Manifest().Slot != manifest.Slot {
		t.Fatalf("historical manifest proof = %#v", historical.Manifest())
	}
	wrongRootPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongRoots, err := trust.ParseKeyring(wrongRootPublic)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyHistoricalManifest(envelope, wrongRoots, expected, authority.policy); !errors.Is(err, trust.ErrUntrustedKey) {
		t.Fatalf("wrong historical root error = %v", err)
	}
	wrongScope := expected
	wrongScope.Slot = "peer-b"
	if _, err := VerifyHistoricalManifest(envelope, authority.roots, wrongScope, authority.policy); !errors.Is(err, trust.ErrScopeMismatch) {
		t.Fatalf("wrong historical manifest scope error = %v", err)
	}
}

func TestHistoricalSeedReceiptVerifiesExpiredExactFacts(t *testing.T) {
	authority := newTestBootstrapAuthority(t)
	manifestEnvelope, err := SignManifest(authority.manifest, authority.now.Add(-30*time.Minute), authority.now.Add(30*time.Minute), authority.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	expected := historyExpectation(authority.manifest)
	currentManifest, err := VerifyManifest(manifestEnvelope, authority.roots, expected, authority.now, authority.policy)
	if err != nil {
		t.Fatal(err)
	}
	historicalManifest, err := VerifyHistoricalManifest(manifestEnvelope, authority.roots, expected, authority.policy)
	if err != nil {
		t.Fatal(err)
	}
	facts := authority.facts(currentManifest, "seed-a")
	receiptEnvelope, err := SignSeedReceipt(currentManifest, facts, authority.now.Add(-20*time.Minute), authority.now.Add(-10*time.Minute), authority.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySeedReceipt(receiptEnvelope, currentManifest, authority.roots, facts, authority.now, authority.policy); !errors.Is(err, trust.ErrExpired) {
		t.Fatalf("expired current receipt error = %v", err)
	}
	historicalReceipt, err := VerifyHistoricalSeedReceipt(receiptEnvelope, historicalManifest, authority.roots, facts, authority.policy)
	if err != nil {
		t.Fatalf("VerifyHistoricalSeedReceipt() error = %v", err)
	}
	if historicalReceipt.InstanceOCID() != facts.InstanceOCID || historicalReceipt.Slot() != facts.Slot || historicalReceipt.ManifestDigest() != historicalManifest.Digest() {
		t.Fatalf("historical receipt proof = %#v", historicalReceipt.Receipt())
	}

	wrongFacts := facts
	wrongFacts.Profile.SubnetOCID = "ocid1.subnet.oc1.iad.foreign"
	if _, err := VerifyHistoricalSeedReceipt(receiptEnvelope, historicalManifest, authority.roots, wrongFacts, authority.policy); !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("wrong historical instance profile error = %v", err)
	}

	wrongScopeEnvelope := cloneEnvelope(receiptEnvelope)
	wrongScopeEnvelope.Scope.Slot = "peer-b"
	if _, err := VerifyHistoricalSeedReceipt(wrongScopeEnvelope, historicalManifest, authority.roots, facts, authority.policy); !errors.Is(err, trust.ErrScopeMismatch) {
		t.Fatalf("wrong historical receipt scope error = %v", err)
	}

	wrongRootPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongRoots, err := trust.ParseKeyring(wrongRootPublic)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyHistoricalSeedReceipt(receiptEnvelope, historicalManifest, wrongRoots, facts, authority.policy); !errors.Is(err, trust.ErrUntrustedKey) {
		t.Fatalf("wrong historical receipt root error = %v", err)
	}

	want, err := receiptForManifest(historicalManifest.manifest, historicalManifest.digest, facts)
	if err != nil {
		t.Fatal(err)
	}
	want.ProfileSHA256 = digestBytes([]byte("wrong-profile"))
	wrongProfileReceipt, err := signReceipt(want, seedReceiptDomain, authority.now.Add(-20*time.Minute), authority.now.Add(-10*time.Minute), authority.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyHistoricalSeedReceipt(wrongProfileReceipt, historicalManifest, authority.roots, facts, authority.policy); !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("wrong signed profile binding error = %v", err)
	}
}

func TestHistoricalPeerReceiptRequiresDelegationTimeBounds(t *testing.T) {
	authority := newTestBootstrapAuthority(t)
	manifest := authority.manifest
	manifest.Slot = "peer-b"
	delegation := authority.delegationForInterval(t, authority.now.Add(-90*time.Minute), authority.now.Add(-60*time.Minute))
	manifest.PeerReceiptDelegation = &delegation
	manifestEnvelope, err := SignManifest(manifest, authority.now.Add(-100*time.Minute), authority.now.Add(-40*time.Minute), authority.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	expected := historyExpectation(manifest)
	if _, err := VerifyManifest(manifestEnvelope, authority.roots, expected, authority.now, authority.policy); !errors.Is(err, trust.ErrExpired) {
		t.Fatalf("expired current peer manifest error = %v", err)
	}
	historicalManifest, err := VerifyHistoricalManifest(manifestEnvelope, authority.roots, expected, authority.policy)
	if err != nil {
		t.Fatalf("VerifyHistoricalManifest() peer error = %v", err)
	}
	facts := historicalFacts(historicalManifest, "peer-b")
	want, err := receiptForManifest(historicalManifest.manifest, historicalManifest.digest, facts)
	if err != nil {
		t.Fatal(err)
	}
	validReceipt, err := signReceipt(want, peerReceiptDomain, authority.now.Add(-85*time.Minute), authority.now.Add(-70*time.Minute), authority.peerPrivate)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyHistoricalPeerReceipt(validReceipt, historicalManifest, facts, authority.policy)
	if err != nil {
		t.Fatalf("VerifyHistoricalPeerReceipt() error = %v", err)
	}
	if verified.InstanceOCID() != facts.InstanceOCID {
		t.Fatalf("historical peer receipt instance = %q", verified.InstanceOCID())
	}

	outsideDelegation, err := signReceipt(want, peerReceiptDomain, authority.now.Add(-55*time.Minute), authority.now.Add(-45*time.Minute), authority.peerPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyHistoricalPeerReceipt(outsideDelegation, historicalManifest, facts, authority.policy); !errors.Is(err, trust.ErrDelegationTime) {
		t.Fatalf("peer receipt outside delegation interval error = %v", err)
	}

	wrongFacts := facts
	wrongFacts.IntentSHA256 = digestBytes([]byte("different-intent"))
	if _, err := VerifyHistoricalPeerReceipt(validReceipt, historicalManifest, wrongFacts, authority.policy); !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("wrong peer intent facts error = %v", err)
	}
}

func historyExpectation(manifest Manifest) ManifestExpectation {
	return ManifestExpectation{
		DeploymentID: manifest.DeploymentID, Environment: manifest.Environment, ClusterID: manifest.ClusterID,
		Cell: manifest.Cell, Slot: manifest.Slot, ImageOCID: manifest.ImageOCID, StorageDomain: manifest.StorageDomain,
		ControllerSlots: append([]string(nil), manifest.ControllerSlots...),
	}
}

func historicalFacts(manifest HistoricalManifest, slot string) InstanceFacts {
	document := manifest.Manifest()
	profile, _ := manifest.Profile(slot)
	return InstanceFacts{
		DeploymentID: document.DeploymentID, Environment: document.Environment, ClusterID: document.ClusterID,
		Cell: document.Cell, OCIRegion: document.OCIRegion, Role: document.ControllerRole, Slot: slot,
		InstanceOCID: "ocid1.instance.oc1.sa-saopaulo-1." + slot, CompartmentOCID: profile.CompartmentOCID,
		ImageOCID: document.ImageOCID, CreateKey: "launch-" + slot,
		IntentSHA256: digestBytes([]byte("intent-" + slot)), Profile: profile,
	}
}

func (authority testBootstrapAuthority) delegationForInterval(t *testing.T, issuedAt, expiresAt time.Time) trust.Envelope {
	t.Helper()
	peerPublic, err := trust.EncodeDelegatedPublicKey(authority.peerPublic)
	if err != nil {
		t.Fatal(err)
	}
	delegation, err := trust.SignDelegation(trust.Delegation{
		SchemaVersion: trust.SchemaVersion, SubjectKeyID: keyID(t, authority.peerPublic), SubjectPublicKey: peerPublic,
		Capabilities: []trust.Capability{{
			Domain: peerReceiptDomain, DeploymentID: "0000000000F9PR1WNVDTEXS31Z", Cell: string(oci.RegionGRU),
			Environment: "production", Role: "controller", Slots: []string{"peer-b"}, Actions: []string{"sign"},
		}},
	}, issuedAt, expiresAt, authority.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	return delegation
}
