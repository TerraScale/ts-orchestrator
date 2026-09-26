package bootstrap

import (
	"errors"
	"testing"
	"time"
)

func TestSeedLedgerSignerSecretRequiresExactSeedSlotAndReceipt(t *testing.T) {
	authority := newTestBootstrapAuthority(t)
	manifest := cloneManifest(authority.manifest)
	reference := SecretReference{
		Purpose: SecretSeedLedgerSigner, Slot: manifest.SeedSlot,
		SecretOCID: "ocid1.secret.oc1.iad.ledger-signer", VersionNumber: 7,
		SHA256: digestBytes([]byte("separate ledger signing key")), MaxBytes: 128,
		TargetFile: "ledger-signer.key",
	}
	manifest.Secrets = append(manifest.Secrets, reference)
	if err := manifest.Validate(); err != nil {
		t.Fatalf("root-signed seed ledger signer reference: %v", err)
	}
	wrongSlot := cloneManifest(manifest)
	wrongSlot.Secrets[len(wrongSlot.Secrets)-1].Slot = "peer-b"
	if err := wrongSlot.Validate(); !errors.Is(err, ErrManifestInvalid) {
		t.Fatalf("ledger signer reference in peer slot = %v", err)
	}
	seedManifest := authority.verifyManifest(t, manifest.SeedSlot, manifest)
	seedFacts := authority.facts(seedManifest, manifest.SeedSlot)
	seedEnvelope, err := SignSeedReceipt(seedManifest, seedFacts, authority.now.Add(-time.Minute),
		authority.now.Add(5*time.Minute), authority.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	seedReceipt, err := VerifySeedReceipt(seedEnvelope, seedManifest, authority.roots, seedFacts,
		authority.now, authority.policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := authorizeSecretMaterialization(seedManifest, seedReceipt, reference, authority.now); err != nil {
		t.Fatalf("exact seed receipt rejected ledger signer reference: %v", err)
	}
	peerManifest := authority.verifyManifest(t, "peer-b", manifest)
	peerFacts := authority.facts(peerManifest, "peer-b")
	peerEnvelope, err := SignPeerReceipt(peerManifest, peerFacts, authority.now.Add(-time.Minute),
		authority.now.Add(5*time.Minute), authority.peerPrivate)
	if err != nil {
		t.Fatal(err)
	}
	peerReceipt, err := VerifyPeerReceipt(peerEnvelope, peerManifest, peerFacts, authority.now, authority.policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := authorizeSecretMaterialization(peerManifest, peerReceipt, reference, authority.now); !errors.Is(err, ErrReceiptInvalid) {
		t.Fatalf("peer receipt authorized seed ledger signer: %v", err)
	}
}
