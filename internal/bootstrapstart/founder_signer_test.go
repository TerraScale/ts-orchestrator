package bootstrapstart

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

type founderSignerFixture struct {
	*founderSelectionFixture
	peerKey   ed25519.PrivateKey
	ledgerKey ed25519.PrivateKey
	store     FounderSignerStore
	current   CurrentFounderAuthority
}

func newFounderSignerFixture(t *testing.T) *founderSignerFixture {
	t.Helper()
	fixture := newFounderSelectionFixture(t)
	peerPublic, peerKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ledgerPublic, ledgerKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	anchorEnvelope, err := trust.DecodeEnvelope(fixture.anchorWire)
	if err != nil {
		t.Fatal(err)
	}
	var anchor bootstrap.BootstrapAnchor
	if err := protocol.DecodeStrict(anchorEnvelope.Payload, &anchor, bootstrap.MaxBootstrapAnchorBytes); err != nil {
		t.Fatal(err)
	}
	anchor.LedgerDelegationWire = signTestDelegation(t, fixture.root, ledgerPublic,
		[]string{"bootstrap-slot-head", "bootstrap-intent", "bootstrap-result", "bootstrap-candidate", "bootstrap-progress"}, anchor.ControllerSlots,
		fixture.now.Add(-time.Hour), fixture.now.Add(24*time.Hour))
	anchorEnvelope, err = bootstrap.SignBootstrapAnchor(anchor, fixture.now.Add(-time.Minute), fixture.now.Add(23*time.Hour), fixture.root)
	if err != nil {
		t.Fatal(err)
	}
	fixture.anchorWire, err = trust.EncodeEnvelope(anchorEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	fixture.baked.AnchorWire = slices.Clone(fixture.anchorWire)
	fixture.accepted.AnchorSHA256 = digestWire(fixture.anchorWire)
	peerDelegationWire := signTestDelegation(t, fixture.root, peerPublic,
		[]string{"terrascale.bootstrap.peer-receipt"}, []string{"controller-a", "controller-b"},
		fixture.now.Add(-time.Hour), fixture.now.Add(23*time.Hour))
	peerDelegation, err := trust.DecodeEnvelope(peerDelegationWire)
	if err != nil {
		t.Fatal(err)
	}
	for slot, wire := range fixture.manifests {
		envelope, err := trust.DecodeEnvelope(wire)
		if err != nil {
			t.Fatal(err)
		}
		var manifest bootstrap.Manifest
		if err := protocol.DecodeStrict(envelope.Payload, &manifest, bootstrap.MaxManifestBytes); err != nil {
			t.Fatal(err)
		}
		manifest.PeerReceiptDelegation = &peerDelegation
		manifest.ReleaseDelegationWire = peerDelegationWire
		if slot == "seed-a" {
			for i, signer := range []struct {
				purpose bootstrap.SecretPurpose
				name    string
				key     ed25519.PrivateKey
			}{
				{bootstrap.SecretSeedFounder, "founder-peer.key", peerKey},
				{bootstrap.SecretSeedLedgerSigner, "founder-ledger.key", ledgerKey},
			} {
				manifest.Secrets = append(manifest.Secrets, bootstrap.SecretReference{
					Purpose: signer.purpose, Slot: slot, TargetFile: signer.name,
					SecretOCID:    "ocid1.vaultsecret.oc1.sa-saopaulo-1.signer-" + string(rune('a'+i)),
					VersionNumber: 1, SHA256: digestWire(signer.key), MaxBytes: 128,
				})
				fixture.accepted.MaterialSHA256[signer.name] = digestWire(signer.key)
			}
		}
		envelope, err = bootstrap.SignManifest(manifest, fixture.now.Add(-time.Minute), fixture.now.Add(22*time.Hour), fixture.root)
		if err != nil {
			t.Fatal(err)
		}
		fixture.manifests[slot], err = trust.EncodeEnvelope(envelope)
		if err != nil {
			t.Fatal(err)
		}
	}
	fixture.accepted.ManifestSHA256 = digestWire(fixture.manifests["seed-a"])
	fixture.plan.AnchorSHA256 = digestWire(fixture.anchorWire)
	fixture.plan.SeedManifestSHA256 = fixture.accepted.ManifestSHA256
	for i := range fixture.plan.Peers {
		fixture.plan.Peers[i].ManifestSHA256 = digestWire(fixture.manifests[fixture.plan.Peers[i].Slot])
	}
	payload, err := trust.EncodePayload(fixture.plan)
	if err != nil {
		t.Fatal(err)
	}
	planEnvelope, err := trust.Sign(payload, trust.Scope{Domain: bootstrap.FounderPlanDomain,
		DeploymentID: "0000000000F9PR1WNVDTEXS31Z", Cell: "GRU", Environment: "production", Role: "controller", Slot: "seed-a"},
		fixture.now.Add(-time.Minute), fixture.now.Add(22*time.Hour), fixture.root)
	if err != nil {
		t.Fatal(err)
	}
	fixture.planWire, err = trust.EncodeEnvelope(planEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	fixture.selection.PlanSHA256 = digestWire(fixture.planWire)
	fixture.selection.AnchorSHA256 = digestWire(fixture.anchorWire)
	for i := range fixture.selection.Manifests {
		fixture.selection.Manifests[i].SHA256 = digestWire(fixture.manifests[fixture.selection.Manifests[i].Slot])
	}
	selectedWire := fixture.publish(t, fixture.selection)
	if err := fixture.floor.Initialize(fixture.selection.Generation, digestWire(selectedWire)); err != nil {
		t.Fatal(err)
	}
	current, err := fixture.reader(t).ReadCurrent(t.Context(), fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(t.TempDir(), "signers")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, key := range map[string]ed25519.PrivateKey{"founder-peer.key": peerKey, "founder-ledger.key": ledgerKey} {
		if err := os.WriteFile(filepath.Join(directory, name), key, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return &founderSignerFixture{founderSelectionFixture: fixture, peerKey: peerKey, ledgerKey: ledgerKey,
		store: FounderSignerStore{directory: directory, uid: uint32(os.Getuid()), gid: uint32(os.Getgid()),
			allowUnsafeAncestors: true}, current: current}
}

func TestFounderSignerStoreLoadsSeparateDelegatedKeysAndClearsThem(t *testing.T) {
	fixture := newFounderSignerFixture(t)
	keys, err := fixture.store.Load(fixture.current, fixture.accepted, fixture.baked.Roots, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(keys.peer, fixture.peerKey) || !bytes.Equal(keys.ledger, fixture.ledgerKey) ||
		bytes.Equal(keys.peer, keys.ledger) {
		t.Fatal("loaded signing keys differ from separately delegated installed material")
	}
	peerAlias, ledgerAlias := keys.peer, keys.ledger
	keys.Close()
	if !bytes.Equal(peerAlias, make([]byte, ed25519.PrivateKeySize)) ||
		!bytes.Equal(ledgerAlias, make([]byte, ed25519.PrivateKeySize)) {
		t.Fatal("closing signing keys did not clear private material")
	}
	keys, err = fixture.store.Load(fixture.current, fixture.accepted, fixture.baked.Roots, fixture.now)
	if err != nil {
		t.Fatalf("reload after restart: %v", err)
	}
	keys.Close()
}

func TestFounderSignerStoreHoldsMissingTamperedOrWrongRoleMaterial(t *testing.T) {
	fixture := newFounderSignerFixture(t)
	assertHold := func(label string, store FounderSignerStore, accepted AcceptedInstall) {
		t.Helper()
		keys, err := store.Load(fixture.current, accepted, fixture.baked.Roots, fixture.now)
		keys.Close()
		if !errors.Is(err, ErrFounderSigner) {
			t.Fatalf("%s: got %v, want founder signer hold", label, err)
		}
	}
	missing := fixture.store
	missing.directory = filepath.Join(t.TempDir(), "missing")
	assertHold("missing directory", missing, fixture.accepted)
	wrongDigest := fixture.accepted
	wrongDigest.MaterialSHA256 = map[string]string{"founder-peer.key": digestWire(fixture.peerKey),
		"founder-ledger.key": digestWire(fixture.peerKey)}
	assertHold("wrong marker digest", fixture.store, wrongDigest)
	peerPath := filepath.Join(fixture.store.directory, "founder-peer.key")
	ledgerPath := filepath.Join(fixture.store.directory, "founder-ledger.key")
	if err := os.Rename(peerPath, peerPath+".saved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(ledgerPath, peerPath); err != nil {
		t.Fatal(err)
	}
	assertHold("wrong key in receipt slot", fixture.store, fixture.accepted)
	if err := os.Rename(peerPath, ledgerPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(peerPath+".saved", peerPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(ledgerPath, 0o640); err != nil {
		t.Fatal(err)
	}
	assertHold("group readable ledger signer", fixture.store, fixture.accepted)
}

func TestPeerStartupSkipsFounderFloorAndLaunchClients(t *testing.T) {
	fixture := newFounderSelectionFixture(t)
	peer := fixture.accepted
	peer.Slot = "controller-a"
	if err := RunAdmittedFounder(t.Context(), fixture.baked, peer, 1000, 1000); err != nil {
		t.Fatalf("peer touched seed-only founder dependencies: %v", err)
	}
	peer.SeedSlot = ""
	if err := RunAdmittedFounder(t.Context(), fixture.baked, peer, 1000, 1000); !errors.Is(err, ErrFounderRuntime) {
		t.Fatalf("missing accepted seed role: %v", err)
	}
	peer = fixture.accepted
	peer.Slot = "controller-a"
	peer.DeploymentID = "00000000000ZGTG9F4ZD9XG0T1"
	if err := RunAdmittedFounder(t.Context(), fixture.baked, peer, 1000, 1000); !errors.Is(err, ErrFounderRuntime) {
		t.Fatalf("contradictory accepted role scope: %v", err)
	}
}

func TestCanceledSeedCannotOpenFounderProviderOrLaunch(t *testing.T) {
	fixture := newFounderSelectionFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := RunAdmittedFounder(ctx, fixture.baked, fixture.accepted, 1000, 1000); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled seed continued toward OCI: %v", err)
	}
}

func TestRestartRejectsTamperedAcceptedSeedRole(t *testing.T) {
	fixture := newAdmissionFlowFixture(t)
	marker, err := fixture.gate.AdmitInitial(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	marker.SeedSlot = "controller-z"
	wire, err := protocol.EncodeJSON(marker)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixture.gate.Markers.directory, markerName), wire, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.gate.AdmitRestart(t.Context()); !errors.Is(err, ErrAdmission) {
		t.Fatalf("contradictory marker seed role survived signed-manifest comparison: %v", err)
	}
}
