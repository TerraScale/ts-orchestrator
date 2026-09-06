package hostagent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/controltransition"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
	"terrascale.tech/orchestrator/src/orchestrator/transitiongrant"
)

func TestCandidatePreparationLocalAdmissionAndExpiredInitialResume(t *testing.T) {
	for _, withDelivery := range []bool{false, true} {
		t.Run(map[bool]string{false: "preliminary", true: "storage-transition"}[withDelivery], func(t *testing.T) { testCandidatePreparationLocalAdmissionAndExpiredInitialResume(t, withDelivery) })
	}
}
func testCandidatePreparationLocalAdmissionAndExpiredInitialResume(t *testing.T, withDelivery bool) {
	if os.Geteuid() != 0 || os.Getenv("TS_INITIAL_R1_ISOLATED_TEST") != "1" {
		t.Skip("requires isolated root /var/lib mount")
	}
	if _, e := os.Lstat(nodeauthority.CandidatePreparationDirectory); !os.IsNotExist(e) {
		t.Fatal("candidate admission directory must be absent")
	}
	t.Cleanup(func() { os.RemoveAll(nodeauthority.CandidatePreparationDirectory) })
	h := newTestHarness(t)
	spec := h.publish(t, "orchestrator", "1.0.0")
	proofDir := t.TempDir()
	cfg := transitiongrant.Config{Version: 1, Mode: transitiongrant.Mode, TransitionID: "first-r3", NodeID: "sfo-one", Region: "sfo", ServerName: "sfo-control", StoreDir: filepath.Join(spec.DataVolume, "control"), GrantFile: filepath.Join(proofDir, "prepare.json"), GrantPublicKeyFile: filepath.Join(proofDir, "owner.pem")}
	if withDelivery {
		cfg.StorageTransition = controltransition.Delivery{TransitionID: cfg.TransitionID, PlanFile: filepath.Join(proofDir, "transition.json"), ReceiptPrivateKeyFile: filepath.Join(proofDir, "receipt.pem")}
		hostStoragePublicationFixture(t, &cfg.StorageTransition, cfg.NodeID, "us-sanjose-1")
	}
	raw, _ := json.Marshal(cfg)
	spec.Arguments = transitiongrant.Arguments
	spec.Configuration = string(raw)
	other := h.publish(t, "terrabase", "1.0.0")
	h.applyDesired(t, other)
	if err := h.lifecycle.BeginDrain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := h.lifecycle.Deploy(context.Background(), other.Name, other.Version); err != nil {
		t.Fatal(err)
	}
	if err := h.lifecycle.ReleaseDrain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := h.systemd.StopUnit(context.Background(), UnitName(other.Name)); err != nil {
		t.Fatal(err)
	}

	manifest := hostmanifest.HostManifest{Components: []hostmanifest.ComponentSpec{other, spec}}
	signer, public, _, initial := bootstrapTestGrant(t, manifest)
	initial.NodeID = cfg.NodeID
	initial.ExpiresAt = time.Now().UTC().Add(1500 * time.Millisecond)
	signedInitial, e := SignBootstrapGrant(signer, initial)
	if e != nil {
		t.Fatal(e)
	}
	authority, e := parseBootstrapAuthority(cfg.NodeID, public, signedInitial)
	if e != nil {
		t.Fatal(e)
	}
	transitionPlan := hostStoragePlan(t, authority)
	signedPlan, e := controltransition.SignPlan(signer, transitionPlan)
	if e != nil {
		t.Fatal(e)
	}
	if withDelivery {
		if e = os.WriteFile(cfg.StorageTransition.PlanFile, signedPlan, 0600); e != nil {
			t.Fatal(e)
		}
	}
	grant := transitiongrant.Grant{Version: 1, TransitionID: cfg.TransitionID, IssuedAt: time.Now().UTC().Add(-time.Minute), ExpiresAt: time.Now().UTC().Add(time.Hour), Source: transitiongrant.SourceIdentity{NodeID: "gru-one", ServerName: "gru-control", InitialGrantSHA256: strings.Repeat("a", 64), StoreScopeSHA256: strings.Repeat("b", 64)}, TargetEpoch: 2, MinimumControlEpoch: 1}
	for _, region := range []string{"gru", "sfo", "fra"} {
		p := transitiongrant.Peer{Region: region, NodeID: region + "-one", ServerName: region + "-control", BootstrapGrantSHA256: strings.Repeat("a", 64), PreparedManifestSHA256: strings.Repeat("b", 64)}
		if region == "sfo" {
			p.BootstrapGrantSHA256 = authority.digest
			p.PreparedManifestSHA256 = authority.manifestDigest
		}
		grant.Peers = append(grant.Peers, p)
	}
	signed, e := transitiongrant.SignGrant(signer, grant)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(cfg.GrantPublicKeyFile, public, 0400); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(cfg.GrantFile, signed, 0400); e != nil {
		t.Fatal(e)
	}
	manifestPath := filepath.Join(h.dataVolume, hostmanifest.TsNodeComponentName, "manifest.json")
	if e = os.MkdirAll(filepath.Dir(manifestPath), 0700); e != nil {
		t.Fatal(e)
	}
	raw, e = hostmanifest.CanonicalHostManifestJSON(manifest)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(manifestPath, raw, 0600); e != nil {
		t.Fatal(e)
	}
	// Stop exactly after durable admission, before install/current/unit effects.
	journal, e := newCommandJournal(filepath.Join(h.dataVolume, hostmanifest.TsNodeComponentName, "command-journal"))
	if e != nil {
		t.Fatal(e)
	}
	if e = journal.initialize(); e != nil {
		t.Fatal(e)
	}
	epochs, e := nodeauthority.NewEpochStore(journal.dir, cfg.NodeID)
	if e != nil {
		t.Fatal(e)
	}
	transport := &NatsTransport{commandContext: context.Background(), authorizer: authority, epochs: epochs, lifecycle: h.lifecycle, journal: journal, manifestPath: manifestPath, requireManifestAdmission: true, closing: make(chan struct{})}
	if e = transport.initializeManifestAuthority(); e != nil {
		t.Fatal(e)
	}
	if withDelivery {
		if _, e = epochs.ResumeStorageTransitionPlan(t.Context(), controltransition.Digest(signedPlan)); e != nil {
			t.Fatal("startup did not pin delivered plan", e)
		}
	}
	epochs.Close()
	receipt, e := nodeauthority.ValidatePublishedPreparation(context.Background(), cfg)
	if e != nil {
		t.Fatal(e)
	}
	if current, _ := CurrentVersion(h.root, spec.Name); current != "" {
		t.Fatal("admission unexpectedly activated release")
	}
	time.Sleep(time.Until(initial.ExpiresAt) + 10*time.Millisecond)
	handled, e := ResumeLocalCandidatePreparation(context.Background(), h.lifecycle, cfg.NodeID, public, signedInitial, manifestPath)
	if e != nil || !handled {
		t.Fatalf("typed recovery: handled=%t err=%v", handled, e)
	}
	if current, e := CurrentVersion(h.root, spec.Name); e != nil || current != spec.Version || !h.systemd.isActive(UnitName(spec.Name)) {
		t.Fatalf("candidate not activated current=%s err=%v", current, e)
	}
	observed, e := nodeauthority.ValidatePublishedPreparation(context.Background(), cfg)
	if e != nil || observed != receipt {
		t.Fatal("resume changed admission", e)
	}
	if handled, e = ResumeLocalCandidatePreparation(context.Background(), h.lifecycle, cfg.NodeID, public, signedInitial, manifestPath); e != nil || !handled {
		t.Fatal("idempotent typed restart", e)
	}
	if current, _ := CurrentVersion(h.root, other.Name); current != other.Version || h.systemd.isActive(UnitName(other.Name)) {
		t.Fatal("expired preparation resumed unrelated component")
	}
	// Normal receiver startup hydrates the full signed manifest for status/CAS.
	// A durable release-drain must not start the ordinary inactive TerraBase
	// after the initial grant expired.
	drain := DrainCommand{CommandId: "initial-release", Drain: false}
	drainBytes, _ := json.Marshal(drain)
	if _, err := journal.storeDone(commandKindDrain, drain.CommandId, drainBytes, []byte(`{"accepted":true}`)); err != nil {
		t.Fatal(err)
	}
	connection := newFakeNatsConnection()
	wrapped, err := NewBootstrapAuthority(testCommandAuthorizer{}, cfg.NodeID, public, signedInitial)
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := NewNatsTransport(NatsTransportConfig{CommandAuthority: wrapped, RequireManifestAdmission: true, ManifestPath: manifestPath, NodeId: NodeId{Value: cfg.NodeID}, Connection: connection, Lifecycle: h.lifecycle, Facts: h.factsSource(t), Ticker: &manualTicker{channel: make(chan time.Time)}, Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	if err = receiver.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if h.systemd.isActive(UnitName(other.Name)) {
		t.Fatal("expired receiver drain replay started ordinary component")
	}
	if !h.systemd.isActive(UnitName(spec.Name)) {
		t.Fatal("expired receiver failed to preserve candidate")
	}
	currentManifestDigest, err := hostmanifest.HostManifestSha256(hostmanifest.HostManifest{Components: h.lifecycle.Desired()})
	if err != nil || currentManifestDigest != authority.manifestDigest {
		t.Fatal("receiver lost full signed manifest CAS identity", err)
	}
	if err = receiver.Close(); err != nil {
		t.Fatal(err)
	}
	// Ordinary regional authority permanently revokes public preparation before
	// accepting its epoch. The service's fixed-publication gate must then refuse.
	epochs, e = nodeauthority.NewEpochStore(journal.dir, cfg.NodeID)
	if e != nil {
		t.Fatal(e)
	}
	defer epochs.Close()
	if withDelivery {
		command := nodeauthority.CommandAuthorization{NodeID: cfg.NodeID, AuthorityID: "sfo-regional", Epoch: 1, CandidateID: "sfo-controller-one", LeaseID: "lease-one"}
		if e = epochs.Admit(command); !errors.Is(e, controltransition.ErrPreparationMissing) {
			t.Fatal("ordinary epoch bypassed transition barrier", e)
		}
		if runtime, err := epochs.AdmittedManifest(authority.manifestDigest); err != nil || runtime {
			t.Fatal("failed barrier advanced epoch", err)
		}
		if _, e = nodeauthority.ValidatePublishedPreparation(t.Context(), cfg); e != nil {
			t.Fatal("failed barrier revoked candidate", e)
		}
		return
	}
	privatePin := filepath.Join(journal.dir, "candidate-preparation.json")
	privateBytes, err := os.ReadFile(privatePin)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(privatePin); err != nil {
		t.Fatal(err)
	}
	command := nodeauthority.CommandAuthorization{NodeID: cfg.NodeID, AuthorityID: "sfo-regional", Epoch: 1, CandidateID: "sfo-controller-one", LeaseID: "lease-one"}
	if err = epochs.Admit(command); err == nil {
		t.Fatal("runtime authority accepted orphan public preparation")
	}
	if _, err = nodeauthority.ValidatePublishedPreparation(context.Background(), cfg); err != nil {
		t.Fatal("failed floor admission altered public proof", err)
	}
	if err = os.WriteFile(privatePin, privateBytes, 0600); err != nil {
		t.Fatal(err)
	}
	if e = epochs.Admit(command); e != nil {
		t.Fatal(e)
	}
	if _, e = nodeauthority.ValidatePublishedPreparation(context.Background(), cfg); e == nil {
		t.Fatal("retired preparation remained usable")
	}
}

func TestCandidatePreparationRejectsOrdinaryInstalledCurrent(t *testing.T) {
	h := newTestHarness(t)
	ordinary := h.publish(t, "orchestrator", "1.0.0")
	h.applyDesired(t, ordinary)
	ctx := context.Background()
	if e := h.lifecycle.BeginDrain(ctx); e != nil {
		t.Fatal(e)
	}
	if e := h.lifecycle.Deploy(ctx, ordinary.Name, ordinary.Version); e != nil {
		t.Fatal(e)
	}
	candidate := ordinary
	cfg := transitiongrant.Config{Version: 1, Mode: transitiongrant.Mode, TransitionID: "first-r3", NodeID: "sfo-one", Region: "sfo", ServerName: "sfo-control", StoreDir: filepath.Join(ordinary.DataVolume, "control"), GrantFile: "/etc/terrascale/prepare.json", GrantPublicKeyFile: "/etc/terrascale/owner.pem"}
	raw, _ := json.Marshal(cfg)
	candidate.Arguments = transitiongrant.Arguments
	candidate.Configuration = string(raw)
	manifest := hostmanifest.HostManifest{Components: []hostmanifest.ComponentSpec{candidate}}
	signer, public, _, initial := bootstrapTestGrant(t, manifest)
	initial.NodeID = cfg.NodeID
	signed, e := SignBootstrapGrant(signer, initial)
	if e != nil {
		t.Fatal(e)
	}
	authority, e := parseBootstrapAuthority(cfg.NodeID, public, signed)
	if e != nil {
		t.Fatal(e)
	}
	transport := &NatsTransport{commandContext: ctx, authorizer: authority, lifecycle: h.lifecycle}
	// Version matches, but the authenticated current launch is an ordinary
	// orchestrator. Reject before reading grant files or allowing any unit effect.
	handled, e := transport.initializeCandidatePreparation(manifest, authority.manifestDigest)
	if !handled || e == nil {
		t.Fatalf("ordinary current accepted handled=%t err=%v", handled, e)
	}
	current, e := CurrentVersion(h.root, ordinary.Name)
	if e != nil || current != ordinary.Version {
		t.Fatal("rejection changed current", e)
	}
}
