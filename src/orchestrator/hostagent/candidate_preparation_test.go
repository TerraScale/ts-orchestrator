package hostagent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
	"terrascale.tech/orchestrator/src/orchestrator/transitiongrant"
)

func TestCandidatePreparationLocalAdmissionAndExpiredInitialResume(t *testing.T) {
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
	raw, _ := json.Marshal(cfg)
	spec.Arguments = transitiongrant.Arguments
	spec.Configuration = string(raw)
	manifest := hostmanifest.HostManifest{Components: []hostmanifest.ComponentSpec{spec}}
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
	// Ordinary regional authority permanently revokes public preparation before
	// accepting its epoch. The service's fixed-publication gate must then refuse.
	epochs, e = nodeauthority.NewEpochStore(journal.dir, cfg.NodeID)
	if e != nil {
		t.Fatal(e)
	}
	defer epochs.Close()
	if e = epochs.Admit(nodeauthority.CommandAuthorization{NodeID: cfg.NodeID, AuthorityID: "sfo-regional", Epoch: 1, CandidateID: "sfo-controller-one", LeaseID: "lease-one"}); e != nil {
		t.Fatal(e)
	}
	if _, e = nodeauthority.ValidatePublishedPreparation(context.Background(), cfg); e == nil {
		t.Fatal("retired preparation remained usable")
	}
}
