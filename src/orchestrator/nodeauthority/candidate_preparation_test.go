package nodeauthority

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/security"
	"terrascale.tech/orchestrator/src/orchestrator/transitiongrant"
)

func TestCandidatePreparationPinsExactScopeAndResumesPublication(t *testing.T) {
	root := t.TempDir()
	private := filepath.Join(root, "private")
	if e := os.Mkdir(private, 0700); e != nil {
		t.Fatal(e)
	}
	s, e := NewEpochStore(private, "sfo-one")
	if e != nil {
		t.Fatal(e)
	}
	defer func() { s.Close() }()
	boot, manifest := strings.Repeat("a", 64), strings.Repeat("b", 64)
	if e = s.AdmitBootstrap(boot, manifest); e != nil {
		t.Fatal(e)
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	signer, e := security.NewCommandSignatureSignerFromKey(key)
	if e != nil {
		t.Fatal(e)
	}
	defer signer.Dispose()
	der, e := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	public := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	cfg := transitiongrant.Config{Version: 1, Mode: transitiongrant.Mode, TransitionID: "first-r3", NodeID: "sfo-one", Region: "sfo", ServerName: "sfo-control", StoreDir: "/var/lib/terrascale/orchestrator/control", GrantFile: "/etc/terrascale/prepare.json", GrantPublicKeyFile: "/etc/terrascale/owner.pem"}
	g := transitiongrant.Grant{Version: 1, TransitionID: cfg.TransitionID, IssuedAt: time.Now().UTC().Add(-time.Minute), ExpiresAt: time.Now().UTC().Add(time.Hour), Source: transitiongrant.SourceIdentity{NodeID: "gru-one", ServerName: "gru-control", InitialGrantSHA256: boot, StoreScopeSHA256: manifest}, TargetEpoch: 2, MinimumControlEpoch: 1}
	for _, region := range []string{"gru", "sfo", "fra"} {
		g.Peers = append(g.Peers, transitiongrant.Peer{Region: region, NodeID: region + "-one", ServerName: region + "-control", BootstrapGrantSHA256: boot, PreparedManifestSHA256: manifest})
	}
	signed, e := transitiongrant.SignGrant(signer, g)
	if e != nil {
		t.Fatal(e)
	}
	publication := filepath.Join(root, "public")
	// Durable private pin survives failed public publication.
	if e = os.WriteFile(publication, []byte("not a directory"), 0600); e != nil {
		t.Fatal(e)
	}
	uid := uint32(os.Geteuid())
	ctx := context.Background()
	if _, e = s.admitCandidatePreparation(ctx, public, signed, cfg, boot, manifest, publication, uid); e == nil {
		t.Fatal("unsafe publication accepted")
	}
	prior, e := readCandidateRecord(filepath.Join(private, candidateRecordName), 0600, uid)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Remove(publication); e != nil {
		t.Fatal(e)
	}
	s.Close()
	s, e = NewEpochStore(private, cfg.NodeID)
	if e != nil {
		t.Fatal(e)
	}
	receipt, e := s.admitCandidatePreparation(ctx, public, signed, cfg, boot, manifest, publication, uid)
	if e != nil {
		t.Fatal(e)
	}
	if receipt != prior.Receipt {
		t.Fatal("restart changed admitted identity")
	}
	observed, e := validatePublishedPreparation(ctx, cfg, publication, uid)
	if e != nil || observed != receipt {
		t.Fatalf("publication %v %+v", e, observed)
	}
	changed := cfg
	changed.StoreDir += "-changed"
	if _, e = validatePublishedPreparation(ctx, changed, publication, uid); e == nil {
		t.Fatal("changed config admitted")
	}
	g.TargetEpoch++
	conflict, e := transitiongrant.SignGrant(signer, g)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.admitCandidatePreparation(ctx, public, conflict, cfg, boot, manifest, publication, uid); e == nil {
		t.Fatal("different signed grant replaced pin")
	}
	if e = validateCandidateRecord(prior, prior.Receipt.ExpiresAt); e == nil {
		t.Fatal("expired preparation accepted")
	}
	// Advance the real private epoch directly in this isolated fixture. The
	// public-path retirement effect is exercised by the privileged host test.
	floor := epochFloor{Version: 1, NodeID: cfg.NodeID, AuthorityID: "sfo-regional", Epoch: 1, CandidateID: "sfo-controller-one", LeaseID: "lease-one"}
	raw, _ := json.Marshal(floor)
	if e = os.WriteFile(s.path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = s.admitCandidatePreparation(ctx, public, signed, cfg, boot, manifest, publication, uid); e == nil {
		t.Fatal("runtime epoch reopened candidate preparation")
	}
}
