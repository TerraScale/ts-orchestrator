package nodeauthority

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/controltransition"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

func storagePlanKey(t *testing.T) (*security.CommandSignatureSigner, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := security.NewCommandSignatureSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { signer.Close() })
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return signer, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func storagePlanFixture(t *testing.T) controltransition.Plan {
	t.Helper()
	h := strings.Repeat("a", 64)
	_, public := storagePlanKey(t)
	p := controltransition.Plan{Version: 1, Mode: controltransition.Mode, EstateID: "launch", TransitionID: "first-r3", IssuedAt: time.Now().UTC().Add(-time.Minute), ExpiresAt: time.Now().UTC().Add(time.Hour), ClusterName: "control-r3", TrustBundleSHA256: h, SourceTopologyEpoch: 1, TargetTopologyEpoch: 2, GlobalElectionFloor: 1, RegionalElectionFloor: 1, Source: controltransition.Source{NodeID: "gru-one", ServerName: "source-r1", BootstrapGrantSHA256: h, InitialManifestSHA256: strings.Repeat("b", 64), CaptureManifestSHA256: initialR1Replacement(), LaunchSHA256: strings.Repeat("c", 64), StoreScopeSHA256: strings.Repeat("d", 64), ProfileSHA256: h, StoreDir: "/data/source", CaptureDir: "/data/capture", ArchiveDir: "/data/archives", ReceiptPublicKeyPEM: string(public)}, Limits: controltransition.Limits{MaxStoreBytes: 1 << 30, MaxStoreFiles: 10000, MaxSnapshotBytes: 1 << 20, MaxTransferBytes: 1 << 30, MaxRestoreBytes: 1 << 30}}
	for i, region := range []string{"gru", "sfo", "fra"} {
		_, key := storagePlanKey(t)
		p.Destinations = append(p.Destinations, controltransition.Destination{Region: region, NodeID: region + "-one", ServerName: region + "-r3", BootstrapGrantSHA256: h, PreparedManifestSHA256: strings.Repeat("b", 64), ActivationManifestSHA256: strings.Repeat("c", 64), RouteURL: "nats-route://" + region + ".internal:6222", CertificateSHA256: strings.Repeat(string(rune('d'+i)), 64), ReceiptPublicKeyPEM: string(key), PreliminaryStoreDir: "/data/preliminary", StoreDir: "/data/r3", StagingDir: "/data/staging", Objects: controltransition.ObjectLocation{OCIRegion: []string{"sa-saopaulo-1", "us-sanjose-1", "eu-frankfurt-1"}[i], Namespace: "tenancy", Bucket: region + "-control", BucketResourceID: "ocid1.bucket." + region, CompartmentID: "ocid1.compartment.launch", OwnershipObservationSHA256: h, Prefix: "control-transitions/first-r3"}})
	}
	for _, role := range []string{"global", "gru-regional"} {
		p.Accounts = append(p.Accounts, controltransition.Account{Role: role, SourceName: role, DestinationName: role, Streams: []controltransition.Stream{{Name: "KV_ORCH_LEADERS", SourceConfigSHA256: h, FinalConfigSHA256: h}}})
	}
	return p
}

func TestStorageTransitionSourcePinRequiresAuthorityAndSurvivesRestart(t *testing.T) {
	f := newInitialR1Fixture(t)
	if err := f.admit(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	p := storagePlanFixture(t)
	signer, public := storagePlanKey(t)
	signed, err := controltransition.SignPlan(signer, p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.admitStorageTransitionPlan(t.Context(), public, signed, nil, f.uid, nil); err == nil {
		t.Fatal("source pin without runtime command")
	}
	c := f.command(t)
	fault := errors.New("directory sync interrupted")
	if _, err = f.store.admitStorageTransitionPlan(t.Context(), public, signed, &c, f.uid, func() error { return fault }); !errors.Is(err, fault) {
		t.Fatal(err)
	}
	path := filepath.Join(filepath.Dir(f.store.path), storageTransitionRecordName)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.guard.Check(t.Context()); err != nil {
		t.Fatal("pin retired source", err)
	}
	v, err := f.store.admitStorageTransitionPlan(t.Context(), public, signed, &c, f.uid, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.store.Close()
	f.store, err = NewEpochStore(filepath.Dir(path), f.identity.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.store.Close() })
	// A stale command cannot re-admit the plan. Reading the already pinned plan
	// does not need or renew that expired lease.
	c.ExpiresAt = time.Now().Add(-time.Second)
	if _, err = f.store.admitStorageTransitionPlan(t.Context(), public, signed, &c, f.uid, nil); err == nil {
		t.Fatal("expired source command admitted")
	}
	if _, err = f.store.resumeStorageTransitionPlan(t.Context(), v.Digest(), f.uid); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("recovery rewrote immutable pin", err)
	}
	if _, err = f.store.resumeStorageTransitionPlan(t.Context(), strings.Repeat("f", 64), f.uid); err == nil {
		t.Fatal("foreign transition resumed")
	}
	// Actual retirement still uses the original separate command path.
	c = f.command(t)
	if err = f.retire(t.Context(), c, nil); err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.admitStorageTransitionPlan(t.Context(), public, signed, &c, f.uid, nil); !errors.Is(err, ErrInitialR1Retired) {
		t.Fatal("post-retirement fresh admission", err)
	}
	if _, err = f.store.resumeStorageTransitionPlan(t.Context(), v.Digest(), f.uid); err != nil {
		t.Fatal("pinned agreement lost across retirement", err)
	}
	if err = f.guard.Check(t.Context()); !errors.Is(err, ErrInitialR1Retired) {
		t.Fatal("plan recovery reactivated source", err)
	}
}

func TestStorageTransitionDestinationPinRejectsReplacementAndUnsafeRecovery(t *testing.T) {
	p := storagePlanFixture(t)
	signer, public := storagePlanKey(t)
	signed, err := controltransition.SignPlan(signer, p)
	if err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Geteuid())
	private := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(private, 0700); err != nil {
		t.Fatal(err)
	}
	s, err := NewEpochStore(private, "sfo-one")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if _, err = s.admitStorageTransitionPlan(t.Context(), public, signed, nil, uid, nil); err == nil {
		t.Fatal("missing bootstrap admitted")
	}
	d := p.Destinations[1]
	if err = s.AdmitBootstrap(d.BootstrapGrantSHA256, d.PreparedManifestSHA256); err != nil {
		t.Fatal(err)
	}
	v, err := s.admitStorageTransitionPlan(t.Context(), public, signed, nil, uid, nil)
	if err != nil {
		t.Fatal(err)
	}
	p.TransitionID = "other-transition"
	replacement, err := controltransition.SignPlan(signer, p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.admitStorageTransitionPlan(t.Context(), public, replacement, nil, uid, nil); err == nil {
		t.Fatal("replacement plan accepted")
	}
	path := filepath.Join(filepath.Dir(s.path), storageTransitionRecordName)
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err = s.resumeStorageTransitionPlan(ctx, v.Digest(), uid); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for name, alter := range map[string]func(){
		"corrupt": func() {
			if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
				t.Fatal(err)
			}
		},
		"writable": func() {
			if err := os.Chmod(path, 0666); err != nil {
				t.Fatal(err)
			}
		},
		"wrong host": func() {
			var r storageTransitionRecord
			if err := json.Unmarshal(original, &r); err != nil {
				t.Fatal(err)
			}
			r.NodeID = "fra-one"
			raw, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			alter()
			if _, err := s.resumeStorageTransitionPlan(t.Context(), v.Digest(), uid); err == nil {
				t.Fatal("unsafe pin resumed")
			}
			if err := os.Chmod(path, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, original, 0600); err != nil {
				t.Fatal(err)
			}
		})
	}
	// Ordinary authority permanently closes preliminary destination recovery.
	if err = s.Admit(CommandAuthorization{NodeID: "sfo-one", AuthorityID: "sfo-regional", Epoch: 1, CandidateID: "sfo-controller-one", LeaseID: "lease-one"}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.resumeStorageTransitionPlan(t.Context(), v.Digest(), uid); err == nil {
		t.Fatal("ordinary destination reopened transition")
	}
}

func TestStorageTransitionExpiredAgreementCannotResumeOrReplacePin(t *testing.T) {
	p := storagePlanFixture(t)
	p.IssuedAt = time.Now().UTC().Add(-2 * time.Hour)
	p.ExpiresAt = p.IssuedAt.Add(time.Hour)
	signer, public := storagePlanKey(t)
	signed, err := controltransition.SignPlan(signer, p)
	if err != nil {
		t.Fatal(err)
	}
	private := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(private, 0700); err != nil {
		t.Fatal(err)
	}
	s, err := NewEpochStore(private, "sfo-one")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	d := p.Destinations[1]
	if err := s.AdmitBootstrap(d.BootstrapGrantSHA256, d.PreparedManifestSHA256); err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Geteuid())
	if _, err := s.admitStorageTransitionPlan(t.Context(), public, signed, nil, uid, nil); err == nil {
		t.Fatal("expired first admission accepted")
	}
	path := filepath.Join(private, storageTransitionRecordName)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("failed admission wrote pin", err)
	}
	// Reproduce a pin that was durably accepted inside its lifetime, then left
	// unfinished across a long outage. No clock override exists in production.
	r := storageTransitionRecord{Version: 1, NodeID: s.node, PublicKey: public, SignedPlan: signed, PlanSHA256: controltransition.Digest(signed), BootstrapGrantSHA256: d.BootstrapGrantSHA256, ManifestSHA256: d.PreparedManifestSHA256, AdmittedAt: p.IssuedAt}
	if err := writeStorageTransitionRecord(path, r, func() error { return nil }, nil); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.resumeStorageTransitionPlan(t.Context(), r.PlanSHA256, uid); err == nil {
		t.Fatal("expired recovery accepted")
	}
	p.IssuedAt = time.Now().UTC().Add(-time.Minute)
	p.ExpiresAt = p.IssuedAt.Add(time.Hour)
	renewed, err := controltransition.SignPlan(signer, p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.admitStorageTransitionPlan(t.Context(), public, renewed, nil, uid, nil); err == nil {
		t.Fatal("renewal replaced expired immutable plan")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("expired pin changed", err)
	}
}
