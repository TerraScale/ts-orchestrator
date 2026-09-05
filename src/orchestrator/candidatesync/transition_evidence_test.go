package candidatesync

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/controltransition"
	"terrascale.tech/orchestrator/src/orchestrator/ociinstance"
	"terrascale.tech/orchestrator/src/orchestrator/preliminarytransfer"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

func (f fixture) fra(t *testing.T) fixture {
	t.Helper()
	candidate := f.verified.Scope.Scope.Candidates[1]
	authorization, err := preliminarytransfer.SignCandidateAuthorization(f.owner, preliminarytransfer.CandidateAuthorization{Version: 1, ScopeSHA256: f.verified.Scope.Digest, NodeID: candidate.NodeID, IssuedAt: time.Now().UTC(), ExpiresAt: f.verified.Authorization.ExpiresAt})
	if err != nil {
		t.Fatal(err)
	}
	request, err := preliminarytransfer.MarshalRequest(f.verified.Scope.Signed, authorization)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := preliminarytransfer.VerifyCandidateRequest(f.ownerPublic, request, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	config := f.config
	sync := *config.Sync
	config.Sync = &sync
	config.NodeID, config.Region, config.ServerName = candidate.NodeID, candidate.Region, candidate.ServerName
	config.StoreDir, config.GrantFile, config.GrantPublicKeyFile = filepath.Join(dir, "final-store"), filepath.Join(dir, "grant.json"), filepath.Join(dir, "owner.pem")
	sync.RequestFile, sync.StagingDir, sync.ReceiptDir = filepath.Join(dir, "request.json"), filepath.Join(dir, "stage"), filepath.Join(dir, "receipts")
	sync.ReceiptPrivateKeyFile, sync.ReceiptPublicKeyPEM = filepath.Join(dir, "candidate.pem"), candidate.ReceiptPublicKeyPEM
	sync.Identity = ociinstance.Config{Region: "eu-frankfurt-1"}
	if err := os.WriteFile(sync.ReceiptPrivateKeyFile, f.fraPrivate, 0600); err != nil {
		t.Fatal(err)
	}
	destination := f.verified.Scope.Scope.Destinations[2]
	objects := &memoryObjects{objects: f.objects.objects, bucket: provider.OCIBucketObservation{ID: destination.BucketResourceID, CompartmentID: destination.CompartmentID, Namespace: destination.Namespace, Name: destination.Bucket, FreeformTags: destination.OwnershipTags}}
	return fixture{config, verified, objects, f.owner, f.ownerPublic, f.source, f.fraPrivate}
}

func transitionPlanFixture(t *testing.T, f fixture) controltransition.Plan {
	t.Helper()
	s := f.verified.Scope.Scope
	h := strings.Repeat("a", 64)
	p := controltransition.Plan{Version: 1, Mode: controltransition.Mode, EstateID: "launch", TransitionID: s.TransitionID, PreliminaryScopeSHA256: f.verified.Scope.Digest, IssuedAt: time.Now().UTC().Add(-time.Minute), ExpiresAt: time.Now().UTC().Add(time.Hour), ClusterName: "control-r3", TrustBundleSHA256: h, SourceTopologyEpoch: 1, TargetTopologyEpoch: 2, GlobalElectionFloor: 5, RegionalElectionFloor: 1,
		Source: controltransition.Source{NodeID: s.SourceNodeID, ServerName: "source-r1", BootstrapGrantSHA256: s.InitialGrantSHA256, InitialManifestSHA256: h, CaptureManifestSHA256: strings.Repeat("b", 64), LaunchSHA256: h, StoreScopeSHA256: s.StoreScopeSHA256, ProfileSHA256: s.ProfileSHA256, StoreDir: "/data/source", CaptureDir: "/data/capture", ArchiveDir: "/data/archive", ReceiptPublicKeyPEM: s.SourcePublicKeyPEM},
		Limits: controltransition.Limits{MaxStoreBytes: 64 << 20, MaxStoreFiles: 10000, MaxSnapshotBytes: s.MaxSnapshotBytes, MaxTransferBytes: s.MaxTotalBytes, MaxRestoreBytes: s.MaxRestoreBytes}}
	for i, region := range []string{"gru", "sfo", "fra"} {
		_, public, _ := testSigner(t)
		d := controltransition.Destination{Region: region, NodeID: region + "-1", ServerName: region + "-candidate-1", BootstrapGrantSHA256: s.InitialGrantSHA256, PreparedManifestSHA256: strings.Repeat("1", 64), ActivationManifestSHA256: strings.Repeat("2", 64), RouteURL: "nats-route://" + region + ".internal:6222", CertificateSHA256: strings.Repeat(string(rune('d'+i)), 64), ReceiptPublicKeyPEM: string(public), PreliminaryStoreDir: "/data/preliminary", StoreDir: "/data/r3", StagingDir: "/data/staging", Objects: controltransition.ObjectLocation{OCIRegion: s.Destinations[i].OCIRegion, Namespace: "tenancy", Bucket: region + "-control", BucketResourceID: "ocid1.bucket." + region, CompartmentID: "ocid1.compartment.launch", OwnershipObservationSHA256: h, Prefix: "control-transitions/first-r3"}}
		if i > 0 {
			c := s.Candidates[i-1]
			d.BootstrapGrantSHA256 = c.BootstrapGrantSHA256
			d.PreparedManifestSHA256 = c.ManifestSHA256
			d.ReceiptPublicKeyPEM = c.ReceiptPublicKeyPEM
		}
		p.Destinations = append(p.Destinations, d)
	}
	capture, err := f.verified.Scope.HistoricalCapture()
	if err != nil {
		t.Fatal(err)
	}
	for i, account := range capture.Request.Accounts {
		a := controltransition.Account{Role: []string{"global", "gru-regional"}[i], SourceName: account.Account, DestinationName: account.Account}
		for _, stream := range account.Streams {
			a.Streams = append(a.Streams, controltransition.Stream{Name: stream, SourceConfigSHA256: h, FinalConfigSHA256: h})
		}
		p.Accounts = append(p.Accounts, a)
	}
	return p
}

func signedTransitionPlan(t *testing.T, f fixture, p controltransition.Plan) controltransition.VerifiedPlan {
	t.Helper()
	raw, err := controltransition.SignPlan(f.owner, p)
	if err != nil {
		t.Fatal(err)
	}
	v, err := controltransition.VerifyPlan(f.ownerPublic, raw)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestTransitionCandidatesBindBothRealRegionalRestores(t *testing.T) {
	f := newFixture(t)
	fra := f.fra(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	sfoRaw, err := run(ctx, f.config, f.verified, f.factory)
	if err != nil {
		t.Fatal(err)
	}
	fraRaw, err := run(ctx, fra.config, fra.verified, fra.factory)
	if err != nil {
		t.Fatal(err)
	}
	p := transitionPlanFixture(t, f)
	v := signedTransitionPlan(t, f, p)
	proof, err := VerifyTransitionCandidates(v, f.verified.Scope, [][]byte{sfoRaw, fraRaw}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	binding, err := proof.Binding(time.Now())
	if err != nil || binding.PlanSHA256 != v.Digest() || binding.ScopeSHA256 != f.verified.Scope.Digest || binding.SFOReceiptSHA256 != preliminarytransfer.Digest(sfoRaw) || binding.FRAReceiptSHA256 != preliminarytransfer.Digest(fraRaw) || binding.CaptureEpoch != 5 {
		t.Fatal("lost candidate evidence binding", err)
	}
	binding.SFOReceiptSHA256 = "changed"
	again, err := proof.Binding(time.Now())
	if err != nil || again.SFOReceiptSHA256 != preliminarytransfer.Digest(sfoRaw) {
		t.Fatal("mutable proof", err)
	}
	if _, err := proof.Binding(p.ExpiresAt); err == nil {
		t.Fatal("expired plan evidence used")
	}
	if _, err := (VerifiedTransitionCandidates{}).Binding(time.Now()); err == nil {
		t.Fatal("zero proof used")
	}
	for name, receipts := range map[string][][]byte{"missing": {sfoRaw}, "reversed": {fraRaw, sfoRaw}, "duplicate": {sfoRaw, sfoRaw}, "extra": {sfoRaw, fraRaw, fraRaw}} {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyTransitionCandidates(v, f.verified.Scope, receipts, time.Now()); err == nil {
				t.Fatal("incomplete candidate evidence accepted")
			}
		})
	}
	for name, mutate := range map[string]func(*controltransition.Plan){
		"wrong scope":             func(p *controltransition.Plan) { p.PreliminaryScopeSHA256 = strings.Repeat("f", 64) },
		"wrong source profile":    func(p *controltransition.Plan) { p.Source.ProfileSHA256 = strings.Repeat("f", 64) },
		"wrong transition":        func(p *controltransition.Plan) { p.TransitionID = "another-transition" },
		"wrong prepared manifest": func(p *controltransition.Plan) { p.Destinations[1].PreparedManifestSHA256 = strings.Repeat("f", 64) },
		"wrong host":              func(p *controltransition.Plan) { p.Destinations[1].NodeID = "sfo-other" },
		"wrong server":            func(p *controltransition.Plan) { p.Destinations[1].ServerName = "sfo-other" },
		"missing stream":          func(p *controltransition.Plan) { p.Accounts[0].Streams[0].Name = "OTHER" },
		"missing account":         func(p *controltransition.Plan) { p.Accounts[0].SourceName = "OTHER" },
		"regressed floor":         func(p *controltransition.Plan) { p.GlobalElectionFloor = 4 },
		"restore bound":           func(p *controltransition.Plan) { p.Limits.MaxRestoreBytes = p.Limits.MaxSnapshotBytes },
	} {
		t.Run(name, func(t *testing.T) {
			changed := transitionPlanFixture(t, f)
			mutate(&changed)
			other := signedTransitionPlan(t, f, changed)
			if _, err := VerifyTransitionCandidates(other, f.verified.Scope, [][]byte{sfoRaw, fraRaw}, time.Now()); err == nil {
				t.Fatal("foreign scope accepted")
			}
		})
	}
	// Both permanent destinations remain untouched by preliminary restoration.
	for _, path := range []string{f.config.StoreDir, fra.config.StoreDir} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("authoritative destination touched", err)
		}
	}
}

func TestScopedReceiptRejectsSignedFalseOrIncompleteClaims(t *testing.T) {
	f := newFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	raw, err := run(ctx, f.config, f.verified, f.factory)
	if err != nil {
		t.Fatal(err)
	}
	private, err := os.ReadFile(f.config.Sync.ReceiptPrivateKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := security.ParseCommandSignatureSignerPEM(private)
	clear(private)
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Close()
	for name, mutate := range map[string]func(*Receipt){
		"scope":               func(r *Receipt) { r.ScopeSHA256 = strings.Repeat("f", 64) },
		"grant":               func(r *Receipt) { r.PreparationGrantSHA256 = strings.Repeat("f", 64) },
		"bootstrap":           func(r *Receipt) { r.BootstrapGrantSHA256 = strings.Repeat("0", 64) },
		"manifest":            func(r *Receipt) { r.ManifestSHA256 = strings.Repeat("f", 64) },
		"source receipt":      func(r *Receipt) { r.SourceReceiptSHA256 = strings.Repeat("f", 64) },
		"epoch":               func(r *Receipt) { r.CaptureEpoch++ },
		"future":              func(r *Receipt) { r.CreatedAt = time.Now().Add(time.Hour) },
		"predates capture":    func(r *Receipt) { r.CreatedAt = time.Unix(1, 0) },
		"missing object":      func(r *Receipt) { r.Objects = r.Objects[:1] },
		"duplicate object":    func(r *Receipt) { r.Objects[1] = r.Objects[0] },
		"wrong archive":       func(r *Receipt) { r.Objects[0].Object.SHA256 = "sha256:" + strings.Repeat("f", 64) },
		"wrong key":           func(r *Receipt) { r.Objects[0].Object.ObjectKey += "-other" },
		"empty restore proof": func(r *Receipt) { r.Objects[0].RestoreSHA256 = "" },
		"noncanonical digest": func(r *Receipt) { r.Objects[0].RestoreSHA256 = strings.Repeat("F", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			r, err := VerifyReceipt([]byte(f.config.Sync.ReceiptPublicKeyPEM), raw)
			if err != nil {
				t.Fatal(err)
			}
			mutate(&r)
			changed, err := signReceipt(signer, r)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyReceipt([]byte(f.config.Sync.ReceiptPublicKeyPEM), changed); err != nil {
				t.Fatal("fixture lost valid attribution", err)
			}
			if _, err := VerifyScopedReceipt(f.verified.Scope, "sfo", changed, time.Now()); err == nil {
				t.Fatal("signed false claim accepted")
			}
		})
	}
	if _, err := VerifyScopedReceipt(f.verified.Scope, "fra", raw, time.Now()); err == nil {
		t.Fatal("foreign regional receipt accepted")
	}
	if _, err := VerifyScopedReceipt(f.verified.Scope, "gru", raw, time.Now()); err == nil {
		t.Fatal("source treated as preliminary candidate")
	}
	replay, err := run(ctx, f.config, f.verified, f.factory)
	if err != nil || !bytes.Equal(replay, raw) {
		t.Fatal("valid completed receipt failed replay", err)
	}
}
