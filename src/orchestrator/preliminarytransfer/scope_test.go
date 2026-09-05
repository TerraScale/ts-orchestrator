package preliminarytransfer

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/preliminarycapture"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

type transferFixture struct {
	owner, source *security.CommandSignatureSigner
	public        []byte
	scope         Scope
	now           time.Time
}

func newTransferFixture(t *testing.T) transferFixture {
	t.Helper()
	owner, public := wireSigner(t)
	source, sourcePublic := wireSigner(t)
	_, sfo := wireSigner(t)
	_, fra := wireSigner(t)
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	issued := now.Add(-48 * time.Hour)
	request := preliminarycapture.Request{Version: 1, TransitionID: "transition-1", SourceNodeID: "gru-1", InitialGrantSHA256: strings.Repeat("a", 64), StoreScopeSHA256: strings.Repeat("b", 64), ProfileSHA256: strings.Repeat("c", 64), Accounts: []preliminarycapture.AccountInventory{{Account: "REGIONAL", Streams: []string{"EVENTS"}}, {Account: "GLOBAL", Streams: []string{"SPEC"}}}, ControlEpoch: 5, IssuedAt: issued, ExpiresAt: issued.Add(time.Hour)}
	capture, err := preliminarycapture.SignRequest(owner, request)
	if err != nil {
		t.Fatal(err)
	}
	receipt := preliminarycapture.Receipt{Version: 1, Preliminary: true, TransitionID: request.TransitionID, RequestSHA256: Digest(capture), SourceNodeID: request.SourceNodeID, ControlEpoch: 5, CreatedAt: issued.Add(2 * time.Minute)}
	for _, a := range request.Accounts {
		key, err := preliminarycapture.ObjectKey(a.Account, a.Streams[0], 5)
		if err != nil {
			t.Fatal(err)
		}
		receipt.Objects = append(receipt.Objects, preliminarycapture.Object{Account: a.Account, Stream: a.Streams[0], Key: key, SHA256: "sha256:" + strings.Repeat("d", 64), Size: 2048, CreatedAt: issued.Add(time.Minute)})
	}
	signedReceipt, err := preliminarycapture.SignReceipt(source, receipt)
	if err != nil {
		t.Fatal(err)
	}
	scope := Scope{Version: 1, TransitionID: request.TransitionID, SourceNodeID: request.SourceNodeID, InitialGrantSHA256: request.InitialGrantSHA256, StoreScopeSHA256: request.StoreScopeSHA256, ProfileSHA256: request.ProfileSHA256, SourcePublicKeyPEM: string(sourcePublic), CaptureRequest: capture, CaptureReceipt: signedReceipt, RequestSHA256: Digest(capture), ReceiptSHA256: Digest(signedReceipt), PreparationGrantSHA256: strings.Repeat("e", 64), Prefix: "preliminary/transition-1", MaxRestoreBytes: 8192, MaxSnapshotBytes: 4096, MaxTotalBytes: 8192}
	for _, region := range []string{"gru", "sfo", "fra"} {
		scope.Destinations = append(scope.Destinations, Destination{Region: region, OCIRegion: "oci-" + region, Namespace: "namespace", Bucket: "bucket-" + region, BucketResourceID: "ocid1.bucket." + region, CompartmentID: "ocid1.compartment.test", OwnershipGeneration: 1, OwnershipTags: map[string]string{"terrascale-managed": "orchestrator", "terrascale-region": region}})
		for _, o := range receipt.Objects {
			scope.Objects = append(scope.Objects, ObjectMapping{Region: region, Account: o.Account, Stream: o.Stream, LocalKey: o.Key, ObjectKey: scope.Prefix + "/" + scope.RequestSHA256 + "/" + o.Key, SHA256: o.SHA256, Size: o.Size})
		}
	}
	for i, region := range []string{"sfo", "fra"} {
		scope.Candidates = append(scope.Candidates, Candidate{Region: region, NodeID: region + "-1", ServerName: region + "-candidate-1", BootstrapGrantSHA256: strings.Repeat("f", 64), ManifestSHA256: strings.Repeat("1", 64), ReceiptPublicKeyPEM: string([][]byte{sfo, fra}[i])})
	}
	return transferFixture{owner, source, public, scope, now}
}
func cloneTransferScope(t *testing.T, s Scope) Scope {
	t.Helper()
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var out Scope
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}
func (f transferFixture) verifiedScope(t *testing.T) VerifiedScope {
	t.Helper()
	signed, err := SignScope(f.owner, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	v, err := VerifyScope(f.public, signed)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func TestScopeHistoricalCaptureAndMutation(t *testing.T) {
	f := newTransferFixture(t)
	v := f.verifiedScope(t)
	if err := v.Check(); err != nil {
		t.Fatal(err)
	}
	epoch, err := v.CaptureEpoch()
	if err != nil || epoch != 5 {
		t.Fatalf("epoch %d %v", epoch, err)
	}
	captured, err := v.CaptureTime()
	if err != nil || !captured.Equal(f.now.Add(-48*time.Hour+2*time.Minute)) {
		t.Fatalf("capture time %v %v", captured, err)
	}
	request, err := preliminarycapture.VerifyRequest(f.public, f.scope.CaptureRequest)
	if err != nil {
		t.Fatal(err)
	}
	if request.Check(f.now) == nil {
		t.Fatal("fixture capture request should be expired")
	}
	for _, mutate := range []func(*VerifiedScope){func(v *VerifiedScope) { v.Digest = strings.Repeat("0", 64) }, func(v *VerifiedScope) { v.OwnerKeyID = "other" }, func(v *VerifiedScope) { v.Scope.Objects[0].Size++ }, func(v *VerifiedScope) { v.Scope.MaxRestoreBytes++ }} {
		changed := f.verifiedScope(t)
		mutate(&changed)
		if changed.Check() == nil {
			t.Fatal("mutated verified scope accepted")
		}
	}
	for _, mutate := range []func(*Scope){func(s *Scope) { s.Destinations = s.Destinations[:2] }, func(s *Scope) { s.Objects = s.Objects[:len(s.Objects)-1] }, func(s *Scope) { s.Objects[0].ObjectKey += "-other" }, func(s *Scope) { s.Objects[0].SHA256 = "sha256:" + strings.Repeat("a", 64) }, func(s *Scope) { s.Destinations[0].OwnershipTags["terrascale-region"] = "sfo" }, func(s *Scope) { s.Candidates[1].ReceiptPublicKeyPEM = s.Candidates[0].ReceiptPublicKeyPEM }, func(s *Scope) { s.MaxRestoreBytes = 0 }, func(s *Scope) { s.MaxTotalBytes = 4095 }} {
		s := cloneTransferScope(t, f.scope)
		mutate(&s)
		if _, err := SignScope(f.owner, s); err == nil {
			t.Fatal("invalid scope signed")
		}
	}
}
func TestScopeRejectsHistoricallyInvalidLineage(t *testing.T) {
	f := newTransferFixture(t)
	for _, mutate := range []func(*preliminarycapture.Receipt){func(r *preliminarycapture.Receipt) { r.CreatedAt = f.now }, func(r *preliminarycapture.Receipt) { r.Objects[0].CreatedAt = f.now.Add(-49 * time.Hour) }, func(r *preliminarycapture.Receipt) { r.Objects = r.Objects[:1] }} {
		s := cloneTransferScope(t, f.scope)
		r, err := preliminarycapture.VerifyReceipt([]byte(s.SourcePublicKeyPEM), s.CaptureReceipt)
		if err != nil {
			t.Fatal(err)
		}
		mutate(&r)
		s.CaptureReceipt, err = preliminarycapture.SignReceipt(f.source, r)
		if err != nil {
			t.Fatal(err)
		}
		s.ReceiptSHA256 = Digest(s.CaptureReceipt)
		if len(r.Objects) == 1 {
			s.Objects = []ObjectMapping{s.Objects[0], s.Objects[2], s.Objects[4]}
		}
		// Bypass signing-time validation to exercise verification of owner-signed bad lineage.
		raw, err := signDocument(f.owner, scopeDomain, s)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyScope(f.public, raw); err == nil {
			t.Fatal("invalid historical capture accepted")
		}
	}
}
