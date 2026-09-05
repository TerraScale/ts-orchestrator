package preliminarytransfer

import (
	"strings"
	"testing"
	"time"
)

func (f transferFixture) upload(t *testing.T, epoch uint64, issued time.Time) VerifiedUpload {
	t.Helper()
	scope := f.verifiedScope(t)
	signed, err := SignUploadAuthorization(f.owner, UploadAuthorization{Version: 1, ScopeSHA256: scope.Digest, ControlEpoch: epoch, IssuedAt: issued, ExpiresAt: issued.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalRequest(scope.Signed, signed)
	if err != nil {
		t.Fatal(err)
	}
	v, err := VerifyUploadRequest(f.public, raw, issued)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func TestUploadRenewalPreservesImmutableCapture(t *testing.T) {
	f := newTransferFixture(t)
	prior := f.upload(t, 7, f.now.Add(-2*time.Hour))
	next := f.upload(t, 8, f.now)
	if err := CheckUploadRenewal(prior, next); err != nil {
		t.Fatal(err)
	}
	epoch, err := next.Scope.CaptureEpoch()
	if err != nil || epoch != 5 {
		t.Fatalf("capture epoch overwritten: %d %v", epoch, err)
	}
	if prior.Check(f.now) == nil {
		t.Fatal("expired prior upload remains live")
	}
	if next.Check(f.now) != nil || next.Check(next.Authorization.ExpiresAt) == nil {
		t.Fatal("upload time bounds")
	}
	regressed := f.upload(t, 6, f.now)
	if CheckUploadRenewal(prior, regressed) == nil {
		t.Fatal("renewal epoch regression accepted")
	}
	changed := f
	changed.scope = cloneTransferScope(t, f.scope)
	changed.scope.Destinations[0].Bucket = "another-bucket"
	conflict := changed.upload(t, 8, f.now)
	if CheckUploadRenewal(prior, conflict) == nil {
		t.Fatal("conflicting destination renewal accepted")
	}
	for _, mutate := range []func(*VerifiedUpload){func(v *VerifiedUpload) { v.Authorization.ControlEpoch++ }, func(v *VerifiedUpload) { v.Digest = strings.Repeat("0", 64) }, func(v *VerifiedUpload) { v.Scope.Scope.Objects[0].ObjectKey += "x" }} {
		v := f.upload(t, 8, f.now)
		mutate(&v)
		if v.Check(f.now) == nil {
			t.Fatal("mutated upload accepted")
		}
	}
	scope := f.verifiedScope(t)
	for _, a := range []UploadAuthorization{{Version: 1, ScopeSHA256: scope.Digest, ControlEpoch: 4, IssuedAt: f.now, ExpiresAt: f.now.Add(time.Hour)}, {Version: 1, ScopeSHA256: strings.Repeat("0", 64), ControlEpoch: 8, IssuedAt: f.now, ExpiresAt: f.now.Add(time.Hour)}, {Version: 1, ScopeSHA256: scope.Digest, ControlEpoch: 8, IssuedAt: f.now.Add(-49 * time.Hour), ExpiresAt: f.now.Add(-48 * time.Hour)}} {
		signed, err := SignUploadAuthorization(f.owner, a)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := MarshalRequest(scope.Signed, signed)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyUploadRequest(f.public, raw, a.IssuedAt); err == nil {
			t.Fatal("bad epoch, scope or capture time accepted")
		}
	}
}
func TestCandidateOfflineAuthorization(t *testing.T) {
	f := newTransferFixture(t)
	scope := f.verifiedScope(t)
	a := CandidateAuthorization{Version: 1, ScopeSHA256: scope.Digest, NodeID: "sfo-1", IssuedAt: f.now, ExpiresAt: f.now.Add(time.Hour)}
	signed, err := SignCandidateAuthorization(f.owner, a)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalRequest(scope.Signed, signed)
	if err != nil {
		t.Fatal(err)
	}
	// All verification uses the completed signed capture; no live source is consulted.
	candidate, err := VerifyCandidateRequest(f.public, raw, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if candidate.Check(f.now) != nil || candidate.Check(a.ExpiresAt) == nil || candidate.Check(a.IssuedAt.Add(-time.Nanosecond)) == nil {
		t.Fatal("candidate time bounds")
	}
	candidate.Authorization.NodeID = "fra-1"
	if candidate.Check(f.now) == nil {
		t.Fatal("mutated candidate accepted")
	}
	for _, node := range []string{"gru-1", "sfo-other"} {
		bad := a
		bad.NodeID = node
		signed, err := SignCandidateAuthorization(f.owner, bad)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := MarshalRequest(scope.Signed, signed)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyCandidateRequest(f.public, wire, f.now); err == nil {
			t.Fatal("wrong node accepted")
		}
	}
	wrongDomain, err := signDocument(f.owner, uploadDomain, a)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := MarshalRequest(scope.Signed, wrongDomain)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyCandidateRequest(f.public, wire, f.now); err == nil {
		t.Fatal("upload domain granted candidate authority")
	}
	if _, err := VerifyUploadRequest(f.public, raw, f.now); err == nil {
		t.Fatal("candidate request granted upload authority")
	}
}
func TestPublicationExactInventoryAndRequestBinding(t *testing.T) {
	f := newTransferFixture(t)
	upload := f.upload(t, 8, f.now)
	fixture := func() PublicationReceipt {
		r := PublicationReceipt{Version: 1, ScopeSHA256: upload.Scope.Digest, UploadRequestSHA256: upload.Digest, ControlEpoch: 8, CreatedAt: f.now.Add(time.Minute)}
		for _, o := range upload.Scope.Scope.Objects {
			r.Objects = append(r.Objects, PublishedObject{ObjectMapping: o, ETag: "etag-" + o.Region + "-" + o.Stream})
		}
		return r
	}
	r := fixture()
	signed, err := SignPublicationReceipt(f.source, r)
	if err != nil {
		t.Fatal(err)
	}
	checked, err := CheckPublication(upload, signed)
	if err != nil || len(checked.Objects) != 6 {
		t.Fatalf("publication %v %v", checked, err)
	}
	if checked.Objects[0].ETag != r.Objects[0].ETag {
		t.Fatal("etag lost")
	}
	for _, mutate := range []func(*PublicationReceipt){func(r *PublicationReceipt) { r.Objects = r.Objects[:4] }, func(r *PublicationReceipt) { r.Objects[0].ObjectKey += "x" }, func(r *PublicationReceipt) { r.Objects[0].ETag = "" }, func(r *PublicationReceipt) { r.CreatedAt = upload.Authorization.ExpiresAt }, func(r *PublicationReceipt) { r.UploadRequestSHA256 = strings.Repeat("0", 64) }, func(r *PublicationReceipt) { r.ControlEpoch = 5 }, func(r *PublicationReceipt) { r.Objects[0].ETag = "changed-without-signature" }} {
		bad := fixture()
		mutate(&bad)
		if bad.Objects[0].ETag == "changed-without-signature" {
			raw := strings.Replace(string(signed), r.Objects[0].ETag, bad.Objects[0].ETag, 1)
			if _, err := CheckPublication(upload, []byte(raw)); err == nil {
				t.Fatal("unsigned etag change accepted")
			}
			continue
		}
		raw, err := SignPublicationReceipt(f.source, bad)
		if err != nil {
			continue
		}
		if _, err := CheckPublication(upload, raw); err == nil {
			t.Fatal("invalid publication accepted")
		}
	}
	wrongSigner, err := SignPublicationReceipt(f.owner, r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CheckPublication(upload, wrongSigner); err == nil {
		t.Fatal("owner substituted for source receipt key")
	}
	renewed := f.upload(t, 9, f.now.Add(time.Minute))
	if _, err := CheckPublication(renewed, signed); err == nil {
		t.Fatal("publication rebound to renewal")
	}
}
