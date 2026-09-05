package sourcepublication

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"terrascale.tech/orchestrator/src/orchestrator/preliminarycapture"
	"terrascale.tech/orchestrator/src/orchestrator/preliminarytransfer"
	"terrascale.tech/orchestrator/src/orchestrator/security"
	"testing"
	"time"
)

func wireSigner(t *testing.T) (*security.CommandSignatureSigner, []byte) {
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

type transferFixture struct {
	owner, source *security.CommandSignatureSigner
	public        []byte
	scope         preliminarytransfer.Scope
	now           time.Time
}

func newTransferFixture(t *testing.T) transferFixture {
	t.Helper()
	owner, public := wireSigner(t)
	source, sourcePublic := wireSigner(t)
	_, sfo := wireSigner(t)
	_, fra := wireSigner(t)
	now := time.Now().UTC().Add(-10 * time.Minute)
	issued := now.Add(-48 * time.Hour)
	request := preliminarycapture.Request{Version: 1, TransitionID: "transition-1", SourceNodeID: "gru-1", InitialGrantSHA256: strings.Repeat("a", 64), StoreScopeSHA256: strings.Repeat("b", 64), ProfileSHA256: strings.Repeat("c", 64), Accounts: []preliminarycapture.AccountInventory{{Account: "REGIONAL", Streams: []string{"EVENTS"}}, {Account: "GLOBAL", Streams: []string{"SPEC"}}}, ControlEpoch: 5, IssuedAt: issued, ExpiresAt: issued.Add(time.Hour)}
	capture, err := preliminarycapture.SignRequest(owner, request)
	if err != nil {
		t.Fatal(err)
	}
	receipt := preliminarycapture.Receipt{Version: 1, Preliminary: true, TransitionID: request.TransitionID, RequestSHA256: preliminarytransfer.Digest(capture), SourceNodeID: request.SourceNodeID, ControlEpoch: 5, CreatedAt: issued.Add(2 * time.Minute)}
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
	scope := preliminarytransfer.Scope{Version: 1, TransitionID: request.TransitionID, SourceNodeID: request.SourceNodeID, InitialGrantSHA256: request.InitialGrantSHA256, StoreScopeSHA256: request.StoreScopeSHA256, ProfileSHA256: request.ProfileSHA256, SourcePublicKeyPEM: string(sourcePublic), CaptureRequest: capture, CaptureReceipt: signedReceipt, RequestSHA256: preliminarytransfer.Digest(capture), ReceiptSHA256: preliminarytransfer.Digest(signedReceipt), PreparationGrantSHA256: strings.Repeat("e", 64), Prefix: "preliminary/transition-1", MaxRestoreBytes: 8192, MaxSnapshotBytes: 4096, MaxTotalBytes: 8192}
	for _, region := range []string{"gru", "sfo", "fra"} {
		scope.Destinations = append(scope.Destinations, preliminarytransfer.Destination{Region: region, OCIRegion: "oci-" + region, Namespace: "namespace", Bucket: "bucket-" + region, BucketResourceID: "ocid1.bucket." + region, CompartmentID: "ocid1.compartment.test", OwnershipGeneration: 1, OwnershipTags: map[string]string{"terrascale-managed": "orchestrator", "terrascale-region": region}})
		for _, o := range receipt.Objects {
			scope.Objects = append(scope.Objects, preliminarytransfer.ObjectMapping{Region: region, Account: o.Account, Stream: o.Stream, LocalKey: o.Key, ObjectKey: scope.Prefix + "/" + scope.RequestSHA256 + "/" + o.Key, SHA256: o.SHA256, Size: o.Size})
		}
	}
	for i, region := range []string{"sfo", "fra"} {
		scope.Candidates = append(scope.Candidates, preliminarytransfer.Candidate{Region: region, NodeID: region + "-1", ServerName: region + "-candidate-1", BootstrapGrantSHA256: strings.Repeat("f", 64), ManifestSHA256: strings.Repeat("1", 64), ReceiptPublicKeyPEM: string([][]byte{sfo, fra}[i])})
	}
	return transferFixture{owner, source, public, scope, now}
}

func (f transferFixture) verifiedScope(t *testing.T) preliminarytransfer.VerifiedScope {
	t.Helper()
	signed, err := preliminarytransfer.SignScope(f.owner, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	v, err := preliminarytransfer.VerifyScope(f.public, signed)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func (f transferFixture) upload(t *testing.T, epoch uint64, issued time.Time) preliminarytransfer.VerifiedUpload {
	t.Helper()
	scope := f.verifiedScope(t)
	signed, err := preliminarytransfer.SignUploadAuthorization(f.owner, preliminarytransfer.UploadAuthorization{Version: 1, ScopeSHA256: scope.Digest, ControlEpoch: epoch, IssuedAt: issued, ExpiresAt: issued.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := preliminarytransfer.MarshalRequest(scope.Signed, signed)
	if err != nil {
		t.Fatal(err)
	}
	v, err := preliminarytransfer.VerifyUploadRequest(f.public, raw, issued)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func stateGuard(context.Context) error { return nil }
func TestStateRenewalFloorAndReceipt(t *testing.T) {
	f := newTransferFixture(t)
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "publication")
	initial := f.upload(t, 5, f.now)
	s, err := OpenState(ctx, dir, initial, stateGuard)
	if err != nil {
		t.Fatal(err)
	}
	if other, err := OpenState(ctx, dir, initial, stateGuard); err == nil {
		other.Close()
		t.Fatal("concurrent ownership accepted")
	}
	if raw, err := s.ReadReceipt(ctx); err != nil || raw != nil {
		t.Fatal("unexpected receipt", err)
	}
	var request preliminarytransfer.Request
	if err := json.Unmarshal(initial.Signed, &request); err != nil {
		t.Fatal(err)
	}
	receipt := preliminarytransfer.PublicationReceipt{Version: 1, UploadAuthorization: request.Authorization, ScopeSHA256: initial.Scope.Digest, UploadRequestSHA256: initial.Digest, ControlEpoch: 5, CreatedAt: f.now.Add(time.Minute)}
	for _, object := range initial.Scope.Scope.Objects {
		receipt.Objects = append(receipt.Objects, preliminarytransfer.PublishedObject{ObjectMapping: object, ETag: "etag"})
	}
	raw, err := preliminarytransfer.SignPublicationReceipt(f.source, receipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SaveReceipt(ctx, raw); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveReceipt(ctx, raw); err != nil {
		t.Fatal(err)
	}
	receipt.Objects[0].ETag = "changed"
	alternate, err := preliminarytransfer.SignPublicationReceipt(f.source, receipt)
	if err != nil {
		t.Fatal(err)
	}
	if s.SaveReceipt(ctx, alternate) == nil {
		t.Fatal("receipt replaced")
	}
	s.Close()
	next := f.upload(t, 6, f.now.Add(time.Minute))
	s, err = OpenState(ctx, dir, next, stateGuard)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.ReadReceipt(ctx)
	if err != nil || string(got) != string(raw) {
		t.Fatal("historical receipt lost", err)
	}
	s.Close()
	for _, old := range []preliminarytransfer.VerifiedUpload{initial, f.upload(t, 6, f.now), f.upload(t, 5, f.now.Add(2*time.Minute))} {
		if s, err := OpenState(ctx, dir, old, stateGuard); err == nil {
			s.Close()
			t.Fatal("authority floor regressed")
		}
	}
	s, err = OpenState(ctx, dir, next, stateGuard)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	f.scope.Prefix = "preliminary/different"
	for i := range f.scope.Objects {
		f.scope.Objects[i].ObjectKey = f.scope.Prefix + "/" + f.scope.RequestSHA256 + "/" + f.scope.Objects[i].LocalKey
	}
	if s, err := OpenState(ctx, dir, f.upload(t, 7, f.now.Add(2*time.Minute)), stateGuard); err == nil {
		s.Close()
		t.Fatal("scope repinned")
	}
}
func TestStateProtectionAndCancellation(t *testing.T) {
	for _, kind := range []string{"canceled", "guard", "foreign", "symlink", "hardlink", "pending-link", "writable", "corrupt-floor", "orphan-receipt"} {
		t.Run(kind, func(t *testing.T) {
			f := newTransferFixture(t)
			upload := f.upload(t, 5, f.now)
			ctx := context.Background()
			dir := filepath.Join(t.TempDir(), "publication")
			s, err := OpenState(ctx, dir, upload, stateGuard)
			if err != nil {
				t.Fatal(err)
			}
			s.Close()
			guard := stateGuard
			switch kind {
			case "canceled":
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			case "guard":
				guard = func(context.Context) error { return errors.New("revoked") }
			case "foreign":
				err = os.WriteFile(filepath.Join(dir, "foreign"), []byte("keep"), 0600)
			case "symlink", "hardlink", "pending-link":
				name := "acceptance.json"
				if kind == "pending-link" {
					name = ".pending"
				} else {
					err = os.Remove(filepath.Join(dir, name))
					if err != nil {
						t.Fatal(err)
					}
				}
				target := filepath.Join(t.TempDir(), "external")
				if err := os.WriteFile(target, []byte("keep"), 0600); err != nil {
					t.Fatal(err)
				}
				if kind == "hardlink" {
					err = os.Link(target, filepath.Join(dir, name))
				} else {
					err = os.Symlink(target, filepath.Join(dir, name))
				}
			case "writable":
				err = os.Chmod(dir, 0777)
			case "corrupt-floor":
				err = os.WriteFile(filepath.Join(dir, "acceptance.json"), []byte("{}"), 0600)
			case "orphan-receipt":
				err = os.Remove(filepath.Join(dir, "acceptance.json"))
				if err == nil {
					err = os.WriteFile(filepath.Join(dir, "receipt.json"), []byte("{}"), 0600)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if s, err := OpenState(ctx, dir, upload, guard); err == nil {
				s.Close()
				t.Fatal("unsafe state accepted")
			}
		})
	}
}
func TestStateGuardFailureAfterFloorPersistenceDoesNotPermitRollback(t *testing.T) {
	f := newTransferFixture(t)
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "publication")
	initial := f.upload(t, 5, f.now)
	s, err := OpenState(ctx, dir, initial, stateGuard)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	next := f.upload(t, 6, f.now.Add(time.Minute))
	guard := func(context.Context) error {
		raw, err := os.ReadFile(filepath.Join(dir, "acceptance.json"))
		if err != nil {
			return err
		}
		var floor acceptance
		if err := json.Unmarshal(raw, &floor); err != nil {
			return err
		}
		if floor.ControlEpoch == 6 {
			return errors.New("revoked after persistence")
		}
		return nil
	}
	if s, err := OpenState(ctx, dir, next, guard); err == nil {
		s.Close()
		t.Fatal("post-persistence guard ignored")
	}
	if s, err := OpenState(ctx, dir, initial, stateGuard); err == nil {
		s.Close()
		t.Fatal("failed response rolled floor back")
	}
	s, err = OpenState(ctx, dir, next, stateGuard)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
}

func TestStateRejectsShorterRenewalExpiry(t *testing.T) {
	f := newTransferFixture(t)
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "publication")
	initial := f.upload(t, 5, f.now)
	s, err := OpenState(ctx, dir, initial, stateGuard)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	for _, epoch := range []uint64{5, 6} {
		scope := f.verifiedScope(t)
		auth := initial.Authorization
		auth.ControlEpoch = epoch
		auth.IssuedAt = auth.IssuedAt.Add(time.Minute)
		auth.ExpiresAt = auth.ExpiresAt.Add(-time.Minute)
		signed, err := preliminarytransfer.SignUploadAuthorization(f.owner, auth)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := preliminarytransfer.MarshalRequest(scope.Signed, signed)
		if err != nil {
			t.Fatal(err)
		}
		shorter, err := preliminarytransfer.VerifyUploadRequest(f.public, raw, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if s, err := OpenState(ctx, dir, shorter, stateGuard); err == nil {
			s.Close()
			t.Fatal("shorter expiry accepted")
		}
	}
	s, err = OpenState(ctx, dir, initial, stateGuard)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
}
