package initialgrant

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
	"terrascale.tech/orchestrator/src/orchestrator/nodebootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/preliminarycapture"
	"terrascale.tech/orchestrator/src/orchestrator/preliminarytransfer"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

func TestReadPreliminaryUploadProtectedBound(t *testing.T) {
	privatePublicationNamespace(t)
	dir := "/var/lib/preliminary-upload-test"
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.Mkdir(dir, 0700))
	path := filepath.Join(dir, "request")
	if _, err := ReadPreliminaryUpload(path); !os.IsNotExist(err) {
		t.Fatalf("missing upload: %v", err)
	}
	body := bytes.Repeat([]byte("x"), preliminarytransfer.MaximumBytes)
	must(os.WriteFile(path, body, 0600))
	if got, err := ReadPreliminaryUpload(path); err != nil || !bytes.Equal(got, body) {
		t.Fatalf("exact upload bound: %v", err)
	}
	if _, err := ReadPreliminaryRequest(path); err == nil {
		t.Fatal("capture request inherited larger upload bound")
	}
	must(os.WriteFile(path, append(body, 'x'), 0600))
	if _, err := ReadPreliminaryUpload(path); err == nil {
		t.Fatal("oversized upload accepted")
	}
	must(os.WriteFile(path, []byte("upload"), 0600))
	must(os.Chmod(dir, 0770))
	if _, err := ReadPreliminaryUpload(path); err == nil {
		t.Fatal("writable ancestry accepted")
	}
	must(os.Chmod(dir, 0700))
	must(os.Chmod(path, 0660))
	if _, err := ReadPreliminaryUpload(path); err == nil {
		t.Fatal("writable upload accepted")
	}
	must(os.Chmod(path, 0600))
	must(os.Link(path, path+".link"))
	if _, err := ReadPreliminaryUpload(path); err == nil {
		t.Fatal("hardlinked upload accepted")
	}
	must(os.Remove(path + ".link"))
	must(os.Remove(path))
	must(os.Symlink("/etc/passwd", path))
	if _, err := ReadPreliminaryUpload(path); err == nil {
		t.Fatal("symlink upload accepted")
	}
}

func publicationSigner(t *testing.T) (*security.CommandSignatureSigner, []byte) {
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

type publicationFixture struct {
	admission     *Admission
	owner, source *security.CommandSignatureSigner
	sourcePublic  []byte
	request       preliminarycapture.Request
	auth          preliminarytransfer.UploadAuthorization
	cfg           Config
}

func newPublicationFixture(t *testing.T) publicationFixture {
	t.Helper()
	cfg := preliminaryConfigFixture(t)
	cfg.PreliminaryCapture.MaxSnapshotBytes = 4096
	cfg.PreliminaryCapture.MaxTotalBytes = 8192
	cfg.PreliminaryCapture.Publication = &PreliminaryPublicationConfig{RequestFile: "/var/lib/terrascale/upload.json", StateDir: "/var/lib/terrascale/upload-state", Journal: configFixture(t).Regional.Runtime}
	configurePublicationIdentity(t, cfg.PreliminaryCapture.Publication)
	owner, public := publicationSigner(t)
	source, sourcePublic := publicationSigner(t)
	block, _ := pem.Decode(sourcePublic)
	cfg.Membership.PublicKey = base64.StdEncoding.EncodeToString(block.Bytes)
	cfg.Peers[0].MembershipPublicKey = cfg.Membership.PublicKey
	if err := cfg.Validate(); err != nil {
		t.Fatalf("publication configuration: %v", err)
	}
	spec := proofFixture(t).Component()
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	spec.Configuration = string(raw)
	manifest, err := hostmanifest.CanonicalHostManifestJSON(hostmanifest.HostManifest{Components: []hostmanifest.ComponentSpec{spec}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	grant, err := nodebootstrap.SignBootstrapGrant(owner, nodebootstrap.BootstrapGrant{Version: 1, GrantID: "upload-owner", NodeID: cfg.NodeID, Manifest: manifest, IssuedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	proof, err := VerifyProof(cfg.NodeID, public, grant)
	if err != nil {
		t.Fatal(err)
	}
	epochDir := "/var/lib/preliminary-upload-epochs"
	if err := os.Mkdir(epochDir, 0700); err != nil {
		t.Fatal(err)
	}
	epochs, err := nodeauthority.NewEpochStore(epochDir, cfg.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { epochs.Close() })
	if err := epochs.AdmitBootstrap(proof.identity.GrantSHA256, proof.identity.ManifestSHA256); err != nil {
		t.Fatal(err)
	}
	if err := Publish(t.Context(), epochs, proof); err != nil {
		t.Fatal(err)
	}
	admission, err := AdmitComponent(t.Context(), spec)
	if err != nil {
		t.Fatal(err)
	}
	request := preliminarycapture.Request{Version: 1, TransitionID: "upload-1", SourceNodeID: cfg.NodeID, InitialGrantSHA256: proof.identity.GrantSHA256, StoreScopeSHA256: proof.identity.StoreScopeSHA256, ProfileSHA256: cfg.ProfileSHA256, Accounts: []preliminarycapture.AccountInventory{{Account: cfg.Regional.Account, Streams: []string{"EVENTS"}}, {Account: cfg.Global.Account, Streams: []string{"SPEC"}}}, ControlEpoch: 1, IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(-30 * time.Minute)}
	return publicationFixture{admission, owner, source, sourcePublic, request, preliminarytransfer.UploadAuthorization{Version: 1, ControlEpoch: 2, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(30 * time.Minute)}, cfg}
}

func (f publicationFixture) wire(t *testing.T, request preliminarycapture.Request, source *security.CommandSignatureSigner, sourcePublic []byte, mutate func(*preliminarytransfer.Scope), auth preliminarytransfer.UploadAuthorization) []byte {
	t.Helper()
	capture, err := preliminarycapture.SignRequest(f.owner, request)
	if err != nil {
		t.Fatal(err)
	}
	created := request.IssuedAt.Add(time.Minute)
	receipt := preliminarycapture.Receipt{Version: 1, Preliminary: true, TransitionID: request.TransitionID, SourceNodeID: request.SourceNodeID, RequestSHA256: preliminarytransfer.Digest(capture), ControlEpoch: request.ControlEpoch, CreatedAt: created}
	for _, a := range request.Accounts {
		key, err := preliminarycapture.ObjectKey(a.Account, a.Streams[0], request.ControlEpoch)
		if err != nil {
			t.Fatal(err)
		}
		receipt.Objects = append(receipt.Objects, preliminarycapture.Object{Account: a.Account, Stream: a.Streams[0], Key: key, SHA256: "sha256:" + strings.Repeat("d", 64), Size: 2048, CreatedAt: created})
	}
	signedReceipt, err := preliminarycapture.SignReceipt(source, receipt)
	if err != nil {
		t.Fatal(err)
	}
	scope := preliminarytransfer.Scope{Version: 1, TransitionID: request.TransitionID, SourceNodeID: request.SourceNodeID, InitialGrantSHA256: request.InitialGrantSHA256, StoreScopeSHA256: request.StoreScopeSHA256, ProfileSHA256: request.ProfileSHA256, SourcePublicKeyPEM: string(sourcePublic), CaptureRequest: capture, CaptureReceipt: signedReceipt, RequestSHA256: preliminarytransfer.Digest(capture), ReceiptSHA256: preliminarytransfer.Digest(signedReceipt), PreparationGrantSHA256: strings.Repeat("e", 64), Prefix: "preliminary/upload-1", MaxRestoreBytes: 8192, MaxSnapshotBytes: 4096, MaxTotalBytes: 8192}
	for _, region := range []string{"gru", "sfo", "fra"} {
		scope.Destinations = append(scope.Destinations, preliminarytransfer.Destination{Region: region, OCIRegion: "oci-" + region, Namespace: "namespace", Bucket: "bucket-" + region, BucketResourceID: "ocid1.bucket." + region, CompartmentID: "ocid1.compartment.test", OwnershipGeneration: 1, OwnershipTags: map[string]string{"terrascale-managed": "orchestrator", "terrascale-region": region}})
		for _, o := range receipt.Objects {
			scope.Objects = append(scope.Objects, preliminarytransfer.ObjectMapping{Region: region, Account: o.Account, Stream: o.Stream, LocalKey: o.Key, ObjectKey: scope.Prefix + "/" + scope.RequestSHA256 + "/" + o.Key, SHA256: o.SHA256, Size: o.Size})
		}
	}
	for _, region := range []string{"sfo", "fra"} {
		_, pub := publicationSigner(t)
		scope.Candidates = append(scope.Candidates, preliminarytransfer.Candidate{Region: region, NodeID: region + "-1", ServerName: region + "-candidate", BootstrapGrantSHA256: strings.Repeat("f", 64), ManifestSHA256: strings.Repeat("1", 64), ReceiptPublicKeyPEM: string(pub)})
	}
	if mutate != nil {
		mutate(&scope)
	}
	scopeRaw, err := preliminarytransfer.CanonicalScope(scope)
	if err != nil {
		t.Fatal(err)
	}
	signedScope, err := preliminarytransfer.SignScope(f.owner, scope)
	if err != nil {
		t.Fatal(err)
	}
	auth.ScopeSHA256 = preliminarytransfer.Digest(scopeRaw)
	signedAuth, err := preliminarytransfer.SignUploadAuthorization(f.owner, auth)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := preliminarytransfer.MarshalRequest(signedScope, signedAuth)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestPreliminaryUploadOriginalAdmissionBinding(t *testing.T) {
	privatePublicationNamespace(t)
	f := newPublicationFixture(t)
	wire := f.wire(t, f.request, f.source, f.sourcePublic, nil, f.auth)
	if _, err := f.admission.VerifyPreliminaryUpload(t.Context(), wire); err != nil {
		t.Fatalf("live upload of expired historical capture: %v", err)
	}
	requestCases := map[string]func(*preliminarycapture.Request){
		"node":                          func(r *preliminarycapture.Request) { r.SourceNodeID = "gru-other" },
		"grant":                         func(r *preliminarycapture.Request) { r.InitialGrantSHA256 = strings.Repeat("b", 64) },
		"store":                         func(r *preliminarycapture.Request) { r.StoreScopeSHA256 = strings.Repeat("b", 64) },
		"profile":                       func(r *preliminarycapture.Request) { r.ProfileSHA256 = strings.Repeat("b", 64) },
		"accounts":                      func(r *preliminarycapture.Request) { r.Accounts[0].Account = "OTHER" },
		"account order":                 func(r *preliminarycapture.Request) { r.Accounts[0], r.Accounts[1] = r.Accounts[1], r.Accounts[0] },
		"historical issue before grant": func(r *preliminarycapture.Request) { r.IssuedAt = f.admission.proof.identity.IssuedAt.Add(-time.Hour) },
		"historical expiry beyond grant": func(r *preliminarycapture.Request) {
			r.ExpiresAt = f.admission.proof.identity.ExpiresAt.Add(time.Minute)
		},
	}
	for name, mutate := range requestCases {
		t.Run(name, func(t *testing.T) {
			request := f.request
			request.Accounts = append([]preliminarycapture.AccountInventory(nil), request.Accounts...)
			mutate(&request)
			raw := f.wire(t, request, f.source, f.sourcePublic, nil, f.auth)
			if _, err := f.admission.VerifyPreliminaryUpload(t.Context(), raw); err == nil {
				t.Fatal("foreign capture scope accepted")
			}
		})
	}
	for _, field := range []string{"snapshot", "total"} {
		t.Run(field+" bound", func(t *testing.T) {
			raw := f.wire(t, f.request, f.source, f.sourcePublic, func(s *preliminarytransfer.Scope) {
				if field == "snapshot" {
					s.MaxSnapshotBytes++
				} else {
					s.MaxTotalBytes++
				}
			}, f.auth)
			if _, err := f.admission.VerifyPreliminaryUpload(t.Context(), raw); err == nil {
				t.Fatal("capacity above original launch accepted")
			}
		})
	}
	foreign, pub := publicationSigner(t)
	raw := f.wire(t, f.request, foreign, pub, nil, f.auth)
	if _, err := f.admission.VerifyPreliminaryUpload(t.Context(), raw); err == nil {
		t.Fatal("owner-nominated foreign source signer accepted")
	}
	auth := f.auth
	auth.ExpiresAt = f.admission.proof.identity.ExpiresAt.Add(time.Minute)
	raw = f.wire(t, f.request, f.source, f.sourcePublic, nil, auth)
	if _, err := f.admission.VerifyPreliminaryUpload(t.Context(), raw); err == nil {
		t.Fatal("upload outliving original grant accepted")
	}
	foreignFixture := f
	foreignFixture.owner = foreign
	raw = foreignFixture.wire(t, f.request, f.source, f.sourcePublic, nil, f.auth)
	if _, err := f.admission.VerifyPreliminaryUpload(t.Context(), raw); err == nil {
		t.Fatal("foreign upload owner accepted")
	}
	var absent *Admission
	if _, err := absent.VerifyPreliminaryUpload(t.Context(), wire); err == nil {
		t.Fatal("missing initial admission accepted")
	}
	if err := os.Remove(filepath.Join(nodeauthority.InitialR1AdmissionDirectory, "initial-r1.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admission.VerifyPreliminaryUpload(t.Context(), wire); err == nil {
		t.Fatal("revoked initial publication accepted")
	}
}

func configurePublicationIdentity(t *testing.T, publication *PreliminaryPublicationConfig) {
	t.Helper()
	publication.Identity.Region = "sa-saopaulo-1"
}
