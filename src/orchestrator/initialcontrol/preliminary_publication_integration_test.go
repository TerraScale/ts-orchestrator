//go:build linux

package initialcontrol_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/initialcontrol"
	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
	"terrascale.tech/orchestrator/src/orchestrator/nodebootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/ociinstance"
	"terrascale.tech/orchestrator/src/orchestrator/preliminarycapture"
	"terrascale.tech/orchestrator/src/orchestrator/preliminarytransfer"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
	ocifixture "terrascale.tech/orchestrator/src/orchestrator/sandboxproviders/ociinstance"
	"terrascale.tech/orchestrator/src/orchestrator/sourcepublication"
	"terrascale.tech/orchestrator/src/orchestrator/transitiongrant"
	"terrascale.tech/orchestrator/src/orchestrator/vmcontrolseed"
)

func publicationDestinations() []preliminarytransfer.Destination {
	var result []preliminarytransfer.Destination
	for i, region := range []string{"gru", "sfo", "fra"} {
		result = append(result, preliminarytransfer.Destination{Region: region, OCIRegion: []string{"sa-saopaulo-1", "us-sanjose-1", "eu-frankfurt-1"}[i], Namespace: "qualification", Bucket: "control-" + region, BucketResourceID: "ocid1.bucket.oc1." + region, CompartmentID: "ocid1.compartment.oc1..qualification", OwnershipGeneration: 1, OwnershipTags: map[string]string{"terrascale-managed": "bucket", "terrascale-region": region}})
	}
	return result
}
func fixtureBucket(d preliminarytransfer.Destination) ocifixture.Bucket {
	return ocifixture.Bucket{OCIRegion: d.OCIRegion, Observation: provider.OCIBucketObservation{ID: d.BucketResourceID, CompartmentID: d.CompartmentID, Namespace: d.Namespace, Name: d.Bucket, FreeformTags: d.OwnershipTags}}
}
func awaitPublication(t *testing.T, runtime *initialcontrol.Runtime, state string, request ...string) initialcontrol.PreliminaryPublicationStatus {
	t.Helper()
	deadline := time.Now().Add(40 * time.Second)
	for time.Now().Before(deadline) {
		status := runtime.PreliminaryPublication()
		if status.State == state && (len(request) == 0 || status.RequestSHA256 == request[0]) {
			return status
		}
		select {
		case <-runtime.Completion():
			t.Fatalf("source stopped waiting for publication %s: %v", state, runtime.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	t.Fatalf("publication did not reach %s: %+v", state, runtime.PreliminaryPublication())
	return initialcontrol.PreliminaryPublicationStatus{}
}
func publicationOwnerPublic(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(nodeauthority.InitialR1AdmissionDirectory, "proof.json"))
	if err != nil {
		t.Fatal(err)
	}
	var proof struct {
		PublicKey []byte `json:"publicKey"`
	}
	if err := json.Unmarshal(raw, &proof); err != nil {
		t.Fatal(err)
	}
	return proof.PublicKey
}

// The exact target descriptors are owner-signed preparations. This helper does
// not run a candidate or claim admission, synchronization or final-cut success.
func publicationScope(t *testing.T, f *fixture, request, receiptRaw []byte, destinations []preliminarytransfer.Destination) preliminarytransfer.VerifiedScope {
	t.Helper()
	public := publicationOwnerPublic(t)
	captured, err := preliminarycapture.VerifyRequest(public, request)
	if err != nil {
		t.Fatal(err)
	}
	der, err := base64.StdEncoding.DecodeString(f.config.Membership.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sourcePublic := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	receipt, err := preliminarycapture.VerifyReceipt(sourcePublic, receiptRaw)
	if err != nil {
		t.Fatal(err)
	}
	identity := f.proof.Identity()
	now := time.Now().UTC()
	scope := preliminarytransfer.Scope{Version: 1, TransitionID: captured.Request.TransitionID, SourceNodeID: identity.NodeID, InitialGrantSHA256: identity.GrantSHA256, StoreScopeSHA256: identity.StoreScopeSHA256, ProfileSHA256: f.config.ProfileSHA256, SourcePublicKeyPEM: string(sourcePublic), CaptureRequest: request, CaptureReceipt: receiptRaw, RequestSHA256: captured.Digest, ReceiptSHA256: preliminarytransfer.Digest(receiptRaw), Prefix: "jetstream/preliminary", Destinations: destinations, MaxSnapshotBytes: f.config.PreliminaryCapture.MaxSnapshotBytes, MaxTotalBytes: f.config.PreliminaryCapture.MaxTotalBytes, MaxRestoreBytes: 128 << 20}
	prep := transitiongrant.Grant{Version: 1, TransitionID: scope.TransitionID, IssuedAt: now.Add(-time.Second), ExpiresAt: now.Add(20 * time.Minute), TargetEpoch: captured.Request.ControlEpoch + 1, MinimumControlEpoch: captured.Request.ControlEpoch, Source: transitiongrant.SourceIdentity{NodeID: identity.NodeID, ServerName: f.config.Broker.ServerName, InitialGrantSHA256: identity.GrantSHA256, StoreScopeSHA256: identity.StoreScopeSHA256}, Peers: []transitiongrant.Peer{{Region: "gru", NodeID: identity.NodeID, ServerName: f.config.Broker.ServerName, BootstrapGrantSHA256: identity.GrantSHA256, PreparedManifestSHA256: identity.ManifestSHA256}}}
	readerRaw, _ := json.Marshal(f.config.AuthorityReader)
	for i, region := range []string{"sfo", "fra"} {
		private, pin := memberKey(t)
		clear(private)
		der, err := base64.StdEncoding.DecodeString(pin)
		if err != nil {
			t.Fatal(err)
		}
		publicPin := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
		cfg := transitiongrant.Config{Version: 1, Mode: transitiongrant.Mode, TransitionID: scope.TransitionID, NodeID: region + "-publication-target", Region: region, ServerName: region + "-publication-store", StoreDir: "/var/lib/terrascale/orchestrator/candidate", GrantFile: "/etc/terrascale/candidate/grant.json", GrantPublicKeyFile: "/etc/terrascale/candidate/owner.pem", Sync: &transitiongrant.CandidateSyncConfig{AuthorityReaderSHA256: preliminarytransfer.Digest(readerRaw), RequestFile: "/etc/terrascale/candidate/request.json", StagingDir: "/var/lib/terrascale/orchestrator/staging", ReceiptDir: "/var/lib/terrascale/orchestrator/receipts", ReceiptPrivateKeyFile: "/etc/terrascale/candidate/receipt.key", ReceiptPublicKeyPEM: string(publicPin), MaxSnapshotBytes: scope.MaxSnapshotBytes, MaxTotalBytes: scope.MaxTotalBytes, MaxRestoreBytes: scope.MaxRestoreBytes, Identity: ociinstance.Config{Region: destinations[i+1].OCIRegion}}}
		manifest, err := bootstrap.PlanControlCandidateManifest(hostmanifest.HostManifest{Components: []hostmanifest.ComponentSpec{f.proof.Component()}}, cfg)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := hostmanifest.CanonicalHostManifestJSON(manifest)
		if err != nil {
			t.Fatal(err)
		}
		signed, err := nodebootstrap.SignBootstrapGrant(f.owner, nodebootstrap.BootstrapGrant{Version: 1, GrantID: region + "-publication-bootstrap", NodeID: cfg.NodeID, Manifest: raw, IssuedAt: prep.IssuedAt, ExpiresAt: prep.ExpiresAt})
		if err != nil {
			t.Fatal(err)
		}
		peer, err := bootstrap.PlanControlCandidatePeer(cfg, public, signed)
		if err != nil {
			t.Fatal(err)
		}
		prep.Peers = append(prep.Peers, peer)
		scope.Candidates = append(scope.Candidates, preliminarytransfer.Candidate{Region: region, NodeID: peer.NodeID, ServerName: peer.ServerName, BootstrapGrantSHA256: peer.BootstrapGrantSHA256, ManifestSHA256: peer.PreparedManifestSHA256, ReceiptPublicKeyPEM: string(publicPin)})
	}
	prepSigned, err := transitiongrant.SignGrant(f.owner, prep)
	if err != nil {
		t.Fatal(err)
	}
	scope.PreparationGrantSHA256 = preliminarytransfer.Digest(prepSigned)
	for _, d := range destinations {
		for _, o := range receipt.Objects {
			scope.Objects = append(scope.Objects, preliminarytransfer.ObjectMapping{Region: d.Region, Account: o.Account, Stream: o.Stream, LocalKey: o.Key, ObjectKey: scope.Prefix + "/" + scope.RequestSHA256 + "/" + o.Key, SHA256: o.SHA256, Size: o.Size})
		}
	}
	signed, err := preliminarytransfer.SignScope(f.owner, scope)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := preliminarytransfer.VerifyScope(public, signed)
	if err != nil {
		t.Fatal(err)
	}
	return verified
}
func publicationUpload(t *testing.T, f *fixture, scope preliminarytransfer.VerifiedScope, epoch uint64) preliminarytransfer.VerifiedUpload {
	t.Helper()
	auth := preliminarytransfer.UploadAuthorization{Version: 1, ScopeSHA256: scope.Digest, ControlEpoch: epoch, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(15 * time.Minute)}
	signed, err := preliminarytransfer.SignUploadAuthorization(f.owner, auth)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := preliminarytransfer.MarshalRequest(scope.Signed, signed)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := preliminarytransfer.VerifyUploadRequest(publicationOwnerPublic(t), raw, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	return verified
}
func publicationPUTs(server *ocifixture.Server) int {
	count := 0
	for _, r := range server.Requests() {
		if r.Method == "PUT" {
			count++
		}
	}
	return count
}

func TestInitialRuntimePreliminaryPublicationRealIdentityAndRestart(t *testing.T) {
	namespace(t)
	destinations := publicationDestinations()
	var buckets []ocifixture.Bucket
	for _, d := range destinations {
		buckets = append(buckets, fixtureBucket(d))
	}
	cloud, err := ocifixture.New(ocifixture.Config{Buckets: buckets, MaxObjectBytes: 32 << 20})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cloud.Close)
	t.Cleanup(func() {
		if t.Failed() {
			requests := cloud.Requests()
			start := max(0, len(requests)-12)
			t.Logf("bounded final OCI observations: %+v", requests[start:])
		}
	})
	keyPath := filepath.Join(t.TempDir(), "fixture-client.key")
	identity, key, err := cloud.Identity("gru-one", "sa-saopaulo-1", keyPath)
	if err != nil {
		t.Fatal(err)
	}
	write(t, keyPath, key)
	clear(key)
	declarationPath := filepath.Join(t.TempDir(), "publication.json")
	declarationRaw, _ := json.Marshal(vmcontrolseed.PreliminaryPublicationDeclaration{Identity: identity})
	write(t, declarationPath, declarationRaw)
	declaration, err := vmcontrolseed.LoadPreliminaryPublicationDeclaration(declarationPath)
	if err != nil {
		t.Fatal(err)
	}
	defer declaration.Clear()
	config, _ := fixtureConfigCaptureDeclaration(t, &vmcontrolseed.PreliminaryCaptureDeclaration{MaxSnapshotBytes: 32 << 20, MaxTotalBytes: 128 << 20, Publication: declaration})
	f := admit(t, config)
	runtime, err := initialcontrol.Start(t.Context(), f.admission)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { runtime.Close() })
	awaitCapture(t, runtime, "idle")
	awaitPublication(t, runtime, "idle")
	t.Log("admitted source capture and publication workers idle")
	for _, store := range []struct {
		identity initialgrant.Connection
		bucket   string
	}{{*config.Regional.Provisioner, "ORCH_DELIVERY"}, {*config.Global.Provisioner, "GLOBAL_DELIVERIES"}} {
		nc := client(t, config, store.identity)
		js, err := jetstream.New(nc)
		if err != nil {
			t.Fatal(err)
		}
		kv, err := js.KeyValue(t.Context(), store.bucket)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := kv.Put(t.Context(), "publication-proof", bytes.Repeat([]byte(store.bucket), 4096)); err != nil {
			t.Fatal(err)
		}
		nc.Close()
	}
	capture := captureRequest(t, f, runtime, "publication-runtime")
	captureRaw := publishCaptureRequest(t, f, capture)
	awaitCapture(t, runtime, "complete")
	t.Log("actual both-account capture complete")
	receiptPath := filepath.Join(config.PreliminaryCapture.OutputDir, "receipt.json")
	receiptRaw, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	scope := publicationScope(t, f, captureRaw, receiptRaw, destinations)
	// A correctly signed future term still cannot borrow the source's live lease.
	wrongTerm := publicationUpload(t, f, scope, uint64(runtime.GlobalAuthority().Epoch)+1)
	write(t, config.PreliminaryCapture.Publication.RequestFile, wrongTerm.Signed)
	awaitPublication(t, runtime, "failed")
	t.Log("wrong live upload epoch refused")
	if len(cloud.Requests()) != 0 {
		t.Fatal("wrong current authority contacted OCI")
	}
	good := publicationUpload(t, f, scope, uint64(runtime.GlobalAuthority().Epoch))
	foreign := fixtureBucket(destinations[0])
	foreign.Observation.CompartmentID = "ocid1.compartment.oc1..foreign"
	if err := cloud.SetBucket(foreign); err != nil {
		t.Fatal(err)
	}
	write(t, config.PreliminaryCapture.Publication.RequestFile, good.Signed)
	deadline := time.Now().Add(40 * time.Second)
	for len(cloud.Requests()) == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	awaitPublication(t, runtime, "failed", good.Digest)
	t.Logf("foreign bucket refused after %d authenticated provider observations", len(cloud.Requests()))
	if publicationPUTs(cloud) != 0 {
		t.Fatal("foreign bucket received objects")
	}
	if !runtime.GlobalAuthority().Ready() {
		t.Fatal("publication failure stopped source authority")
	}
	if err := cloud.SetBucket(fixtureBucket(destinations[0])); err != nil {
		t.Fatal(err)
	}
	status := awaitPublication(t, runtime, "complete")
	if status.ScopeSHA256 != scope.Digest || status.RequestSHA256 != good.Digest || status.ReceiptSHA256 == "" {
		t.Fatalf("public publication status lacks exact receipts: %+v", status)
	}
	expectedPUTs := len(scope.Scope.Objects) + len(destinations)
	if publicationPUTs(cloud) != expectedPUTs {
		t.Fatalf("PUT count=%d want%d", publicationPUTs(cloud), expectedPUTs)
	}
	var publicationReceipt []byte
	for _, d := range destinations {
		body, found := cloud.Object(d.OCIRegion, d.Namespace, d.Bucket, preliminarytransfer.PublicationKey(scope.Scope))
		if !found {
			t.Fatal("regional publication receipt missing")
		}
		if publicationReceipt == nil {
			publicationReceipt = body
		} else if !bytes.Equal(body, publicationReceipt) {
			t.Fatal("regional receipt bytes differ")
		}
		if _, err := preliminarytransfer.CheckPublication(good, body); err != nil {
			t.Fatal(err)
		}
	}
	if preliminarytransfer.Digest(publicationReceipt) != status.ReceiptSHA256 {
		t.Fatal("public status differs from actual provider receipt")
	}
	for _, o := range scope.Scope.Objects {
		var d preliminarytransfer.Destination
		for _, candidate := range destinations {
			if candidate.Region == o.Region {
				d = candidate
			}
		}
		body, found := cloud.Object(d.OCIRegion, d.Namespace, d.Bucket, o.ObjectKey)
		if !found || int64(len(body)) != o.Size || "sha256:"+preliminarytransfer.Digest(body) != o.SHA256 {
			t.Fatal("provider snapshot bytes differ from signed source capture")
		}
	}
	// Prove provider effects were journaled by the actual embedded source store.
	nc := client(t, config, *config.Regional.Provisioner)
	js, _ := jetstream.New(nc)
	journal, err := js.KeyValue(t.Context(), "ORCH_OPERATIONS")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range destinations {
		entry, err := journal.Get(t.Context(), sourcepublication.OwnershipKey(d.BucketResourceID))
		if err != nil || len(entry.Value()) == 0 {
			t.Fatal("bucket ownership was not durably journaled", err)
		}
	}
	nc.Close()
	methods := map[string]bool{}
	federated := false
	for _, r := range cloud.Requests() {
		methods[r.Method] = true
		if strings.Contains(r.Path, "x509") {
			federated = true
		}
	}
	if !methods["GET"] || !methods["HEAD"] || !methods["PUT"] || !federated {
		t.Fatalf("missing actual provider/identity operations: %v federation=%v", methods, federated)
	}
	t.Logf("source captured both accounts and published %d exact snapshots with signed instance-principal HTTP and durable journal", len(scope.Scope.Objects))
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	runtime, err = initialcontrol.Start(t.Context(), f.admission)
	if err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(25 * time.Second)
	for time.Now().Before(deadline) {
		a := runtime.GlobalAuthority()
		if a.Ready() && a.IsLeader && uint64(a.Epoch) > capture.ControlEpoch {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	authority := runtime.GlobalAuthority()
	if !authority.Ready() || uint64(authority.Epoch) <= capture.ControlEpoch {
		t.Fatal("actual restarted source did not advance authority")
	}
	awaitPublication(t, runtime, "failed")
	renewed := publicationUpload(t, f, scope, uint64(authority.Epoch))
	if err := preliminarytransfer.CheckUploadRenewal(good, renewed); err != nil {
		t.Fatal(err)
	}
	write(t, config.PreliminaryCapture.Publication.RequestFile, renewed.Signed)
	resumed := awaitPublication(t, runtime, "complete")
	if resumed.ReceiptSHA256 != status.ReceiptSHA256 || resumed.RequestSHA256 != renewed.Digest || publicationPUTs(cloud) != expectedPUTs {
		t.Fatal("renewed source changed immutable publication or repeated PUT")
	}
	after, err := os.ReadFile(receiptPath)
	if err != nil || !bytes.Equal(after, receiptRaw) {
		t.Fatal("new upload epoch changed historical capture receipt", err)
	}
	for _, d := range destinations {
		body, found := cloud.Object(d.OCIRegion, d.Namespace, d.Bucket, preliminarytransfer.PublicationKey(scope.Scope))
		if !found || !bytes.Equal(body, publicationReceipt) {
			t.Fatal("restart changed provider receipt")
		}
	}
	t.Logf("actual source restart advanced upload epoch %d to%d without recapture or provider object rewrite", capture.ControlEpoch, authority.Epoch)
}
