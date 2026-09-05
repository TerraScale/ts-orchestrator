package candidatesync

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"terrascale.tech/orchestrator/src/orchestrator/delivery"
	"terrascale.tech/orchestrator/src/orchestrator/ociinstance"
	"terrascale.tech/orchestrator/src/orchestrator/preliminarycapture"
	"terrascale.tech/orchestrator/src/orchestrator/preliminarytransfer"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
	"terrascale.tech/orchestrator/src/orchestrator/restoredrill"
	ocifixture "terrascale.tech/orchestrator/src/orchestrator/sandboxproviders/ociinstance"
	"terrascale.tech/orchestrator/src/orchestrator/security"
	"terrascale.tech/orchestrator/src/orchestrator/transitiongrant"
)

type memoryObjects struct {
	objects map[string][]byte
	bucket  provider.OCIBucketObservation
}

func (m *memoryObjects) Put(_ context.Context, _, _, key string, raw []byte) error {
	m.objects[key] = bytes.Clone(raw)
	return nil
}
func (m *memoryObjects) GetSnapshot(_ context.Context, _, _, key string) ([]byte, bool, error) {
	raw, ok := m.objects[key]
	return bytes.Clone(raw), ok, nil
}
func (m *memoryObjects) Head(_ context.Context, _, _, key string) (delivery.ObjectIdentity, bool, error) {
	raw, ok := m.objects[key]
	return delivery.ObjectIdentity{Digest: delivery.SHA256Digest(raw), Size: int64(len(raw)), ETag: "etag"}, ok, nil
}
func (m *memoryObjects) ObserveBucket(context.Context) (provider.OCIBucketObservation, bool, error) {
	return m.bucket, true, nil
}
func (m *memoryObjects) HeadObject(_ context.Context, r provider.ObjectRef) (provider.ObjectMetadata, bool, error) {
	raw, ok := m.objects[r.Name]
	return provider.ObjectMetadata{SHA256: delivery.SHA256Digest(raw), Size: int64(len(raw)), ETag: "etag"}, ok, nil
}
func (m *memoryObjects) GetObject(ctx context.Context, r provider.ObjectRef) (io.ReadCloser, provider.ObjectMetadata, error) {
	meta, _, _ := m.HeadObject(ctx, r)
	return io.NopCloser(bytes.NewReader(m.objects[r.Name])), meta, nil
}
func testSigner(t *testing.T) (*security.CommandSignatureSigner, []byte, []byte) {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	s, e := security.NewCommandSignatureSignerFromKey(key)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	pub, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	priv, _ := x509.MarshalPKCS8PrivateKey(key)
	return s, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: priv})
}

type fixture struct {
	config      transitiongrant.Config
	verified    preliminarytransfer.VerifiedCandidate
	objects     *memoryObjects
	owner       *security.CommandSignatureSigner
	ownerPublic []byte
	source      *security.CommandSignatureSigner
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	owner, ownerPublic, _ := testSigner(t)
	source, sourcePublic, _ := testSigner(t)
	_, candidatePublic, candidatePrivate := testSigner(t)
	_, fraPublic, _ := testSigner(t)
	now := time.Now().UTC()
	h := func(s string) string { return strings.Repeat(s, 64) }
	request := preliminarycapture.Request{Version: 1, TransitionID: "transition-1", SourceNodeID: "gru-1", InitialGrantSHA256: h("a"), StoreScopeSHA256: h("b"), ProfileSHA256: h("c"), Accounts: []preliminarycapture.AccountInventory{{Account: "GLOBAL", Streams: []string{"SPEC"}}, {Account: "REGIONAL", Streams: []string{"EVENTS"}}}, ControlEpoch: 5, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)}
	signedRequest, e := preliminarycapture.SignRequest(owner, request)
	if e != nil {
		t.Fatal(e)
	}
	objects := &memoryObjects{objects: map[string][]byte{}}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	mappings := []preliminarytransfer.ObjectMapping{{Account: "GLOBAL", Stream: "SPEC"}, {Account: "REGIONAL", Stream: "EVENTS"}}
	broker, e := startBroker(ctx, t.TempDir(), 32<<20, mappings)
	if e != nil {
		t.Fatal(e)
	}
	defer broker.close()
	receipt := preliminarycapture.Receipt{Version: 1, Preliminary: true, TransitionID: request.TransitionID, RequestSHA256: preliminarytransfer.Digest(signedRequest), SourceNodeID: request.SourceNodeID, ControlEpoch: 5}
	for _, o := range mappings {
		nc := broker.connections[o.Account]
		js, _ := jetstream.New(nc)
		stream, e := js.CreateStream(ctx, jetstream.StreamConfig{Name: o.Stream, Subjects: []string{"events.>"}, Storage: jetstream.FileStorage, MaxBytes: 1 << 20})
		if e != nil {
			t.Fatal(e)
		}
		for i := 0; i < 3; i++ {
			if _, e = js.PublishMsg(ctx, &nats.Msg{Subject: "events.one", Data: []byte{byte(i), 0, 255}, Header: nats.Header{"X-Account": []string{o.Account}}}); e != nil {
				t.Fatal(e)
			}
		}
		consumer, e := stream.CreateConsumer(ctx, jetstream.ConsumerConfig{Durable: "CHECKPOINT", AckPolicy: jetstream.AckExplicitPolicy, AckWait: time.Hour})
		if e != nil {
			t.Fatal(e)
		}
		batch, e := consumer.Fetch(2, jetstream.FetchMaxWait(time.Second))
		if e != nil {
			t.Fatal(e)
		}
		i := 0
		for msg := range batch.Messages() {
			if i == 0 {
				if e = msg.DoubleAck(ctx); e != nil {
					t.Fatal(e)
				}
			}
			i++
		}
		key, _ := preliminarycapture.ObjectKey(o.Account, o.Stream, 5)
		snapshotter, e := restoredrill.NewNATSJetStreamSnapshotter(restoredrill.NATSJetStreamSnapshotterConfig{Connection: nc, Stream: o.Stream, Store: objects, Region: "gru", Bucket: o.Account, MaxBytes: 8 << 20, Timeout: 10 * time.Second})
		if e != nil {
			t.Fatal(e)
		}
		snap, e := snapshotter.Snapshot(ctx, restoredrill.SnapshotRequest{RunID: request.TransitionID, IdempotencyKey: request.TransitionID, ObjectKey: key, ControlEpoch: 5})
		if e != nil {
			t.Fatal(e)
		}
		receipt.Objects = append(receipt.Objects, preliminarycapture.Object{Account: o.Account, Stream: o.Stream, Key: key, SHA256: snap.Checksum, Size: snap.Size, CreatedAt: snap.CreatedAt})
	}
	receipt.CreatedAt = time.Now().UTC()
	signedReceipt, e := preliminarycapture.SignReceipt(source, receipt)
	if e != nil {
		t.Fatal(e)
	}
	scope := preliminarytransfer.Scope{Version: 1, TransitionID: request.TransitionID, SourceNodeID: request.SourceNodeID, InitialGrantSHA256: request.InitialGrantSHA256, StoreScopeSHA256: request.StoreScopeSHA256, ProfileSHA256: request.ProfileSHA256, SourcePublicKeyPEM: string(sourcePublic), CaptureRequest: signedRequest, CaptureReceipt: signedReceipt, RequestSHA256: receipt.RequestSHA256, ReceiptSHA256: preliminarytransfer.Digest(signedReceipt), PreparationGrantSHA256: h("e"), Prefix: "preliminary/transition-1", MaxRestoreBytes: 32 << 20, MaxSnapshotBytes: 8 << 20, MaxTotalBytes: 32 << 20}
	for i, region := range []string{"gru", "sfo", "fra"} {
		d := preliminarytransfer.Destination{Region: region, OCIRegion: []string{"sa-saopaulo-1", "us-sanjose-1", "eu-frankfurt-1"}[i], Namespace: "namespace", Bucket: "bucket-" + region, BucketResourceID: "ocid1.bucket." + region, CompartmentID: "ocid1.compartment.test", OwnershipGeneration: 1, OwnershipTags: map[string]string{"terrascale-managed": "orchestrator", "terrascale-region": region}}
		scope.Destinations = append(scope.Destinations, d)
		if region == "sfo" {
			objects.bucket = provider.OCIBucketObservation{ID: d.BucketResourceID, CompartmentID: d.CompartmentID, Namespace: d.Namespace, Name: d.Bucket, FreeformTags: d.OwnershipTags}
		}
		for _, o := range receipt.Objects {
			mapping := preliminarytransfer.ObjectMapping{Region: region, Account: o.Account, Stream: o.Stream, LocalKey: o.Key, ObjectKey: scope.Prefix + "/" + scope.RequestSHA256 + "/" + o.Key, SHA256: o.SHA256, Size: o.Size}
			scope.Objects = append(scope.Objects, mapping)
			objects.objects[mapping.ObjectKey] = objects.objects[o.Key]
		}
	}
	for i, region := range []string{"sfo", "fra"} {
		scope.Candidates = append(scope.Candidates, preliminarytransfer.Candidate{Region: region, NodeID: region + "-1", ServerName: region + "-candidate-1", BootstrapGrantSHA256: h("f"), ManifestSHA256: h("1"), ReceiptPublicKeyPEM: string([][]byte{candidatePublic, fraPublic}[i])})
	}
	signedScope, e := preliminarytransfer.SignScope(owner, scope)
	if e != nil {
		t.Fatal(e)
	}
	auth, e := preliminarytransfer.SignCandidateAuthorization(owner, preliminarytransfer.CandidateAuthorization{Version: 1, ScopeSHA256: preliminarytransfer.Digest(mustScope(t, scope)), NodeID: "sfo-1", IssuedAt: time.Now().UTC(), ExpiresAt: now.Add(time.Hour)})
	if e != nil {
		t.Fatal(e)
	}
	raw, e := preliminarytransfer.MarshalRequest(signedScope, auth)
	if e != nil {
		t.Fatal(e)
	}
	verified, e := preliminarytransfer.VerifyCandidateRequest(ownerPublic, raw, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	uploadAuth, e := preliminarytransfer.SignUploadAuthorization(owner, preliminarytransfer.UploadAuthorization{Version: 1, ScopeSHA256: verified.Scope.Digest, ControlEpoch: 5, IssuedAt: time.Now().UTC(), ExpiresAt: now.Add(time.Hour)})
	if e != nil {
		t.Fatal(e)
	}
	uploadRaw, e := preliminarytransfer.MarshalRequest(signedScope, uploadAuth)
	if e != nil {
		t.Fatal(e)
	}
	publication := preliminarytransfer.PublicationReceipt{Version: 1, UploadAuthorization: uploadAuth, ScopeSHA256: verified.Scope.Digest, UploadRequestSHA256: preliminarytransfer.Digest(uploadRaw), ControlEpoch: 5, CreatedAt: time.Now().UTC()}
	for _, o := range scope.Objects {
		publication.Objects = append(publication.Objects, preliminarytransfer.PublishedObject{ObjectMapping: o, ETag: "etag"})
	}
	publicationRaw, e := preliminarytransfer.SignPublicationReceipt(source, publication)
	if e != nil {
		t.Fatal(e)
	}
	objects.objects[preliminarytransfer.PublicationKey(scope)] = publicationRaw
	dir := t.TempDir()
	privatePath := filepath.Join(dir, "candidate.pem")
	if e = os.WriteFile(privatePath, candidatePrivate, 0600); e != nil {
		t.Fatal(e)
	}
	config := transitiongrant.Config{Version: 1, Mode: transitiongrant.Mode, TransitionID: request.TransitionID, NodeID: "sfo-1", Region: "sfo", ServerName: "sfo-candidate-1", StoreDir: filepath.Join(dir, "final-store"), GrantFile: filepath.Join(dir, "grant.json"), GrantPublicKeyFile: filepath.Join(dir, "owner.pem"), Sync: &transitiongrant.CandidateSyncConfig{AuthorityReaderSHA256: h("2"), RequestFile: filepath.Join(dir, "request.json"), StagingDir: filepath.Join(dir, "stage"), ReceiptDir: filepath.Join(dir, "receipts"), ReceiptPrivateKeyFile: privatePath, ReceiptPublicKeyPEM: string(candidatePublic), MaxSnapshotBytes: scope.MaxSnapshotBytes, MaxTotalBytes: scope.MaxTotalBytes, MaxRestoreBytes: scope.MaxRestoreBytes, Identity: ociinstance.Config{Region: "us-sanjose-1"}}}
	return fixture{config, verified, objects, owner, ownerPublic, source}
}
func mustScope(t *testing.T, s preliminarytransfer.Scope) []byte {
	t.Helper()
	raw, e := preliminarytransfer.CanonicalScope(s)
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func (f fixture) factory(context.Context, transitiongrant.CandidateSyncConfig, preliminarytransfer.Destination, string) (objectReader, func(), error) {
	return f.objects, func() {}, nil
}
func TestCandidateRestoresAndReverifiesReceipt(t *testing.T) {
	f := newFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	raw, e := run(ctx, f.config, f.verified, f.factory)
	if e != nil {
		t.Fatal(e)
	}
	r, e := VerifyReceipt([]byte(f.config.Sync.ReceiptPublicKeyPEM), raw)
	if e != nil || len(r.Objects) != 2 || len(r.Objects[0].RestoreSHA256) != 64 {
		t.Fatalf("receipt %+v %v", r, e)
	}
	if _, e = os.Stat(f.config.StoreDir); !os.IsNotExist(e) {
		t.Fatal("final runtime store touched")
	}
	replay, e := run(ctx, f.config, f.verified, f.factory)
	if e != nil || !bytes.Equal(raw, replay) {
		t.Fatalf("replay receipt changed: %v", e)
	}
	// A completed receipt never skips local corruption checks.
	var object preliminarytransfer.ObjectMapping
	for _, o := range f.verified.Scope.Scope.Objects {
		if o.Region == "sfo" {
			object = o
			break
		}
	}
	path := filepath.Join(f.config.Sync.StagingDir, artifactName(object))
	if e = os.WriteFile(path, []byte("corrupt"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = run(ctx, f.config, f.verified, f.factory); e == nil {
		t.Fatal("corrupt immutable staged object accepted")
	}
}

func TestCandidateRenewalRetainsReceiptAndRejectsChangedCheckpoint(t *testing.T) {
	f := newFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	raw, e := run(ctx, f.config, f.verified, f.factory)
	if e != nil {
		t.Fatal(e)
	}
	authorization := f.verified.Authorization
	authorization.IssuedAt = time.Now().UTC()
	authorization.ExpiresAt = authorization.ExpiresAt.Add(time.Minute)
	signed, e := preliminarytransfer.SignCandidateAuthorization(f.owner, authorization)
	if e != nil {
		t.Fatal(e)
	}
	request, e := preliminarytransfer.MarshalRequest(f.verified.Scope.Signed, signed)
	if e != nil {
		t.Fatal(e)
	}
	renewed, e := preliminarytransfer.VerifyCandidateRequest(f.ownerPublic, request, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	replay, e := run(ctx, f.config, renewed, f.factory)
	if e != nil || !bytes.Equal(raw, replay) {
		t.Fatalf("renewed authorization changed receipt: %v", e)
	}
	mappings := []preliminarytransfer.ObjectMapping{}
	for _, o := range f.verified.Scope.Scope.Objects {
		if o.Region == "sfo" {
			mappings = append(mappings, o)
		}
	}
	b, e := startBroker(ctx, filepath.Join(f.config.Sync.StagingDir, "target"), f.config.Sync.MaxRestoreBytes, mappings)
	if e != nil {
		t.Fatal(e)
	}
	js, _ := jetstream.New(b.connections[mappings[0].Account])
	stream, e := js.Stream(ctx, mappings[0].Stream)
	if e != nil {
		b.close()
		t.Fatal(e)
	}
	consumer, e := stream.Consumer(ctx, "CHECKPOINT")
	if e != nil {
		b.close()
		t.Fatal(e)
	}
	batch, e := consumer.Fetch(1, jetstream.FetchMaxWait(time.Second))
	if e != nil {
		b.close()
		t.Fatal(e)
	}
	for msg := range batch.Messages() {
		if e = msg.DoubleAck(ctx); e != nil {
			b.close()
			t.Fatal(e)
		}
	}
	b.close()
	if _, e = run(ctx, f.config, renewed, f.factory); e == nil {
		t.Fatal("changed persistent consumer checkpoint accepted")
	}
	retained, e := os.ReadFile(filepath.Join(f.config.Sync.ReceiptDir, "receipt.json"))
	if e != nil || !bytes.Equal(retained, raw) {
		t.Fatal("conflicting replay replaced receipt")
	}
}
func TestCandidateRefusesWrongOwnershipAndMissingPublication(t *testing.T) {
	for _, test := range []string{"bucket", "publication"} {
		t.Run(test, func(t *testing.T) {
			f := newFixture(t)
			if test == "bucket" {
				f.objects.bucket.ID = "ocid1.bucket.foreign"
			} else {
				delete(f.objects.objects, preliminarytransfer.PublicationKey(f.verified.Scope.Scope))
			}
			if _, e := run(context.Background(), f.config, f.verified, f.factory); e == nil {
				t.Fatal("unproven object store accepted")
			}
			if _, e := os.Stat(filepath.Join(f.config.Sync.StagingDir, "target")); !os.IsNotExist(e) {
				t.Fatal("broker started before publication was proven")
			}
		})
	}
}
func TestCandidateRecoversOnlyOwnedTemporaryState(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, e := run(ctx, f.config, f.verified, f.factory); e != nil {
		t.Fatal(e)
	}
	s, e := newStage(f.config.Sync.StagingDir, func() error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	pin := mustScope(t, f.verified.Scope.Scope)
	reference, e := newReference(ctx, s, pin)
	if e != nil {
		s.close()
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(reference, "interrupted"), []byte("temporary"), 0600); e != nil {
		s.close()
		t.Fatal(e)
	}
	temporary := filepath.Join(f.config.Sync.StagingDir, ".staging-"+strings.Repeat("a", 32))
	if e = os.WriteFile(temporary, []byte("incomplete"), 0600); e != nil {
		s.close()
		t.Fatal(e)
	}
	s.close()
	if _, e = run(ctx, f.config, f.verified, f.factory); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(temporary); !os.IsNotExist(e) {
		t.Fatal("owned temporary file was not recovered")
	}
	unknown := filepath.Join(f.config.Sync.StagingDir, ".reference-"+strings.Repeat("b", 32))
	if e = os.Mkdir(unknown, 0700); e != nil {
		t.Fatal(e)
	}
	foreign := filepath.Join(unknown, "foreign")
	if e = os.WriteFile(foreign, []byte("keep"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = run(ctx, f.config, f.verified, f.factory); e == nil {
		t.Fatal("unknown reference state accepted")
	}
	if raw, e := os.ReadFile(foreign); e != nil || string(raw) != "keep" {
		t.Fatal("unknown reference state deleted")
	}
}

func TestCandidateProductionSDKMTLSReadAndPrivateRestore(t *testing.T) {
	f := newFixture(t)
	destination := f.verified.Scope.Scope.Destinations[1]
	server, e := ocifixture.New(ocifixture.Config{Buckets: []ocifixture.Bucket{{OCIRegion: destination.OCIRegion, Observation: f.objects.bucket}}, MaxObjectBytes: f.config.Sync.MaxSnapshotBytes})
	if e != nil {
		t.Fatal(e)
	}
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	uploadConfig, uploadKey, e := server.Identity("source-uploader", destination.OCIRegion, "/qualification/source.key")
	if e != nil {
		t.Fatal(e)
	}
	uploader, e := ociinstance.NewFromConfig(ctx, uploadConfig, func(string) ([]byte, error) { return bytes.Clone(uploadKey), nil })
	if e != nil {
		t.Fatal(e)
	}
	defer uploader.Close()
	transport, e := uploader.NewTransport(provider.OCIServiceObjectStorage, f.config.Sync.MaxSnapshotBytes)
	if e != nil {
		t.Fatal(e)
	}
	put := func(name string, raw []byte) string {
		t.Helper()
		response, e := transport.PutObjectBody(ctx, provider.ObjectRef{Namespace: destination.Namespace, Bucket: destination.Bucket, Name: name}, bytes.NewReader(raw), map[string]string{"Content-Type": "application/octet-stream", "If-None-Match": "*", "opc-meta-terrascale-sha256": strings.TrimPrefix(delivery.SHA256Digest(raw), "sha256:")})
		if e != nil {
			t.Fatal(e)
		}
		defer response.Body.Close()
		if response.StatusCode != 200 {
			body, _ := io.ReadAll(response.Body)
			t.Fatalf("fixture upload status %d: %s", response.StatusCode, body)
		}
		io.Copy(io.Discard, response.Body)
		return response.Header.Get("ETag")
	}
	publicationKey := preliminarytransfer.PublicationKey(f.verified.Scope.Scope)
	publication, e := preliminarytransfer.CheckPublicationForScope(f.verified.Scope, f.objects.objects[publicationKey])
	if e != nil {
		t.Fatal(e)
	}
	for i, o := range publication.Objects {
		if o.Region == "sfo" {
			publication.Objects[i].ETag = put(o.ObjectKey, f.objects.objects[o.ObjectKey])
		}
	}
	publication.CreatedAt = time.Now().UTC()
	publicationRaw, e := preliminarytransfer.SignPublicationReceipt(f.source, publication)
	if e != nil {
		t.Fatal(e)
	}
	put(publicationKey, publicationRaw)
	uploader.Close()
	clientKeyFile := filepath.Join(filepath.Dir(f.config.Sync.StagingDir), "oci-client.key")
	identity, key, e := server.Identity(f.config.NodeID, destination.OCIRegion, clientKeyFile)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(clientKeyFile, key, 0600); e != nil {
		t.Fatal(e)
	}
	f.config.Sync.Identity = identity
	before := len(server.Requests())
	raw, e := Run(ctx, f.config, f.verified)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = VerifyReceipt([]byte(f.config.Sync.ReceiptPublicKeyPEM), raw); e != nil {
		t.Fatal(e)
	}
	federation, head, get := 0, 0, 0
	for _, request := range server.Requests()[before:] {
		if request.Failure != "" {
			t.Fatalf("candidate HTTP qualification failure: %+v", request)
		}
		if request.Method == "PUT" || request.Method == "DELETE" {
			t.Fatalf("candidate mutated OCI: %+v", request)
		}
		if strings.HasPrefix(request.Host, "auth.") {
			federation++
		}
		if strings.HasPrefix(request.Host, "objectstorage.") {
			switch request.Method {
			case "HEAD":
				head++
			case "GET":
				get++
			}
		}
	}
	if federation != 1 || head != 3 || get != 4 {
		t.Fatalf("candidate SDK traffic federation=%d HEAD=%d GET=%d", federation, head, get)
	}
	if _, e = os.Stat(f.config.StoreDir); !os.IsNotExist(e) {
		t.Fatal("production sync touched final runtime store")
	}
}
