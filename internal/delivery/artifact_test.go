package delivery

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go/jetstream"
)

type putCountingObjectStore struct {
	jetstream.ObjectStore
	puts atomic.Int32
}

func (s *putCountingObjectStore) Put(ctx context.Context, metadata jetstream.ObjectMeta, source io.Reader) (*jetstream.ObjectInfo, error) {
	s.puts.Add(1)
	return s.ObjectStore.Put(ctx, metadata, source)
}

type delayedVisibilityObjectStore struct {
	jetstream.ObjectStore
	getInfoCalls          int
	getCalls              int
	putCalls              int
	getInfoMisses         int
	getMisses             int
	afterPutGetInfoMisses int
	afterPutGetMisses     int
}

func (s *delayedVisibilityObjectStore) GetInfo(ctx context.Context, name string, opts ...jetstream.GetObjectInfoOpt) (*jetstream.ObjectInfo, error) {
	s.getInfoCalls++
	if s.getInfoMisses > 0 {
		s.getInfoMisses--
		return nil, jetstream.ErrObjectNotFound
	}
	return s.ObjectStore.GetInfo(ctx, name, opts...)
}

func (s *delayedVisibilityObjectStore) Get(ctx context.Context, name string, opts ...jetstream.GetObjectOpt) (jetstream.ObjectResult, error) {
	s.getCalls++
	if s.getMisses > 0 {
		s.getMisses--
		return nil, jetstream.ErrObjectNotFound
	}
	return s.ObjectStore.Get(ctx, name, opts...)
}

func (s *delayedVisibilityObjectStore) Put(ctx context.Context, metadata jetstream.ObjectMeta, source io.Reader) (*jetstream.ObjectInfo, error) {
	s.putCalls++
	info, err := s.ObjectStore.Put(ctx, metadata, source)
	if err == nil {
		s.getInfoMisses += s.afterPutGetInfoMisses
		s.getMisses += s.afterPutGetMisses
	}
	return info, err
}

func TestPrepareArtifactRetriesOnlyTemporaryObjectVisibilityMisses(t *testing.T) {
	for _, test := range []struct {
		name                  string
		afterPutGetInfoMisses int
		afterPutGetMisses     int
		wantGetCalls          int
		wantGetInfoCalls      int
	}{
		{name: "metadata temporarily unavailable", afterPutGetInfoMisses: 2, wantGetCalls: 1, wantGetInfoCalls: 3},
		{name: "metadata replica misses object read", afterPutGetMisses: 2, wantGetCalls: 3, wantGetInfoCalls: 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			service, ctx := testService(t, &testWriter{})
			store := &delayedVisibilityObjectStore{
				ObjectStore: service.artifacts, afterPutGetInfoMisses: test.afterPutGetInfoMisses,
				afterPutGetMisses: test.afterPutGetMisses,
			}
			service.artifacts = store

			content := []byte("replicated object becomes visible shortly after put")
			record, _, err := service.PrepareArtifact(ctx, bytes.NewReader(content), artifactTestRequest())
			if err != nil {
				t.Fatalf("PrepareArtifact() error = %v", err)
			}
			if store.putCalls != 1 {
				t.Fatalf("Put calls = %d, want one immutable upload", store.putCalls)
			}
			if store.getCalls != test.wantGetCalls {
				t.Fatalf("object read calls = %d, want %d", store.getCalls, test.wantGetCalls)
			}
			if store.getInfoCalls != test.wantGetInfoCalls {
				t.Fatalf("metadata reads = %d, want %d", store.getInfoCalls, test.wantGetInfoCalls)
			}
			if err := service.verifyArtifact(ctx, record); err != nil {
				t.Fatalf("verified object does not match the admitted digest: %v", err)
			}
		})
	}
}

func TestAcceptArtifactClaimRetriesTemporaryObjectReadMiss(t *testing.T) {
	service, ctx := testService(t, &testWriter{})
	store := &delayedVisibilityObjectStore{ObjectStore: service.artifacts}
	service.artifacts = store
	_, claim, err := service.PrepareArtifact(ctx, bytes.NewReader([]byte("admitted artifact")), artifactTestRequest())
	if err != nil {
		t.Fatalf("PrepareArtifact() error = %v", err)
	}
	store.getMisses = 1
	if _, err := service.AcceptArtifactClaim(ctx, claim); err != nil {
		t.Fatalf("AcceptArtifactClaim() during temporary object read miss = %v", err)
	}
	if store.getCalls < 3 {
		t.Fatalf("object read calls = %d, want initial upload verification plus retry", store.getCalls)
	}
}

func TestVerifyArtifactFailsClosedAfterVisibilityRetryBound(t *testing.T) {
	service, ctx := testService(t, &testWriter{})
	record, _, err := service.PrepareArtifact(ctx, bytes.NewReader([]byte("artifact that must remain visible")), artifactTestRequest())
	if err != nil {
		t.Fatalf("PrepareArtifact() error = %v", err)
	}
	store := &delayedVisibilityObjectStore{ObjectStore: service.artifacts, getInfoMisses: artifactVisibilityAttempts}
	service.artifacts = store

	err = service.verifyArtifact(ctx, record)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("verifyArtifact() after persistent absence = %v, want ErrInvalid", err)
	}
	if store.getInfoCalls != artifactVisibilityAttempts {
		t.Fatalf("metadata read attempts = %d, want bounded limit %d", store.getInfoCalls, artifactVisibilityAttempts)
	}
}

func TestPrepareArtifactSkipsPutWhenStoredDigestAndSizeVerify(t *testing.T) {
	service, ctx := testService(t, &testWriter{})
	counting := &putCountingObjectStore{ObjectStore: service.artifacts}
	service.artifacts = counting

	request := artifactTestRequest()
	content := bytes.Repeat([]byte("artifact-chunk-"), 24_000)
	first, _, err := service.PrepareArtifact(ctx, bytes.NewReader(content), request)
	if err != nil {
		t.Fatalf("first PrepareArtifact() error = %v", err)
	}
	firstInfo, err := counting.GetInfo(ctx, artifactKey(first.Digest))
	if err != nil {
		t.Fatalf("GetInfo(first) error = %v", err)
	}
	if got := counting.puts.Load(); got != 1 {
		t.Fatalf("Put calls after initial upload = %d, want 1", got)
	}

	second, _, err := service.PrepareArtifact(ctx, bytes.NewReader(content), request)
	if err != nil {
		t.Fatalf("repeated PrepareArtifact() error = %v", err)
	}
	secondInfo, err := counting.GetInfo(ctx, artifactKey(second.Digest))
	if err != nil {
		t.Fatalf("GetInfo(second) error = %v", err)
	}
	if first != second {
		t.Fatalf("repeated artifact record changed: first=%+v second=%+v", first, second)
	}
	if got := counting.puts.Load(); got != 1 {
		t.Fatalf("Put calls after verified retry = %d, want 1", got)
	}
	if firstInfo.Chunks != secondInfo.Chunks {
		t.Fatalf("stored object chunks changed on retry: first=%d second=%d", firstInfo.Chunks, secondInfo.Chunks)
	}
}

func TestPrepareArtifactUsesLeaderMetadataBeforeReplacingExistingObject(t *testing.T) {
	service, ctx := testService(t, &testWriter{})
	request := artifactTestRequest()
	content := bytes.Repeat([]byte("same immutable artifact"), 1024)
	existing, _, err := service.PrepareArtifact(ctx, bytes.NewReader(content), request)
	if err != nil {
		t.Fatalf("initial PrepareArtifact() error = %v", err)
	}
	store := &delayedVisibilityObjectStore{ObjectStore: service.artifacts, getInfoMisses: 1}
	service.artifacts = store
	before, err := store.ObjectStore.GetInfo(ctx, artifactKey(existing.Digest))
	if err != nil {
		t.Fatalf("GetInfo(before retry) error = %v", err)
	}

	retried, _, err := service.PrepareArtifact(ctx, bytes.NewReader(content), request)
	if err != nil {
		t.Fatalf("PrepareArtifact() with stale direct-read miss = %v", err)
	}
	if retried != existing {
		t.Fatalf("retry changed immutable record: before=%+v after=%+v", existing, retried)
	}
	if store.putCalls != 0 {
		t.Fatalf("Put calls after stale direct-read miss = %d, want no replacement", store.putCalls)
	}
	after, err := store.ObjectStore.GetInfo(ctx, artifactKey(existing.Digest))
	if err != nil {
		t.Fatalf("GetInfo(after retry) error = %v", err)
	}
	if after.NUID != before.NUID || after.Chunks != before.Chunks {
		t.Fatalf("retry replaced stored chunks: before NUID=%s chunks=%d, after NUID=%s chunks=%d", before.NUID, before.Chunks, after.NUID, after.Chunks)
	}
}

func TestPrepareArtifactHashesAndUploadsTheSameSnapshot(t *testing.T) {
	service, ctx := testService(t, &testWriter{})
	original := []byte("artifact bytes from the first read")
	mutated := []byte("artifact bytes returned after a second seek")
	reader := &changingArtifactReader{
		first:  bytes.NewReader(original),
		second: bytes.NewReader(mutated),
	}

	record, _, err := service.PrepareArtifact(ctx, reader, artifactTestRequest())
	if err != nil {
		t.Fatalf("PrepareArtifact() error = %v", err)
	}
	if reader.seeks != 1 {
		t.Fatalf("source seek count = %d, want one snapshot read", reader.seeks)
	}
	wantDigest := sha256.Sum256(original)
	if got := record.Digest; got != hex.EncodeToString(wantDigest[:]) {
		t.Fatalf("artifact digest = %s, want digest of first read %s", got, hex.EncodeToString(wantDigest[:]))
	}
	if err := service.verifyArtifact(ctx, record); err != nil {
		t.Fatalf("stored snapshot does not match its digest: %v", err)
	}
}

func TestArtifactStoreQuotaRejectsNewObjectsAndPreservesExistingData(t *testing.T) {
	service, ctx := testService(t, &testWriter{})
	objects, err := service.js.CreateOrUpdateObjectStore(ctx, jetstream.ObjectStoreConfig{
		Bucket: ArtifactBucket, Storage: jetstream.FileStorage, Replicas: 1, MaxBytes: 2 << 10,
	})
	if err != nil {
		t.Fatalf("set small artifact store limit: %v", err)
	}
	service.artifacts = objects
	request := artifactTestRequest()
	existing, _, err := service.PrepareArtifact(ctx, bytes.NewReader(bytes.Repeat([]byte("a"), 256)), request)
	if err != nil {
		t.Fatalf("PrepareArtifact(existing object) error = %v", err)
	}

	objects, err = service.js.CreateOrUpdateObjectStore(ctx, jetstream.ObjectStoreConfig{
		Bucket: ArtifactBucket, Storage: jetstream.FileStorage, Replicas: 1, MaxBytes: 1,
	})
	if err != nil {
		t.Fatalf("reduce artifact store limit below stored bytes: %v", err)
	}
	service.artifacts = objects
	_, _, err = service.PrepareArtifact(ctx, bytes.NewReader([]byte("new artifact after quota reduction")), request)
	if !errors.Is(err, ErrArtifactStoreFull) {
		t.Fatalf("PrepareArtifact() after quota reduction = %v, want ErrArtifactStoreFull", err)
	}
	if err := service.verifyArtifact(ctx, existing); err != nil {
		t.Fatalf("existing artifact was lost after quota reduction: %v", err)
	}
}

func TestOpenRejectsNegativeArtifactStoreLimit(t *testing.T) {
	service, ctx := testService(t, &testWriter{})
	_, err := Open(ctx, Config{JS: service.js, Cell: "lab", Replicas: 1, ArtifactStoreMaxBytes: -1})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("Open() with negative artifact store limit = %v, want ErrInvalid", err)
	}
}

type changingArtifactReader struct {
	first  *bytes.Reader
	second *bytes.Reader
	seeks  int
}

func (r *changingArtifactReader) Read(p []byte) (int, error) {
	if r.seeks > 1 {
		return r.second.Read(p)
	}
	return r.first.Read(p)
}

func (r *changingArtifactReader) Seek(offset int64, whence int) (int64, error) {
	r.seeks++
	if r.seeks > 1 {
		return r.second.Seek(offset, whence)
	}
	return r.first.Seek(offset, whence)
}

func TestRevokedArtifactSignerCanBeReplacedByAuthorizedSignerConcurrently(t *testing.T) {
	service, ctx := testService(t, &testWriter{})
	oldCodec := artifactTestCodec(t, "old-operator", 0x11)
	newCodec := artifactTestCodec(t, "new-operator", 0x22)
	currentActor := "old-operator"
	service.config.AuthorizeArtifact = func(_ context.Context, actor string, _ ArtifactRecord) error {
		if actor != currentActor {
			return ErrUnauthorized
		}
		return nil
	}
	service.config.ArtifactSigner = oldCodec
	service.config.ArtifactVerifier = oldCodec

	request := artifactTestRequest()
	content := []byte("same immutable artifact content")
	original, oldEnvelope, err := service.PrepareArtifact(ctx, bytes.NewReader(content), request)
	if err != nil {
		t.Fatalf("PrepareArtifact(old signer) error = %v", err)
	}
	if admitted, err := service.AcceptArtifactClaim(ctx, oldEnvelope); err != nil || admitted != original {
		t.Fatalf("AcceptArtifactClaim(old signer) = %+v, %v", admitted, err)
	}

	currentActor = "new-operator"
	service.config.ArtifactSigner = newCodec
	service.config.ArtifactVerifier = newCodec
	if _, err := service.readAdmission(ctx, original.Digest, original.Cell, original.Role, original.Environment); err == nil {
		t.Fatal("revoked signer admission remained readable")
	}

	refreshed, newEnvelope, err := service.PrepareArtifact(ctx, bytes.NewReader(content), request)
	if err != nil {
		t.Fatalf("PrepareArtifact(new signer) error = %v", err)
	}
	if refreshed != original {
		t.Fatalf("fresh claim changed immutable artifact record: old=%+v new=%+v", original, refreshed)
	}

	const concurrentClaims = 8
	var wait sync.WaitGroup
	results := make(chan error, concurrentClaims)
	for range concurrentClaims {
		wait.Go(func() {
			admitted, err := service.AcceptArtifactClaim(ctx, newEnvelope)
			if err == nil && admitted != original {
				err = ErrConflict
			}
			results <- err
		})
	}
	wait.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("concurrent same-record admission failed: %v", err)
		}
	}

	admitted, err := service.readAdmission(ctx, original.Digest, original.Cell, original.Role, original.Environment)
	if err != nil || admitted != original {
		t.Fatalf("read replaced admission = %+v, %v", admitted, err)
	}
	entry, err := service.admissions.Get(ctx, admissionKey(original.Digest, original.Cell, original.Role, original.Environment))
	if err != nil {
		t.Fatalf("read replacement entry: %v", err)
	}
	stored, err := decodeStoredAdmission(entry.Value(), original.Digest, original.Cell, original.Role, original.Environment)
	if err != nil {
		t.Fatalf("decode replacement entry: %v", err)
	}
	if stored.Actor != "new-operator" || !bytes.Equal(stored.Envelope, newEnvelope) {
		t.Fatalf("stored signer was not replaced: actor=%q", stored.Actor)
	}

	otherSource := request.Source
	otherSource.Commit = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	otherRequest := request
	otherRequest.Source = otherSource
	_, conflictingEnvelope, err := service.PrepareArtifact(ctx, bytes.NewReader(content), otherRequest)
	if err != nil {
		t.Fatalf("PrepareArtifact(other provenance) error = %v", err)
	}
	if _, err := service.AcceptArtifactClaim(ctx, conflictingEnvelope); !errors.Is(err, ErrConflict) {
		t.Fatalf("same content with different provenance = %v, want ErrConflict", err)
	}
}

func TestResolveAdmittedArtifactRequiresCurrentAdmissionAndVerifiedBytes(t *testing.T) {
	service, ctx := testService(t, &testWriter{})
	intent := testIntent(t, service, ctx)
	resolved, err := service.ResolveAdmittedArtifact(ctx, intent.ArtifactDigest, intent.Role, intent.Environment)
	if err != nil || resolved.Digest != intent.ArtifactDigest || resolved.ManifestDigest != intent.ManifestDigest {
		t.Fatalf("ResolveAdmittedArtifact() = %+v, %v", resolved, err)
	}
	if _, err := service.ResolveAdmittedArtifact(ctx, intent.ArtifactDigest, "missing", intent.Environment); !errors.Is(err, jetstream.ErrKeyNotFound) {
		t.Fatalf("ResolveAdmittedArtifact(missing role) error = %v, want ErrKeyNotFound", err)
	}
}

func artifactTestRequest() ArtifactClaimRequest {
	tree := sha256.Sum256([]byte("source tree"))
	return ArtifactClaimRequest{
		Source: ArtifactSource{
			Repository: "https://git.terrascale.tech/TerraScale/ts-orchestrator",
			Commit:     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			TreeDigest: hex.EncodeToString(tree[:]),
		},
		Cell: "lab", Role: "worker", Environment: "production",
	}
}

func artifactTestCodec(t *testing.T, actor string, seedByte byte) Ed25519Codec {
	t.Helper()
	seed := bytes.Repeat([]byte{seedByte}, ed25519.SeedSize)
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	keyID, err := protocol.KeyID(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	return Ed25519Codec{
		Cell: "lab", Actor: actor, PrivateKey: privateKey,
		Trusted:  map[string]TrustedSigner{keyID: {Actor: actor, PublicKey: publicKey}},
		Lifetime: time.Minute, MaxLifetime: time.Minute,
		Now: func() time.Time { return time.Date(2026, time.September, 24, 9, 0, 0, 0, time.UTC) },
	}
}
