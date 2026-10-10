package delivery

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/artifact"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
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

func TestRetryArtifactMetadataReadRecoversFromTransientLeaderFailure(t *testing.T) {
	info := &nats.RawStreamMsg{}
	var reads int
	got, missing, err := retryArtifactMetadataRead(t.Context(), func(context.Context) (*nats.RawStreamMsg, bool, error) {
		reads++
		if reads == 1 {
			return nil, false, &nats.APIError{Code: 503, ErrorCode: 10008, Description: "JetStream system temporarily unavailable"}
		}
		return info, false, nil
	})
	if err != nil || missing || got != info || reads != 2 {
		t.Fatalf("authoritative metadata retry = (%p, %t, %v), reads = %d; want recovered info after two reads", got, missing, err, reads)
	}
}

func TestRetryArtifactMetadataReadFailsClosedOnPersistentLeaderFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
	defer cancel()
	var calls int
	info, missing, err := retryArtifactMetadataRead(ctx, func(context.Context) (*nats.RawStreamMsg, bool, error) {
		calls++
		return nil, false, &nats.APIError{Code: 503, ErrorCode: 10008, Description: "JetStream system temporarily unavailable"}
	})
	if info != nil || missing || !errors.Is(err, context.DeadlineExceeded) || calls < 1 {
		t.Fatalf("persistent metadata read failure = (%p, %t, %v), calls = %d; want caller deadline and no object", info, missing, err, calls)
	}
}

func TestRetryArtifactMetadataReadPreservesAbsenceAndPermanentErrors(t *testing.T) {
	permanent := &nats.APIError{Code: 403, ErrorCode: 10039}
	for _, test := range []struct {
		name        string
		wantMissing bool
		wantErr     error
	}{
		{name: "absent object", wantMissing: true},
		{name: "missing bucket", wantErr: nats.ErrStreamNotFound},
		{name: "permanent API rejection", wantErr: permanent},
	} {
		t.Run(test.name, func(t *testing.T) {
			var reads int
			info, missing, err := retryArtifactMetadataRead(t.Context(), func(context.Context) (*nats.RawStreamMsg, bool, error) {
				reads++
				return nil, test.wantMissing, test.wantErr
			})
			if info != nil || missing != test.wantMissing || (test.wantMissing && err != nil) ||
				(test.wantErr != nil && !errors.Is(err, test.wantErr)) || reads != 1 {
				t.Fatalf("metadata result = (%p, %t, %v), reads = %d; want absence = %t, error = %v", info, missing, err, reads, test.wantMissing, test.wantErr)
			}
		})
	}
}

func TestRetryArtifactMetadataReadStopsOnCallerCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	var reads int
	info, missing, err := retryArtifactMetadataRead(ctx, func(context.Context) (*nats.RawStreamMsg, bool, error) {
		reads++
		cancel()
		return nil, false, &nats.APIError{Code: 503, ErrorCode: 10008}
	})
	if info != nil || missing || !errors.Is(err, context.Canceled) || reads != 1 {
		t.Fatalf("canceled metadata read = (%p, %t, %v), reads = %d; want cancellation after one attempt", info, missing, err, reads)
	}
}

func TestArtifactMetadataReadCancelsBlockedBrokerRequest(t *testing.T) {
	srv, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS did not start")
	}
	t.Cleanup(func() { srv.Shutdown(); srv.WaitForShutdown() })
	conn, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	requests := make(chan struct{}, 1)
	_, err = conn.Subscribe("$JS.API.STREAM.MSG.GET.OBJ_"+ArtifactBucket, func(*nats.Msg) {
		select {
		case requests <- struct{}{}:
		default:
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Flush(); err != nil {
		t.Fatal(err)
	}
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	s := &Service{js: js}
	ctx, cancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
	defer cancel()
	started := time.Now()
	exists, err := s.artifactExistsForUpload(ctx, ArtifactRecord{Digest: "digest"})
	if exists || !errors.Is(err, context.DeadlineExceeded) || time.Since(started) >= 2*time.Second {
		t.Fatalf("blocked authoritative broker read = (exists=%t, err=%v, elapsed=%s); want prompt caller deadline", exists, err, time.Since(started))
	}
	select {
	case <-requests:
	default:
		t.Fatal("broker did not receive authoritative MSG.GET request")
	}
}

func TestArtifactMetadataReadDistinguishesMissingObjectAndBucket(t *testing.T) {
	s, ctx := testService(t, &testWriter{})
	legacyJS, err := s.js.Conn().JetStream()
	if err != nil {
		t.Fatal(err)
	}
	info, missing, err := authoritativeArtifactMetadata(ctx, legacyJS, "missing")
	if info != nil || !missing || err != nil {
		t.Fatalf("missing object = (%p, %t, %v); want object absence", info, missing, err)
	}
	if err := legacyJS.DeleteObjectStore(ArtifactBucket); err != nil {
		t.Fatal(err)
	}
	info, missing, err = authoritativeArtifactMetadata(ctx, legacyJS, "missing")
	if info != nil || missing || !errors.Is(err, nats.ErrStreamNotFound) {
		t.Fatalf("missing bucket = (%p, %t, %v); want stream-not-found error", info, missing, err)
	}
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
		wantGetInfoCalls      int
	}{
		{name: "metadata temporarily unavailable", afterPutGetInfoMisses: 2, wantGetInfoCalls: 3},
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
			if store.getInfoCalls != test.wantGetInfoCalls {
				t.Fatalf("metadata reads = %d, want %d", store.getInfoCalls, test.wantGetInfoCalls)
			}
			if err := service.verifyArtifact(ctx, record); err != nil {
				t.Fatalf("verified object does not match the admitted digest: %v", err)
			}
		})
	}
}

// storedBeforeSigning signs a claim only once its artifact bytes are stored.
type storedBeforeSigning struct {
	testCodec
	service *Service
	signed  bool
}

func (signer *storedBeforeSigning) SignArtifact(ctx context.Context, record ArtifactRecord) ([]byte, error) {
	if _, err := signer.service.artifacts.GetInfo(ctx, artifactKey(record.Digest)); err != nil {
		return nil, fmt.Errorf("claim signed before its artifact was stored: %w", err)
	}
	signer.signed = true
	return signer.testCodec.SignArtifact(ctx, record)
}

// The claim's short validity must cover admission, not the upload.
func TestPrepareArtifactSignsTheClaimAfterStoringTheBytes(t *testing.T) {
	service, ctx := testService(t, &testWriter{})
	signer := &storedBeforeSigning{service: service}
	service.config.ArtifactSigner = signer
	if _, _, err := service.PrepareArtifact(ctx, bytes.NewReader([]byte("artifact stored before its claim")), artifactTestRequest()); err != nil || !signer.signed {
		t.Fatalf("PrepareArtifact() = %v, signed=%t", err, signer.signed)
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

func TestPrepareArtifactRepairsMetadataWithMissingChunks(t *testing.T) {
	t.Parallel()
	service, ctx := testService(t, &testWriter{})
	content := bytes.Repeat([]byte("interrupted upload"), 1024)
	record, _, err := service.PrepareArtifact(ctx, bytes.NewReader(content), artifactTestRequest())
	if err != nil {
		t.Fatal(err)
	}
	before, err := service.artifacts.GetInfo(ctx, artifactKey(record.Digest))
	if err != nil {
		t.Fatal(err)
	}
	stream, err := service.js.Stream(ctx, "OBJ_"+ArtifactBucket)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Purge(ctx, jetstream.WithPurgeSubject(artifactChunkPrefix+before.NUID)); err != nil {
		t.Fatal(err)
	}
	store := &putCountingObjectStore{ObjectStore: service.artifacts}
	service.artifacts = store
	repaired, _, err := service.PrepareArtifact(ctx, bytes.NewReader(content), artifactTestRequest())
	if err != nil || repaired != record || store.puts.Load() != 1 {
		t.Fatalf("repair = %+v, %v, puts=%d; want same record and one upload", repaired, err, store.puts.Load())
	}
	after, err := service.artifacts.GetInfo(ctx, artifactKey(record.Digest))
	if err != nil || after.NUID == before.NUID {
		t.Fatalf("repair metadata = %+v, %v; want new verified chunks", after, err)
	}
	if err := service.verifyArtifact(ctx, record); err != nil {
		t.Fatalf("repaired artifact: %v", err)
	}
}

func TestPrepareArtifactRefusesInvalidExistingMetadata(t *testing.T) {
	t.Parallel()
	service, ctx := testService(t, &testWriter{})
	content := []byte("existing artifact with malformed size")
	record, _, err := service.PrepareArtifact(ctx, bytes.NewReader(content), artifactTestRequest())
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := service.js.Conn().JetStream()
	if err != nil {
		t.Fatal(err)
	}
	metadata, _, err := authoritativeArtifactMetadata(ctx, legacy, record.Digest)
	if err != nil {
		t.Fatal(err)
	}
	var info jetstream.ObjectInfo
	if err := json.Unmarshal(metadata.Data, &info); err != nil {
		t.Fatal(err)
	}
	info.Size++
	wire, err := json.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Publish(metadata.Subject, wire, nats.Context(ctx)); err != nil {
		t.Fatal(err)
	}
	store := &putCountingObjectStore{ObjectStore: service.artifacts}
	service.artifacts = store
	if _, _, err := service.PrepareArtifact(ctx, bytes.NewReader(content), artifactTestRequest()); !errors.Is(err, artifact.ErrInvalid) || store.puts.Load() != 0 {
		t.Fatalf("invalid metadata = %v, puts=%d; want refusal without replacement", err, store.puts.Load())
	}
	after, _, err := authoritativeArtifactMetadata(ctx, legacy, record.Digest)
	if err != nil || !bytes.Equal(after.Data, wire) {
		t.Fatalf("invalid metadata changed during refusal: %v", err)
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

func TestArtifactAdmissionCreateAndReplayIgnoreStaleFollower(t *testing.T) {
	service, ctx := testService(t, &testWriter{})
	record, envelope, err := service.PrepareArtifact(ctx, bytes.NewReader([]byte("artifact admitted despite stale follower")), artifactTestRequest())
	if err != nil {
		t.Fatal(err)
	}
	var followerReads int
	service.admissions = overriddenAdmissionGet{KeyValue: service.admissions, get: func(context.Context, string) (jetstream.KeyValueEntry, error) {
		followerReads++
		return nil, jetstream.ErrKeyNotFound
	}}
	for _, attempt := range []string{"create", "replay"} {
		admitted, err := service.AcceptArtifactClaim(ctx, envelope)
		if err != nil || admitted != record {
			t.Fatalf("%s admission = %+v, %v", attempt, admitted, err)
		}
	}
	resolved, err := service.ResolveAdmittedArtifact(ctx, record.Digest, record.Role, record.Environment)
	if err != nil || resolved != record {
		t.Fatalf("resolved admission = %+v, %v", resolved, err)
	}
	if followerReads != 0 {
		t.Fatalf("admission made %d follower reads", followerReads)
	}
}

func TestArtifactAdmissionSignerReplacementUsesLeaderRevision(t *testing.T) {
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

	content := []byte("artifact with replaced signer")
	record, oldEnvelope, err := service.PrepareArtifact(ctx, bytes.NewReader(content), artifactTestRequest())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.AcceptArtifactClaim(ctx, oldEnvelope); err != nil {
		t.Fatal(err)
	}
	key := admissionKey(record.Digest, record.Cell, record.Role, record.Environment)
	underlying := service.admissions
	staleEntry, err := underlying.Get(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := underlying.Put(ctx, key, staleEntry.Value()); err != nil {
		t.Fatal(err)
	}
	currentActor = "new-operator"
	service.config.ArtifactSigner = newCodec
	service.config.ArtifactVerifier = newCodec
	_, newEnvelope, err := service.PrepareArtifact(ctx, bytes.NewReader(content), artifactTestRequest())
	if err != nil {
		t.Fatal(err)
	}
	var followerReads int
	service.admissions = overriddenAdmissionGet{KeyValue: underlying, get: func(context.Context, string) (jetstream.KeyValueEntry, error) {
		followerReads++
		return staleEntry, nil
	}}
	admitted, err := service.AcceptArtifactClaim(ctx, newEnvelope)
	if err != nil || admitted != record {
		t.Fatalf("replacement admission = %+v, %v", admitted, err)
	}
	currentEntry, err := underlying.Get(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := decodeStoredAdmission(currentEntry.Value(), record.Digest, record.Cell, record.Role, record.Environment)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Actor != "new-operator" || !bytes.Equal(stored.Envelope, newEnvelope) || currentEntry.Revision() <= staleEntry.Revision() {
		t.Fatalf("replacement did not use leader revision: actor=%q revision=%d stale=%d", stored.Actor, currentEntry.Revision(), staleEntry.Revision())
	}
	if followerReads != 0 {
		t.Fatalf("replacement made %d follower reads", followerReads)
	}
}

func TestArtifactAdmissionRejectsLeaderConflictDespiteStaleFollower(t *testing.T) {
	service, ctx := testService(t, &testWriter{})
	content := []byte("same content with conflicting provenance")
	record, envelope, err := service.PrepareArtifact(ctx, bytes.NewReader(content), artifactTestRequest())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.AcceptArtifactClaim(ctx, envelope); err != nil {
		t.Fatal(err)
	}
	key := admissionKey(record.Digest, record.Cell, record.Role, record.Environment)
	underlying := service.admissions
	staleEntry, err := underlying.Get(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	conflictingRequest := artifactTestRequest()
	conflictingRequest.Source.Commit = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	conflictingRecord, conflictingEnvelope, err := service.PrepareArtifact(ctx, bytes.NewReader(content), conflictingRequest)
	if err != nil {
		t.Fatal(err)
	}
	conflictingValue, err := json.Marshal(signedAdmission{Record: conflictingRecord, Envelope: conflictingEnvelope, Actor: "operator"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := underlying.Put(ctx, key, conflictingValue); err != nil {
		t.Fatal(err)
	}
	var followerReads int
	service.admissions = overriddenAdmissionGet{KeyValue: underlying, get: func(context.Context, string) (jetstream.KeyValueEntry, error) {
		followerReads++
		return staleEntry, nil
	}}
	if _, err := service.AcceptArtifactClaim(ctx, envelope); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting leader admission error = %v, want ErrConflict", err)
	}
	currentEntry, err := underlying.Get(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(currentEntry.Value(), conflictingValue) {
		t.Fatal("conflicting leader admission was overwritten")
	}
	if followerReads != 0 {
		t.Fatalf("conflict decision made %d follower reads", followerReads)
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
