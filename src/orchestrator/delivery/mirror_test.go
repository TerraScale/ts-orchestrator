package delivery

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/estate"
)

type mirrorIdentityStore struct {
	mu       sync.Mutex
	objects  map[string]ObjectIdentity
	failPut  map[string]error
	failHead map[string]error
	puts     []string
	fences   []OperationFence
}

func (s *mirrorIdentityStore) PutFenced(ctx context.Context, region, bucket, object string, body []byte, fence OperationFence) error {
	s.mu.Lock()
	s.fences = append(s.fences, fence)
	s.mu.Unlock()
	return s.Put(ctx, region, bucket, object, body)
}

func (s *mirrorIdentityStore) Put(_ context.Context, region, bucket, object string, body []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := region + "/" + bucket + "/" + object
	s.puts = append(s.puts, key)
	if err := s.failPut[region]; err != nil {
		return err
	}
	s.objects[key] = ObjectIdentity{Digest: SHA256Digest(body), Size: int64(len(body)), ETag: "etag-" + region, Version: "1"}
	return nil
}

func (s *mirrorIdentityStore) Head(_ context.Context, region, bucket, object string) (ObjectIdentity, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.failHead[region]; err != nil {
		return ObjectIdentity{}, false, err
	}
	identity, found := s.objects[region+"/"+bucket+"/"+object]
	return identity, found, nil
}

func mirrorArtifact() *ReleaseArtifact {
	body := []byte("release bytes")
	return &ReleaseArtifact{Service: "terrabase", Digest: SHA256Digest(body), Body: body}
}

func TestMirrorAllVerifiesReadAfterWriteIdentity(t *testing.T) {
	store := &mirrorIdentityStore{objects: map[string]ObjectIdentity{}, failPut: map[string]error{}, failHead: map[string]error{}}
	mirror, err := NewArtifactMirror(estate.Default(), store)
	if err != nil {
		t.Fatal(err)
	}
	if err := mirror.MirrorAll(context.Background(), mirrorArtifact()); err != nil {
		t.Fatalf("MirrorAll = %v", err)
	}
	if len(store.puts) != len(estate.Default().Regions) {
		t.Fatalf("puts = %d, want %d", len(store.puts), len(estate.Default().Regions))
	}
}

func TestMirrorAllFencedPassesFenceAtProviderBoundary(t *testing.T) {
	store := &mirrorIdentityStore{objects: map[string]ObjectIdentity{}, failPut: map[string]error{}, failHead: map[string]error{}}
	mirror, err := NewArtifactMirror(estate.Default(), store)
	if err != nil {
		t.Fatal(err)
	}
	journal := NewJournal()
	request := journalTestRequest("mirror-fence")
	operation, _, err := journal.Begin(request, OperationLease{OwnerID: "owner", TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	fence := fenceFor(operation)
	if err := mirror.MirrorAllFenced(context.Background(), mirrorArtifact(), fence, journal.VerifyFence); err != nil {
		t.Fatalf("fenced mirror = %v", err)
	}
	if len(store.fences) != len(estate.Default().Regions) {
		t.Fatalf("fence dispatches = %d, want %d", len(store.fences), len(estate.Default().Regions))
	}
	for _, received := range store.fences {
		if received != fence {
			t.Fatalf("provider received fence %+v, want %+v", received, fence)
		}
	}
}

func TestMirrorAllFailsClosedOnIdentityMismatchAndPreservesDetails(t *testing.T) {
	store := &mirrorIdentityStore{objects: map[string]ObjectIdentity{}, failPut: map[string]error{}, failHead: map[string]error{}}
	store.failPut["sfo"] = errors.New("already exists")
	mirror, err := NewArtifactMirror(estate.Default(), store)
	if err != nil {
		t.Fatal(err)
	}
	artifact := mirrorArtifact()
	object := MirrorObject(artifact.Service, artifact.Digest)
	store.objects["sfo/releases/"+object] = ObjectIdentity{Digest: SHA256Digest([]byte("different")), Size: int64(len("different"))}
	err = mirror.MirrorAll(context.Background(), artifact)
	if err == nil {
		t.Fatal("identity mismatch must block mirroring")
	}
	var batch *MirrorBatchError
	if !errors.As(err, &batch) || len(batch.Failures) != 1 {
		t.Fatalf("error = %T %v, want one typed failure", err, err)
	}
	var failure *MirrorError
	if !errors.As(err, &failure) || failure.Region != "sfo" || failure.Kind != MirrorFailureMismatch || failure.Expected.Digest != artifact.Digest {
		t.Fatalf("failure = %+v", failure)
	}
}

func TestMirrorAllResolvesIndeterminateWriteByRead(t *testing.T) {
	store := &mirrorIdentityStore{objects: map[string]ObjectIdentity{}, failPut: map[string]error{}, failHead: map[string]error{}}
	store.failPut["gru"] = ErrMirrorIndeterminate
	artifact := mirrorArtifact()
	store.objects["gru/releases/"+MirrorObject(artifact.Service, artifact.Digest)] = ObjectIdentity{Digest: artifact.Digest, Size: int64(len(artifact.Body))}
	mirror, err := NewArtifactMirror(estate.Default(), store)
	if err != nil {
		t.Fatal(err)
	}
	if err := mirror.MirrorAll(context.Background(), artifact); err != nil {
		t.Fatalf("matching read must resolve indeterminate write: %v", err)
	}
}

func TestMirrorAllAttemptsRegionsConcurrentlyAndAggregatesFailures(t *testing.T) {
	store := &mirrorIdentityStore{objects: map[string]ObjectIdentity{}, failPut: map[string]error{}, failHead: map[string]error{}}
	store.failPut["gru"] = errors.New("unavailable")
	store.failPut["sfo"] = errors.New("unavailable")
	mirror, err := NewArtifactMirror(estate.Default(), store)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err = mirror.MirrorAll(ctx, mirrorArtifact())
	if err == nil {
		t.Fatal("partial mirrors must fail closed")
	}
	var batch *MirrorBatchError
	if !errors.As(err, &batch) || len(batch.Failures) != 2 {
		t.Fatalf("batch = %+v", err)
	}
	if batch.Failures[0].Region != "gru" || batch.Failures[1].Region != "sfo" {
		t.Fatalf("failures are not deterministic: %+v", batch.Failures)
	}
	if len(store.puts) != len(estate.Default().Regions) {
		t.Fatalf("puts = %d, want all Regions attempted", len(store.puts))
	}
}
