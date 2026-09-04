package provider

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/delivery"
)

type deliveryRegionStoreFake struct {
	mu       sync.Mutex
	objects  map[string][]byte
	reported map[string]ObjectMetadata
	puts     int
	gets     int
	deletes  int
}

func (f *deliveryRegionStoreFake) key(object ObjectRef) string {
	return object.Namespace + "/" + object.Bucket + "/" + object.Name
}

func (f *deliveryRegionStoreFake) PutObject(_ context.Context, request ObjectPutRequest) (ObjectMetadata, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.puts++
	key := f.key(request.Object)
	if _, exists := f.objects[key]; exists {
		return ObjectMetadata{}, errors.New("already exists")
	}
	f.objects[key] = append([]byte(nil), request.Content...)
	return ObjectMetadata{ETag: "etag-1", SHA256: request.SHA256, Size: int64(len(request.Content))}, nil
}

func (f *deliveryRegionStoreFake) HeadObject(_ context.Context, object ObjectRef) (ObjectMetadata, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body, found := f.objects[f.key(object)]
	if !found {
		return ObjectMetadata{}, false, nil
	}
	return ObjectMetadata{ETag: "etag-1", SHA256: digestHex(body), Size: int64(len(body))}, true, nil
}

func (f *deliveryRegionStoreFake) GetObject(_ context.Context, object ObjectRef) (io.ReadCloser, ObjectMetadata, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gets++
	body, found := f.objects[f.key(object)]
	if !found {
		return nil, ObjectMetadata{}, errors.New("not found")
	}
	metadata := ObjectMetadata{ETag: "etag-1", SHA256: digestHex(body), Size: int64(len(body))}
	if reported, ok := f.reported[f.key(object)]; ok {
		metadata = reported
	}
	return io.NopCloser(bytes.NewReader(body)), metadata, nil
}

func (f *deliveryRegionStoreFake) DeleteObject(_ context.Context, request ObjectDeleteRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deletes++
	delete(f.objects, f.key(request.Object))
	return nil
}

func newDeliveryRegionStoreTest(t *testing.T, fake *deliveryRegionStoreFake) *DeliveryRegionStore {
	t.Helper()
	journal, err := NewCASProviderMutationJournal(newTestOwnershipCAS())
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewDeliveryRegionStore(DeliveryRegionStoreConfig{Journal: journal, Regions: map[string]DeliveryRegionStoreRegion{
		"gru": {Provider: fake, Region: "gru", CompartmentID: "ocid1.compartment.oc1.x", Namespace: "namespace", Bucket: "releases", Owner: deliveryObjectOwner},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestDeliveryRegionStoreRejectsScopeAndDigestBeforeProviderIO(t *testing.T) {
	fake := &deliveryRegionStoreFake{objects: map[string][]byte{}, reported: map[string]ObjectMetadata{}}
	store := newDeliveryRegionStoreTest(t, fake)
	body := []byte("release")
	digest := digestHex(body)
	for _, test := range []struct {
		name, region, bucket, object string
		body                         []byte
	}{
		{"wrong region", "sfo", "releases", "releases/service/" + digest, body},
		{"wrong bucket", "gru", "other", "releases/service/" + digest, body},
		{"wrong key", "gru", "releases", "releases/service/not-a-digest", body},
		{"wrong bytes", "gru", "releases", "releases/service/" + digest, []byte("different")},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := store.Put(context.Background(), test.region, test.bucket, test.object, test.body); err == nil {
				t.Fatal("unsafe delivery write succeeded")
			}
		})
	}
	if fake.puts != 0 {
		t.Fatalf("provider PUTs = %d, want 0", fake.puts)
	}
}

func TestDeliveryRegionStoreBindsOCIProviderMutationAndIdentity(t *testing.T) {
	body := []byte("release")
	digest := digestHex(body)
	requestCount := 0
	transport := testOCITransport(t, OCIServiceObjectStorage, func(request *http.Request) (*http.Response, error) {
		requestCount++
		if request.Method == http.MethodHead {
			return testHTTPResponse(http.StatusNotFound, "", nil), nil
		}
		if request.Method != http.MethodPut || request.Header.Get("If-None-Match") != "*" {
			t.Fatalf("unexpected OCI delivery request: %s %s headers=%v", request.Method, request.URL, request.Header)
		}
		return testHTTPResponse(http.StatusOK, "", http.Header{"Etag": {"etag-oci"}}), nil
	})
	journal := testJournal(t)
	adapter, err := NewOCIObjectStorageAdapter(transport, journal)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewDeliveryRegionStore(DeliveryRegionStoreConfig{Journal: journal, Regions: map[string]DeliveryRegionStoreRegion{
		"gru": {Provider: adapter, Region: "gru", OCIRegion: "sa-saopaulo-1", CompartmentID: "ocid1.compartment.oc1.x", Namespace: "namespace", Bucket: "releases", Owner: deliveryObjectOwner},
	}})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := store.PutWithIdentity(context.Background(), "gru", "releases", delivery.MirrorObject("terrabase", "sha256:"+digest), body)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Digest != "sha256:"+digest || identity.Size != int64(len(body)) || identity.ETag != "etag-oci" {
		t.Fatalf("OCI delivery identity = %+v", identity)
	}
	if requestCount != 2 {
		t.Fatalf("OCI delivery provider calls = %d, want HEAD and PUT", requestCount)
	}
}

func TestDeliveryRegionStoreMirrorsReadsAndDeletesImmutableObject(t *testing.T) {
	fake := &deliveryRegionStoreFake{objects: map[string][]byte{}, reported: map[string]ObjectMetadata{}}
	store := newDeliveryRegionStoreTest(t, fake)
	body := []byte("release")
	object := delivery.MirrorObject("terrabase", digestHex(body))
	identity, err := store.PutWithIdentity(context.Background(), "gru", "releases", object, body)
	if err != nil || identity.Digest != "sha256:"+digestHex(body) || identity.Size != int64(len(body)) {
		t.Fatalf("put identity = %+v, err=%v", identity, err)
	}
	reader, identity, err := store.Get(context.Background(), "gru", "releases", object)
	if err != nil {
		t.Fatal(err)
	}
	read, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(read, body) || identity.ETag != "etag-1" {
		t.Fatalf("get = %q, identity=%+v, read=%v close=%v", read, identity, readErr, closeErr)
	}
	if err := store.Delete(context.Background(), "gru", "releases", object, "etag-1"); err != nil {
		t.Fatal(err)
	}
	if fake.deletes != 1 {
		t.Fatalf("provider DELETEs = %d, want 1", fake.deletes)
	}
}

func TestDeliveryRegionStoreSerializesConcurrentImmutablePuts(t *testing.T) {
	fake := &deliveryRegionStoreFake{objects: map[string][]byte{}}
	store := newDeliveryRegionStoreTest(t, fake)
	body := []byte("release")
	object := delivery.MirrorObject("terrabase", digestHex(body))
	var wait sync.WaitGroup
	for range 16 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if err := store.Put(context.Background(), "gru", "releases", object, body); err != nil {
				t.Errorf("concurrent put = %v", err)
			}
		}()
	}
	wait.Wait()
	if fake.puts != 1 {
		t.Fatalf("provider PUTs = %d, want exactly one", fake.puts)
	}
}

func TestDeliveryDigestReaderRejectsTruncatedProviderContent(t *testing.T) {
	fake := &deliveryRegionStoreFake{objects: map[string][]byte{}, reported: map[string]ObjectMetadata{}}
	store := newDeliveryRegionStoreTest(t, fake)
	body := []byte("release")
	object := delivery.MirrorObject("terrabase", digestHex(body))
	fake.objects["namespace/releases/"+object] = []byte("short")
	fake.reported["namespace/releases/"+object] = ObjectMetadata{ETag: "etag-1", SHA256: digestHex(body), Size: int64(len(body))}
	reader, _, err := store.Get(context.Background(), "gru", "releases", object)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.ReadAll(reader)
	_ = reader.Close()
	if err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("truncated read error = %v", err)
	}
}
