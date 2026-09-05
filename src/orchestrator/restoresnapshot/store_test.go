package restoresnapshot

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/delivery"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
	"terrascale.tech/orchestrator/src/orchestrator/restoredrill"
)

type cas struct {
	mu        sync.Mutex
	values    map[string][]byte
	revisions map[string]uint64
	fail      bool
}

func (c *cas) Get(_ context.Context, k string) ([]byte, uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fail {
		return nil, 0, errors.New("journal unavailable")
	}
	return append([]byte(nil), c.values[k]...), c.revisions[k], nil
}
func (c *cas) CompareAndSwap(_ context.Context, k string, v uint64, b []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fail {
		return errors.New("journal unavailable")
	}
	if c.revisions[k] != v {
		return provider.OwnershipCASConflict{}
	}
	c.values[k] = append([]byte(nil), b...)
	c.revisions[k]++
	return nil
}

type signer struct{}

func (signer) Sign(r *http.Request) error {
	r.Header.Set("Authorization", "test-signature")
	return nil
}

type roundtrip func(*http.Request) (*http.Response, error)

func (f roundtrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type backend struct {
	mu       sync.Mutex
	bodies   map[string][]byte
	puts     int
	corrupt  bool
	afterPut func()
}

func (b *backend) serve(r *http.Request) (*http.Response, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if r.Header.Get("Authorization") == "" {
		return nil, errors.New("unsigned")
	}
	key := r.URL.Host + r.URL.Path
	body, found := b.bodies[key]
	status := 200
	header := make(http.Header)
	switch r.Method {
	case "PUT":
		if r.Header.Get("If-None-Match") != "*" {
			return nil, errors.New("missing immutable condition")
		}
		if found {
			status = 412
		} else {
			body, _ = io.ReadAll(r.Body)
			if "sha256:"+r.Header.Get("opc-meta-terrascale-sha256") != delivery.SHA256Digest(body) {
				return nil, errors.New("digest missing")
			}
			b.bodies[key] = body
			b.puts++
			if b.afterPut != nil {
				b.afterPut()
			}
		}
	case "HEAD", "GET":
		if !found {
			status = 404
		}
	default:
		return nil, errors.New("unexpected method")
	}
	header.Set("ETag", "object-etag")
	header.Set("opc-meta-terrascale-sha256", strings.TrimPrefix(delivery.SHA256Digest(body), "sha256:"))
	header.Set("Content-Length", fmt.Sprint(len(body)))
	if b.corrupt && r.Method == "GET" {
		body = bytes.Repeat([]byte("x"), len(body))
	}
	if r.Method != "GET" {
		body = nil
	}
	return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(bytes.NewReader(body))}, nil
}
func fixture(t *testing.T) (*Store, *backend, *cas, *uint64) {
	t.Helper()
	state := &cas{values: map[string][]byte{}, revisions: map[string]uint64{}}
	journal, err := provider.NewCASProviderMutationJournal(state)
	if err != nil {
		t.Fatal(err)
	}
	ownership, err := provider.NewDurableOwnershipJournal(state, 16)
	if err != nil {
		t.Fatal(err)
	}
	back := &backend{bodies: map[string][]byte{}}
	regions := map[string]Region{}
	for code, oci := range map[string]string{"gru": "sa-saopaulo-1", "sfo": "us-sanjose-1"} {
		cfg, err := provider.NewOCIServiceTransportConfig(provider.OCIServiceObjectStorage, oci, "https://objectstorage."+oci+".oraclecloud.com")
		if err != nil {
			t.Fatal(err)
		}
		transport, err := provider.NewOCIHTTPTransport(cfg, &http.Client{Transport: roundtrip(back.serve)}, signer{})
		if err != nil {
			t.Fatal(err)
		}
		regions[code] = Region{Transport: transport, OCIRegion: oci, Namespace: "namespace", Bucket: "snapshots", BucketResourceID: "bucket-" + code, CompartmentID: "compartment", OwnershipGeneration: 1}
		if err = ownership.Record(context.Background(), provider.ProviderOwnershipRecord{ResourceId: provider.ProviderResourceId{Value: "bucket-" + code}, CellId: provider.ProviderCellId{Value: code}, CompartmentId: provider.ProviderCompartmentId{Value: "compartment"}, Generation: provider.ProviderGeneration{Value: 1}}); err != nil {
			t.Fatal(err)
		}
	}
	epoch := uint64(7)
	s, err := New(Config{Regions: regions, SourceRegion: "gru", Journal: journal, Ownership: ownership, Authorize: func(_ context.Context, destination string, globalTerm uint64) error {
		if destination != "gru" && destination != "sfo" {
			return errors.New("destination outside global authority")
		}
		if globalTerm != epoch {
			return errors.New("stale global term")
		}
		return nil
	}, MaxBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	return s, back, state, &epoch
}
func TestOCIImmutableSnapshotsAndRegionalMirror(t *testing.T) {
	s, b, _, _ := fixture(t)
	ctx := context.Background()
	key := "jetstream/control/run.epoch-7.snapshot"
	body := []byte("binary snapshot payload")
	for range 2 {
		if err := s.Put(ctx, "gru", "snapshots", key, body); err != nil {
			t.Fatal(err)
		}
	}
	if b.puts != 1 {
		t.Fatalf("puts=%d", b.puts)
	}
	snapshot := restoredrill.ControlStateSnapshot{ObjectKey: key, Checksum: delivery.SHA256Digest(body), Size: int64(len(body)), ControlEpoch: 7}
	if err := s.Mirror(ctx, snapshot, "sfo"); err != nil {
		t.Fatal(err)
	}
	if b.puts != 2 {
		t.Fatalf("mirror puts=%d", b.puts)
	}
	if err := s.Put(ctx, "gru", "snapshots", key, []byte("different")); err == nil {
		t.Fatal("overwrote immutable snapshot")
	}
	b.corrupt = true
	if _, _, err := s.GetSnapshot(ctx, "sfo", "snapshots", key); err == nil {
		t.Fatal("accepted corrupt bytes")
	}
	if err := s.VerifyMirror(ctx, snapshot, "sfo"); err == nil {
		t.Fatal("accepted corrupt mirror")
	}
}
func TestRejectsStaleAuthorityAndUnavailableOwnership(t *testing.T) {
	s, b, state, epoch := fixture(t)
	*epoch = 8
	key := "jetstream/control/run.epoch-7.snapshot"
	if err := s.Put(context.Background(), "gru", "snapshots", key, []byte("payload")); err == nil {
		t.Fatal("accepted stale epoch")
	}
	if b.puts != 0 {
		t.Fatal("published stale snapshot")
	}
	*epoch = 7
	state.fail = true
	if err := s.Put(context.Background(), "gru", "snapshots", key, []byte("payload")); err == nil {
		t.Fatal("accepted unavailable ownership")
	}
	if b.puts != 0 {
		t.Fatal("published without journal")
	}
}
func TestRejectsScopeAndLimits(t *testing.T) {
	s, b, _, _ := fixture(t)
	for _, key := range []string{"releases/x", "jetstream/control/../run.epoch-7.snapshot", "jetstream/control/run.epoch-0.snapshot"} {
		if err := s.Put(context.Background(), "gru", "snapshots", key, []byte("x")); err == nil {
			t.Fatalf("accepted %s", key)
		}
	}
	if err := s.Put(context.Background(), "gru", "snapshots", "jetstream/control/run.epoch-7.snapshot", make([]byte, 1025)); err == nil {
		t.Fatal("accepted oversized snapshot")
	}
	if b.puts != 0 {
		t.Fatal("invalid publication")
	}
}

func TestAcknowledgedPutRequiresReadableBytes(t *testing.T) {
	s, b, _, _ := fixture(t)
	b.corrupt = true
	if err := s.Put(context.Background(), "gru", "snapshots", "jetstream/control/run.epoch-7.snapshot", []byte("payload")); err == nil {
		t.Fatal("PUT acknowledgement accepted without verified readback")
	}
	if b.puts != 1 {
		t.Fatal("test did not reach OCI PUT")
	}
}
func TestChangedOwnershipStopsReadAndWrite(t *testing.T) {
	s, b, _, _ := fixture(t)
	binding := s.regions["gru"]
	binding.region.OwnershipGeneration = 2
	s.regions["gru"] = binding
	key := "jetstream/control/run.epoch-7.snapshot"
	if _, _, err := s.Head(context.Background(), "gru", "snapshots", key); err == nil {
		t.Fatal("read accepted changed ownership")
	}
	if err := s.Put(context.Background(), "gru", "snapshots", key, []byte("payload")); err == nil {
		t.Fatal("write accepted changed ownership")
	}
	if b.puts != 0 {
		t.Fatal("ownership mismatch reached PUT")
	}
}
func TestConcurrentReadback(t *testing.T) {
	s, _, _, _ := fixture(t)
	ctx := context.Background()
	key := "jetstream/control/run.epoch-7.snapshot"
	body := []byte("payload")
	if err := s.Put(ctx, "gru", "snapshots", key, body); err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	for range 12 {
		group.Go(func() {
			got, found, err := s.GetSnapshot(ctx, "gru", "snapshots", key)
			if err != nil || !found || !bytes.Equal(got, body) {
				t.Errorf("concurrent read: %q %v %v", got, found, err)
			}
		})
	}
	group.Wait()
}

func TestGlobalAuthorityReceivesDestinationAndSnapshotTerm(t *testing.T) {
	s, b, _, _ := fixture(t)
	const regionalTerm uint64 = 91
	const globalTerm uint64 = 7
	var destinations []string
	s.authorize = func(_ context.Context, destination string, term uint64) error {
		if term != globalTerm || term == regionalTerm {
			t.Fatalf("snapshot authorized with wrong authority term: %d", term)
		}
		destinations = append(destinations, destination)
		if destination != "gru" {
			return errors.New("global authority excludes destination")
		}
		return nil
	}
	ctx := context.Background()
	body := []byte("snapshot")
	key := "jetstream/control/run.epoch-7.snapshot"
	if err := s.Put(ctx, "gru", "snapshots", key, body); err != nil {
		t.Fatal(err)
	}
	snapshot := restoredrill.ControlStateSnapshot{ObjectKey: key, Checksum: delivery.SHA256Digest(body), Size: int64(len(body)), ControlEpoch: globalTerm}
	if err := s.Mirror(ctx, snapshot, "sfo"); err == nil {
		t.Fatal("mirrored outside global authority destination scope")
	}
	if b.puts != 1 {
		t.Fatal("unauthorized destination reached PUT")
	}
	if len(destinations) != 2 || destinations[0] != "gru" || destinations[1] != "sfo" {
		t.Fatalf("authorization destinations = %v", destinations)
	}
}
