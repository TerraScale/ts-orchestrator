package provider

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
)

type testOwnershipCAS struct {
	mu    sync.Mutex
	value map[string][]byte
	vers  map[string]uint64
}

func newTestOwnershipCAS() *testOwnershipCAS {
	return &testOwnershipCAS{value: map[string][]byte{}, vers: map[string]uint64{}}
}
func (s *testOwnershipCAS) Get(_ context.Context, key string) ([]byte, uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.value[key]...), s.vers[key], nil
}
func (s *testOwnershipCAS) CompareAndSwap(_ context.Context, key string, version uint64, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.vers[key] != version {
		return OwnershipCASConflict{}
	}
	s.value[key] = append([]byte(nil), value...)
	s.vers[key]++
	return nil
}

func TestOCIValidationRejectsLookalikeIdentities(t *testing.T) {
	for _, id := range []string{"ocid1.volume.oc1", "ocid1.volume.oc1.x/escape", "ocid1.volume.oc1.x.", "ocid1.volume.bad.x"} {
		if isOCID(id, "volume") {
			t.Fatalf("accepted malformed OCID %q", id)
		}
	}
	for _, endpoint := range []string{"http://iaas-gru.oraclecloud.com", "https://iaas.gru.oraclecloud.com:443", "https://user@iaas.gru.oraclecloud.com", "https://iaas.gru.oraclecloud.com/path"} {
		if _, err := NewOCITransportConfig("gru", endpoint); err == nil {
			t.Fatalf("accepted malformed endpoint %q", endpoint)
		}
	}
}

func TestDurableOwnershipJournalConcurrentRecordIsIdempotent(t *testing.T) {
	store := newTestOwnershipCAS()
	journal, err := NewDurableOwnershipJournal(store, 4)
	if err != nil {
		t.Fatal(err)
	}
	record := ProviderOwnershipRecord{ResourceId: ProviderResourceId{"ocid1.instance.oc1.x"}, CellId: ProviderCellId{"gru"}, CompartmentId: ProviderCompartmentId{"ocid1.compartment.oc1.x"}, Generation: ProviderGeneration{1}}
	results := make(chan error, 16)
	for i := 0; i < cap(results); i++ {
		go func() { results <- journal.Record(context.Background(), record) }()
	}
	for i := 0; i < cap(results); i++ {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	got, ok, err := journal.Lookup(context.Background(), record.ResourceId)
	if err != nil || !ok || got != record {
		t.Fatalf("lookup = %+v, %v, %v", got, ok, err)
	}
}

func TestOCITransportCancellationDoesNotCallRoundTripper(t *testing.T) {
	called := false
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		called = true
		return nil, errors.New("unexpected transport call")
	})}
	cfg, err := NewOCITransportConfig("gru", "https://iaas.gru.oraclecloud.com")
	if err != nil {
		t.Fatal(err)
	}
	transport, err := NewOCIHTTPTransport(cfg, client, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = transport.Do(ctx, http.MethodGet, "/20160918/instances", nil)
	if !errors.Is(err, context.Canceled) || called {
		t.Fatalf("cancellation = %v, round trip called = %v", err, called)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestSafeErrorDoesNotEchoProviderBody(t *testing.T) {
	secret := "private-key-material"
	resp := &http.Response{StatusCode: http.StatusBadRequest, Body: http.NoBody, Header: make(http.Header)}
	if err := ociStatus(resp, secret); err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("provider response leaked into error: %v", err)
	}
}
