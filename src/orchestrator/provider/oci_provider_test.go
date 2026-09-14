package provider

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
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
	record := ProviderOwnershipRecord{ResourceId: ProviderResourceId{"ocid1.instance.oc1.sa-saopaulo-1.testinstance"}, CellId: ProviderCellId{"gru"}, CompartmentId: ProviderCompartmentId{"ocid1.compartment.oc1..testcompartment"}, Generation: ProviderGeneration{1}}
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

func TestOCIComputeLaunchTransmitsCompleteRunnerConfiguration(t *testing.T) {
	bootstrap := []byte("#cloud-config\nruncmd: []\n")
	digest := sha256.Sum256(bootstrap)
	demand, err := NewOciCiRunnerDemand("runner-1", TrustUntrustedProduct, 7,
		base64.StdEncoding.EncodeToString(bootstrap), hex.EncodeToString(digest[:]))
	if err != nil {
		t.Fatal(err)
	}
	template, err := NewOciCiRunnerLaunchTemplate(
		"ocid1.compartment.oc1..testcompartment", "AD-1", "FAULT-1", "ocid1.subnet.oc1.sa-saopaulo-1.testsubnet",
		[]string{"ocid1.networksecuritygroup.oc1.sa-saopaulo-1.testnsg"}, "ocid1.image.oc1.sa-saopaulo-1.testimage", 3)
	if err != nil {
		t.Fatal(err)
	}

	var requestBody []byte
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		var err error
		requestBody, err = io.ReadAll(request.Body)
		if err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"id":"ocid1.instance.oc1.sa-saopaulo-1.testinstance"}`))}, nil
	})}
	config, err := NewOCITransportConfig("gru", "https://iaas.gru.oraclecloud.com")
	if err != nil {
		t.Fatal(err)
	}
	transport, err := NewOCIHTTPTransport(config, client, nil)
	if err != nil {
		t.Fatal(err)
	}
	compute, err := NewOCIComputeClient(transport)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := compute.Execute(context.Background(), LaunchOciCiRunnerAction{Demand: demand, Template: template})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.ETag != "instance-etag" {
		t.Fatalf("launch ETag = %q, want response header fence", receipt.ETag)
	}
	var body map[string]any
	if err := json.Unmarshal(requestBody, &body); err != nil {
		t.Fatal(err)
	}
	if body["sourceDetails"].(map[string]any)["imageId"] != template.ImageId ||
		body["sourceDetails"].(map[string]any)["sourceType"] != "image" {
		t.Fatalf("launch omitted image source: %s", requestBody)
	}
	if body["createVnicDetails"].(map[string]any)["subnetId"] != template.SubnetId {
		t.Fatalf("launch omitted subnet: %s", requestBody)
	}
	nsgs := body["createVnicDetails"].(map[string]any)["nsgIds"].([]any)
	if len(nsgs) != 1 || nsgs[0] != template.NetworkSecurityGroupIds[0] {
		t.Fatalf("launch omitted network security groups: %s", requestBody)
	}
	shape := body["shapeConfig"].(map[string]any)
	if shape["ocpus"] != float64(4) || shape["memoryInGBs"] != float64(24) {
		t.Fatalf("launch omitted shape config: %s", requestBody)
	}
	if body["metadata"].(map[string]any)["user_data"] != demand.BootstrapCloudInitBase64 {
		t.Fatalf("launch omitted cloud-init bootstrap: %s", requestBody)
	}
}
