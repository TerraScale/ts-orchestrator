package ociclient_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json/v2"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/identity"
)

func TestOperationCardinalityThroughVerifiedTLSHTTP(t *testing.T) {
	var routes []string
	expected := map[string]uint64{"other": 10}
	for index := range 74 {
		route := "/route" + string(rune('a'+index%26)) + string(rune('a'+index/26))
		routes = append(routes, route)
		if index < 64 {
			expected["GET "+route] = 1
		}
	}
	var received atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		index := int(received.Add(1)) - 1
		if index >= len(routes) || request.TLS == nil || request.Method != http.MethodGet || request.URL.RequestURI() != routes[index] {
			t.Errorf("unexpected TLS request %d: %s %s", index+1, request.Method, request.URL.RequestURI())
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	client := server.Client()
	defer client.CloseIdleConnections()
	service := "cardinality-" + t.Name()
	dispatcher := ociclient.Instrument(client, service)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	for _, route := range routes {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+route, nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := dispatcher.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_, readErr := io.Copy(io.Discard, response.Body)
		closeErr := response.Body.Close()
		if response.StatusCode != http.StatusOK || readErr != nil || closeErr != nil {
			t.Fatalf("HTTP result = %d, read=%v, close=%v", response.StatusCode, readErr, closeErr)
		}
	}
	views := 0
	var calls uint64
	for _, operation := range ociclient.APIOperations() {
		if operation.Service != service {
			continue
		}
		views++
		calls += operation.Calls
		want, known := expected[operation.Operation]
		if !known || operation.Calls != want || operation.Errors != 0 || operation.Throttled != 0 || operation.LastStatus != http.StatusOK {
			t.Errorf("API operation = %+v, want known operation with %d successful calls", operation, want)
		}
	}
	if views != 65 || calls != 74 || received.Load() != 74 {
		t.Fatalf("bounded operations: views=%d calls=%d wire=%d, want 65/74/74", views, calls, received.Load())
	}
	var metrics bytes.Buffer
	ociclient.Metrics.WritePrometheus(&metrics)
	for operation, count := range expected {
		want := fmt.Sprintf("ts_orch_oci_requests_total{service=%q,operation=%q,code=\"200\"} %d\n", service, operation, count)
		if !strings.Contains(metrics.String(), want) {
			t.Errorf("Prometheus output lacks %q", want)
		}
	}
}

func TestFactoryAdmissionThroughSignedSDKHTTP(t *testing.T) {
	const instanceID = "ocid1.instance.oc1..a"
	provider := factoryBoundaryProvider(t)
	var received atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		received.Add(1)
		assertSignedFactoryBoundaryRequest(t, request, "/20160918/instances/"+instanceID)
		w.Header().Set("Content-Type", "application/json")
		if err := json.MarshalWrite(w, map[string]string{"id": instanceID, "lifecycleState": "RUNNING"}); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	client := server.Client()
	defer client.CloseIdleConnections()
	t.Run("valid", func(t *testing.T) {
		factory, err := ociclient.New(provider, ociclient.Options{Region: "sa-saopaulo-1", Retry: ociclient.RetryOptions{MaxAttempts: 1}})
		if err != nil {
			t.Fatal(err)
		}
		compute, err := factory.Compute()
		if err != nil {
			t.Fatal(err)
		}
		ociclient.PinHost(&compute.BaseClient, server.URL)
		compute.HTTPClient = client
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		response, err := compute.GetInstance(ctx, core.GetInstanceRequest{InstanceId: new(instanceID)})
		if err != nil {
			t.Fatal(err)
		}
		if response.Id == nil || *response.Id != instanceID || response.LifecycleState != core.InstanceLifecycleStateRunning || received.Load() != 1 {
			t.Fatalf("signed SDK result = %+v, wire=%d", response.Instance, received.Load())
		}
	})
	for _, test := range []struct {
		name     string
		provider common.ConfigurationProvider
		options  ociclient.Options
	}{
		{"uncatalogued_region", provider, ociclient.Options{Region: "xx-nowhere-1"}},
		{"nil_provider", nil, ociclient.Options{Region: "sa-saopaulo-1"}},
		{"zero_compute_limit", provider, ociclient.Options{Region: "sa-saopaulo-1", Limits: map[ociclient.Service]ociclient.Limit{ociclient.ServiceCompute: {}}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			factory, err := ociclient.New(test.provider, test.options)
			if err == nil || factory != nil {
				t.Fatalf("invalid factory admitted: factory=%v err=%v", factory, err)
			}
			if received.Load() != 1 {
				t.Fatalf("invalid factory dispatched: wire=%d, want positive control only", received.Load())
			}
		})
	}
}

func TestTenancyHomeRegionThroughSignedSDKHTTP(t *testing.T) {
	const tenancyID = "ocid1.tenancy.oc1..t"
	provider := factoryBoundaryProvider(t)
	for _, test := range []struct {
		name string
		key  string
		want string
	}{
		{"GRU", "GRU", "sa-saopaulo-1"},
		{"sjc", "sjc", "us-sanjose-1"},
		{"FRA", "FRA", "eu-frankfurt-1"},
		{"unknown", "XXX", ""},
		{"missing", "", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			var received atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				received.Add(1)
				assertSignedFactoryBoundaryRequest(t, request, "/20160918/tenancies/"+tenancyID)
				body := map[string]string{"id": tenancyID}
				if test.key != "" {
					body["homeRegionKey"] = test.key
				}
				w.Header().Set("Content-Type", "application/json")
				if err := json.MarshalWrite(w, body); err != nil {
					t.Error(err)
				}
			}))
			defer server.Close()
			client := server.Client()
			defer client.CloseIdleConnections()
			factory, err := ociclient.New(provider, ociclient.Options{Region: "sa-saopaulo-1", Retry: ociclient.RetryOptions{MaxAttempts: 1}})
			if err != nil {
				t.Fatal(err)
			}
			identityClient, err := factory.Identity()
			if err != nil {
				t.Fatal(err)
			}
			ociclient.PinHost(&identityClient.BaseClient, server.URL)
			identityClient.HTTPClient = client
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			response, err := identityClient.GetTenancy(ctx, identity.GetTenancyRequest{TenancyId: new(tenancyID)})
			if err != nil {
				t.Fatal(err)
			}
			if response.Id == nil || *response.Id != tenancyID || received.Load() != 1 {
				t.Fatalf("decoded tenancy = %+v, wire=%d", response.Tenancy, received.Load())
			}
			if test.key == "" {
				if response.HomeRegionKey != nil {
					t.Fatalf("missing homeRegionKey decoded as %q", *response.HomeRegionKey)
				}
			} else if response.HomeRegionKey == nil || *response.HomeRegionKey != test.key {
				t.Fatalf("homeRegionKey did not decode exact %q", test.key)
			}
			// Factory.HomeRegion maps this same SDK-decoded field after GetTenancy.
			region, err := ociclient.TenancyHomeRegion(response.HomeRegionKey)
			if test.want == "" {
				if err == nil {
					t.Fatalf("accepted home region key %q as %q", test.key, region)
				}
			} else if err != nil || region != test.want {
				t.Fatalf("home region key %q = %q, %v; want %q", test.key, region, err, test.want)
			}
		})
	}
}

func factoryBoundaryProvider(t *testing.T) common.ConfigurationProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	privateKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return common.NewRawConfigurationProvider("ocid1.tenancy.oc1..t", "ocid1.user.oc1..u", "sa-saopaulo-1", "fp", string(privateKey), nil)
}

func assertSignedFactoryBoundaryRequest(t *testing.T, request *http.Request, path string) {
	t.Helper()
	_, signature, present := strings.Cut(request.Header.Get("Authorization"), `signature="`)
	signature, _, closed := strings.Cut(signature, `"`)
	if request.TLS == nil || request.Method != http.MethodGet || request.URL.RequestURI() != path || !present || !closed || signature == "" {
		t.Errorf("expected signed TLS GET %s, got %s %s", path, request.Method, request.URL.RequestURI())
	}
}
