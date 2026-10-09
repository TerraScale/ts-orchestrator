package ociclient

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
)

type fakeResponse struct{ raw *http.Response }

func (f fakeResponse) HTTPResponse() *http.Response { return f.raw }

type fakeServiceError struct{ status int }

func (e fakeServiceError) Error() string           { return http.StatusText(e.status) }
func (e fakeServiceError) GetHTTPStatusCode() int  { return e.status }
func (e fakeServiceError) GetMessage() string      { return "" }
func (e fakeServiceError) GetCode() string         { return "" }
func (e fakeServiceError) GetOpcRequestID() string { return "" }

func pemKey(key *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

func attempt(method string, status int, token string, err error) common.OCIOperationResponse {
	request, _ := http.NewRequest(method, "https://iaas.sa-saopaulo-1.oraclecloud.com/x", nil)
	if token != "" {
		request.Header.Set("opc-retry-token", token)
	}
	raw := &http.Response{StatusCode: status, Request: request, Header: http.Header{}}
	if err == nil && status >= 300 {
		err = fakeServiceError{status: status}
	}
	return common.OCIOperationResponse{Response: fakeResponse{raw: raw}, Error: err, AttemptNumber: 1}
}

func TestShouldRetryNeverReplaysUnsafeMutations(t *testing.T) {
	for _, tc := range []struct {
		name   string
		method string
		status int
		token  string
		want   bool
	}{
		{"success", http.MethodGet, 200, "", false},
		{"read throttled", http.MethodGet, 429, "", true},
		{"delete throttled", http.MethodDelete, 429, "", true},
		{"put throttled", http.MethodPut, 429, "", true},
		{"read 503", http.MethodGet, 503, "", true},
		{"head 500", http.MethodHead, 500, "", true},
		{"read 501", http.MethodGet, 501, "", false},
		{"read 404", http.MethodGet, 404, "", false},
		{"read 409", http.MethodGet, 409, "", false},
		{"tokened post 502", http.MethodPost, 502, "token", true},
		{"untokened post 502", http.MethodPost, 502, "", false},
		{"delete 503", http.MethodDelete, 503, "", false},
		{"put 500", http.MethodPut, 500, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ShouldRetry(attempt(tc.method, tc.status, tc.token, nil)); got != tc.want {
				t.Fatalf("ShouldRetry=%v want %v", got, tc.want)
			}
		})
	}
	if !ShouldRetry(common.OCIOperationResponse{Error: fakeServiceError{status: 429}}) {
		t.Fatal("429 without a raw response was not retried")
	}
	if ShouldRetry(common.OCIOperationResponse{Error: fakeServiceError{status: 503}}) {
		t.Fatal("5xx on an unknown request was retried")
	}
	if !ShouldRetry(attempt(http.MethodGet, 0, "", io.ErrUnexpectedEOF)) {
		t.Fatal("transport error on a read was not retried")
	}
	if ShouldRetry(attempt(http.MethodPost, 0, "", io.ErrUnexpectedEOF)) {
		t.Fatal("transport error on an untokened post was retried")
	}
	parts := IdempotentPutRetryPolicy(RetryOptions{})
	if !parts.ShouldRetryOperation(attempt(http.MethodPut, 503, "", nil)) ||
		parts.ShouldRetryOperation(attempt(http.MethodDelete, 503, "", nil)) ||
		parts.ShouldRetryOperation(attempt(http.MethodPost, 503, "", nil)) {
		t.Fatal("idempotent PUT policy classified a method incorrectly")
	}
}

func TestBackoffIsExponentialJitteredAndHonorsRetryAfter(t *testing.T) {
	options := RetryOptions{BaseDelay: time.Second, MaxDelay: 10 * time.Second, Jitter: func() float64 { return 0.5 }}.normalized()
	var previous time.Duration
	for n := uint(1); n <= 4; n++ {
		response := attempt(http.MethodGet, 503, "", nil)
		response.AttemptNumber = n
		delay := nextDelay(options, response)
		if delay <= previous {
			t.Fatalf("attempt %d delay %v did not grow from %v", n, delay, previous)
		}
		previous = delay
	}
	response := attempt(http.MethodGet, 503, "", nil)
	response.AttemptNumber = 30
	if got := nextDelay(options, response); got > options.MaxDelay {
		t.Fatalf("delay %v exceeds cap", got)
	}
	options.Jitter = func() float64 { return 0 }
	low := nextDelay(options, attempt(http.MethodGet, 503, "", nil))
	options.Jitter = func() float64 { return 0.999 }
	high := nextDelay(options, attempt(http.MethodGet, 503, "", nil))
	if low >= high || low < options.BaseDelay/2 {
		t.Fatalf("jitter range low=%v high=%v", low, high)
	}
	throttled := attempt(http.MethodGet, 429, "", nil)
	throttled.Response.HTTPResponse().Header.Set("Retry-After", "4")
	if got := nextDelay(options, throttled); got != 4*time.Second {
		t.Fatalf("Retry-After delay=%v", got)
	}
	throttled.Response.HTTPResponse().Header.Set("Retry-After", "3600")
	if got := nextDelay(options, throttled); got != options.MaxDelay {
		t.Fatalf("Retry-After was not capped: %v", got)
	}
}

func testProvider(t *testing.T) common.ConfigurationProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return common.NewRawConfigurationProvider("ocid1.tenancy.oc1..t", "ocid1.user.oc1..u", "sa-saopaulo-1", "fp",
		string(pemKey(key)), nil)
}

func TestFactoryRejectsUncataloguedRegionsAndBadLimits(t *testing.T) {
	provider := testProvider(t)
	if _, err := New(provider, Options{Region: "uk-london-1"}); err == nil {
		t.Fatal("accepted a region outside the catalog")
	}
	if _, err := New(nil, Options{Region: "sa-saopaulo-1"}); err == nil {
		t.Fatal("accepted a nil provider")
	}
	if _, err := New(provider, Options{Region: "sa-saopaulo-1", Limits: map[Service]Limit{ServiceCompute: {}}}); err == nil {
		t.Fatal("accepted a zero limit")
	}
}

func TestConfiguredClientSharesLimiterAndRetriesThrottling(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < 3 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, `{"code":"TooManyRequests","message":"slow down"}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"ocid1.instance.oc1.sa-saopaulo-1.x","lifecycleState":"RUNNING"}`)
	}))
	defer server.Close()
	factory, err := New(testProvider(t), Options{Region: "sa-saopaulo-1",
		Limits: map[Service]Limit{ServiceCompute: {PerSecond: 1000, Burst: 1}},
		Retry:  RetryOptions{BaseDelay: time.Millisecond, MaxDelay: 2 * time.Millisecond}})
	if err != nil {
		t.Fatal(err)
	}
	compute, err := factory.Compute()
	if err != nil {
		t.Fatal(err)
	}
	PinHost(&compute.BaseClient, server.URL)
	compute.HTTPClient = server.Client()
	response, err := compute.GetInstance(t.Context(), core.GetInstanceRequest{InstanceId: new("ocid1.instance.oc1.sa-saopaulo-1.x")})
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 3 || response.LifecycleState != core.InstanceLifecycleStateRunning {
		t.Fatalf("calls=%d state=%s", calls.Load(), response.LifecycleState)
	}
	if factory.Limiter(ServiceCompute) != factory.Limiter(ServiceCompute) {
		t.Fatal("limiter is not shared")
	}

	// The limiter rejects a reservation beyond the deadline without waiting.
	blocked, err := New(testProvider(t), Options{Region: "sa-saopaulo-1",
		Limits: map[Service]Limit{ServiceCompute: {PerSecond: 0.001, Burst: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	slow, err := blocked.Compute()
	if err != nil {
		t.Fatal(err)
	}
	PinHost(&slow.BaseClient, server.URL)
	slow.HTTPClient = server.Client()
	blocked.Limiter(ServiceCompute).Allow()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	before := calls.Load()
	_, err = slow.GetInstance(ctx, core.GetInstanceRequest{InstanceId: new("ocid1.instance.oc1.sa-saopaulo-1.x")})
	if err == nil || calls.Load() != before {
		t.Fatalf("limiter admitted a request: err=%v", err)
	}
	if ctx.Err() != nil || !strings.Contains(err.Error(), "rate limiter") {
		t.Fatalf("expected immediate limiter rejection before deadline: %v", err)
	}
}

// TestTransportFailuresRetryReadsOnly drives a real SDK client against a server
// that drops the connection before any response. The SDK then reports no raw
// response, so the method must be recovered from the transport error.
func TestTransportFailuresRetryReadsOnly(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < 3 {
			connection, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = connection.Close()
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"ocid1.instance.oc1.sa-saopaulo-1.x","lifecycleState":"RUNNING"}`)
	}))
	defer server.Close()
	factory, err := New(testProvider(t), Options{Region: "sa-saopaulo-1",
		Limits: map[Service]Limit{ServiceCompute: {PerSecond: 1000, Burst: 10}},
		Retry:  RetryOptions{BaseDelay: time.Millisecond, MaxDelay: 2 * time.Millisecond}})
	if err != nil {
		t.Fatal(err)
	}
	compute, err := factory.Compute()
	if err != nil {
		t.Fatal(err)
	}
	PinHost(&compute.BaseClient, server.URL)
	compute.HTTPClient = server.Client()
	if _, err := compute.GetInstance(t.Context(), core.GetInstanceRequest{InstanceId: new("ocid1.instance.oc1.sa-saopaulo-1.x")}); err != nil {
		t.Fatalf("read was not retried after dropped connections: %v", err)
	}
	if calls.Load() != 3 {
		t.Fatalf("read attempts = %d, want 3", calls.Load())
	}

	calls.Store(0)
	_, err = compute.UpdateInstance(t.Context(), core.UpdateInstanceRequest{InstanceId: new("ocid1.instance.oc1.sa-saopaulo-1.x"),
		UpdateInstanceDetails: core.UpdateInstanceDetails{DisplayName: new("x")}})
	if err == nil || calls.Load() != 1 {
		t.Fatalf("PUT was replayed after a dropped connection: calls=%d err=%v", calls.Load(), err)
	}
}

func TestTenancyHomeRegionComesFromTheCatalog(t *testing.T) {
	t.Parallel()
	for key, want := range map[string]string{"GRU": "sa-saopaulo-1", "sjc": "us-sanjose-1", "FRA": "eu-frankfurt-1"} {
		if got, err := TenancyHomeRegion(&key); err != nil || got != want {
			t.Errorf("%s = %q, %v", key, got, err)
		}
	}
	unknown := "IAD"
	if _, err := TenancyHomeRegion(&unknown); err == nil {
		t.Error("a home region outside the catalog was accepted")
	}
	if _, err := TenancyHomeRegion(nil); err == nil {
		t.Error("a tenancy without a home region key was accepted")
	}
}
