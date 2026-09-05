package ociinstance

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"terrascale.tech/orchestrator/src/orchestrator/internal/ociworker"
	"testing"
	"time"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestCredentialEndpointAndRegionPins(t *testing.T) {
	const region = "sa-saopaulo-1"
	for _, tc := range []struct {
		body   string
		accept bool
	}{{"sa-saopaulo-1", true}, {"gru", true}, {"fra", false}, {"sea", false}, {"unknown-region", false}, {"GRU", false}} {
		calls := 0
		ctx, cancel := context.WithCancel(context.Background())
		i := &Identity{lifetime: ctx, active: ctx, region: region, cancel: cancel}
		d := credentialDispatcher{identity: i, client: &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) {
			calls++
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
		}), CheckRedirect: noRedirect}}
		request, _ := http.NewRequest("GET", "http://169.254.169.254/opc/v2/instance/region", nil)
		response, err := d.Do(request)
		if response != nil {
			response.Body.Close()
		}
		if (err == nil) != tc.accept || calls != 1 {
			t.Fatalf("region %q accepted=%v", tc.body, err == nil)
		}
		cancel()
	}
	for _, url := range []string{"http://169.254.169.254/other", "http://169.254.169.254/opc/v1/identity/key.pem", "http://127.0.0.1/opc/v2/identity/key.pem", "https://auth.eu-frankfurt-1.oraclecloud.com/v1/x509", "https://auth.sa-saopaulo-1.oraclecloud.com/other", "https://auth.sa-saopaulo-1.oraclecloud.com/v1/x509?redirect=1"} {
		ctx, cancel := context.WithCancel(context.Background())
		i := &Identity{lifetime: ctx, active: ctx, region: region, cancel: cancel}
		d := credentialDispatcher{identity: i, client: &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) {
			t.Fatal("unapproved credential endpoint reached transport")
			return nil, nil
		})}}
		request, _ := http.NewRequest("GET", url, nil)
		if _, err := d.Do(request); err == nil {
			t.Fatalf("accepted endpoint %s", url)
		}
		cancel()
	}
	for _, region := range []string{"gru", "unknown-1", "us-gov-ashburn-1"} {
		if ValidateConfig(Config{Region: region}) == nil {
			t.Fatalf("accepted unpinned commercial region %s", region)
		}
	}
}
func TestMetadataCancellationStopsSubsequentSDKRequests(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	calls := 0
	instance, err := New(ctx, "sa-saopaulo-1", Options{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		cancel()
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("gru"))}, nil
	})})
	if err == nil || instance != nil {
		t.Fatal("canceled metadata admitted identity")
	}
	// run's caller can return before the SDK processes its successful region
	// response. Joining the shared worker proves it dispatched no later request.
	wait, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	select {
	case ociworker.Gate <- struct{}{}:
		defer func() { <-ociworker.Gate }()
	case <-wait.Done():
		t.Fatal("canceled successful metadata worker did not exit")
	}
	if calls != 1 {
		t.Fatal("SDK continued after metadata cancellation")
	}
}
func TestCredentialResponsesBoundedAndRedirectsDenied(t *testing.T) {
	for _, oversize := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		calls := 0
		i := &Identity{lifetime: ctx, active: ctx, region: "sa-saopaulo-1", cancel: cancel}
		d := credentialDispatcher{identity: i, client: &http.Client{CheckRedirect: noRedirect, Transport: roundTrip(func(*http.Request) (*http.Response, error) {
			calls++
			if oversize {
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(strings.Repeat("x", (256<<10)+1)))}, nil
			}
			return &http.Response{StatusCode: 307, Header: http.Header{"Location": {"https://attacker.invalid/"}}, Body: io.NopCloser(strings.NewReader(""))}, nil
		})}}
		r, _ := http.NewRequest("GET", "http://169.254.169.254/opc/v2/identity/key.pem", nil)
		resp, err := d.Do(r)
		if resp != nil {
			resp.Body.Close()
		}
		if oversize && err == nil {
			t.Fatal("oversized credential response accepted")
		}
		if !oversize && (err != nil || resp.StatusCode != 307) {
			t.Fatal("redirect response changed")
		}
		if calls != 1 {
			t.Fatal("credential redirect followed")
		}
	}
}

func TestQualificationTransportKeepsPinnedTLSVerification(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.Write([]byte("metadata")) }))
	defer server.Close()
	endpoint, _ := url.Parse(server.URL)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	transport := productionTransport()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: "wrong-fixture.invalid"}
	pinned := &qualificationTransport{transport: transport, endpoint: endpoint}
	defer pinned.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	request, _ := http.NewRequestWithContext(ctx, "GET", "http://169.254.169.254/opc/v2/instance/region", nil)
	if _, err := pinned.RoundTrip(request); err == nil {
		t.Fatal("wrong server name accepted")
	}
	if calls.Load() != 0 {
		t.Fatal("failed TLS identity reached metadata handler")
	}
}
