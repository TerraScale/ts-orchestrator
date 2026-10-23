package alertdelivery

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type probeTransport func(*http.Request) (*http.Response, error)

func (f probeTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestReadinessMetrics(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		want       string
	}{
		{"ready", `{"status":"ready"}`, 200, "1"},
		{"unavailable", `{"status":"ready"}`, 503, "0"},
		{"redirect", `{"status":"ready"}`, 302, "0"},
		{"malformed", `{`, 200, "0"},
		{"wrong status", `{"status":"ok"}`, 200, "0"},
		{"trailing JSON", `{"status":"ready"} {}`, 200, "0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := newReadinessClient()
			client.Transport = probeTransport(func(r *http.Request) (*http.Response, error) {
				if r.URL.Scheme != "https" || r.URL.Path != "/readyz" || len(r.Header) != 0 {
					t.Errorf("unexpected probe request: %v", r.URL)
				}
				switch r.URL.Host {
				case "api.terrascale.tech", "auth.terrascale.tech", "dash.terrascale.tech":
				default:
					t.Errorf("unapproved probe host: %s", r.URL.Host)
				}
				body := tc.body
				if r.URL.Host == "dash.terrascale.tech" && tc.name == "ready" {
					body = `{"status":"ok","dependencies":{"ts-auth":"ok","terrabase":"ok"}}`
				}
				return &http.Response{StatusCode: tc.status, Header: http.Header{"Location": []string{"https://unapproved.invalid/"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
			})
			recorder := httptest.NewRecorder()
			readinessMetrics(client)(recorder, httptest.NewRequest("GET", "/metrics?target=https://unapproved.invalid", nil))
			for _, service := range []string{"terrabase", "ts-auth", "ts-dashboard"} {
				if !strings.Contains(recorder.Body.String(), `terrascale_service_readiness{service="`+service+`"} `+tc.want+"\n") {
					t.Fatalf("unexpected metrics: %s", recorder.Body.String())
				}
			}
		})
	}
}

func TestReadinessDashboardDependencies(t *testing.T) {
	for _, body := range []string{`{"status":"ok"}`, `{"status":"ok","dependencies":{"ts-auth":"ok","terrabase":"failed"}}`} {
		client := newReadinessClient()
		client.Transport = probeTransport(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
		})
		if probeReady(t.Context(), client, "ts-dashboard") {
			t.Fatal("accepted missing or failed dependency")
		}
	}
}

func TestReadinessTimeoutAndClientPolicy(t *testing.T) {
	client := newReadinessClient()
	transport := client.Transport.(*http.Transport)
	if transport.Proxy != nil || client.Timeout != 3*time.Second || (transport.TLSClientConfig != nil && transport.TLSClientConfig.InsecureSkipVerify) {
		t.Fatal("unsafe probe client")
	}
	if client.CheckRedirect(nil, nil) != http.ErrUseLastResponse {
		t.Fatal("redirects permitted")
	}
	client.Timeout = 20 * time.Millisecond
	client.Transport = probeTransport(func(r *http.Request) (*http.Response, error) { <-r.Context().Done(); return nil, r.Context().Err() })
	start := time.Now()
	recorder := httptest.NewRecorder()
	readinessMetrics(client)(recorder, httptest.NewRequest("GET", "/metrics", nil))
	if time.Since(start) > time.Second {
		t.Fatal("probes exceeded bounded test timeout")
	}
	if strings.Count(recorder.Body.String(), "} 0\n") != 3 {
		t.Fatal(recorder.Body.String())
	}
}
