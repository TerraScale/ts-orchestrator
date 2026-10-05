package liveverify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
)

func clearVerifyEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{"TS_VERIFY_LIVE", "TS_VERIFY_CELL", "E2E_REGION", "E2E_TERRABASE_URL", "E2E_AUTH_URL", "E2E_DASHBOARD_URL", "E2E_STATUS_URL", "TS_VERIFY_ORCHESTRATOR_URL", "TS_VERIFY_ORCHESTRATOR_TOKEN", "TS_VERIFY_OIDC_JWT", "TS_VERIFY_OIDC_AUDIENCE", "E2E_MANAGEMENT_CREDENTIAL", "E2E_API_KEY"} {
		t.Setenv(name, "")
	}
}

func localArgs(origin string) []string {
	return []string{"--terrabase-url", origin, "--auth-url", origin, "--dashboard-url", origin, "--status-url", origin, "--orchestrator-url", "", "--region", "gru-1", "--cell", "gru", "--timeout", "1s"}
}

func localVerifier(t *testing.T) verifier {
	t.Helper()
	return verifier{ctx: t.Context(), region: "gru-1", cell: "gru", http: &http.Client{
		Timeout:       time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

func assertRow(t *testing.T, v verifier, item, status string) {
	t.Helper()
	for _, r := range v.rows {
		if r.Item == item {
			if r.Status != status {
				t.Fatalf("%s = %s, want %s; evidence: %s", item, r.Status, status, r.Evidence)
			}
			return
		}
	}
	t.Fatalf("missing row %q: %+v", item, v.rows)
}

func TestRunRequiresOptInBeforeRequests(t *testing.T) {
	clearVerifyEnv(t)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer server.Close()
	for _, optIn := range []string{"", "0", "true"} {
		t.Run("env="+optIn, func(t *testing.T) {
			t.Setenv("TS_VERIFY_LIVE", optIn)
			err := Run(t.Context(), localArgs(server.URL), io.Discard)
			if err == nil || !strings.Contains(err.Error(), "no requests sent") {
				t.Fatalf("Run error = %v, want explicit opt-in error", err)
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatalf("sent %d requests without opt-in", calls.Load())
	}
}

func TestRunRejectsInvalidOriginsBeforeAnyRequests(t *testing.T) {
	clearVerifyEnv(t)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer server.Close()
	for _, origin := range []string{"http://example.invalid", "http://192.0.2.1", "ftp://localhost", "https://user:secret@example.invalid", server.URL + "?token=secret", server.URL + "?", server.URL + "#fragment", server.URL + "/path", "://bad", "https:///missing-host"} {
		t.Run(origin, func(t *testing.T) {
			args := append(localArgs(server.URL), "--live", "--status-url", origin)
			if err := Run(t.Context(), args, io.Discard); err == nil || !strings.Contains(err.Error(), "origins must be") {
				t.Fatalf("invalid origin %q: error = %v", origin, err)
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatalf("sent %d requests before validating every origin", calls.Load())
	}
	for _, origin := range []string{"https://example.invalid", "https://example.invalid/", "http://localhost:1234", "http://127.0.0.1:1234", "http://[::1]:1234"} {
		if !validOrigin(origin) {
			t.Errorf("rejected valid origin %q", origin)
		}
	}
}

func TestRunLivenessLeavesMissingEvidenceUnknownAndOnlyReads(t *testing.T) {
	clearVerifyEnv(t)
	var mu sync.Mutex
	requests := make(map[string]int)
	var origin string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests[r.URL.Path]++
		mu.Unlock()
		if r.Method != http.MethodGet || r.URL.RawQuery != "" || r.Header.Get("Cache-Control") != "no-cache" {
			t.Errorf("unexpected request: %s %s, headers=%v", r.Method, r.URL, r.Header)
		}
		body, _ := io.ReadAll(r.Body)
		if len(body) != 0 || r.Header.Get("Cookie") != "" {
			t.Errorf("request included a body or cookie")
		}
		switch r.URL.Path {
		case "/healthz", "/health/live", "/health/ready":
			w.Header().Set("X-TerraBase-Region", "gru-1")
			io.WriteString(w, `{"status":"ok","version":"fixture-1","region":"gru-1"}`)
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]string{"issuer": origin, "jwks_uri": origin + "/.well-known/jwks.json"})
		case "/.well-known/jwks.json":
			io.WriteString(w, `{"keys":[{"kty":"RSA","kid":"fixture"}]}`)
		case "/api/v1/status":
			io.WriteString(w, `{"status":"operational","generatedAt":"2026-10-05T00:00:00Z","groups":[{"components":[{"name":"fixture","status":"operational"}]}]}`)
		default:
			t.Errorf("unreviewed request path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	origin = server.URL
	t.Setenv("TS_VERIFY_LIVE", "1")
	t.Setenv("E2E_MANAGEMENT_CREDENTIAL", "must-not-send-management-secret")
	t.Setenv("E2E_API_KEY", "must-not-send-api-secret")
	var output bytes.Buffer
	if err := Run(t.Context(), localArgs(origin), &output); err == nil {
		t.Fatal("liveness without deployment/storage/JWT evidence reported complete")
	}
	for _, item := range []string{"TerraBase liveness", "ts-auth liveness", "Dashboard liveness", "Dashboard readiness", "OIDC discovery/nonempty JWKS retrieved", "Status API response"} {
		if !strings.Contains(output.String(), "| "+item+" | PASS |") {
			t.Errorf("missing passing row %q:\n%s", item, &output)
		}
	}
	for _, item := range []string{"1. Orchestrator deployed and working", "2. Orchestrator deployed healthy TerraBase", "3. ts-auth persists in TerraBase", "4. Dashboard persists in TerraBase", "5. TerraBase validates ts-auth user JWTs"} {
		if !strings.Contains(output.String(), "| "+item+" | UNKNOWN |") {
			t.Errorf("missing UNKNOWN row %q:\n%s", item, &output)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	want := map[string]int{"/healthz": 2, "/health/live": 1, "/health/ready": 1, "/.well-known/openid-configuration": 1, "/.well-known/jwks.json": 1, "/api/v1/status": 1}
	if len(requests) != len(want) {
		t.Fatalf("unexpected paths: %v", requests)
	}
	for path, count := range want {
		if requests[path] != count {
			t.Errorf("GET %s count = %d, want %d", path, requests[path], count)
		}
	}
}

func TestRunNeverFollowsRedirects(t *testing.T) {
	clearVerifyEnv(t)
	var calls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/collect", http.StatusFound)
	}))
	defer server.Close()
	var output bytes.Buffer
	if err := Run(t.Context(), append(localArgs(server.URL), "--live"), &output); err == nil {
		t.Fatal("redirects reported complete")
	}
	if calls.Load() != 0 || !strings.Contains(output.String(), "HTTP 302") {
		t.Fatalf("redirect followed or status lost: requests=%d output=%s", calls.Load(), &output)
	}
}

func TestHealthRejectsInvalidEvidence(t *testing.T) {
	for _, tc := range []struct {
		name, body, region, want string
		code                     int
	}{
		{"valid", `{"status":"ok","version":"v1","region":"gru-1"}`, "gru-1", "PASS", 200},
		{"unhealthy", `{"status":"error","version":"v1","region":"gru-1"}`, "gru-1", "FAIL", 200},
		{"missing version", `{"status":"ok","region":"gru-1"}`, "gru-1", "FAIL", 200},
		{"wrong body region", `{"status":"ok","version":"v1","region":"iad-1"}`, "gru-1", "FAIL", 200},
		{"wrong header region", `{"status":"ok","version":"v1","region":"gru-1"}`, "iad-1", "FAIL", 200},
		{"missing header region", `{"status":"ok","version":"v1","region":"gru-1"}`, "", "FAIL", 200},
		{"malformed", `{`, "gru-1", "FAIL", 200},
		{"wrong type", `{"status":"ok","version":1}`, "gru-1", "FAIL", 200},
		{"http failure", `{"status":"ok","version":"v1","region":"gru-1"}`, "gru-1", "FAIL", 503},
		{"oversized valid JSON", `{"status":"ok","version":"v1","region":"gru-1","padding":"` + strings.Repeat("x", 1<<20) + `"}`, "gru-1", "FAIL", 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/healthz" || r.Header.Get("Authorization") != "" {
					t.Errorf("unexpected health request: %s %s, headers=%v", r.Method, r.URL, r.Header)
				}
				w.Header().Set("X-TerraBase-Region", tc.region)
				w.WriteHeader(tc.code)
				io.WriteString(w, tc.body)
			}))
			defer server.Close()
			v := localVerifier(t)
			v.health("health", server.URL, "/healthz", "ok", true, "ticket")
			assertRow(t, v, "health", tc.want)
			if tc.name == "oversized valid JSON" && !strings.Contains(v.rows[0].Evidence, "oversized") {
				t.Fatalf("oversized body was not diagnosed: %s", v.rows[0].Evidence)
			}
		})
	}
}

func TestOrchestratorRejectsInvalidSnapshot(t *testing.T) {
	clearVerifyEnv(t)
	for _, tc := range []struct {
		name   string
		mutate func(*observability.MemberSnapshot)
		want   string
	}{
		{"valid", func(*observability.MemberSnapshot) {}, "PASS"},
		{"wire version", func(s *observability.MemberSnapshot) { s.Version++ }, "FAIL"},
		{"cell", func(s *observability.MemberSnapshot) { s.Cell = "iad-1" }, "FAIL"},
		{"role", func(s *observability.MemberSnapshot) { s.Role = "host" }, "FAIL"},
		{"not ready", func(s *observability.MemberSnapshot) { s.Ready = false }, "FAIL"},
		{"missing build", func(s *observability.MemberSnapshot) { s.BuildVersion = "" }, "FAIL"},
		{"missing member", func(s *observability.MemberSnapshot) { s.Member = "" }, "FAIL"},
		{"stale", func(s *observability.MemberSnapshot) { s.ObservedAt = time.Now().Add(-time.Minute) }, "FAIL"},
		{"future", func(s *observability.MemberSnapshot) { s.ObservedAt = time.Now().Add(time.Minute) }, "FAIL"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snapshot := observability.MemberSnapshot{Version: observability.SnapshotVersion, Cell: "gru", Role: "controller", Ready: true, BuildVersion: "fixture", Member: "controller-a", ObservedAt: time.Now()}
			tc.mutate(&snapshot)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/snapshot" {
					json.NewEncoder(w).Encode(snapshot)
				}
			}))
			defer server.Close()
			v := localVerifier(t)
			v.orchestrator(server.URL)
			assertRow(t, v, "1. Orchestrator deployed and working", tc.want)
		})
	}
}

func TestOrchestratorFailedHealthCannotBecomeUnknown(t *testing.T) {
	clearVerifyEnv(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/snapshot" {
			w.WriteHeader(http.StatusUnauthorized)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer server.Close()
	v := localVerifier(t)
	v.orchestrator(server.URL)
	assertRow(t, v, "1. Orchestrator deployed and working", "FAIL")
}

type failingWriter struct{ err error }

func (w failingWriter) Write([]byte) (int, error) { return 0, w.err }

func TestRunPreservesCancellationWithoutRequests(t *testing.T) {
	clearVerifyEnv(t)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer server.Close()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	args := append(localArgs(server.URL), "--live")
	if err := Run(ctx, args, io.Discard); !errors.Is(err, context.Canceled) {
		t.Errorf("Run canceled context: error = %v, want context.Canceled", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("canceled run sent %d requests", calls.Load())
	}
}

func TestRunPreservesOutputErrors(t *testing.T) {
	clearVerifyEnv(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	for _, want := range []error{io.ErrClosedPipe, io.ErrShortWrite} {
		writer := failingWriter{err: want}
		if want == io.ErrShortWrite {
			writer.err = nil
		}
		if err := Run(t.Context(), append(localArgs(server.URL), "--live"), writer); !errors.Is(err, want) {
			t.Errorf("Run output error = %v, want %v", err, want)
		}
	}
}

func TestRunRedactsSecretsAndDoesNotPrintBodies(t *testing.T) {
	clearVerifyEnv(t)
	const secret = "private-fixture-secret"
	t.Setenv("E2E_API_KEY", secret)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Version", secret+"|\tforged-row")
		w.WriteHeader(http.StatusServiceUnavailable)
		io.WriteString(w, "response-body-must-not-appear "+secret)
	}))
	defer server.Close()
	var output bytes.Buffer
	Run(t.Context(), append(localArgs(server.URL), "--live"), &output)
	if strings.Contains(output.String(), secret) || strings.Contains(output.String(), "response-body-must-not-appear") || !strings.Contains(output.String(), `[redacted]\| forged-row`) {
		t.Fatalf("unsafe report output: %s", &output)
	}
}

func TestGetCancelsInflightRequest(t *testing.T) {
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	v := localVerifier(t)
	v.ctx = ctx
	done := make(chan string, 1)
	go func() {
		_, _, _, evidence := v.get(server.URL, "/healthz", "")
		done <- evidence
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("request never started")
	}
	cancel()
	select {
	case evidence := <-done:
		if !strings.Contains(evidence, "canceled") {
			t.Fatalf("cancellation evidence = %q", evidence)
		}
	case <-time.After(time.Second):
		t.Fatal("request did not stop after cancellation")
	}
}
