package liveverify

import (
	"bytes"

	"encoding/json"

	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"

	"testing"
	"time"
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

func TestHealthRejectsInvalidEvidence(t *testing.T) {
	for _, tc := range []struct {
		name, body, region, want string
		code                     int
	}{
		{"valid", `{"status":"ok","version":"v1","region":"gru-1"}`, "gru-1", "PASS", 200},

		{"missing version", `{"status":"ok","region":"gru-1"}`, "gru-1", "FAIL", 200},
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
