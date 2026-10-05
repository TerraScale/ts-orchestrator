package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInvalidTargetWritesFailReport(t *testing.T) {
	t.Setenv("E2E_TARGET", "typo")
	t.Setenv("E2E_FORGEJO_TOKEN", "never-leak-this")
	path := filepath.Join(t.TempDir(), "report.json")
	t.Setenv("E2E_REPORT", path)
	var stdout, stderr bytes.Buffer
	if code := run(t.Context(), &stdout, &stderr); code != 1 {
		t.Fatalf("exit=%d", code)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got report
	if err = json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Results) != len(scenarios())+1 || got.Results[0].Status != "fail" || !strings.Contains(stdout.String(), "FAIL stack") {
		t.Fatalf("report=%s, summary=%s", data, &stdout)
	}
	if strings.Contains(string(data), "never-leak-this") {
		t.Fatal("credential in report")
	}
}
func TestPendingScenarioInventory(t *testing.T) {
	names := map[string]bool{}
	for _, s := range scenarios() {
		if names[s.name] || len(s.components) == 0 || len(s.tickets) == 0 || s.run == nil {
			t.Fatalf("invalid scenario: %+v", s)
		}
		names[s.name] = true
		switch s.name {
		case "terrabase.shape", "auth.signup-oidc-pkce-tokens-userinfo", "dashboard.signin-management-restart", "atlas.discovery-pin-misdirected", "ouroboros.internal-state":
			err := s.run(context.Background(), &environment{Target: "local"})
			var p pending
			if !errors.As(err, &p) || p.ticket == "" || p.reason == "" {
				t.Fatalf("%s must explicitly report pending: %v", s.name, err)
			}
		}
	}
	if len(names) != 10 {
		t.Fatalf("scenario count=%d", len(names))
	}
}
func TestProductionFailsBeforeNetworkWithoutDedicatedConfig(t *testing.T) {
	for _, name := range []string{"E2E_MANAGEMENT_CREDENTIAL", "E2E_USER_ID", "E2E_ORGANIZATION_ID", "E2E_API_KEY", "E2E_DASHBOARD_URL"} {
		t.Setenv(name, "")
	}
	if _, err := production(); err == nil {
		t.Fatal("prod accepted missing credentials")
	}
	for name, value := range map[string]string{"E2E_MANAGEMENT_CREDENTIAL": strings.Repeat("x", 32), "E2E_USER_ID": "e2e", "E2E_ORGANIZATION_ID": "dedicated", "E2E_API_KEY": "tb_" + strings.Repeat("x", 43), "E2E_DASHBOARD_URL": "https://dashboard.example.test"} {
		t.Setenv(name, value)
	}
	for _, origin := range []string{"http://example.test", "https://user:password@example.test", "https://example.test/?token=secret", "https://example.test/api"} {
		t.Setenv("E2E_TERRABASE_URL", origin)
		if _, err := production(); err == nil {
			t.Fatalf("accepted unsafe origin %q", origin)
		}
	}
}
func TestBootstrapCannotReachRemoteAdmin(t *testing.T) {
	for _, origin := range []string{"http://example.test:9464", "https://127.0.0.1:9464", "http://[::ffff:8.8.8.8]:9464"} {
		_, err := issueLocalKey(t.Context(), &environment{AdminURL: origin}, "org", "project")
		if err == nil {
			t.Fatalf("accepted remote admin %q", origin)
		}
	}
}

func TestReportCannotGreenwashFailureAsPending(t *testing.T) {
	p := pending{"TS-489", "not shipped"}
	for _, tc := range []struct {
		err  error
		want string
	}{{nil, "pass"}, {p, "pending"}, {errors.New("assertion failed"), "fail"}, {errors.Join(p, errors.New("cleanup failed")), "fail"}} {
		if got := resultStatus(tc.err); got != tc.want {
			t.Fatalf("status(%v)=%s, want %s", tc.err, got, tc.want)
		}
	}
	for _, tc := range []struct {
		err            error
		target, reason string
		want           string
	}{
		{probeError{path: "/readyz", status: 503, readinessStatus: "not_ready"}, "local", "unshipped storage probe", "pending"},
		{probeError{path: "/readyz", status: 500}, "local", "unshipped storage probe", "fail"},
		{probeError{path: "/readyz", status: 503, readinessStatus: "not_ready"}, "prod", "unshipped storage probe", "fail"},
		{probeError{path: "/readyz", status: 503, readinessStatus: "not_ready"}, "local", "", "fail"},
		{probeError{path: "/readyz", status: 503, readinessStatus: "other_failure"}, "local", "unshipped storage probe", "fail"},
		{probeError{path: "/readyz", status: 503}, "local", "unshipped storage probe", "fail"},
		{context.DeadlineExceeded, "local", "unshipped storage probe", "fail"},
		{nil, "local", "unshipped storage probe", "pass"},
		{errors.Join(probeError{path: "/readyz", status: 503, readinessStatus: "not_ready"}, errors.New("cleanup failed")), "local", "unshipped storage probe", "fail"},
	} {
		if got := resultStatus(knownUnavailable(tc.err, tc.target, tc.reason, 503, "TS-489")); got != tc.want {
			t.Fatalf("readiness(%v,%s)=%s, want %s", tc.err, tc.target, got, tc.want)
		}
	}
}

func TestMalformedReadinessCannotBecomePending(t *testing.T) {
	for _, body := range []string{`<html>not_ready</html>`, `{"status":"not_ready"} trailing`, `{"status":"not_ready","status":503}`, `{"status":false}`} {
		if status := decodeReadiness([]byte(body)); status != "" {
			t.Fatalf("malformed body produced readiness %q", status)
		}
	}
	if status := decodeReadiness([]byte(`{"status":"not_ready","version":"test"}`)); status != "not_ready" {
		t.Fatalf("valid readiness=%q", status)
	}
}
