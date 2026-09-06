package reaper

import (
	"context"
	"crypto/tls"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func policyFixture() map[string]any {
	return map[string]any{"schemaVersion": 1, "organizationId": "org", "projectId": "project", "databaseId": "db", "revision": "revision-1", "observedAt": "2026-09-05T12:00:00Z", "plan": "free", "lastAuthorizedRequestAt": "2026-07-01T00:00:00Z", "deletionProtection": false, "ownerEmails": []string{"owner@example.com"}, "pauseEligible": true, "deletionEligible": false, "deletionReasons": []string{"verified_notice_schedule_unavailable"}, "accessRevoked": false, "usageStoppedAt": nil, "retainUntil": nil}
}
func policyTestNow() time.Time { return time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC) }
func policyTestScope() LifecyclePolicyScope {
	return LifecyclePolicyScope{OrganizationID: "org", ProjectID: "project", DatabaseID: "db"}
}
func policyTestClient(t *testing.T, s *httptest.Server, check func(context.Context) error) *LifecyclePolicyClient {
	t.Helper()
	c, err := NewLifecyclePolicyClient(LifecyclePolicyClientConfig{Endpoint: s.URL + "/api/internal/lifecycle/evaluate", ServiceKey: strings.Repeat("k", 32), Transport: s.Client().Transport, CheckEffectAuthority: check, Clock: ClockFunc(policyTestNow)})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestLifecyclePolicyClientContractAndFence(t *testing.T) {
	var calls atomic.Int32
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "POST" || r.URL.Path != "/api/internal/lifecycle/evaluate" || r.Header.Get("x-terrascale-lifecycle-service-key") != strings.Repeat("k", 32) || r.Header.Get("Content-Type") != "application/json" {
			t.Error("incorrect authenticated request")
		}
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		var request map[string]any
		if err := json.Unmarshal(raw, &request); err != nil {
			t.Error(err)
		}
		if len(request) != 5 || request["schemaVersion"] != float64(1) || request["organizationId"] != "org" || request["projectId"] != "project" || request["databaseId"] != "db" || request["expectedRevision"] != "revision-1" {
			t.Errorf("wrong request: %s", raw)
		}
		raw, _ = json.Marshal(policyFixture())
		_, _ = w.Write(raw)
	}))
	defer s.Close()
	c := policyTestClient(t, s, func(context.Context) error { return nil })
	scope := policyTestScope()
	scope.ExpectedRevision = "revision-1"
	facts, err := c.Evaluate(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}
	if facts.Plan != "free" || facts.LastAuthorizedRequestAt == nil || !facts.PauseEligible || facts.DeletionEligible || len(facts.DeletionReasons) != 1 {
		t.Fatalf("incorrect facts: %+v", facts)
	}
	fence := errors.New("authority lost")
	c.check = func(context.Context) error { return fence }
	if _, err := c.Evaluate(t.Context(), scope); !errors.Is(err, fence) {
		t.Fatalf("wrong fence error: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatal("effect after authority lost")
	}
}

func TestLifecyclePolicyClientRejectsInvalidFacts(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"schema", func(m map[string]any) { m["schemaVersion"] = 2 }},
		{"scope", func(m map[string]any) { m["organizationId"] = "another" }},
		{"revision", func(m map[string]any) { m["revision"] = "" }},
		{"old", func(m map[string]any) { m["observedAt"] = "2026-09-05T11:58:59Z" }},
		{"future", func(m map[string]any) { m["observedAt"] = "2026-09-05T12:00:06Z" }},
		{"unknown plan", func(m map[string]any) { m["plan"] = "paid" }},
		{"missing protection", func(m map[string]any) { delete(m, "deletionProtection") }},
		{"null protection", func(m map[string]any) { m["deletionProtection"] = nil }},
		{"empty owners", func(m map[string]any) { m["ownerEmails"] = []string{} }},
		{"invalid owner", func(m map[string]any) { m["ownerEmails"] = []string{"not an address"} }},
		{"unknown field", func(m map[string]any) { m["allowDestroy"] = true }},
		{"missing activity", func(m map[string]any) { delete(m, "lastAuthorizedRequestAt") }},
		{"future activity", func(m map[string]any) { m["lastAuthorizedRequestAt"] = "2026-09-06T00:00:00Z" }},
		{"accounting mismatch", func(m map[string]any) { m["accessRevoked"] = true }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := policyFixture()
			tc.mutate(payload)
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { raw, _ := json.Marshal(payload); _, _ = w.Write(raw) }))
			defer s.Close()
			c := policyTestClient(t, s, func(context.Context) error { return nil })
			if _, err := c.Evaluate(t.Context(), policyTestScope()); !errors.Is(err, ErrLifecyclePolicy) {
				t.Fatalf("accepted invalid facts: %v", err)
			}
		})
	}
}

func TestLifecyclePolicyClientPreservesUnknownActivityAndPaidPlans(t *testing.T) {
	for _, plan := range []string{"free", "starter", "pro", "scale"} {
		t.Run(plan, func(t *testing.T) {
			payload := policyFixture()
			payload["plan"] = plan
			payload["lastAuthorizedRequestAt"] = nil
			payload["pauseEligible"] = false
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { raw, _ := json.Marshal(payload); _, _ = w.Write(raw) }))
			defer s.Close()
			c := policyTestClient(t, s, func(context.Context) error { return nil })
			facts, err := c.Evaluate(t.Context(), policyTestScope())
			if err != nil {
				t.Fatal(err)
			}
			if facts.Plan != plan || facts.LastAuthorizedRequestAt != nil || facts.PauseEligible {
				t.Fatal("invented activity or eligibility")
			}
		})
	}
}

func TestLifecyclePolicyClientRejectsTransportAndRevisionFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"unknown source", 503, `{"secret":"must not escape"}`},
		{"revision conflict", 409, `{}`},
		{"redirect", 307, `{}`},
		{"oversized", 200, strings.Repeat(" ", 65<<10)},
		{"malformed", 200, `{`},
		{"duplicate", 200, `{"schemaVersion":1,"schemaVersion":1}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Location", "/redirected")
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer s.Close()
			c := policyTestClient(t, s, func(context.Context) error { return nil })
			if _, err := c.Evaluate(t.Context(), policyTestScope()); !errors.Is(err, ErrLifecyclePolicy) {
				t.Fatalf("unexpected error: %v", err)
			}
			if calls.Load() != 1 {
				t.Fatal("redirect or retry occurred")
			}
		})
	}
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := json.Marshal(policyFixture())
		_, _ = w.Write(raw)
	}))
	defer s.Close()
	c := policyTestClient(t, s, func(context.Context) error { return nil })
	scope := policyTestScope()
	scope.ExpectedRevision = "stale"
	if _, err := c.Evaluate(t.Context(), scope); !errors.Is(err, ErrLifecyclePolicy) {
		t.Fatal("accepted mismatched expected revision")
	}
}

func TestLifecyclePolicyClientConfiguration(t *testing.T) {
	config := LifecyclePolicyClientConfig{Endpoint: "https://dashboard.example/api/internal/lifecycle/evaluate", ServiceKey: strings.Repeat("k", 32), CheckEffectAuthority: func(context.Context) error { return nil }}
	for _, endpoint := range []string{"http://dashboard.example/api/internal/lifecycle/evaluate", "https://dashboard.example/other", "https://dashboard.example/api/internal/lifecycle/evaluate?", "https://user@dashboard.example/api/internal/lifecycle/evaluate"} {
		c := config
		c.Endpoint = endpoint
		if _, err := NewLifecyclePolicyClient(c); err == nil {
			t.Fatalf("accepted endpoint %q", endpoint)
		}
	}
	c := config
	c.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	if _, err := NewLifecyclePolicyClient(c); err == nil {
		t.Fatal("accepted unverified TLS")
	}
	c = config
	c.CheckEffectAuthority = nil
	if _, err := NewLifecyclePolicyClient(c); err == nil {
		t.Fatal("accepted missing authority")
	}
	c = config
	c.ServiceKey = "bad\r\nkey"
	if _, err := NewLifecyclePolicyClient(c); err == nil {
		t.Fatal("accepted unsafe key")
	}
	var zero LifecyclePolicyClient
	if _, err := zero.Evaluate(t.Context(), policyTestScope()); err == nil {
		t.Fatal("zero value accepted")
	}
}
