package main

import (
	"encoding/base64"
	"encoding/json/v2"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const (
	testKeyID   = "00000000000000000000000001"
	testOrg     = "00000000000000000000000002"
	testProject = "00000000000000000000000003"
	testOther   = "00000000000000000000000004"
)

func testProjectCredential() projectCredential {
	return projectCredential{APIKey: projectKeyMetadata{ID: testKeyID, OrganizationID: testOrg, ProjectID: testProject,
		Database: "e2e", Scopes: []string{"documents:read"}, ExpiresAt: time.Now().UTC().Add(time.Hour)}, Key: testKeyID + "_" + strings.Repeat("a", 52)}
}

func setProjectConfig(t *testing.T, credential projectCredential) {
	t.Helper()
	data, err := json.Marshal(credential)
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{"E2E_PROJECT_CREDENTIAL": string(data), "E2E_ORGANIZATION_ID": testOrg,
		"E2E_PROJECT_ID": testProject, "E2E_DATABASE": "e2e", "E2E_UNRELATED_PROJECT_ID": testOther} {
		t.Setenv(name, value)
	}
}

func TestProductionRequiresExactApprovedNativeProjectCredential(t *testing.T) {
	setProjectConfig(t, testProjectCredential())
	// Production origins and region cannot be redirected by old harness settings.
	t.Setenv("E2E_TERRABASE_URL", "https://untrusted.example")
	t.Setenv("E2E_AUTH_URL", "https://untrusted.example")
	e, err := production()
	if err != nil || e.TerraBaseURL != "https://api.terrascale.tech" || e.AuthURL != "https://auth.terrascale.tech" || e.Region != "gru" || e.Credential != "" || e.UserID != "" || e.APIKey != "" {
		t.Fatal("production must use fixed public origins with no management credential or data key")
	}
	for _, mutate := range []func(*projectCredential){
		func(c *projectCredential) { c.APIKey.ProjectID = "" },
		func(c *projectCredential) { c.APIKey.Database = "" },
		func(c *projectCredential) { c.APIKey.Scopes = []string{"documents:read", "documents:write"} },
		func(c *projectCredential) { c.APIKey.Scopes = []string{"documents:read", "documents:read"} },
		func(c *projectCredential) { c.APIKey.ExpiresAt = time.Time{} },
		func(c *projectCredential) { c.APIKey.ExpiresAt = time.Now().Add(-time.Second) },
		func(c *projectCredential) { c.APIKey.ExpiresAt = time.Now().Add(25 * time.Hour) },
		func(c *projectCredential) { c.APIKey.OrganizationID = testOther },
		func(c *projectCredential) { c.APIKey.ProjectID = testOther },
		func(c *projectCredential) { c.APIKey.Database = "other" },
		func(c *projectCredential) { c.Key = "tb_" + strings.Repeat("a", 43) },
		func(c *projectCredential) { c.APIKey.ID = testOther },
	} {
		c := testProjectCredential()
		mutate(&c)
		setProjectConfig(t, c)
		if _, err := production(); err == nil || strings.Contains(err.Error(), c.Key) {
			t.Fatal("broad, expired, mismatched or legacy credentials must fail without exposing the key")
		}
	}
	setProjectConfig(t, testProjectCredential())
	for _, raw := range []string{"invalid", `{"api_key":{},"key":"a","key":"b"}`, strings.Repeat("x", 65537)} {
		t.Setenv("E2E_PROJECT_CREDENTIAL", raw)
		if _, err := production(); err == nil {
			t.Fatal("accepted invalid or oversized credential JSON")
		}
	}
	setProjectConfig(t, testProjectCredential())
	t.Setenv("E2E_UNRELATED_PROJECT_ID", testProject)
	if _, err := production(); err == nil {
		t.Fatal("accepted same project as negative control")
	}
}

func fakeJWT(t *testing.T, e *environment, mutate func(map[string]any)) string {
	t.Helper()
	m := e.ProjectCredential.APIKey
	claims := map[string]any{"iss": e.AuthURL + "/terrascale", "aud": e.TerraBaseURL, "sub": m.ID,
		"org_id": m.OrganizationID, "project_id": m.ProjectID, "database": m.Database, "scope": "documents:read",
		"iat": time.Now().Unix(), "exp": time.Now().Add(15 * time.Minute).Unix()}
	if mutate != nil {
		mutate(claims)
	}
	data, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"at+jwt"}`)) + "." + base64.RawURLEncoding.EncodeToString(data) + ".c2lnbmF0dXJl"
}

func productionFake(t *testing.T, override func(http.ResponseWriter, *http.Request, *environment) bool) *environment {
	t.Helper()
	e := &environment{Target: "prod", Region: "gru", ProjectCredential: testProjectCredential(), UnrelatedProjectID: testOther}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-TerraBase-Region", "gru")
		if r.Header.Get("X-TerraBase-User-Id") != "" || (r.Method != http.MethodGet && r.URL.Path != "/terrascale/oauth/token") {
			t.Error("production sent a management identity or mutating data request")
		}
		if strings.HasPrefix(r.URL.Path, "/v1/") && r.Header.Get("Authorization") != "Bearer "+e.APIKey {
			t.Error("positive and negative reads must both present the exchanged project token")
		}
		if override != nil && override(w, r, e) {
			return
		}
		switch r.Method + " " + r.URL.Path {
		case "GET /readyz":
			fmt.Fprint(w, `{"status":"ready"}`)
		case "GET /terrascale/.well-known/openid-configuration":
			fmt.Fprintf(w, `{"issuer":%q,"token_endpoint":%q}`, e.AuthURL+"/terrascale", e.AuthURL+"/terrascale/oauth/token")
		case "POST /terrascale/oauth/token":
			id, key, ok := r.BasicAuth()
			if !ok || id != testKeyID || key != e.ProjectCredential.Key || r.ParseForm() != nil || r.Form.Get("grant_type") != "client_credentials" {
				t.Error("native client credentials contract was not used")
			}
			switch {
			case r.Form.Get("project") == testOther:
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprint(w, `{"error":"invalid_target"}`)
			case r.Form.Get("scope") == "documents:write":
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprint(w, `{"error":"invalid_scope"}`)
			default:
				if len(r.Form) != 1 {
					t.Error("positive exchange must not narrow a broad key")
				}
				fmt.Fprintf(w, `{"access_token":%q,"token_type":"Bearer","expires_in":900,"scope":"documents:read"}`, fakeJWT(t, e, nil))
			}
		case "GET /v1/projects/" + testProject + "/databases/e2e/collections":
			if r.Header.Get("Authorization") != "Bearer "+e.APIKey || r.URL.Query().Get("limit") != "1" {
				t.Error("SDK collections read must use the exchanged JWT and bounded limit")
			}
			fmt.Fprint(w, `{"items":[]}`)
		case "GET /v1/projects/" + testOther + "/databases/e2e/collections", "GET /v1/management/organizations":
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":{"code":"unknown_database"}}`)
		case "GET /v1/terrascale/organizations":
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":{"code":"unauthorized"}}`)
		default:
			t.Error("unexpected production request")
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(server.Close)
	e.TerraBaseURL, e.AuthURL, e.HTTP = server.URL, server.URL, server.Client()
	e.HTTP.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return e
}

func TestProductionReadAndEveryDenialWithHTTPFakes(t *testing.T) {
	e := productionFake(t, nil)
	for _, s := range productionScenarios() {
		if err := s.run(t.Context(), e); err != nil {
			t.Fatalf("%s: %v", s.name, err)
		}
	}
	if err := documents(t.Context(), e); err == nil {
		t.Fatal("production can enter the local mutating scenario")
	}
}

func TestProductionCannotPassUnexpectedDenialsOrAvailabilityFailures(t *testing.T) {
	for _, scenarioIndex := range []int{0, 2, 3, 4, 5, 6, 7} {
		t.Run(productionScenarios()[scenarioIndex].name, func(t *testing.T) {
			e := productionFake(t, func(w http.ResponseWriter, r *http.Request, e *environment) bool {
				if scenarioIndex == 0 && r.URL.Path == "/readyz" {
					w.WriteHeader(http.StatusServiceUnavailable)
					fmt.Fprint(w, `{"status":"not_ready"}`)
					return true
				}
				if (scenarioIndex == 2 || scenarioIndex == 5) && strings.HasSuffix(r.URL.Path, "/collections") ||
					(scenarioIndex == 6 || scenarioIndex == 7) && strings.HasSuffix(r.URL.Path, "/organizations") {
					w.WriteHeader(http.StatusServiceUnavailable)
					fmt.Fprint(w, `{"error":{"code":"unavailable"}}`)
					return true
				}
				if (scenarioIndex == 3 || scenarioIndex == 4) && r.URL.Path == "/terrascale/oauth/token" {
					r.ParseForm()
					if r.Form.Get("project") != "" || r.Form.Get("scope") != "" {
						fmt.Fprint(w, `{"access_token":"must-not-log-this","token_type":"Bearer"}`)
						return true
					}
				}
				return false
			})
			if scenarioIndex != 0 {
				if err := productionHealth(t.Context(), e); err != nil {
					t.Fatal(err)
				}
				if err := projectToken(t.Context(), e); err != nil {
					t.Fatal(err)
				}
			}
			if err := productionScenarios()[scenarioIndex].run(t.Context(), e); err == nil || strings.Contains(err.Error(), "must-not-log-this") {
				t.Fatal("unexpected success or sensitive response exposed")
			}
		})
	}
}

func TestProjectTokenRejectsForgedMetadataAndBroadJWTs(t *testing.T) {
	for _, mutate := range []func(map[string]any){
		func(c map[string]any) { delete(c, "project_id") },
		func(c map[string]any) { c["project_id"] = testOther },
		func(c map[string]any) { c["database"] = "other" },
		func(c map[string]any) { c["org_id"] = testOther },
		func(c map[string]any) { c["iss"] = "https://other.example/terrascale" },
		func(c map[string]any) { c["aud"] = "https://other.example" },
		func(c map[string]any) { c["scope"] = "documents:read documents:write" },
		func(c map[string]any) { c["exp"] = time.Now().Add(time.Hour).Unix() },
	} {
		e := productionFake(t, func(w http.ResponseWriter, r *http.Request, e *environment) bool {
			if r.URL.Path != "/terrascale/oauth/token" {
				return false
			}
			fmt.Fprintf(w, `{"access_token":%q,"token_type":"Bearer","expires_in":900,"scope":"documents:read"}`, fakeJWT(t, e, mutate))
			return true
		})
		if err := productionHealth(t.Context(), e); err != nil {
			t.Fatal(err)
		}
		if err := projectToken(t.Context(), e); err == nil || e.APIKey != "" {
			t.Fatal("unscoped or incorrect JWT accepted")
		}
	}
	if err := projectToken(t.Context(), &environment{}); err == nil {
		t.Fatal("token exchange can run before health checks")
	}
}

func TestProductionResponsesStayBoundedAndSecretFree(t *testing.T) {
	for _, body := range []string{"credential-echo-not-json", strings.Repeat("x", 65537)} {
		e := productionFake(t, func(w http.ResponseWriter, r *http.Request, _ *environment) bool {
			fmt.Fprint(w, body)
			return true
		})
		e.ProductionReady = true
		if err := projectToken(t.Context(), e); err == nil || strings.Contains(err.Error(), body[:10]) {
			t.Fatal("invalid response must fail without including its body")
		}
	}
	e := &environment{ProjectCredential: testProjectCredential(), APIKey: "fake.jwt.signature"}
	if got := redact(e.ProjectCredential.Key+" "+e.APIKey, e); got != "[redacted] [redacted]" {
		t.Fatal("project key or JWT leaked")
	}
}
