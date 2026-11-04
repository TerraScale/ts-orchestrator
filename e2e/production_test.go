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
	testDB      = "00000000000000000000000005"
)

func testProjectCredential() projectCredential {
	return projectCredential{APIKey: projectKeyMetadata{ID: testKeyID, OrganizationID: testOrg, ProjectID: testProject,
		Database: testDB, Scopes: []string{"documents:read"}, ExpiresAt: time.Now().UTC().Add(time.Hour)}, Key: testKeyID + "_" + strings.Repeat("a", 52)}
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
	e := &environment{Target: "prod", Region: "gru", ProjectCredential: testProjectCredential(), Database: "e2e_read", UnrelatedDatabase: "e2e_negative"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-TerraBase-Region", "gru")
		if r.Header.Get("X-TerraBase-User-Id") != "" || (r.Method != http.MethodGet && r.URL.Path != "/terrascale/oauth/token") {
			t.Error("production sent a management identity or mutating data request")
		}
		if strings.HasPrefix(r.URL.Path, "/v1/") && r.Header.Get("Authorization") != "Bearer "+e.APIKey && (e.OIDCToken == "" || r.Header.Get("Authorization") != "Bearer "+e.OIDCToken) {
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
			case r.Form.Get("project") != "" && r.Form.Get("project") != e.ProjectCredential.APIKey.ProjectID:
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
		case "GET /v1/projects/" + testProject + "/databases/e2e_read/collections":
			if r.URL.Query().Get("limit") != "1" {
				t.Error("SDK collections read must use the exchanged JWT and bounded limit")
			}
			fmt.Fprint(w, `{"items":[]}`)
		case "GET /v1/projects/" + testProject + "/databases/e2e_negative/collections", "GET /v1/management/organizations":
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
	e := githubProductionFake(t, nil)
	for _, s := range productionScenarios() {
		if err := s.run(t.Context(), e); err != nil {
			t.Fatalf("%s: %v", s.name, err)
		}
	}
	if err := documents(t.Context(), e); err == nil {
		t.Fatal("production can enter the local mutating scenario")
	}
}
