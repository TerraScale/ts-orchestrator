package main

import (
	"encoding/base64"
	"encoding/json/v2"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

const testActionsURL = "https://run-actions-1.actions.githubusercontent.com/job/idtoken?api-version=2.0"

type oidcTestTransport func(*http.Request) (*http.Response, error)

func (f oidcTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func setGitHubContext(t *testing.T) {
	t.Helper()
	for k, v := range map[string]string{
		"GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/heads/main",
		"GITHUB_REPOSITORY": githubRepository, "GITHUB_REPOSITORY_ID": "1422428095",
		"GITHUB_REPOSITORY_OWNER_ID": "206395477", "GITHUB_WORKFLOW_REF": githubWorkflow,
		"ACTIONS_ID_TOKEN_REQUEST_URL": testActionsURL, "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "actions-bearer-never-print",
	} {
		t.Setenv(k, v)
	}
}

func fakeGitHubJWT(t *testing.T, jti string, mutate func(map[string]any)) string {
	t.Helper()
	claims := map[string]any{
		"iss": "https://token.actions.githubusercontent.com", "aud": githubAuthIssuer, "sub": githubSubject,
		"repository": githubRepository, "repository_id": "1422428095", "repository_owner_id": "206395477",
		"workflow_ref": githubWorkflow, "event_name": "workflow_dispatch", "ref": "refs/heads/main", "environment": "production",
		"jti": jti, "iat": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix(),
	}
	if mutate != nil {
		mutate(claims)
	}
	data, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`)) + "." + base64.RawURLEncoding.EncodeToString(data) + ".c2ln"
}

func githubProductionFake(t *testing.T, override func(http.ResponseWriter, *http.Request, *environment) bool) *environment {
	t.Helper()
	setGitHubContext(t)
	used := map[string]bool{}
	e := productionFake(t, func(w http.ResponseWriter, r *http.Request, e *environment) bool {
		if override != nil && override(w, r, e) {
			return true
		}
		if r.URL.Path != "/terrascale/oauth/token" || r.ParseForm() != nil || r.Form.Get("grant_type") != githubGrant {
			return false
		}
		if len(r.Form) < 3 || r.Form.Get("client_id") != "01M4GHA0E2E000000000000000" || r.Header.Get("Authorization") != "" || validateGitHubAssertion(r.Form.Get("subject_token")) != nil {
			t.Error("OIDC must use the fixed public client and a GitHub subject_token without native credentials")
		}
		assertion := r.Form.Get("subject_token")
		switch {
		case used[assertion]:
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid_grant"}`)
		case r.Form.Get("scope") == "sql:write":
			used[assertion] = true
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid_scope"}`)
		default:
			if len(r.Form) != 3 {
				t.Error("positive OIDC exchange must attest the configured trust without target or scope narrowing")
			}
			used[assertion] = true
			fmt.Fprintf(w, `{"access_token":%q,"token_type":"Bearer","expires_in":900,"scope":"sql:read"}`,
				fakeJWT(t, e, func(c map[string]any) { c["sub"] = "workflow-principal" }))
		}
		return true
	})
	base := e.HTTP.Transport
	requests := 0
	e.HTTP.Transport = oidcTestTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "run-actions-1.actions.githubusercontent.com" {
			return base.RoundTrip(r)
		}
		if r.Method != http.MethodGet || r.URL.Query().Get("audience") != githubAuthIssuer || r.URL.Query().Get("api-version") != "2.0" ||
			r.Header.Get("Authorization") != "Bearer actions-bearer-never-print" {
			t.Error("native Actions HTTPS request must preserve query and use the bearer header with exact audience")
		}
		requests++
		body, _ := json.Marshal(map[string]string{"value": fakeGitHubJWT(t, fmt.Sprint(requests), nil)})
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(body))), Request: r}, nil
	})
	return e
}

func prepareGitHubToken(t *testing.T, e *environment) {
	t.Helper()
	for _, run := range []func() error{
		func() error { return productionHealth(t.Context(), e) },
		func() error { return projectToken(t.Context(), e) },
		func() error { return githubProjectToken(t.Context(), e) },
	} {
		if err := run(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestGitHubAssertionRequiresExactWorkflowTrust(t *testing.T) {
	for field, wrong := range map[string]any{
		"iss": "https://evil.example", "aud": "api://wrong", "sub": "repo:TerraScale/ts-orchestrator:ref:refs/heads/main",
		"repository": "TerraScale/other", "repository_id": "1", "repository_owner_id": "1", "workflow_ref": strings.ReplaceAll(githubWorkflow, "main", "other"),
		"job_workflow_ref": githubWorkflow, "ref": "refs/heads/other", "event_name": "push", "environment": "staging",
		"jti": "", "iat": time.Now().Add(time.Hour).Unix(), "exp": time.Now().Add(-time.Second).Unix(),
	} {
		t.Run(field, func(t *testing.T) {
			if err := validateGitHubAssertion(fakeGitHubJWT(t, "jti", func(c map[string]any) { c[field] = wrong })); err == nil {
				t.Fatal("incorrect workflow assertion accepted")
			}
		})
	}
	for _, raw := range []string{"", "not.jwt", "x.e30.", "x.%%%.sig", fakeGitHubJWT(t, "jti", func(c map[string]any) { c["job_workflow_ref"] = nil })} {
		if validateGitHubAssertion(raw) == nil {
			t.Fatal("malformed or reusable assertion accepted")
		}
	}
}

func TestSDKReadsUseOwnTokensAndDistinctDatabasesInSameProject(t *testing.T) {
	for _, unavailable := range []bool{false, true} {
		reads := map[string]int{}
		e := githubProductionFake(t, func(w http.ResponseWriter, r *http.Request, e *environment) bool {
			if !strings.HasSuffix(r.URL.Path, "/sql/execute") {
				return false
			}
			reads[r.URL.Path]++
			if unavailable {
				w.WriteHeader(http.StatusServiceUnavailable)
				fmt.Fprint(w, `{"error":{"code":"unavailable"}}`)
				return true
			}
			switch r.URL.Path {
			case "/v1/projects/" + testProject + "/databases/e2e_read/sql/execute":
				fmt.Fprint(w, `{"results":[{"columns":[{"name":"1","decltype":null}],"rows":[[1]],"rows_affected":0,"last_insert_rowid":null}]}`)
			case "/v1/projects/" + testProject + "/databases/e2e_negative/sql/execute":
				w.WriteHeader(http.StatusNotFound)
				fmt.Fprint(w, `{"error":{"code":"unknown_database"}}`)
			default:
				t.Error("read used an unexpected project/database")
			}
			return true
		})
		prepareGitHubToken(t, e)
		base := e.HTTP.Transport
		wantToken := e.APIKey
		e.HTTP.Transport = oidcTestTransport(func(r *http.Request) (*http.Response, error) {
			if r.Header.Get("Authorization") != "Bearer "+wantToken || e.APIKey == e.OIDCToken {
				t.Error("native and OIDC reads must each use their own exchanged token")
			}
			return base.RoundTrip(r)
		})
		for _, run := range []func() error{
			func() error { return projectSQLRead(t.Context(), e) },
			func() error { return unrelatedSQLDenied(t.Context(), e) },
			func() error { wantToken = e.OIDCToken; return githubProjectSQLRead(t.Context(), e) },
			func() error { return githubUnrelatedSQLDenied(t.Context(), e) },
		} {
			if err := run(); (err != nil) != unavailable {
				t.Fatal("read must pass only its exact positive/denial response and fail on outage")
			}
		}
		if len(reads) != 2 || reads["/v1/projects/"+testProject+"/databases/e2e_read/sql/execute"] != 2 ||
			reads["/v1/projects/"+testProject+"/databases/e2e_negative/sql/execute"] != 2 {
			t.Fatal("native and OIDC must each read both distinct databases in the same project")
		}
	}
}
