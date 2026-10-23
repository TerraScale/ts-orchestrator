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
		case r.Form.Get("scope") == "documents:write":
			used[assertion] = true
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid_scope"}`)
		default:
			if len(r.Form) != 3 {
				t.Error("positive OIDC exchange must attest the configured trust without target or scope narrowing")
			}
			used[assertion] = true
			fmt.Fprintf(w, `{"access_token":%q,"token_type":"Bearer","expires_in":900,"scope":"documents:read"}`,
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

func TestGitHubRequestURLPinsHTTPSDomainAndAudience(t *testing.T) {
	for _, raw := range []string{
		"http://run-actions-1.actions.githubusercontent.com/job/idtoken", "https://actions.githubusercontent.com/job/idtoken",
		"https://actions.githubusercontent.com.evil.example/job/idtoken", "https://evil.example/idtoken",
		"https://run-actions-1.actions.githubusercontent.com:443/job/idtoken", "https://user@run-actions-1.actions.githubusercontent.com/job/idtoken",
		testActionsURL + "#fragment", "https://run-actions-1.actions.githubusercontent.com/other", "https://[::1]/idtoken", ":invalid",
		testActionsURL + "&bad=%GG",
	} {
		if _, err := githubRequestURL(raw); err == nil || strings.Contains(err.Error(), raw) {
			t.Fatal("untrusted Actions endpoint accepted or reflected")
		}
	}
	u, err := githubRequestURL(testActionsURL + "&audience=unexpected&audience=extra")
	if err != nil || u.Query().Get("audience") != githubAuthIssuer || len(u.Query()["audience"]) != 1 || u.Query().Get("api-version") != "2.0" {
		t.Fatal("Actions URL must retain native parameters and set one exact audience")
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

func TestGitHubScopeProbeRequiresFreshAssertionAndJTI(t *testing.T) {
	e := githubProductionFake(t, nil)
	prepareGitHubToken(t, e)
	base := e.HTTP.Transport
	for _, changeBytes := range []bool{false, true} {
		e.HTTP.Transport = oidcTestTransport(func(r *http.Request) (*http.Response, error) {
			if r.URL.Host != "run-actions-1.actions.githubusercontent.com" {
				t.Error("scope exchange must not start with a used assertion or jti")
				return base.RoundTrip(r)
			}
			assertion := e.OIDCAssertion
			if changeBytes {
				assertion = fakeGitHubJWT(t, "1", func(c map[string]any) { c["extra"] = "different bytes, same jti" })
			}
			body, _ := json.Marshal(map[string]string{"value": assertion})
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(body))), Header: make(http.Header)}, nil
		})
		if githubScopeDenied(t.Context(), e) == nil {
			t.Fatal("scope probe reused a spent assertion")
		}
	}
}

func TestGitHubDenialsRejectOutageWrongErrorSuccessAndTokenLeak(t *testing.T) {
	for _, probe := range []string{"scope", "replay"} {
		for _, response := range []struct {
			status int
			body   string
		}{
			{503, `{"error":"invalid_grant"}`}, {400, `{"error":"invalid_target"}`}, {200, `{"error":"invalid_scope"}`},
			{400, `{"error":"invalid_scope","access_token":"must-not-log-this"}`},
			{400, `{"error":"invalid_grant","refresh_token":"must-not-log-this"}`},
			{400, `{"error":"invalid_grant","id_token":"must-not-log-this"}`},
		} {
			t.Run(probe+fmt.Sprint(response.status)+response.body, func(t *testing.T) {
				deny := false
				e := githubProductionFake(t, func(w http.ResponseWriter, r *http.Request, _ *environment) bool {
					if !deny || r.URL.Path != "/terrascale/oauth/token" {
						return false
					}
					w.WriteHeader(response.status)
					fmt.Fprint(w, response.body)
					return true
				})
				prepareGitHubToken(t, e)
				deny = true
				var err error
				if probe == "scope" {
					err = githubScopeDenied(t.Context(), e)
				} else {
					err = githubReplayDenied(t.Context(), e)
				}
				if err == nil || strings.Contains(err.Error(), "must-not-log-this") {
					t.Fatal("incorrect denial passed or exposed a token")
				}
			})
		}
	}
}

func TestGitHubTokenAndSDKReadCannotAcceptWrongProjectOrBroadClaims(t *testing.T) {
	for field, value := range map[string]any{
		"org_id": testOther, "project_id": testOther, "database": "other", "scope": "documents:read documents:write",
		"aud": []string{"https://other.example"}, "iss": "https://other.example", "sub": "", "exp": time.Now().Add(time.Hour).Unix(),
	} {
		t.Run(field, func(t *testing.T) {
			e := githubProductionFake(t, func(w http.ResponseWriter, r *http.Request, e *environment) bool {
				if r.URL.Path != "/terrascale/oauth/token" || r.ParseForm() != nil || r.Form.Get("grant_type") != githubGrant {
					return false
				}
				fmt.Fprintf(w, `{"access_token":%q,"token_type":"Bearer","expires_in":900,"scope":"documents:read"}`,
					fakeJWT(t, e, func(c map[string]any) { c[field] = value }))
				return true
			})
			if err := productionHealth(t.Context(), e); err != nil {
				t.Fatal(err)
			}
			if err := projectToken(t.Context(), e); err != nil {
				t.Fatal(err)
			}
			if githubProjectToken(t.Context(), e) == nil || e.OIDCToken != "" {
				t.Fatal("wrong project or broad OIDC token accepted")
			}
		})
	}
	e := githubProductionFake(t, nil)
	prepareGitHubToken(t, e)
	e.ProjectCredential.APIKey.ExpiresAt = time.Now().Add(time.Minute)
	if githubProjectToken(t.Context(), e) == nil {
		t.Fatal("OIDC token exceeded the approved deadline")
	}
}

func TestGitHubSDKReadsUseOnlyOIDCTokenAndExactSameNameDatabase(t *testing.T) {
	for _, unavailable := range []bool{false, true} {
		reads := 0
		e := githubProductionFake(t, func(w http.ResponseWriter, r *http.Request, e *environment) bool {
			if !strings.HasSuffix(r.URL.Path, "/collections") {
				return false
			}
			reads++
			if e.OIDCToken == "" || r.Header.Get("Authorization") != "Bearer "+e.OIDCToken || e.OIDCToken == e.APIKey {
				t.Error("OIDC read must use its own exchanged token, never the native project token")
			}
			if unavailable {
				w.WriteHeader(http.StatusServiceUnavailable)
				fmt.Fprint(w, `{"error":{"code":"unavailable"}}`)
				return true
			}
			switch r.URL.Path {
			case "/v1/projects/" + testProject + "/databases/e2e/collections":
				fmt.Fprint(w, `{"items":[]}`)
			case "/v1/projects/" + testOther + "/databases/e2e/collections":
				w.WriteHeader(http.StatusNotFound)
				fmt.Fprint(w, `{"error":{"code":"unknown_database"}}`)
			default:
				t.Error("OIDC read used an unexpected project/database")
			}
			return true
		})
		prepareGitHubToken(t, e)
		for _, run := range []func() error{func() error { return githubProjectCollections(t.Context(), e) }, func() error { return githubUnrelatedCollections(t.Context(), e) }} {
			if err := run(); (err != nil) != unavailable {
				t.Fatal("OIDC read must pass only its exact positive/denial response and fail on outage")
			}
		}
		if reads != 2 {
			t.Fatal("both project/database targets must be read with OIDC")
		}
	}
}

func TestProjectTokenDeadlineAndResponseLifetimeStayConsistent(t *testing.T) {
	e := &environment{TerraBaseURL: "https://api.terrascale.tech", AuthURL: "https://auth.terrascale.tech", ProjectCredential: testProjectCredential()}
	e.ProjectCredential.APIKey.ExpiresAt = time.Now().Add(time.Minute)
	body := oauthResponse{AccessToken: fakeJWT(t, e, func(c map[string]any) { c["exp"] = e.ProjectCredential.APIKey.ExpiresAt.Unix() }), TokenType: "Bearer", ExpiresIn: 60, Scope: "documents:read"}
	if err := validateProjectToken(e, body, testKeyID); err != nil {
		t.Fatal("token capped to the approved deadline must pass")
	}
	for _, mutate := range []func(*oauthResponse){
		func(b *oauthResponse) { b.ExpiresIn = 900 },
		func(b *oauthResponse) { b.RefreshToken = "not-allowed" },
		func(b *oauthResponse) { b.IDToken = "not-allowed" },
		func(b *oauthResponse) { b.Scope = "documents:read documents:write" },
		func(b *oauthResponse) {
			b.AccessToken = fakeJWT(t, e, func(c map[string]any) {
				c["exp"] = e.ProjectCredential.APIKey.ExpiresAt.Unix()
				c["aud"] = []string{e.TerraBaseURL, "https://unexpected.example"}
			})
		},
	} {
		wrong := body
		mutate(&wrong)
		if validateProjectToken(e, wrong, testKeyID) == nil {
			t.Fatal("overstated lifetime, extra token or broad audience/scope accepted")
		}
	}
}

func TestGitHubRequestsRefuseUnexpectedContextAndRedirects(t *testing.T) {
	e := githubProductionFake(t, nil)
	prepareGitHubToken(t, e)
	base := e.HTTP.Transport
	for _, name := range []string{"GITHUB_ACTIONS", "GITHUB_EVENT_NAME", "GITHUB_REF", "GITHUB_REPOSITORY", "GITHUB_REPOSITORY_ID", "GITHUB_REPOSITORY_OWNER_ID", "GITHUB_WORKFLOW_REF", "ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_TOKEN"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, "unexpected")
			if name == "ACTIONS_ID_TOKEN_REQUEST_TOKEN" {
				t.Setenv(name, "")
			}
			e.HTTP.Transport = oidcTestTransport(func(*http.Request) (*http.Response, error) {
				t.Fatal("invalid context sent a request")
				return nil, nil
			})
			if _, err := githubAssertion(t.Context(), e); err == nil {
				t.Fatal("invalid context accepted")
			}
		})
	}
	for _, endpoint := range []string{"run-actions-1.actions.githubusercontent.com", strings.TrimPrefix(e.AuthURL, "http://")} {
		e.HTTP.Transport = oidcTestTransport(func(r *http.Request) (*http.Response, error) {
			if r.URL.Host == endpoint {
				return &http.Response{StatusCode: 302, Header: http.Header{"Location": {"https://unexpected.example/idtoken"}}, Body: io.NopCloser(strings.NewReader(`{}`)), Request: r}, nil
			}
			if r.URL.Host == "unexpected.example" {
				t.Fatal("credential sent to a redirect target")
			}
			return base.RoundTrip(r)
		})
		if endpoint == "run-actions-1.actions.githubusercontent.com" {
			if _, err := githubAssertion(t.Context(), e); err == nil {
				t.Fatal("Actions redirect accepted")
			}
		} else if githubReplayDenied(t.Context(), e) == nil {
			t.Fatal("auth redirect accepted as denial")
		}
	}
	if got := redact(e.OIDCAssertion+" "+e.OIDCToken+" actions-bearer-never-print", e); got != "[redacted] [redacted] [redacted]" {
		t.Fatal("OIDC assertion, access token or Actions bearer was not redacted")
	}
}
