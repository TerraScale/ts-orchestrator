package main

import (
	"context"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	githubClientID   = "01M4GHA0E2E000000000000000"
	githubGrant      = "urn:terrascale:params:oauth:grant-type:github-actions"
	githubRepository = "TerraScale/ts-orchestrator"
	githubWorkflow   = githubRepository + "/.github/workflows/e2e.yml@refs/heads/main"
	githubSubject    = "repo:" + githubRepository + ":environment:production"
	githubAuthIssuer = "https://auth.terrascale.tech/terrascale"
)

func githubRequestURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" || u.Fragment != "" ||
		u.Host != u.Hostname() || !strings.HasSuffix(u.Hostname(), ".actions.githubusercontent.com") ||
		!strings.HasPrefix(u.Path, "/") || !strings.HasSuffix(u.Path, "/idtoken") || u.RawPath != "" || u.Opaque != "" {
		return nil, errors.New("Actions ID-token endpoint must be an HTTPS actions.githubusercontent.com subdomain idtoken URL")
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, errors.New("Actions ID-token endpoint query is invalid")
	}
	query.Set("audience", githubAuthIssuer)
	u.RawQuery = query.Encode()
	return u, nil
}

func githubAssertion(ctx context.Context, e *environment) (string, error) {
	for name, want := range map[string]string{
		"GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/heads/main",
		"GITHUB_REPOSITORY": githubRepository, "GITHUB_REPOSITORY_ID": "1422428095",
		"GITHUB_REPOSITORY_OWNER_ID": "206395477", "GITHUB_WORKFLOW_REF": githubWorkflow,
	} {
		if os.Getenv(name) != want {
			return "", errors.New("GitHub OIDC requires the exact manual main production workflow context")
		}
	}
	u, err := githubRequestURL(os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL"))
	bearer := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if err != nil || bearer == "" || len(bearer) > 65536 || e.Target != "prod" || !e.ProductionReady || e.APIKey == "" {
		return "", errors.New("GitHub OIDC requires a valid Actions endpoint, request bearer and passed native production checks")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", errors.New("create Actions ID-token request failed")
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	var body struct {
		Value string `json:"value"`
	}
	status, err := productionJSON(e, req, &body)
	if err != nil || status != http.StatusOK || validateGitHubAssertion(body.Value) != nil {
		return "", errors.New("Actions ID-token request failed or returned an unexpected workflow assertion")
	}
	return body.Value, nil
}

// Auth verifies the GitHub signature and single-use jti; these checks attest the requested workflow contract.
func validateGitHubAssertion(token string) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[2] == "" {
		return errors.New("GitHub assertion must be a signed JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	var claims struct {
		Issuer       string         `json:"iss"`
		Audience     string         `json:"aud"`
		Subject      string         `json:"sub"`
		Repository   string         `json:"repository"`
		RepositoryID string         `json:"repository_id"`
		OwnerID      string         `json:"repository_owner_id"`
		Workflow     string         `json:"workflow_ref"`
		Reusable     jsontext.Value `json:"job_workflow_ref"`
		Ref          string         `json:"ref"`
		Event        string         `json:"event_name"`
		Environment  string         `json:"environment"`
		JTI          string         `json:"jti"`
		IssuedAt     int64          `json:"iat"`
		Expires      int64          `json:"exp"`
	}
	now := time.Now().Unix()
	if err != nil || json.Unmarshal(payload, &claims) != nil || claims.Issuer != "https://token.actions.githubusercontent.com" ||
		claims.Audience != githubAuthIssuer || claims.Subject != githubSubject || claims.Repository != githubRepository ||
		claims.RepositoryID != "1422428095" || claims.OwnerID != "206395477" || claims.Workflow != githubWorkflow || claims.Reusable != nil ||
		claims.Ref != "refs/heads/main" || claims.Event != "workflow_dispatch" || claims.Environment != "production" ||
		claims.JTI == "" || claims.IssuedAt <= 0 || claims.IssuedAt > now+30 || claims.Expires <= now || claims.Expires <= claims.IssuedAt {
		return errors.New("GitHub assertion does not match the exact approved workflow trust")
	}
	return nil
}

func exchangeGitHubAssertion(ctx context.Context, e *environment, assertion, scope string) (int, oauthResponse, error) {
	var body oauthResponse
	if e.Target != "prod" || !e.ProductionReady || assertion == "" {
		return 0, body, errors.New("GitHub exchange requires passed production health and a workflow assertion")
	}
	form := url.Values{"client_id": {githubClientID}, "grant_type": {githubGrant}, "subject_token": {assertion}}
	if scope != "" {
		form.Set("scope", scope)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.AuthURL+"/terrascale/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return 0, body, errors.New("create GitHub token exchange request failed")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	status, err := productionJSON(e, req, &body)
	return status, body, err
}

func githubProjectToken(ctx context.Context, e *environment) error {
	e.OIDCAssertion, e.OIDCToken = "", ""
	assertion, err := githubAssertion(ctx, e)
	if err != nil {
		return err
	}
	e.OIDCAssertion = assertion
	status, body, err := exchangeGitHubAssertion(ctx, e, assertion, "")
	if err != nil || status != http.StatusOK || body.AccessToken == e.APIKey || validateProjectToken(e, body, "") != nil {
		return errors.New("GitHub project exchange failed or exceeded the approved project, database, scope or expiry")
	}
	e.OIDCToken = body.AccessToken
	return nil
}

func githubProjectCollections(ctx context.Context, e *environment) error {
	if e.OIDCToken == "" {
		return errors.New("GitHub project token check has not passed")
	}
	project := *e
	project.APIKey = e.OIDCToken
	return projectCollections(ctx, &project)
}

func githubUnrelatedCollections(ctx context.Context, e *environment) error {
	if e.OIDCToken == "" {
		return errors.New("GitHub project token check has not passed")
	}
	project := *e
	project.APIKey = e.OIDCToken
	return unrelatedCollections(ctx, &project)
}

func githubScopeDenied(ctx context.Context, e *environment) error {
	if e.OIDCToken == "" {
		return errors.New("GitHub project token check has not passed")
	}
	assertion, err := githubAssertion(ctx, e)
	if err != nil || assertion == e.OIDCAssertion || sameGitHubJTI(assertion, e.OIDCAssertion) {
		return errors.New("scope elevation probe requires a fresh GitHub assertion and jti")
	}
	return deniedGitHubExchange(ctx, e, assertion, "documents:write", "invalid_scope")
}

func sameGitHubJTI(a, b string) bool {
	// Both assertions were validated before comparing their replay identifiers.
	jti := func(token string) string {
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			return ""
		}
		payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
		var claims struct {
			JTI string `json:"jti"`
		}
		_ = json.Unmarshal(payload, &claims)
		return claims.JTI
	}
	return jti(a) == jti(b)
}

func githubReplayDenied(ctx context.Context, e *environment) error {
	if e.OIDCToken == "" || e.OIDCAssertion == "" {
		return errors.New("GitHub project token check has not passed")
	}
	return deniedGitHubExchange(ctx, e, e.OIDCAssertion, "", "invalid_grant")
}

func deniedGitHubExchange(ctx context.Context, e *environment, assertion, scope, code string) error {
	status, body, err := exchangeGitHubAssertion(ctx, e, assertion, scope)
	if err != nil || status != http.StatusBadRequest || body.Error != code || body.AccessToken != "" || body.RefreshToken != "" || body.IDToken != "" {
		return errors.New("GitHub exchange must deny with HTTP 400, the exact OAuth error and no tokens")
	}
	return nil
}
