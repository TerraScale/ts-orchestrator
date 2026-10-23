package main

import (
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	tb "terrascale.tech/sdk/v1"
)

type projectKeyMetadata struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organization_id"`
	ProjectID      string    `json:"project_id"`
	Database       string    `json:"database"`
	Scopes         []string  `json:"scopes"`
	ExpiresAt      time.Time `json:"expires_at"`
}

type projectCredential struct {
	APIKey projectKeyMetadata `json:"api_key"`
	Key    string             `json:"key"`
}

type negativeReadTarget struct {
	OrganizationID string `json:"organization_id"`
	ProjectID      string `json:"project_id"`
	Database       string `json:"database"`
	Prerequisite   string `json:"prerequisite"`
}

var (
	nativeKeyPattern = regexp.MustCompile(`^[0-7][0-9A-HJKMNP-TV-Z]{25}_[0123456789abcdefghjkmnpqrstvwxyz]{52}$`)
	databasePattern  = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)
)

func production() (*environment, error) {
	var credential projectCredential
	raw := os.Getenv("E2E_PROJECT_CREDENTIAL")
	if len(raw) == 0 || len(raw) > 65536 || json.Unmarshal([]byte(raw), &credential) != nil {
		return nil, errors.New("E2E_PROJECT_CREDENTIAL must contain the native key creation response JSON")
	}
	m := credential.APIKey
	if !nativeKeyPattern.MatchString(credential.Key) || !strings.HasPrefix(credential.Key, m.ID+"_") || tb.ValidateID(m.ID) != nil ||
		tb.ValidateID(m.OrganizationID) != nil || tb.ValidateID(m.ProjectID) != nil || !databasePattern.MatchString(m.Database) ||
		!slices.Equal(m.Scopes, []string{"documents:read"}) || !m.ExpiresAt.After(time.Now()) || m.ExpiresAt.After(time.Now().Add(24*time.Hour)) {
		return nil, errors.New("project credential must have native ids/key, one database, only documents:read and expiry within 24 hours")
	}
	for name, want := range map[string]string{"E2E_ORGANIZATION_ID": m.OrganizationID, "E2E_PROJECT_ID": m.ProjectID, "E2E_DATABASE": m.Database} {
		if os.Getenv(name) != want {
			return nil, fmt.Errorf("%s must match the approved project credential metadata", name)
		}
	}
	unrelated := os.Getenv("E2E_UNRELATED_DATABASE")
	if !databasePattern.MatchString(unrelated) || unrelated == m.Database {
		return nil, errors.New("E2E_UNRELATED_DATABASE must name an owner-confirmed existing different database in the same approved project")
	}
	return &environment{
		Target: "prod", TerraBaseURL: "https://api.terrascale.tech", AuthURL: "https://auth.terrascale.tech", Region: "gru",
		ProjectCredential: credential, UnrelatedDatabase: unrelated,
		HTTP: &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}, nil
}

func productionScenarios() []scenario {
	return []scenario{
		{"production.health", []string{"terrabase", "ts-auth"}, []string{"TS-749"}, productionHealth},
		{"auth.project-client-credentials", []string{"ts-auth"}, []string{"TS-749"}, projectToken},
		{"terrabase.project-collections-read", []string{"terrabase", "ts-go"}, []string{"TS-749"}, projectCollections},
		{"auth.cross-project-exchange-denied", []string{"ts-auth"}, []string{"TS-749"}, func(ctx context.Context, e *environment) error {
			// A valid alternate id tests token targeting without provisioning another project.
			project := "00000000000000000000000000"
			if project == e.ProjectCredential.APIKey.ProjectID {
				project = "00000000000000000000000001"
			}
			return deniedExchange(ctx, e, url.Values{"project": {project}}, "invalid_target")
		}},
		{"auth.scope-elevation-denied", []string{"ts-auth"}, []string{"TS-749"}, func(ctx context.Context, e *environment) error {
			return deniedExchange(ctx, e, url.Values{"scope": {"documents:write"}}, "invalid_scope")
		}},
		{"terrabase.cross-database-read-denied", []string{"terrabase", "ts-go"}, []string{"TS-749"}, unrelatedCollections},
		{"auth.admin-read-denied", []string{"ts-auth"}, []string{"TS-749"}, func(ctx context.Context, e *environment) error {
			return deniedRead(ctx, e, e.AuthURL+"/v1/terrascale/organizations", http.StatusUnauthorized, "unauthorized")
		}},
		{"terrabase.management-read-denied", []string{"terrabase"}, []string{"TS-749"}, func(ctx context.Context, e *environment) error {
			return deniedRead(ctx, e, e.TerraBaseURL+"/v1/management/organizations", http.StatusNotFound, "unknown_database")
		}},
		{"auth.github-actions-project-exchange", []string{"ts-auth"}, nil, githubProjectToken},
		{"terrabase.github-actions-project-read", []string{"terrabase", "ts-go"}, nil, githubProjectCollections},
		{"terrabase.github-actions-cross-database-read-denied", []string{"terrabase", "ts-go"}, nil, githubUnrelatedCollections},
		{"auth.github-actions-scope-elevation-denied", []string{"ts-auth"}, nil, githubScopeDenied},
		{"auth.github-actions-replay-denied", []string{"ts-auth"}, nil, githubReplayDenied},
	}
}

func productionHealth(ctx context.Context, e *environment) error {
	for _, origin := range []string{e.TerraBaseURL, e.AuthURL} {
		if err := probe(ctx, e, origin, "/readyz"); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.AuthURL+"/terrascale/.well-known/openid-configuration", nil)
	if err != nil {
		return errors.New("create discovery request failed")
	}
	var discovery struct {
		Issuer        string `json:"issuer"`
		TokenEndpoint string `json:"token_endpoint"`
	}
	status, err := productionJSON(e, req, &discovery)
	if err != nil || status != http.StatusOK || discovery.Issuer != e.AuthURL+"/terrascale" || discovery.TokenEndpoint != e.AuthURL+"/terrascale/oauth/token" {
		return errors.New("OIDC discovery must name the expected issuer and token endpoint")
	}
	e.ProductionReady = true
	return nil
}

type oauthResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	Error        string `json:"error"`
}

// The pinned SDK's API-key source requires the retired tsk_ key format.
// Native HTTP also preserves denial token fields for the no-token assertion.
func exchangeProjectKey(ctx context.Context, e *environment, form url.Values) (int, oauthResponse, error) {
	var body oauthResponse
	if !e.ProductionReady {
		return 0, body, errors.New("production health checks have not passed")
	}
	form.Set("grant_type", "client_credentials")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.AuthURL+"/terrascale/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return 0, body, errors.New("create token request failed")
	}
	req.SetBasicAuth(e.ProjectCredential.APIKey.ID, e.ProjectCredential.Key)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	status, err := productionJSON(e, req, &body)
	return status, body, err
}

func projectToken(ctx context.Context, e *environment) error {
	// No project or scope narrowing: the server must attest the key's own restrictions.
	status, body, err := exchangeProjectKey(ctx, e, url.Values{})
	if err != nil || status != http.StatusOK {
		return errors.New("native project key exchange failed or returned an unexpected token contract")
	}
	if err := validateProjectToken(e, body, e.ProjectCredential.APIKey.ID); err != nil {
		return err
	}
	// TerraBase verifies the JWT signature on the following SDK read.
	e.APIKey = body.AccessToken
	return nil
}

func validateProjectToken(e *environment, body oauthResponse, subject string) error {
	parts := strings.Split(body.AccessToken, ".")
	if len(parts) != 3 || parts[2] == "" {
		return errors.New("project exchange must return a JWT")
	}
	header, headerErr := base64.RawURLEncoding.DecodeString(parts[0])
	payload, payloadErr := base64.RawURLEncoding.DecodeString(parts[1])
	var h struct {
		Algorithm string `json:"alg"`
		Type      string `json:"typ"`
	}
	var claims struct {
		Issuer         string `json:"iss"`
		Audience       any    `json:"aud"`
		Subject        string `json:"sub"`
		OrganizationID string `json:"org_id"`
		ProjectID      string `json:"project_id"`
		Database       string `json:"database"`
		Scope          string `json:"scope"`
		IssuedAt       int64  `json:"iat"`
		Expires        int64  `json:"exp"`
	}
	if headerErr != nil || payloadErr != nil || json.Unmarshal(header, &h) != nil || json.Unmarshal(payload, &claims) != nil {
		return errors.New("project JWT contract is malformed")
	}
	audienceOK := claims.Audience == e.TerraBaseURL
	if audiences, ok := claims.Audience.([]any); ok {
		audienceOK = len(audiences) == 1 && audiences[0] == e.TerraBaseURL
	}
	m := e.ProjectCredential.APIKey
	now := time.Now().Unix()
	if h.Algorithm != "ES256" || h.Type != "at+jwt" || claims.Issuer != e.AuthURL+"/terrascale" || !audienceOK ||
		claims.Subject == "" || subject != "" && claims.Subject != subject || claims.OrganizationID != m.OrganizationID || claims.ProjectID != m.ProjectID || claims.Database != m.Database ||
		claims.Scope != "documents:read" || claims.IssuedAt <= 0 || claims.IssuedAt > now+30 || claims.Expires <= now || claims.Expires <= claims.IssuedAt || claims.Expires-claims.IssuedAt > 900 || claims.Expires > m.ExpiresAt.Unix() ||
		body.ExpiresIn < 1 || body.ExpiresIn > 900 || int64(body.ExpiresIn) > m.ExpiresAt.Unix()-now+1 ||
		claims.Expires > now+int64(body.ExpiresIn)+30 || claims.Expires < now+int64(body.ExpiresIn)-30 ||
		body.Scope != "documents:read" || body.TokenType != "Bearer" || body.Error != "" || body.RefreshToken != "" || body.IDToken != "" {
		return errors.New("project JWT exceeds the approved identity, audience, scope, database or 15-minute lifetime")
	}
	return nil
}

func projectClient(e *environment) (*tb.Client, error) {
	if e.APIKey == "" {
		return nil, errors.New("project token check has not passed")
	}
	hc := *e.HTTP
	base := hc.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	hc.Transport = regionTransport{base: base, region: e.Region}
	return tb.New(tb.Config{Resolver: tb.StaticResolver(e.TerraBaseURL), Token: e.APIKey, HTTPClient: &hc, MaxRetries: -1})
}

func projectCollections(ctx context.Context, e *environment) error {
	c, err := projectClient(e)
	if err != nil {
		return err
	}
	m := e.ProjectCredential.APIKey
	page, err := c.Database(m.ProjectID, m.Database).Collections(ctx, tb.ListOptions{Limit: 1})
	if err != nil || page == nil || page.Items == nil {
		return errors.New("SDK read of the approved project's collections failed")
	}
	return nil
}

func deniedExchange(ctx context.Context, e *environment, form url.Values, code string) error {
	if e.APIKey == "" {
		return errors.New("project token check has not passed")
	}
	status, body, err := exchangeProjectKey(ctx, e, form)
	if err != nil || status != http.StatusBadRequest || body.Error != code || body.AccessToken != "" || body.RefreshToken != "" || body.IDToken != "" {
		return fmt.Errorf("token exchange must deny with HTTP 400 %s and no token", code)
	}
	return nil
}

func unrelatedCollections(ctx context.Context, e *environment) error {
	c, err := projectClient(e)
	if err != nil {
		return err
	}
	// The owner must confirm this database exists in the approved project; absence returns the same denial.
	_, err = c.Database(e.ProjectCredential.APIKey.ProjectID, e.UnrelatedDatabase).Collections(ctx, tb.ListOptions{Limit: 1})
	denied, ok := errors.AsType[*tb.APIError](err)
	if !ok || denied.Status != http.StatusNotFound || string(denied.Code) != "unknown_database" {
		return errors.New("unrelated database collections must deny with HTTP 404 unknown_database")
	}
	return nil
}

// The pinned SDK has no native ts-auth administration API or raw denial-response method.
func deniedRead(ctx context.Context, e *environment, endpoint string, wantStatus int, wantCode string) error {
	if e.APIKey == "" {
		return errors.New("project token check has not passed")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return errors.New("create read-only denial request failed")
	}
	req.Header.Set("Authorization", "Bearer "+e.APIKey)
	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	status, err := productionJSON(e, req, &body)
	if err != nil || status != wantStatus || body.Error.Code != wantCode {
		return fmt.Errorf("administrative read must deny with HTTP %d %s", wantStatus, wantCode)
	}
	return nil
}

// Never include response bodies or transport errors: either may echo a credential.
func productionJSON(e *environment, req *http.Request, out any) (int, error) {
	hc := *e.HTTP
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res, err := hc.Do(req)
	if err != nil {
		return 0, errors.New("production HTTP request failed")
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, 65537))
	if err != nil || len(data) > 65536 || json.Unmarshal(data, out) != nil {
		return res.StatusCode, errors.New("production response must be bounded valid JSON")
	}
	return res.StatusCode, nil
}
