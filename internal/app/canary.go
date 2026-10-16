package app

import (
	"bytes"
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"

	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/terrabase"
	"github.com/TerraScale/ts-orchestrator/internal/tsauth"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

// A release fence's canary (TS-623) is the first node a fenced service
// release restarts. Before the node changes, the leader runs the canary
// gate against it (the baseline); once the node serves the release, still
// out of rotation, it runs the gate again. A check that passed before and
// still fails after canaryAttempts tries fails the release: the node keeps
// its backends out, the release rolls back (the canary first) and its
// digest is recorded known bad. A check that already failed before is
// logged, not blamed on the release, so a broken dependency neither blocks
// a fix forward nor marks a good release bad. Rollbacks are not gated.
const (
	canaryAttempts = 3
	canaryRetry    = 15 * time.Second
	// canaryCheckTimeout bounds each request of the smoke gate.
	canaryCheckTimeout = 15 * time.Second
	// canaryCollection holds the smoke gate's documents; it creates it.
	canaryCollection = "canary"
)

// canaryTarget is the node a release reaches first.
type canaryTarget struct {
	Role, Node, Address string
	Canary              cellspec.Canary
	Baseline            bool
	Profile             WorkloadProfile
}

// canaryGate runs live checks against a release's canary and returns each
// failed check's reason by name. smokeGate is the gate until TS-601's live
// cross-product E2E suite replaces it.
type canaryGate func(context.Context, canaryTarget) map[string]string

// canaryRecord is a sequenced release's canary, the value of its mark
// (sequencedKey): written before the canary changes, so a new leader keeps
// the baseline and does not gate the release again once it passed.
type canaryRecord struct {
	Node     string   `json:"node,omitempty"`
	Baseline []string `json:"baseline,omitempty"`
	Passed   bool     `json:"passed,omitzero"`
}

// regressions are the checks of failed that passed in the baseline.
func (r canaryRecord) regressions(failed map[string]string) []string {
	var names []string
	for name, reason := range failed {
		if !slices.Contains(r.Baseline, name) {
			names = append(names, name+": "+reason)
		}
	}
	slices.Sort(names)
	return names
}

// Smoke gate checks.
const (
	checkAuthDiscovery = "ts-auth discovery"
	checkAuthToken     = "ts-auth token"
	checkDocuments     = "terrabase documents"
	checkDashboard     = "dashboard login"
)

// smokeGate is the canary gate until TS-601: ts-auth's OIDC discovery and
// its token endpoint, TerraBase document CRUD with If-Match in the canary's
// database, and the dashboard's own sign-in form (never the hosted page).
// The canary's role is checked on the canary node over the private network,
// the other role through the cell's public origin.
//
// The canary's credentials secret holds a ts-auth API key (tsk_…), a
// TerraBase API key (tb_…) or both, separated by white space. With a ts-auth
// key the token endpoint must issue a token for it; without one it must
// refuse an unknown key as invalid_client, which still reads ts-auth's
// storage. Documents are written with the TerraBase key, else with the
// ts-auth token: TerraBase serves data routes to tb_ keys until TS-589
// moves them to ts-auth project tokens.
type smokeGate struct {
	// memberCA verifies a TerraBase canary's member certificate
	// (controller.terrabase_ca_cert_file); nil fails its document check.
	memberCA []byte
	// credentials reads the canary's credentials from Vault.
	credentials func(context.Context, vaultsecret.Ref) (string, error)
	// public is the client of the public origins and of a ts-auth canary.
	public *http.Client
	// authPort is a ts-auth canary's port, tsauth.Port unless a test
	// changes it.
	authPort int
}

// newSmokeGate is the controller's gate: Vault through the instance
// principal, and no redirect followed.
func newSmokeGate(memberCA []byte) smokeGate {
	return smokeGate{memberCA: memberCA,
		credentials: func(ctx context.Context, ref vaultsecret.Ref) (string, error) {
			values, err := vaultsecret.ReadRefs(ctx, map[string]vaultsecret.Ref{cellspec.CanaryKey: ref})
			return values[cellspec.CanaryKey], err
		},
		public: &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (g smokeGate) check(ctx context.Context, target canaryTarget) map[string]string {
	failed := map[string]string{}
	fail := func(check string, err error) {
		if err != nil {
			failed[check] = err.Error()
		}
	}
	canary := target.Canary
	authURL, apiURL, api := canary.AuthURL, canary.APIURL, g.public
	var memberErr error
	switch target.Role {
	case tsauth.Role:
		authURL = "http://" + net.JoinHostPort(target.Address, strconv.Itoa(cmp.Or(g.authPort, tsauth.Port)))
	case terrabase.Role:
		var memberProfile terrabase.Profile
		memberProfile, memberErr = terrabase.ParseProfile(target.Profile.Env)
		if memberErr == nil && memberProfile.ClientPort == 0 {
			memberErr = errors.New("the selected terrabase profile has no client port")
		}
		if memberErr == nil {
			apiURL = "https://" + net.JoinHostPort(target.Address, strconv.Itoa(memberProfile.ClientPort))
			api, memberErr = g.member(target.Address)
		}
	}
	fail(checkAuthDiscovery, discoverAuth(ctx, g.public, authURL))
	authKey, terraBaseKey, err := g.keys(ctx, canary.Credentials)
	if err != nil {
		failed[checkAuthToken], failed[checkDocuments] = err.Error(), err.Error()
	} else {
		token, err := g.token(ctx, authURL, authKey)
		fail(checkAuthToken, err)
		switch bearer := cmp.Or(terraBaseKey, token); {
		case bearer == "":
			failed[checkDocuments] = "no TerraBase credential: no tb_ key and no ts-auth token"
		case memberErr != nil:
			failed[checkDocuments] = memberErr.Error()
		default:
			fail(checkDocuments, documentCRUD(ctx, api, apiURL, bearer, canary))
		}
	}
	if canary.DashboardLoginURL != "" {
		fail(checkDashboard, dashboardLogin(ctx, g.public, canary.DashboardLoginURL))
	}
	return failed
}

// member is a client of the TerraBase member at address: its certificate
// names the private address and chains to the member CA.
func (g smokeGate) member(address string) (*http.Client, error) {
	roots := x509.NewCertPool()
	if len(g.memberCA) == 0 || !roots.AppendCertsFromPEM(g.memberCA) {
		return nil, errors.New("this controller has no TerraBase member CA")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: roots, ServerName: address, MinVersion: tls.VersionTLS12}
	return &http.Client{Transport: transport, CheckRedirect: g.public.CheckRedirect}, nil
}

// call sends one request and returns the response with its body, at most
// 1 MiB.
func call(ctx context.Context, client *http.Client, method, target string, header http.Header, body []byte,
) (*http.Response, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, canaryCheckTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	if header != nil {
		request.Header = header
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, nil, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	return response, data, err
}

// unexpected describes a response with the wrong status; the body of an
// error answer names no secret.
func unexpected(step string, response *http.Response, body []byte) error {
	return fmt.Errorf("%s answered %d: %s", step, response.StatusCode, clipText(string(body), 200))
}

func clipText(text string, limit int) string {
	text = strings.TrimSpace(text)
	if len(text) > limit {
		return text[:limit] + "…"
	}
	return text
}

// discoverAuth reads the issuer's OpenID Provider metadata.
func discoverAuth(ctx context.Context, client *http.Client, authURL string) error {
	response, body, err := call(ctx, client, http.MethodGet, authURL+"/terrascale/.well-known/openid-configuration", nil, nil)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		return unexpected("discovery", response, body)
	}
	var metadata struct {
		Issuer        string `json:"issuer"`
		TokenEndpoint string `json:"token_endpoint"`
		JWKSURI       string `json:"jwks_uri"`
	}
	if err := json.Unmarshal(body, &metadata); err != nil || metadata.Issuer == "" || metadata.TokenEndpoint == "" ||
		metadata.JWKSURI == "" {
		return errors.New("discovery metadata lacks issuer, token_endpoint or jwks_uri")
	}
	return nil
}

// canaryProbeKey is a well-formed ts-auth API key that no one holds.
const canaryProbeKey = "tsk_00000000000000000000_0000000000000000000000000000000000000000000000000000"

// keys reads the canary's ts-auth and TerraBase API keys; either may be
// empty.
func (g smokeGate) keys(ctx context.Context, ref vaultsecret.Ref) (authKey, terraBaseKey string, err error) {
	value, err := g.credentials(ctx, ref)
	if err != nil {
		return "", "", fmt.Errorf("read the canary credentials: %w", err)
	}
	for _, key := range strings.Fields(value) {
		switch {
		case strings.HasPrefix(key, "tsk_") && len(key) == len(canaryProbeKey) && key[24] == '_':
			authKey = key
		case strings.HasPrefix(key, "tb_"):
			terraBaseKey = key
		default:
			return "", "", errors.New("the canary credentials hold something other than a tsk_ and a tb_ key")
		}
	}
	return authKey, terraBaseKey, nil
}

// token exchanges authKey for an access token at authURL. A key is tsk_,
// its 20-character id, _ and its secret; the id is the client. Without a
// key, an unknown one must be refused as invalid_client, and the token is
// empty.
func (g smokeGate) token(ctx context.Context, authURL, authKey string) (string, error) {
	key := cmp.Or(authKey, canaryProbeKey)
	header := http.Header{"Content-Type": {"application/x-www-form-urlencoded"},
		"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte(key[:24]+":"+key))}}
	response, body, err := call(ctx, g.public, http.MethodPost, authURL+"/terrascale/oauth/token", header,
		[]byte(url.Values{"grant_type": {"client_credentials"}}.Encode()))
	if err != nil {
		return "", err
	}
	if authKey == "" {
		var refusal struct {
			Error string `json:"error"`
		}
		if (response.StatusCode == http.StatusBadRequest || response.StatusCode == http.StatusUnauthorized) &&
			json.Unmarshal(body, &refusal) == nil && refusal.Error == "invalid_client" {
			return "", nil
		}
		return "", unexpected("the token endpoint, for an unknown API key,", response, body)
	}
	if response.StatusCode != http.StatusOK {
		return "", unexpected("the token endpoint", response, body)
	}
	var answer struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal(body, &answer); err != nil || answer.AccessToken == "" || !strings.EqualFold(answer.TokenType, "Bearer") {
		return "", errors.New("the token endpoint answered no bearer access token")
	}
	return answer.AccessToken, nil
}

// documentCRUD creates, reads, replaces and deletes one document of the
// canary collection, each write conditional: a stale If-Match must fail
// with 412.
func documentCRUD(ctx context.Context, client *http.Client, apiURL, token string, canary cellspec.Canary) (err error) {
	collections := apiURL + "/v1/projects/" + url.PathEscape(canary.Project) + "/databases/" +
		url.PathEscape(canary.Database) + "/collections"
	send := func(method, target string, extra http.Header, body []byte) (*http.Response, []byte, error) {
		header := http.Header{"Authorization": {"Bearer " + token}}
		if body != nil {
			header.Set("Content-Type", "application/json")
		}
		for name, values := range extra {
			header[name] = values
		}
		return call(ctx, client, method, target, header, body)
	}
	expect := func(step string, status int, response *http.Response, body []byte, err error) error {
		if err != nil {
			return fmt.Errorf("%s: %w", step, err)
		}
		if response.StatusCode != status {
			return unexpected(step, response, body)
		}
		return nil
	}
	// The collection is created on first use; 409 means it exists.
	response, body, err := send(http.MethodPost, collections, nil, []byte(`{"name":"`+canaryCollection+`"}`))
	if err == nil && response.StatusCode == http.StatusConflict {
		response.StatusCode = http.StatusCreated
	}
	if err := expect("create the collection", http.StatusCreated, response, body, err); err != nil {
		return err
	}
	document := collections + "/" + canaryCollection + "/documents/" + entityid.New()
	response, body, err = send(http.MethodPut, document, http.Header{"If-None-Match": {"*"}}, []byte(`{"n":1}`))
	if err := expect("create a document", http.StatusCreated, response, body, err); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			// Best effort: a failed check leaves no document behind.
			_, _, _ = send(http.MethodDelete, document, nil, nil)
		}
	}()
	created := response.Header.Get("ETag")
	response, body, err = send(http.MethodGet, document, nil, nil)
	if err := expect("read the document", http.StatusOK, response, body, err); err != nil {
		return err
	}
	var read struct {
		Document struct {
			N int `json:"n"`
		} `json:"document"`
	}
	if created == "" || response.Header.Get("ETag") != created || json.Unmarshal(body, &read) != nil || read.Document.N != 1 {
		return errors.New("the document read back differs from the one written")
	}
	response, body, err = send(http.MethodPut, document, http.Header{"If-Match": {created}}, []byte(`{"n":2}`))
	if err := expect("replace the document with If-Match", http.StatusOK, response, body, err); err != nil {
		return err
	}
	replaced := response.Header.Get("ETag")
	if replaced == "" || replaced == created {
		return errors.New("the replaced document has no new ETag")
	}
	response, body, err = send(http.MethodPut, document, http.Header{"If-Match": {created}}, []byte(`{"n":3}`))
	if err := expect("replace the document with a stale If-Match", http.StatusPreconditionFailed, response, body, err); err != nil {
		return err
	}
	response, body, err = send(http.MethodDelete, document, http.Header{"If-Match": {replaced}}, nil)
	return expect("delete the document with If-Match", http.StatusOK, response, body, err)
}

// dashboardLogin requires the dashboard's own password form at loginURL:
// users sign in on the dashboard, never on ts-auth's hosted page, so a
// redirect fails.
func dashboardLogin(ctx context.Context, client *http.Client, loginURL string) error {
	response, body, err := call(ctx, client, http.MethodGet, loginURL, http.Header{"Accept": {"text/html"}}, nil)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s answered %d %s", loginURL, response.StatusCode, response.Header.Get("Location"))
	}
	page := string(body)
	for _, want := range []string{`type="password"`, `/login/code`, `/login/sso`} {
		if !strings.Contains(page, want) {
			return fmt.Errorf("the sign-in page lacks %s", want)
		}
	}
	return nil
}
