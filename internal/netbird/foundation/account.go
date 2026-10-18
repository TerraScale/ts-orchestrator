package foundation

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/netbird"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"golang.org/x/net/html"
)

const accountLocalOrigin = "http://127.0.0.1:18081"
const accountPublicOrigin = "https://netbird.terrascale.tech"
const accountOwnerEmail = "netbird-owner@terrascale.tech"
const accountServiceName = "ts-orchestrator"

func (o *owner) accountAuthority(ctx context.Context, material region.NetBirdComponents) (region.NetBirdAccount, error) {
	if err := o.authorize(ctx, material); err != nil {
		return region.NetBirdAccount{}, err
	}
	guarded := ociclient.WithRequestGuard(ctx, func(context.Context) error { return o.authorize(ctx, material) })
	return region.ReadNetBirdAccount(guarded, o.factory, o.resolver, o.manager, material)
}

// prepareAccount runs before consuming genesis and never creates local identity.
func (o *owner) prepareAccount(ctx context.Context, material region.NetBirdComponents) error {
	a, err := o.accountAuthority(ctx, material)
	if err != nil {
		return err
	}
	password, err := a.OwnerPassword(ociclient.WithRequestGuard(ctx, func(context.Context) error { return o.authorize(ctx, material) }))
	clear(password)
	return err
}

// initializeAccount is called only in the uninterrupted fresh-genesis branch.
func (o *owner) initializeAccount(ctx context.Context, material region.NetBirdComponents) error {
	if err := o.authorize(ctx, material); err != nil {
		return err
	}
	var existing accountJournal
	found, err := o.custody.loadAccount(&existing)
	if err != nil {
		return err
	}
	if found {
		return errors.New("NetBird fresh genesis found an existing account identity")
	}
	return o.saveAccount(ctx, material, accountJournal{Binding: o.custody.binding(), SetupState: "unattempted"})
}

type accountUser struct {
	Current *bool  `json:"is_current"`
	ID      string `json:"id"`
	Email   string `json:"email"`
	Name    string `json:"name"`
	Role    string `json:"role"`
	Service bool   `json:"is_service_user"`
}
type accountToken struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	Expires time.Time `json:"expiration_date"`
}
type accountStatus struct{ code int }

func (e *accountStatus) Error() string {
	return fmt.Sprintf("NetBird local API returned HTTP %d", e.code)
}

type accountTransport struct {
	base  http.RoundTripper
	check func(context.Context) error
}

func (t accountTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != "http" || r.URL.Host != "127.0.0.1:18081" || r.URL.User != nil {
		return nil, errors.New("NetBird account refused a foreign transport destination")
	}
	if err := t.check(r.Context()); err != nil {
		return nil, err
	}
	return t.base.RoundTrip(r)
}

type accountClient struct{ http *http.Client }

func (o *owner) accountClient(ctx context.Context, material region.NetBirdComponents) *accountClient {
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, ResponseHeaderTimeout: 10 * time.Second}
	jar, _ := cookiejar.New(nil)
	return &accountClient{http: &http.Client{Transport: accountTransport{base: transport, check: func(requestCtx context.Context) error { return o.authorize(requestCtx, material) }}, Jar: jar, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}
func (c *accountClient) close() { c.http.CloseIdleConnections() }
func (t accountTransport) CloseIdleConnections() {
	if c, ok := t.base.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}

func (c *accountClient) request(ctx context.Context, method, path, authorization, contentType string, body io.Reader) ([]byte, http.Header, int, error) {
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") {
		return nil, nil, 0, errors.New("NetBird account request path invalid")
	}
	r, err := http.NewRequestWithContext(ctx, method, accountLocalOrigin+path, body)
	if err != nil {
		return nil, nil, 0, errors.New("NetBird account request invalid")
	}
	r.Header.Set("Authorization", authorization)
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	response, err := c.http.Do(r)
	if err != nil {
		return nil, nil, 0, errors.New("NetBird local request failed")
	}
	defer response.Body.Close()
	wire, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil || len(wire) > 1<<20 {
		return nil, nil, 0, errors.New("NetBird local response unreadable or oversized")
	}
	return wire, response.Header, response.StatusCode, nil
}
func (c *accountClient) api(ctx context.Context, method, path, authorization string, in, out any) error {
	var body io.Reader
	if in != nil {
		wire, err := json.Marshal(in)
		if err != nil {
			return errors.New("NetBird local request encoding failed")
		}
		body = bytes.NewReader(wire)
	}
	wire, _, status, err := c.request(ctx, method, "/api"+path, authorization, "application/json", body)
	if err != nil {
		return err
	}
	defer clear(wire)
	if status < 200 || status >= 300 {
		return &accountStatus{status}
	}
	if out != nil && json.Unmarshal(wire, out) != nil {
		return errors.New("NetBird local response shape invalid")
	}
	return nil
}
func (c *accountClient) setupRequired(ctx context.Context) (bool, error) {
	var instance struct {
		SetupRequired *bool `json:"setup_required"`
	}
	if err := c.api(ctx, "GET", "/instance", "", nil, &instance); err != nil {
		return false, err
	}
	if instance.SetupRequired == nil {
		return false, errors.New("NetBird instance omitted setup status")
	}
	return *instance.SetupRequired, nil
}
func (o *owner) accountReady(ctx context.Context, material region.NetBirdComponents) error {
	c := o.accountClient(ctx, material)
	defer c.close()
	required, err := c.setupRequired(ctx)
	if err != nil {
		return err
	}
	if required {
		return errors.New("NetBird account setup remains open")
	}
	return nil
}

func (o *owner) drainAccount(ctx context.Context, material region.NetBirdComponents) (region.NetBirdComponents, error) {
	// Retained physical shutdown must finish even if the remote proof has expired.
	if err := o.runtime.quiesce(context.WithoutCancel(ctx)); err != nil {
		return region.NetBirdComponents{}, err
	}
	fresh, err := o.refresh(ctx, material)
	if err != nil {
		return region.NetBirdComponents{}, err
	}
	if err = o.runtime.backend(ctx, o, fresh); err != nil {
		return region.NetBirdComponents{}, err
	}
	return fresh, nil
}

func (o *owner) ensureAccount(ctx context.Context, material region.NetBirdComponents) error {
	j, err := o.loadAccount()
	if err != nil {
		return err
	}
	if j.SetupState == "attempted" || j.ServiceAttempt != "" || j.TokenAttempt != "" {
		material, err = o.drainAccount(ctx, material)
		if err != nil {
			return err
		}
	}
	a, err := o.accountAuthority(ctx, material)
	if err != nil {
		return err
	}
	guarded := ociclient.WithRequestGuard(ctx, func(context.Context) error { return o.authorize(ctx, material) })
	password, err := a.OwnerPassword(guarded)
	if err != nil {
		return err
	}
	defer clear(password)
	c := o.accountClient(ctx, material)
	defer c.close()
	required, err := c.setupRequired(ctx)
	if err != nil {
		return err
	}
	if required {
		if j.SetupState == "verified" || j.OwnerID != "" {
			return errors.New("NetBird retained account requires store restoration")
		}
		j.SetupState = "attempted"
		if err = o.saveAccount(ctx, material, j); err != nil {
			return err
		}
		err = c.api(ctx, "POST", "/setup", "", map[string]any{"email": accountOwnerEmail, "password": string(password), "name": "TerraScale foundation owner"}, nil)
		if err != nil {
			_, drainErr := o.drainAccount(ctx, material)
			return errors.Join(errors.New("NetBird setup response uncertain; reobserve the drained original store"), drainErr)
		}
		required, err = c.setupRequired(ctx)
		if err != nil {
			return err
		}
		if required {
			return errors.New("NetBird setup did not close")
		}
	}
	if j.SetupState == "unattempted" {
		return errors.New("NetBird existing account has no retained setup attempt; restore its identity")
	}
	jwt, err := c.login(ctx, string(password))
	if err != nil {
		return err
	}
	var users []accountUser
	if err = c.api(ctx, "GET", "/users", "Bearer "+jwt, nil, &users); err != nil {
		return err
	}
	ownerID, err := accountOwner(users, j.OwnerID)
	if err != nil {
		return err
	}
	j.OwnerID = ownerID
	j.SetupState = "verified"
	if err = o.saveAccount(ctx, material, j); err != nil {
		return err
	}
	serviceID, err := accountService(users, j.ServiceID)
	if err != nil {
		return err
	}
	if serviceID == "" {
		j.ServiceAttempt = "attempted"
		if err = o.saveAccount(ctx, material, j); err != nil {
			return err
		}
		var user accountUser
		if err = c.api(ctx, "POST", "/users", "Bearer "+jwt, map[string]any{"name": accountServiceName, "role": "admin", "is_service_user": true, "auto_groups": []string{}}, &user); err != nil {
			_, drainErr := o.drainAccount(ctx, material)
			return errors.Join(errors.New("NetBird service-user response uncertain; reobserve drained inventory"), drainErr)
		}
		if user.Name != accountServiceName || user.Role != "admin" || !user.Service || !accountID(user.ID) {
			return errors.New("NetBird service creation returned a foreign identity")
		}
		serviceID = user.ID
	}
	j.ServiceID = serviceID
	j.ServiceAttempt = ""
	if err = o.saveAccount(ctx, material, j); err != nil {
		return err
	}
	if j.PAT != "" {
		if err = c.verifyPAT(ctx, j.PAT, j); err != nil {
			return err
		}
		if err = a.PublishPAT(guarded, []byte(j.PAT)); err != nil {
			return err
		}
		current, err := a.CurrentPAT(guarded)
		if err != nil {
			return err
		}
		if current.Value() != j.PAT {
			return errors.New("NetBird published PAT differs from retained escrow")
		}
		if err = c.verifyPAT(ctx, current.Value(), j); err != nil {
			return err
		}
		j.PublishedPATID = j.PATID
		j.PAT = ""
		j.PATID = ""
		j.TokenAttempt = ""
		j.PreviousTokens = nil
		if err = o.saveAccount(ctx, material, j); err != nil {
			return err
		}
	}
	current, readErr := a.CurrentPAT(guarded)
	if readErr == nil {
		if err = c.verifyPAT(ctx, current.Value(), j); err == nil {
			if j.TokenAttempt == "" {
				return o.accountReady(ctx, material)
			}
		} else {
			status, ok := errors.AsType[*accountStatus](err)
			if !ok || status.code != 401 {
				return err
			}
		}
	} else if !errors.Is(readErr, region.ErrFoundationMissing) {
		return readErr
	}
	path := "/users/" + serviceID + "/tokens"
	var tokens []accountToken
	if err = c.api(ctx, "GET", path, "Bearer "+jwt, nil, &tokens); err != nil {
		return err
	}
	if len(tokens) > 128 {
		return errors.New("NetBird service token inventory exceeds finite bound")
	}
	if j.TokenAttempt != "" {
		for _, token := range tokens {
			if !accountID(token.ID) {
				return errors.New("NetBird token inventory contains an invalid identity")
			}
			if token.Name == accountServiceName && !containsAccountID(j.PreviousTokens, token.ID) {
				if token.ID == j.PublishedPATID {
					return errors.New("NetBird uncertain mint overlaps original published credential")
				}
				if err = c.api(ctx, "DELETE", path+"/"+token.ID, "Bearer "+jwt, nil, nil); err != nil {
					_, drainErr := o.drainAccount(ctx, material)
					return errors.Join(errors.New("NetBird orphan token cleanup uncertain"), drainErr)
				}
			}
		}
		j.TokenAttempt = ""
		j.PreviousTokens = nil
		if err = o.saveAccount(ctx, material, j); err != nil {
			return err
		}
		return errors.New("NetBird uncertain issuance reconciled; retry from the retained original account")
	}
	j.TokenAttempt = "attempted"
	j.PreviousTokens = nil
	for _, token := range tokens {
		if !accountID(token.ID) {
			return errors.New("NetBird token inventory contains an invalid identity")
		}
		j.PreviousTokens = append(j.PreviousTokens, token.ID)
	}
	if err = o.saveAccount(ctx, material, j); err != nil {
		return err
	}
	var minted struct {
		Plain    string       `json:"plain_token"`
		Metadata accountToken `json:"personal_access_token"`
	}
	if err = c.api(ctx, "POST", path, "Bearer "+jwt, map[string]any{"name": accountServiceName, "expires_in": 365}, &minted); err != nil {
		_, drainErr := o.drainAccount(ctx, material)
		return errors.Join(errors.New("NetBird PAT mint response uncertain; retain attempt and reobserve drained inventory"), drainErr)
	}
	if !netbird.ValidAdminPAT([]byte(minted.Plain)) || !accountID(minted.Metadata.ID) || minted.Metadata.Name != accountServiceName || containsAccountID(j.PreviousTokens, minted.Metadata.ID) {
		return errors.New("NetBird minted PAT differs from its retained issuance")
	}
	j.PAT = minted.Plain
	j.PATID = minted.Metadata.ID
	if err = o.saveAccount(ctx, material, j); err != nil {
		return err
	}
	if err = c.verifyPAT(ctx, j.PAT, j); err != nil {
		return err
	}
	if err = a.PublishPAT(guarded, []byte(j.PAT)); err != nil {
		return err
	}
	published, err := a.CurrentPAT(guarded)
	if err != nil {
		return err
	}
	if published.Value() != j.PAT {
		return errors.New("NetBird PAT publication readback differs from escrow")
	}
	if err = c.verifyPAT(ctx, published.Value(), j); err != nil {
		return err
	}
	j.PublishedPATID = j.PATID
	j.PAT = ""
	j.PATID = ""
	j.TokenAttempt = ""
	j.PreviousTokens = nil
	if err = o.saveAccount(ctx, material, j); err != nil {
		return err
	}
	return o.accountReady(ctx, material)
}

func containsAccountID(ids []string, id string) bool { return slices.Contains(ids, id) }
func accountOwner(users []accountUser, expected string) (string, error) {
	var id string
	for _, u := range users {
		if u.Email == accountOwnerEmail {
			if id != "" || u.Role != "owner" || u.Service || !accountID(u.ID) {
				return "", errors.New("NetBird owner identity is ambiguous")
			}
			id = u.ID
		}
	}
	if id == "" || expected != "" && expected != id {
		return "", errors.New("NetBird account differs from its retained owner")
	}
	return id, nil
}
func accountService(users []accountUser, expected string) (string, error) {
	var id string
	for _, u := range users {
		if u.Name == accountServiceName {
			if id != "" || u.Role != "admin" || !u.Service || !accountID(u.ID) {
				return "", errors.New("NetBird service identity is ambiguous")
			}
			id = u.ID
		}
	}
	if expected != "" && id != expected {
		return "", errors.New("NetBird service differs from retained identity")
	}
	return id, nil
}
func (c *accountClient) verifyPAT(ctx context.Context, pat string, j accountJournal) error {
	if !netbird.ValidAdminPAT([]byte(pat)) {
		return errors.New("NetBird PAT shape invalid")
	}
	var users []accountUser
	if err := c.api(ctx, "GET", "/users", "Token "+pat, nil, &users); err != nil {
		return err
	}
	if _, err := accountOwner(users, j.OwnerID); err != nil {
		return err
	}
	if _, err := accountService(users, j.ServiceID); err != nil {
		return err
	}
	var current string
	for _, u := range users {
		if u.Current != nil && *u.Current {
			if current != "" || u.ID != j.ServiceID || !u.Service || u.Role != "admin" || u.Name != accountServiceName {
				return errors.New("NetBird PAT subject differs from retained admin service")
			}
			current = u.ID
		}
	}
	if current == "" {
		return errors.New("NetBird PAT omitted its authenticated subject")
	}
	return nil
}

// login follows the pinned embedded Dex authorization-code flow through loopback.
func (c *accountClient) login(ctx context.Context, password string) (string, error) {
	state := rand.Text()
	verifier := rand.Text() + rand.Text()
	sum := sha256.Sum256([]byte(verifier))
	callback := accountPublicOrigin + "/nb-auth"
	values := url.Values{"client_id": {"netbird-dashboard"}, "response_type": {"code"}, "redirect_uri": {callback}, "scope": {"openid profile email"}, "state": {state}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}, "connector_id": {"local"}}
	path := "/oauth2/auth?" + values.Encode()
	method := "GET"
	var body io.Reader
	contentType := ""
	submitted := false
	for range 12 {
		wire, headers, status, err := c.request(ctx, method, path, "", contentType, body)
		if err != nil {
			return "", err
		}
		if status >= 300 && status < 400 {
			clear(wire)
			next, err := url.Parse(headers.Get("Location"))
			if err != nil || next.User != nil || next.Fragment != "" {
				return "", errors.New("NetBird login redirect invalid")
			}
			if next.IsAbs() && next.Scheme == "https" && next.Host == "netbird.terrascale.tech" && next.Path == "/nb-auth" {
				query := next.Query()
				if len(query["state"]) != 1 || query.Get("state") != state || len(query["code"]) != 1 || query.Get("code") == "" {
					return "", errors.New("NetBird login callback invalid")
				}
				form := url.Values{"client_id": {"netbird-dashboard"}, "grant_type": {"authorization_code"}, "code": {query.Get("code")}, "redirect_uri": {callback}, "code_verifier": {verifier}}
				tokenWire, _, tokenStatus, err := c.request(ctx, "POST", "/oauth2/token", "", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
				if err != nil {
					return "", err
				}
				defer clear(tokenWire)
				var token struct {
					ID string `json:"id_token"`
				}
				if tokenStatus != 200 || json.Unmarshal(tokenWire, &token) != nil || token.ID == "" || len(token.ID) > 16384 {
					return "", errors.New("NetBird login token exchange failed")
				}
				return token.ID, nil
			}
			if next.IsAbs() && (next.Scheme != "https" || next.Host != "netbird.terrascale.tech") || next.Host != "" && !next.IsAbs() || !strings.HasPrefix(next.Path, "/oauth2/") {
				return "", errors.New("NetBird login refused a foreign redirect")
			}
			path = next.RequestURI()
			method = "GET"
			body = nil
			contentType = ""
			continue
		}
		if status != 200 || submitted {
			clear(wire)
			return "", errors.New("NetBird embedded owner login failed")
		}
		doc, err := html.Parse(bytes.NewReader(wire))
		clear(wire)
		if err != nil {
			return "", errors.New("NetBird login page invalid")
		}
		var action string
		forms := 0
		var visit func(*html.Node)
		visit = func(n *html.Node) {
			if n.Type == html.ElementNode && n.Data == "form" {
				forms++
				for _, a := range n.Attr {
					if a.Key == "action" {
						action = a.Val
					}
				}
			}
			for child := n.FirstChild; child != nil; child = child.NextSibling {
				visit(child)
			}
		}
		visit(doc)
		target, err := url.Parse(action)
		if err != nil || forms != 1 || target.IsAbs() || target.Host != "" || target.User != nil || target.Fragment != "" || !strings.HasPrefix(target.Path, "/oauth2/auth/local/") {
			return "", errors.New("NetBird embedded login form changed")
		}
		path = target.RequestURI()
		method = "POST"
		contentType = "application/x-www-form-urlencoded"
		body = strings.NewReader(url.Values{"login": {accountOwnerEmail}, "password": {password}}.Encode())
		submitted = true
	}
	return "", errors.New("NetBird login exceeded redirect bound")
}
