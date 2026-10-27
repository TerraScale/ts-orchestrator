package manager

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/netbird"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

// ServerURL is netbird-server's loopback listener on ts-gru-1; the edge
// publishes it as DefaultManagementURL.
const ServerURL = "http://127.0.0.1:8095"

// ServerConfigTemplate is netbird-server's config. `ts-orch vault render
// --scope gru-1` fills each {{KEY}} from Vault secret gru-1-<key>.
const ServerConfigTemplate = `server:
  listenAddress: "127.0.0.1:8095"
  exposedAddress: "https://netbird.terrascale.tech:443"
  stunPorts: [3478]
  # Upstream binds metrics on every interface; only loopback and the VCN reach it.
  metricsPort: 9096
  healthcheckAddress: "127.0.0.1:9095"
  logLevel: "info"
  logFile: "console"
  dataDir: "/var/lib/netbird"
  disableAnonymousMetrics: true
  authSecret: {{NETBIRD_RELAY_AUTH_SECRET}}
  auth:
    issuer: "https://netbird.terrascale.tech/oauth2"
    signKeyRefreshEnabled: true
    sessionCookieEncryptionKey: {{NETBIRD_SESSION_COOKIE_KEY}}
    dashboardRedirectURIs:
      - "https://netbird.terrascale.tech/nb-auth"
      - "https://netbird.terrascale.tech/nb-silent-auth"
    cliRedirectURIs: ["http://localhost:53000/"]
  # Only the loopback edge may set X-Forwarded-For.
  reverseProxy:
    trustedPeers: ["127.0.0.1/32"]
  store:
    engine: "sqlite"
    encryptionKey: {{NETBIRD_DATASTORE_ENCRYPTION_KEY}}
`

// Vault secrets of the NetBird server, scope gru-1.
const (
	ownerEmail         = "mariogk@terrascale.tech"
	adminPATSecret     = "gru-1-netbird-admin-pat"
	ownerSecret        = "gru-1-netbird-owner-password"
	serversKeySecret   = "gru-1-netbird-setup-key"
	operatorsKeySecret = "gru-1-netbird-operators-setup-key"
)

// generatedServerSecrets are the config keys made once from 32 random bytes.
var generatedServerSecrets = []string{"NETBIRD_RELAY_AUTH_SECRET", "NETBIRD_SESSION_COOKIE_KEY", "NETBIRD_DATASTORE_ENCRYPTION_KEY"}

// ServerVault stores the server's secrets once and reads them back.
type ServerVault struct {
	Target     vaultsecret.Target
	Management vaultsecret.VaultClient
	Versions   vaultsecret.VersionClient
	Bundles    vaultsecret.BundleClient
}

func (v ServerVault) ensure(ctx context.Context, name string, value func(context.Context) (string, error)) error {
	stored, err := vaultsecret.Ensure(ctx, v.Management, v.Target, name, "TerraScale NetBird server", value)
	if err != nil {
		return err
	}
	// A secret created just now may not be readable yet; wait for it so the
	// next step never reads a missing value.
	for range 30 {
		if !stored.Created && !stored.Provisioning {
			return nil
		}
		if _, err := vaultsecret.Read(ctx, v.Bundles, v.Target.VaultID, name); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return fmt.Errorf("Vault secret %s is not readable yet", name)
}

func random32(context.Context) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// PrepareServer creates the generated config secrets once, so `vault render`
// can write the config before netbird-server starts.
func PrepareServer(ctx context.Context, vault ServerVault) error {
	for _, key := range generatedServerSecrets {
		if err := vault.ensure(ctx, vaultsecret.Name("gru-1", key), random32); err != nil {
			return err
		}
	}
	return vault.ensure(ctx, ownerSecret, random32)
}

// BootstrapServer makes a running netbird-server TerraScale's manager: the
// first run claims the owner over loopback and keeps its PAT in Vault; every
// run syncs GRU() and makes sure Vault holds the servers' and operators'
// setup keys. Rerunning it changes nothing.
func BootstrapServer(ctx context.Context, vault ServerVault, base string) error {
	base, err := ValidateManagementURL(base)
	if err != nil {
		return err
	}
	var instance struct {
		SetupRequired bool `json:"setup_required"`
	}
	if err := anonymous(ctx, base, "GET", "/instance", nil, &instance); err != nil {
		return err
	}
	if instance.SetupRequired {
		password, err := vaultsecret.Read(ctx, vault.Bundles, vault.Target.VaultID, ownerSecret)
		if err != nil {
			return err
		}
		var setup struct {
			PAT string `json:"personal_access_token"`
		}
		err = anonymous(ctx, base, "POST", "/setup", map[string]any{"email": ownerEmail, "password": password,
			"name": "TerraScale owner", "create_pat": true, "pat_expire_in": credentialDays}, &setup)
		if err != nil {
			return err
		}
		if !netbird.ValidAdminPAT([]byte(setup.PAT)) {
			return errors.New("NetBird /setup returned no valid PAT; reset the server data")
		}
		// The owner exists now and /setup never answers again: keep retrying
		// the store until it succeeds or the process stops.
		for {
			err = vault.ensure(ctx, adminPATSecret, func(context.Context) (string, error) { return setup.PAT, nil })
			if err == nil {
				break
			}
			select {
			case <-ctx.Done():
				return fmt.Errorf("NetBird admin PAT was created but not saved; reset the server data: %w", err)
			case <-time.After(5 * time.Second):
			}
		}
	}
	token, err := vaultsecret.Read(ctx, vault.Bundles, vault.Target.VaultID, adminPATSecret)
	if err != nil {
		return err
	}
	api, err := NewAPI(base, token)
	if err != nil {
		return err
	}
	defer api.Close()
	{
		// Access is only what GRU() grants: drop the upstream allow-all policy.
		var policies []apiPolicy
		if err := api.do(ctx, "GET", "/policies", nil, &policies); err != nil {
			return err
		}
		for _, policy := range policies {
			if policy.Name == "Default" {
				if err := api.do(ctx, "DELETE", "/policies/"+policy.ID, nil, nil); err != nil {
					return err
				}
			}
		}
	}
	d := GRU()
	if _, err := Sync(ctx, api, d, true); err != nil {
		return err
	}
	if err := rotateSetupKey(ctx, api, vault, d.ServersGroup, serversKeySecret); err != nil {
		return err
	}
	if err := rotateSetupKey(ctx, api, vault, "operators", operatorsKeySecret); err != nil {
		return err
	}
	return rotateAdminPAT(ctx, api, vault)
}

// Credentials live credentialDays and get a successor within rotateBefore of
// expiry, so a stopped loop surfaces as an expiry instead of a forever key.
const (
	credentialDays = 90
	rotateBefore   = 30 * 24 * time.Hour
)

// store keeps value as the CURRENT version of secret name, creating it first.
func (v ServerVault) store(ctx context.Context, name, value string) error {
	ref := vaultsecret.Ref{Vault: v.Target.VaultID, Name: name}
	current, err := vaultsecret.ReadCurrent(ctx, v.Bundles, ref)
	if vaultsecret.Absent(err) {
		return v.ensure(ctx, name, func(context.Context) (string, error) { return value, nil })
	}
	if err != nil {
		return err
	}
	_, err = vaultsecret.PublishVersion(ctx, v.Versions, ref, current.ID, current.Version, []byte(value))
	return err
}

// rotateSetupKey keeps a reusable key named and auto-assigning group valid:
// when no live key outlives rotateBefore it creates one, stores it in Vault and
// then revokes the older keys. Enrolled peers do not depend on the key.
func rotateSetupKey(ctx context.Context, api *API, vault ServerVault, group, secret string) error {
	var keys []apiSetupKey
	if err := api.do(ctx, "GET", "/setup-keys", nil, &keys); err != nil {
		return err
	}
	var live []apiSetupKey
	for _, key := range keys {
		if key.Name == group && key.Valid && !key.Revoked {
			if key.Expires.After(time.Now().Add(rotateBefore)) {
				return nil
			}
			live = append(live, key)
		}
	}
	var groups []apiGroup
	if err := api.do(ctx, "GET", "/groups", nil, &groups); err != nil {
		return err
	}
	match, err := matchName(groups, func(g apiGroup) string { return g.Name }, group, nil, "group")
	if err != nil || match == nil {
		return errors.Join(fmt.Errorf("NetBird group %s is missing", group), err)
	}
	var created struct {
		Key string `json:"key"`
	}
	if err := api.do(ctx, "POST", "/setup-keys", setupKeyRequest{Name: group, Type: "reusable",
		ExpiresIn: credentialDays * 24 * 3600, AutoGroups: []string{match.ID}}, &created); err != nil {
		return err
	}
	if created.Key == "" {
		return fmt.Errorf("manager returned no value for setup key %s; revoke it", group)
	}
	if err := vault.store(ctx, secret, created.Key); err != nil {
		return fmt.Errorf("setup key %s was created but not stored; it lapses in %d days: %w", group, credentialDays, err)
	}
	for _, key := range live {
		if err := api.do(ctx, "PUT", "/setup-keys/"+key.ID, map[string]any{"revoked": true, "auto_groups": key.AutoGroups}, nil); err != nil {
			return err
		}
	}
	return nil
}

type apiToken struct {
	ID         string    `json:"id"`
	Expiration time.Time `json:"expiration_date"`
}

// rotateAdminPAT gives the owner a successor PAT within rotateBefore of the
// newest one's expiry, stores it in Vault, then deletes the older tokens.
func rotateAdminPAT(ctx context.Context, api *API, vault ServerVault) error {
	var users []struct {
		ID   string `json:"id"`
		Role string `json:"role"`
	}
	if err := api.do(ctx, "GET", "/users?service_user=false", nil, &users); err != nil {
		return err
	}
	owner := ""
	for _, user := range users {
		if user.Role == "owner" {
			owner = user.ID
		}
	}
	if owner == "" {
		return errors.New("NetBird account has no owner")
	}
	var tokens []apiToken
	if err := api.do(ctx, "GET", "/users/"+owner+"/tokens", nil, &tokens); err != nil {
		return err
	}
	for _, token := range tokens {
		if token.Expiration.After(time.Now().Add(rotateBefore)) {
			return nil
		}
	}
	var created struct {
		Plain string   `json:"plain_token"`
		Token apiToken `json:"personal_access_token"`
	}
	if err := api.do(ctx, "POST", "/users/"+owner+"/tokens", map[string]any{"name": "ts-orchestrator", "expires_in": credentialDays}, &created); err != nil {
		return err
	}
	if !netbird.ValidAdminPAT([]byte(created.Plain)) {
		return errors.New("NetBird returned no valid successor PAT; delete it")
	}
	if err := vault.store(ctx, adminPATSecret, created.Plain); err != nil {
		return err
	}
	for _, token := range tokens {
		if err := api.do(ctx, "DELETE", "/users/"+owner+"/tokens/"+token.ID, nil, nil); err != nil {
			return err
		}
	}
	return nil
}

// anonymous calls the unauthenticated instance API.
func anonymous(ctx context.Context, base, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		wire, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(wire)
	}
	request, err := http.NewRequestWithContext(ctx, method, base+"/api"+path, body)
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	// Never follow a redirect: /setup carries the owner password.
	client := &http.Client{Timeout: requestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("NetBird API %s %s: %w", method, path, err)
	}
	defer response.Body.Close()
	if response.StatusCode/100 != 2 {
		return fmt.Errorf("NetBird API %s %s: HTTP %d", method, path, response.StatusCode)
	}
	return json.UnmarshalRead(io.LimitReader(response.Body, 1<<20), out)
}
