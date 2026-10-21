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
	"strings"
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
    cliRedirectURIs: ["http://localhost:53000/"]
  store:
    engine: "sqlite"
    encryptionKey: {{NETBIRD_STORE_ENCRYPTION_KEY}}
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
var generatedServerSecrets = []string{"NETBIRD_RELAY_AUTH_SECRET", "NETBIRD_SESSION_COOKIE_KEY", "NETBIRD_STORE_ENCRYPTION_KEY"}

// ServerVault stores the server's secrets once and reads them back.
type ServerVault struct {
	Target     vaultsecret.Target
	Management vaultsecret.VaultClient
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
			"name": "TerraScale owner", "create_pat": true, "pat_expire_in": 365}, &setup)
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
	if err := vault.ensure(ctx, serversKeySecret, func(ctx context.Context) (string, error) {
		var key bytes.Buffer
		_, err := CreateServerSetupKey(ctx, api, d, &key, true)
		return strings.TrimSpace(key.String()), err
	}); err != nil {
		return err
	}
	return vault.ensure(ctx, operatorsKeySecret, func(ctx context.Context) (string, error) {
		return createGroupSetupKey(ctx, api, "operators")
	})
}

// createGroupSetupKey creates a reusable, never expiring key named and
// auto-assigning group.
func createGroupSetupKey(ctx context.Context, api *API, group string) (string, error) {
	var groups []apiGroup
	if err := api.do(ctx, "GET", "/groups", nil, &groups); err != nil {
		return "", err
	}
	match, err := matchName(groups, func(g apiGroup) string { return g.Name }, group, nil, "group")
	if err != nil || match == nil {
		return "", errors.Join(fmt.Errorf("NetBird group %s is missing", group), err)
	}
	var response struct {
		Key string `json:"key"`
	}
	if err := api.do(ctx, "POST", "/setup-keys", setupKeyRequest{Name: group, Type: "reusable",
		AutoGroups: []string{match.ID}}, &response); err != nil {
		return "", err
	}
	if response.Key == "" {
		return "", fmt.Errorf("manager returned no value for setup key %s; revoke it", group)
	}
	return response.Key, nil
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
