package cloudflare

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// SecretStoreDecl declares references to material held by Cloudflare Secrets
// Store. Values are intentionally absent: rotation writes are owned by the
// security coordinator, while this reconciler only verifies that references
// required by the deployed Snippet exist.
type SecretStoreDecl struct {
	Name        string
	SecretNames []string
}

type SecretStore struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type SecretMetadata struct {
	Name      string `json:"name"`
	Version   int    `json:"version,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
	// ID and Active are provider metadata only. Values are intentionally not
	// represented by this type.
	ID     string `json:"id,omitempty"`
	Active bool   `json:"active,omitempty"`
}

type SecretsStoreAPI interface {
	ListSecretStores(context.Context) ([]SecretStore, error)
	CreateSecretStore(context.Context, string) error
	ListSecretMetadata(context.Context, string) ([]SecretMetadata, error)
}

// SecretValueAPI is the write/activation/retirement boundary for a Secrets
// Store. Every method accepts the value only transiently and returns metadata;
// values are never decoded from responses, logged, or put in plans.
type SecretValueAPI interface {
	WriteSecretValue(context.Context, string, string, []byte) (SecretMetadata, error)
	ActivateSecretVersion(context.Context, string, string, int) error
	RetireSecretVersion(context.Context, string, string, int) error
}

// SecretsStoreValuesAPI is the descriptive alias used by rotation wiring.
type SecretsStoreValuesAPI = SecretValueAPI

var _ SecretsStoreAPI = (*Client)(nil)
var _ SecretValueAPI = (*Client)(nil)

func (c *Client) ListSecretStores(ctx context.Context) ([]SecretStore, error) {
	var out []SecretStore
	err := c.do(ctx, "list secrets stores", http.MethodGet, c.accountPath("/secrets_store/stores"), nil, &out)
	return out, err
}

func (c *Client) CreateSecretStore(ctx context.Context, name string) error {
	return c.do(ctx, "create secrets store", http.MethodPost, c.accountPath("/secrets_store/stores"), map[string]string{"name": name}, nil)
}

func (c *Client) ListSecretMetadata(ctx context.Context, store string) ([]SecretMetadata, error) {
	if strings.TrimSpace(store) == "" {
		return nil, errors.New("cloudflare: secrets store name is required")
	}
	var out []SecretMetadata
	path := c.accountPath("/secrets_store/stores/" + url.PathEscape(store) + "/secrets")
	err := c.do(ctx, "list secrets metadata", http.MethodGet, path, nil, &out)
	return out, err
}

// WriteSecretValue creates a new provider version. Base64 keeps arbitrary key
// bytes out of JSON string escaping and the API response is metadata-only.
func (c *Client) WriteSecretValue(ctx context.Context, store, name string, value []byte) (SecretMetadata, error) {
	if err := validateSecretCoordinates(store, name); err != nil {
		return SecretMetadata{}, err
	}
	payload := map[string]string{
		"value_base64": base64.StdEncoding.EncodeToString(value),
	}
	var out SecretMetadata
	path := c.accountPath("/secrets_store/stores/" + url.PathEscape(store) + "/secrets/" + url.PathEscape(name) + "/versions")
	if err := c.do(ctx, "write secret value", http.MethodPost, path, payload, &out); err != nil {
		return SecretMetadata{}, err
	}
	// Some Cloudflare responses omit the logical name; retaining the caller's
	// non-secret identifier makes the receipt useful without exposing bytes.
	if out.Name == "" {
		out.Name = name
	}
	return out, nil
}

// PutSecretValue is a compatibility spelling for WriteSecretValue.
func (c *Client) PutSecretValue(ctx context.Context, store, name string, value []byte) (SecretMetadata, error) {
	return c.WriteSecretValue(ctx, store, name, value)
}

// ActivateSecretVersion selects a staged version for Snippet reads. The
// version number is the only value carried in the request.
func (c *Client) ActivateSecretVersion(ctx context.Context, store, name string, version int) error {
	if err := validateSecretCoordinates(store, name); err != nil {
		return err
	}
	if version <= 0 {
		return errors.New("cloudflare: secret version is required")
	}
	path := c.accountPath("/secrets_store/stores/" + url.PathEscape(store) + "/secrets/" + url.PathEscape(name) + "/versions/" + fmt.Sprint(version) + "/activate")
	return c.do(ctx, "activate secret version", http.MethodPost, path, nil, nil)
}

// RetireSecretVersion removes a no-longer-accepted version after overlap.
func (c *Client) RetireSecretVersion(ctx context.Context, store, name string, version int) error {
	if err := validateSecretCoordinates(store, name); err != nil {
		return err
	}
	if version <= 0 {
		return errors.New("cloudflare: secret version is required")
	}
	path := c.accountPath("/secrets_store/stores/" + url.PathEscape(store) + "/secrets/" + url.PathEscape(name) + "/versions/" + fmt.Sprint(version))
	return c.do(ctx, "retire secret version", http.MethodDelete, path, nil, nil)
}

// WriteValue, ActivateVersion, and RetireVersion keep provider adapters terse
// while preserving the explicit SecretValueAPI contract.
func (c *Client) WriteValue(ctx context.Context, store, name string, value []byte) (SecretMetadata, error) {
	return c.WriteSecretValue(ctx, store, name, value)
}
func (c *Client) ActivateVersion(ctx context.Context, store, name string, version int) error {
	return c.ActivateSecretVersion(ctx, store, name, version)
}
func (c *Client) RetireVersion(ctx context.Context, store, name string, version int) error {
	return c.RetireSecretVersion(ctx, store, name, version)
}

func validateSecretCoordinates(store, name string) error {
	if strings.TrimSpace(store) == "" {
		return errors.New("cloudflare: secrets store name is required")
	}
	if strings.TrimSpace(name) == "" || strings.ContainsAny(name, "/\\\r\n\x00") {
		return errors.New("cloudflare: secret name is required")
	}
	return nil
}

func (z *Zone) reconcileSecrets(ctx context.Context, c *Client, p *Plan) error {
	if len(z.SecretStores) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(z.SecretStores))
	for _, want := range z.SecretStores {
		if strings.TrimSpace(want.Name) == "" {
			return errors.New("cloudflare: secrets store name is required")
		}
		if _, ok := seen[want.Name]; ok {
			return fmt.Errorf("cloudflare: secrets store %q declared twice", want.Name)
		}
		seen[want.Name] = struct{}{}
		for _, name := range want.SecretNames {
			if strings.TrimSpace(name) == "" || strings.ContainsAny(name, "\r\n\x00") {
				return fmt.Errorf("cloudflare: invalid secret reference in store %q", want.Name)
			}
		}
	}
	api := SecretsStoreAPI(c)
	live, err := api.ListSecretStores(ctx)
	if err != nil {
		return err
	}
	byName := make(map[string]SecretStore, len(live))
	for _, store := range live {
		name := store.Name
		if name == "" {
			name = store.ID
		}
		if name != "" {
			byName[name] = store
		}
	}
	for _, want := range z.SecretStores {
		store, ok := byName[want.Name]
		if !ok {
			name := want.Name
			p.Changes = append(p.Changes, Change{Action: Create, Resource: "secrets-store", Ref: name, Detail: name,
				apply: func(ctx context.Context) error { return api.CreateSecretStore(ctx, name) }})
			continue
		}
		metadata, err := api.ListSecretMetadata(ctx, store.ID)
		if err != nil {
			return err
		}
		present := make(map[string]bool, len(metadata))
		for _, item := range metadata {
			present[item.Name] = true
		}
		missing := make([]string, 0)
		for _, name := range want.SecretNames {
			if !present[name] {
				missing = append(missing, name)
			}
		}
		if len(missing) > 0 {
			sort.Strings(missing)
			// Material is not available to the zone reconciler. Alert and
			// fail closed; never invent or print a secret value.
			p.Changes = append(p.Changes, Change{Action: Alert, Resource: "secret-reference", Ref: want.Name,
				Detail: fmt.Sprintf("missing Secrets Store references: %s", strings.Join(missing, ", "))})
		}
	}
	return nil
}
