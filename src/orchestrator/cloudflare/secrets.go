package cloudflare

import (
	"context"
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
}

type SecretsStoreAPI interface {
	ListSecretStores(context.Context) ([]SecretStore, error)
	CreateSecretStore(context.Context, string) error
	ListSecretMetadata(context.Context, string) ([]SecretMetadata, error)
}

var _ SecretsStoreAPI = (*Client)(nil)

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
