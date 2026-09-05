package cloudflare

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// SecretStoreDecl contains public references; zone reconciliation cannot supply values.
type SecretStoreDecl struct {
	Name        string
	SecretNames []string
}
type SecretStore struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Created  time.Time `json:"created"`
	Modified time.Time `json:"modified"`
}

// SecretMetadata contains the documented write-only secret's public metadata.
// Cloudflare does not expose numbered versions or an activation operation.
type SecretMetadata struct {
	ID       string    `json:"id"`
	StoreID  string    `json:"store_id"`
	Name     string    `json:"name"`
	Status   string    `json:"status"`
	Created  time.Time `json:"created"`
	Modified time.Time `json:"modified"`
	Scopes   []string  `json:"scopes,omitempty"`
	Comment  string    `json:"comment,omitempty"`
}
type SecretInput struct {
	Name    string   `json:"name"`
	Value   string   `json:"value"`
	Scopes  []string `json:"scopes"`
	Comment string   `json:"comment,omitempty"`
}
type SecretUpdate struct {
	Value   *string  `json:"value,omitempty"`
	Scopes  []string `json:"scopes,omitempty"`
	Comment *string  `json:"comment,omitempty"`
}

// SecretsAPI mutates resources by provider ID, without pretending that updating
// an existing secret stages its value: consumers of that secret receive the update.
type SecretsAPI interface {
	CreateSecret(context.Context, string, SecretInput) (SecretMetadata, error)
	UpdateSecret(context.Context, string, string, SecretUpdate) (SecretMetadata, error)
	DeleteSecret(context.Context, string, string) error
	GetSecretMetadata(context.Context, string, string) (SecretMetadata, error)
}
type SecretsStoreAPI interface {
	ListSecretStores(context.Context) ([]SecretStore, error)
	CreateSecretStore(context.Context, string) error
	ListSecretMetadata(context.Context, string) ([]SecretMetadata, error)
}

var _ SecretsAPI = (*Client)(nil)
var _ SecretsStoreAPI = (*Client)(nil)

func (c *Client) ListSecretStores(ctx context.Context) ([]SecretStore, error) {
	if !validSecretID(c.AccountID) {
		return nil, errors.New("cloudflare: invalid account ID")
	}
	return readSecretsPages[SecretStore](ctx, c, "list secrets stores", c.accountPath("/secrets_store/stores"), func(v SecretStore) (string, string, bool) {
		return v.ID, v.Name, validSecretID(v.ID) && validSecretName(v.Name) && !v.Created.IsZero() && !v.Modified.Before(v.Created)
	})
}
func (c *Client) CreateSecretStore(ctx context.Context, name string) error {
	if !validSecretID(c.AccountID) || !validSecretName(name) {
		return errors.New("cloudflare: invalid secret store declaration")
	}
	var out SecretStore
	if _, err := c.secretsRequest(ctx, "create secrets store", http.MethodPost, c.accountPath("/secrets_store/stores"), map[string]string{"name": name}, &out); err != nil {
		return err
	}
	if !validSecretID(out.ID) || out.Name != name || out.Created.IsZero() || out.Modified.Before(out.Created) {
		return ErrSecretMutationOutcomeUnknown
	}
	return nil
}
func (c *Client) ListSecretMetadata(ctx context.Context, storeID string) ([]SecretMetadata, error) {
	path, err := c.secretPath(storeID, "")
	if err != nil {
		return nil, err
	}
	return readSecretsPages[SecretMetadata](ctx, c, "list secrets metadata", path, func(v SecretMetadata) (string, string, bool) {
		return v.ID, v.Name, validSecretMetadata(v, storeID, "")
	})
}
func (c *Client) CreateSecret(ctx context.Context, storeID string, input SecretInput) (SecretMetadata, error) {
	path, err := c.secretPath(storeID, "")
	if err != nil {
		return SecretMetadata{}, err
	}
	if !validSecretName(input.Name) || !validSecretValue(input.Value) || !validSecretScopes(input.Scopes) || !validSecretComment(input.Comment) {
		return SecretMetadata{}, errors.New("cloudflare: invalid secret input")
	}
	var out []SecretMetadata
	if _, err := c.secretsRequest(ctx, "create secret", http.MethodPost, path, []SecretInput{input}, &out); err != nil {
		return SecretMetadata{}, err
	}
	if len(out) != 1 || !validSecretMetadata(out[0], storeID, "") || out[0].Name != input.Name || out[0].Status == "deleted" || !sameSecretScopes(out[0].Scopes, input.Scopes) || out[0].Comment != input.Comment {
		return SecretMetadata{}, ErrSecretMutationOutcomeUnknown
	}
	return out[0], nil
}
func (c *Client) UpdateSecret(ctx context.Context, storeID, secretID string, input SecretUpdate) (SecretMetadata, error) {
	path, err := c.secretPath(storeID, secretID)
	if err != nil {
		return SecretMetadata{}, err
	}
	if secretID == "" || input.Value == nil && input.Scopes == nil && input.Comment == nil || input.Value != nil && !validSecretValue(*input.Value) || input.Scopes != nil && !validSecretScopes(input.Scopes) || input.Comment != nil && !validSecretComment(*input.Comment) {
		return SecretMetadata{}, errors.New("cloudflare: invalid secret update")
	}
	var out SecretMetadata
	if _, err := c.secretsRequest(ctx, "update secret", http.MethodPatch, path, input, &out); err != nil {
		return SecretMetadata{}, err
	}
	if !validSecretMetadata(out, storeID, secretID) || out.Status == "deleted" || input.Scopes != nil && !sameSecretScopes(out.Scopes, input.Scopes) || input.Comment != nil && out.Comment != *input.Comment {
		return SecretMetadata{}, ErrSecretMutationOutcomeUnknown
	}
	return out, nil
}
func (c *Client) DeleteSecret(ctx context.Context, storeID, secretID string) error {
	path, err := c.secretPath(storeID, secretID)
	if err != nil {
		return err
	}
	if secretID == "" {
		return errors.New("cloudflare: secret ID required")
	}
	_, err = c.secretsRequest(ctx, "delete secret", http.MethodDelete, path, nil, nil)
	return err
}
func (c *Client) GetSecretMetadata(ctx context.Context, storeID, secretID string) (SecretMetadata, error) {
	path, err := c.secretPath(storeID, secretID)
	if err != nil {
		return SecretMetadata{}, err
	}
	if secretID == "" {
		return SecretMetadata{}, errors.New("cloudflare: secret ID required")
	}
	var out SecretMetadata
	if _, err := c.secretsRequest(ctx, "get secret metadata", http.MethodGet, path, nil, &out); err != nil {
		return SecretMetadata{}, err
	}
	if !validSecretMetadata(out, storeID, secretID) {
		return SecretMetadata{}, errors.New("cloudflare: invalid secret metadata")
	}
	return out, nil
}
func (c *Client) secretPath(storeID, secretID string) (string, error) {
	if !validSecretID(c.AccountID) || !validSecretID(storeID) || secretID != "" && !validSecretID(secretID) {
		return "", errors.New("cloudflare: invalid secrets resource ID")
	}
	path := c.accountPath("/secrets_store/stores/" + url.PathEscape(storeID) + "/secrets")
	if secretID != "" {
		path += "/" + url.PathEscape(secretID)
	}
	return path, nil
}
func validSecretID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}
func validSecretName(value string) bool {
	return len(value) > 0 && len(value) <= 255 && utf8.ValidString(value) && strings.TrimSpace(value) == value && strings.IndexFunc(value, unicode.IsControl) < 0
}
func validSecretValue(value string) bool { return len(value) <= 65536 && utf8.ValidString(value) }
func validSecretComment(value string) bool {
	return len(value) <= 4096 && utf8.ValidString(value) && strings.IndexFunc(value, unicode.IsControl) < 0
}
func validSecretScopes(scopes []string) bool {
	if len(scopes) == 0 || len(scopes) > 6 {
		return false
	}
	seen := map[string]bool{}
	for _, scope := range scopes {
		switch scope {
		case "workers", "ai_gateway", "dex", "access", "containers", "websearch":
		default:
			return false
		}
		if seen[scope] {
			return false
		}
		seen[scope] = true
	}
	return true
}
func validSecretMetadata(v SecretMetadata, storeID, secretID string) bool {
	return validSecretID(v.ID) && v.StoreID == storeID && (secretID == "" || v.ID == secretID) && validSecretName(v.Name) && !v.Created.IsZero() && !v.Modified.Before(v.Created) && (v.Status == "pending" || v.Status == "active" || v.Status == "deleted") && (len(v.Scopes) == 0 || validSecretScopes(v.Scopes)) && validSecretComment(v.Comment)
}

func (z *Zone) reconcileSecrets(ctx context.Context, c *Client, p *Plan) error {
	if len(z.SecretStores) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(z.SecretStores))
	for _, want := range z.SecretStores {
		if !validSecretName(want.Name) {
			return errors.New("cloudflare: secrets store name is required")
		}
		if _, ok := seen[want.Name]; ok {
			return fmt.Errorf("cloudflare: secrets store %q declared twice", want.Name)
		}
		seen[want.Name] = struct{}{}
		for _, name := range want.SecretNames {
			if !validSecretName(name) {
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
		byName[store.Name] = store
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
			present[item.Name] = item.Status == "active"
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

func sameSecretScopes(first, second []string) bool {
	if len(first) != len(second) {
		return false
	}
	seen := map[string]bool{}
	for _, scope := range first {
		seen[scope] = true
	}
	for _, scope := range second {
		if !seen[scope] {
			return false
		}
	}
	return true
}
