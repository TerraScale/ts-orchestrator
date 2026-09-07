package keyrotation

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/oracle/oci-go-sdk/v65/secrets"
	"github.com/oracle/oci-go-sdk/v65/vault"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

// Both roles intentionally share one provider fixture, so a namespace or
// idempotency collision cannot be hidden by separate mocks.
type roleSecrets struct {
	entries map[string]*capabilityFake
	tokens  map[string]string
}

func (f *roleSecrets) ListSecrets(context.Context, vault.ListSecretsRequest) (vault.ListSecretsResponse, error) {
	result := vault.ListSecretsResponse{}
	for _, entry := range f.entries {
		result.Items = append(result.Items, vault.SecretSummary{Id: entry.secret.Id, SecretName: entry.secret.SecretName})
	}
	return result, nil
}
func (f *roleSecrets) CreateSecret(ctx context.Context, r vault.CreateSecretRequest) (vault.CreateSecretResponse, error) {
	if _, exists := f.tokens[*r.OpcRetryToken]; exists {
		return vault.CreateSecretResponse{}, errors.New("retry token collision")
	}
	entry := &capabilityFake{}
	entry.CreateSecret(ctx, r)
	entry.secret.Id = new("ref/" + *r.SecretName)
	f.entries[*entry.secret.Id] = entry
	f.tokens[*r.OpcRetryToken] = *entry.secret.Id
	// Exercise reconciliation after a provider commits but loses its reply.
	return vault.CreateSecretResponse{}, errors.New("unknown outcome")
}
func (f *roleSecrets) GetSecret(ctx context.Context, r vault.GetSecretRequest) (vault.GetSecretResponse, error) {
	entry := f.entries[*r.SecretId]
	if entry == nil {
		return vault.GetSecretResponse{}, errors.New("missing")
	}
	return entry.GetSecret(ctx, r)
}
func (f *roleSecrets) GetSecretBundle(ctx context.Context, r secrets.GetSecretBundleRequest) (secrets.GetSecretBundleResponse, error) {
	entry := f.entries[*r.SecretId]
	if entry == nil {
		return secrets.GetSecretBundleResponse{}, errors.New("missing")
	}
	return entry.GetSecretBundle(ctx, r)
}
func (f *roleSecrets) ScheduleSecretDeletion(ctx context.Context, r vault.ScheduleSecretDeletionRequest) (vault.ScheduleSecretDeletionResponse, error) {
	entry := f.entries[*r.SecretId]
	if entry == nil {
		return vault.ScheduleSecretDeletionResponse{}, errors.New("missing")
	}
	return entry.ScheduleSecretDeletion(ctx, r)
}
func TestOCIOriginProofPurposeAndRetryRemainIndependentAcrossRestart(t *testing.T) {
	capability, _, request := capabilityFixture()
	provider := &roleSecrets{entries: map[string]*capabilityFake{}, tokens: map[string]string{}}
	capability.management, capability.bundles = provider, provider
	origin := &OCIOriginProofVault{&ociHMACVault{purpose: "ts-origin-proof", config: capability.config, management: provider, bundles: provider}}
	c, err := capability.Generate(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(c.Key)
	o, err := origin.Generate(t.Context(), security.OriginProofRequest(request))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(o.Secret)
	if c.ID == o.ID || c.Reference == o.Reference || bytes.Equal(c.Key, o.Secret) || len(provider.entries) != 2 || len(provider.tokens) != 2 {
		t.Fatal("roles shared material or provider identity")
	}
	if !strings.HasPrefix(c.ID, "ts-capability-") || !strings.HasPrefix(o.ID, "ts-origin-proof-") {
		t.Fatal("role namespace lost")
	}
	if provider.entries[o.Reference].secret.FreeformTags["purpose"] != "ts-origin-proof" {
		t.Fatal("origin secret tagged as capability")
	}
	restarted := &OCIOriginProofVault{&ociHMACVault{purpose: "ts-origin-proof", config: origin.config, management: provider, bundles: provider}}
	replay, err := restarted.Generate(t.Context(), security.OriginProofRequest(request))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(replay.Secret)
	if replay.Reference != o.Reference || !bytes.Equal(replay.Secret, o.Secret) || len(provider.entries) != 2 {
		t.Fatal("restart generated another origin key")
	}
	if _, err := origin.Fetch(t.Context(), c.Reference); err == nil {
		t.Fatal("origin fetched capability")
	}
	if _, err := capability.Fetch(t.Context(), o.Reference); err == nil {
		t.Fatal("capability fetched origin")
	}
	if err := origin.Retire(t.Context(), c.Reference, "retire"); err == nil {
		t.Fatal("origin retired capability")
	}
	changed := security.OriginProofRequest(request)
	changed.Generation++
	if _, err := restarted.Generate(t.Context(), changed); err == nil {
		t.Fatal("changed generation reused origin operation")
	}
	if err := origin.Retire(t.Context(), o.Reference, "retire"); err != nil {
		t.Fatal(err)
	}
	if provider.entries[c.Reference].deletes != 0 || provider.entries[o.Reference].deletes != 1 {
		t.Fatal("retirement crossed roles")
	}
}
