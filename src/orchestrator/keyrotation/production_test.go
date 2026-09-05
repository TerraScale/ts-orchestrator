package keyrotation

import (
	"context"
	"strings"
	"terrascale.tech/orchestrator/src/orchestrator/control/authority"
	"terrascale.tech/orchestrator/src/orchestrator/security"
	"testing"
	"time"
)

type productionIssuer struct{ material security.IdentityMaterial }

func (p *productionIssuer) Issue(_ context.Context, request security.IdentityRequest) (security.IdentityMaterial, error) {
	p.material = security.IdentityMaterial{Reference: "identity", Version: request.Generation, NotBefore: request.NotBefore, ExpiresAt: request.ExpiresAt}
	return p.material, nil
}
func (p *productionIssuer) Fetch(context.Context, string) (security.IdentityMaterial, error) {
	return p.material, nil
}
func (*productionIssuer) Retire(context.Context, string, string) error { return nil }

type productionVault struct{ material security.CapabilityMaterial }

func (p *productionVault) Generate(_ context.Context, request security.CapabilityRequest) (security.CapabilityMaterial, error) {
	p.material = security.CapabilityMaterial{ID: "capability", Reference: "capability", Version: request.Generation, Bucket: request.Bucket, NotBefore: request.NotBefore, ExpiresAt: request.ExpiresAt, Key: []byte("generated")}
	return p.material, nil
}
func (p *productionVault) Fetch(context.Context, string) (security.CapabilityMaterial, error) {
	return p.material, nil
}
func (*productionVault) Retire(context.Context, string, string) error { return nil }

type productionMembers struct{}

func (*productionMembers) Members(context.Context, string) ([]string, error) {
	return []string{"member"}, nil
}
func (*productionMembers) Distribute(context.Context, string, security.CredentialSet, string) error {
	return nil
}
func (*productionMembers) Verify(_ context.Context, _ string, generation uint64) (security.ConsumerObservation, error) {
	return security.ConsumerObservation{Generation: generation, ValidUntil: time.Now().UTC().Add(48 * time.Hour)}, nil
}
func (*productionMembers) Activate(context.Context, string, uint64, string) error { return nil }
func (*productionMembers) Retire(context.Context, string, uint64, string) error   { return nil }
func (*productionMembers) Rollback(context.Context, string, uint64, string) error { return nil }
func (*productionMembers) Fence(context.Context, string, string) error            { return nil }

type productionReload struct{}

func (*productionReload) Reload(context.Context, string, security.CredentialSet, string) error {
	return nil
}
func (*productionReload) Verify(_ context.Context, _ string, generation uint64) (security.ConsumerObservation, error) {
	return security.ConsumerObservation{Generation: generation, ValidUntil: time.Now().UTC().Add(48 * time.Hour)}, nil
}
func (*productionReload) Rollback(context.Context, string, uint64, string) error { return nil }
func (*productionReload) Fence(context.Context, string, string) error            { return nil }

type productionSecrets struct{}

func (*productionSecrets) Distribute(context.Context, security.CredentialSet, string) error {
	return nil
}
func (*productionSecrets) Verify(_ context.Context, generation uint64) (security.ConsumerObservation, error) {
	return security.ConsumerObservation{Generation: generation, ValidUntil: time.Now().UTC().Add(48 * time.Hour)}, nil
}
func (*productionSecrets) Activate(context.Context, uint64, string) error { return nil }
func (*productionSecrets) Retire(context.Context, uint64, string) error   { return nil }
func (*productionSecrets) Rollback(context.Context, uint64, string) error { return nil }
func (*productionSecrets) Fence(context.Context, string) error            { return nil }

func TestNewProductionRequiresEveryAuthority(t *testing.T) {
	if _, err := NewProduction(Config{Regions: []string{"gru"}}); err == nil || !strings.Contains(err.Error(), "identity authority") {
		t.Fatalf("missing authority error = %v", err)
	}
	issuer, vault := &productionIssuer{}, &productionVault{}
	_, err := NewProduction(Config{Issuer: issuer, Vault: vault, Members: &productionMembers{}, Secrets: &productionSecrets{}, Reloader: &productionReload{}, State: &NATSStateStoreConfig{}, Regions: []string{"gru"}})
	if err == nil {
		t.Fatal("production accepted missing live global state authority")
	}
	cluster := newRotationStateCluster(t)
	connection := cluster.connect(t)
	kv := openRotationTestLeaseStore(t, t.Context(), connection, true)
	coordinator, err := authority.RegionalAuthorityCoordinatorStartGlobalAsync(t.Context(), kv, "gru", "production")
	if err != nil {
		t.Fatal(err)
	}
	defer coordinator.Dispose()
	lease := readRotationTestLease(t, t.Context(), kv)
	stateConfig := &NATSStateStoreConfig{Connection: connection, CandidateID: lease.CandidateId, AuthorityEpoch: uint64(lease.Epoch)}
	_, err = NewProduction(Config{Issuer: issuer, Vault: vault, Members: &productionMembers{}, Secrets: &productionSecrets{}, Reloader: &productionReload{}, State: stateConfig, Regions: []string{"gru"}})
	if err != nil {
		t.Fatal(err)
	}
}
