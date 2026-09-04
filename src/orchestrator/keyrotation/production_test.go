package keyrotation

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/cloudflare"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

type valueAPI struct {
	mu      sync.Mutex
	writes  []string
	active  []string
	retired []string
	fail    bool
}

func (a *valueAPI) WriteSecretValue(_ context.Context, _, name string, value []byte) (cloudflare.SecretMetadata, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.fail {
		return cloudflare.SecretMetadata{}, errors.New("provider response contained secret-value")
	}
	a.writes = append(a.writes, name+":"+string(value))
	return cloudflare.SecretMetadata{Name: name, Version: len(a.writes)}, nil
}
func (a *valueAPI) ActivateSecretVersion(_ context.Context, _, name string, version int) error {
	a.mu.Lock()
	a.active = append(a.active, name+":"+itoa(version))
	a.mu.Unlock()
	return nil
}
func (a *valueAPI) RetireSecretVersion(_ context.Context, _, name string, version int) error {
	a.mu.Lock()
	a.retired = append(a.retired, name+":"+itoa(version))
	a.mu.Unlock()
	return nil
}

func itoa(value int) string {
	if value == 1 {
		return "1"
	}
	if value == 2 {
		return "2"
	}
	return "version"
}

type capabilityAuthority struct{ fenced bool }

func (a *capabilityAuthority) VerifyCapability(_ context.Context, generation uint64, _, _ string) (security.ConsumerObservation, error) {
	return security.ConsumerObservation{Generation: generation, ValidUntil: time.Now().UTC().Add(time.Hour)}, nil
}
func (a *capabilityAuthority) FenceCapability(context.Context, string) error {
	a.fenced = true
	return nil
}

func capabilityMaterial(version uint64, key string) security.CapabilityMaterial {
	return security.CapabilityMaterial{ID: "id-" + itoa(int(version)), Reference: "ref-" + itoa(int(version)), Version: version, Bucket: int64(version), NotBefore: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(24 * time.Hour), Key: []byte(key)}
}

func TestNewCloudflareSecretsStoreRequiresGenerationAuthorities(t *testing.T) {
	values := &valueAPI{}
	if _, err := NewCloudflareSecretsStore(CloudflareSecretsConfig{Values: values, Store: "rotation", CurrentName: "current", PreviousName: "previous"}); err == nil {
		t.Fatal("missing observer/fencer was accepted")
	}
	if _, err := NewCloudflareSecretsStore(CloudflareSecretsConfig{Values: values, Store: "rotation", CurrentName: "current", PreviousName: "current", Observer: &capabilityAuthority{}, Fencer: &capabilityAuthority{}}); err == nil {
		t.Fatal("ambiguous secret names were accepted")
	}
}

func TestCloudflareSecretsStorePublishesCurrentAndPreviousWithoutLeakingErrors(t *testing.T) {
	values := &valueAPI{}
	authority := &capabilityAuthority{}
	store, err := NewCloudflareSecretsStore(CloudflareSecretsConfig{Values: values, Store: "rotation", CurrentName: "current", PreviousName: "previous", Observer: authority, Fencer: authority})
	if err != nil {
		t.Fatal(err)
	}
	credentials := security.CredentialSet{Capability: capabilityMaterial(2, "new-secret"), PreviousCapability: capabilityMaterial(1, "old-secret")}
	if err := store.Distribute(context.Background(), credentials, "operation-key"); err != nil {
		t.Fatal(err)
	}
	if err := store.Activate(context.Background(), 2, "activate-key"); err != nil {
		t.Fatal(err)
	}
	values.mu.Lock()
	writes, active := append([]string(nil), values.writes...), append([]string(nil), values.active...)
	values.mu.Unlock()
	if len(writes) != 2 || writes[0] != "current:new-secret" || writes[1] != "previous:old-secret" {
		t.Fatalf("staged ring = %v", writes)
	}
	if len(active) != 2 || active[0] != "current:1" || active[1] != "previous:2" {
		t.Fatalf("activation order = %v", active)
	}
	if _, err := store.Verify(context.Background(), 2); err != nil {
		t.Fatal(err)
	}
	if err := store.Rollback(context.Background(), 2, "rollback-key"); err != nil {
		t.Fatal(err)
	}
	values.fail = true
	if err := store.Distribute(context.Background(), security.CredentialSet{Capability: capabilityMaterial(3, "secret-value")}, "operation-key"); err == nil || strings.Contains(err.Error(), "secret-value") || strings.Contains(err.Error(), "provider response") {
		t.Fatalf("provider detail leaked: %v", err)
	}
}

func TestCloudflareSecretsStoreDistributeIsIdempotentAndRaceSafe(t *testing.T) {
	values := &valueAPI{}
	authority := &capabilityAuthority{}
	store, err := NewCloudflareSecretsStore(CloudflareSecretsConfig{Values: values, Store: "rotation", CurrentName: "current", PreviousName: "previous", Observer: authority, Fencer: authority})
	if err != nil {
		t.Fatal(err)
	}
	credentials := security.CredentialSet{Capability: capabilityMaterial(1, "secret")}
	var wait sync.WaitGroup
	for i := 0; i < 32; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if err := store.Distribute(context.Background(), credentials, "same-operation"); err != nil {
				t.Errorf("distribute: %v", err)
			}
		}()
	}
	wait.Wait()
	values.mu.Lock()
	writes := len(values.writes)
	values.mu.Unlock()
	if writes != 1 {
		t.Fatalf("idempotent distribution made %d writes", writes)
	}
}

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
	_, err := NewProduction(Config{Issuer: issuer, Vault: vault, Members: &productionMembers{}, Secrets: &productionSecrets{}, Reloader: &productionReload{}, State: &memoryState{}, Regions: []string{"gru"}})
	if err != nil {
		t.Fatal(err)
	}
}

type memoryState struct{}

func (*memoryState) Load(context.Context) (security.PersistedState, error) {
	return security.PersistedState{}, security.ErrNoState
}
func (*memoryState) Save(context.Context, security.PersistedState) error { return nil }
