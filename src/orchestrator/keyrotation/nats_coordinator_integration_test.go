package keyrotation

import (
	"context"
	"fmt"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/control/authority"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

// This exercises the real coordinator and R3 state adapter together. Provider
// ports are fixtures; this test does not qualify external provider effects.
func TestNATSProductionCoordinatorRotatesRestartsAndAdvancesGeneration(t *testing.T) {
	cluster := newRotationStateCluster(t)
	ctx := t.Context()
	connection := cluster.connect(t)
	kv := openRotationTestLeaseStore(t, ctx, connection, true)
	global, err := authority.RegionalAuthorityCoordinatorStartGlobalAsync(ctx, kv, "gru", "coordinator-integration")
	if err != nil {
		t.Fatal(err)
	}
	defer global.Dispose()
	lease := readRotationTestLease(t, ctx, kv)
	now := time.Now().UTC()
	issuer := &coordinatorIntegrationIssuer{materials: map[string]security.IdentityMaterial{}}
	vault := &coordinatorIntegrationVault{materials: map[string]security.CapabilityMaterial{}}
	publisher := &coordinatorIntegrationPublisher{receipts: map[string]security.PublicationReceipt{}}
	config := Config{Issuer: issuer, Vault: vault, Members: &productionMembers{}, Secrets: &productionSecrets{}, Reloader: &productionReload{}, Publisher: publisher, State: &NATSStateStoreConfig{Connection: connection, CandidateID: lease.CandidateId, AuthorityEpoch: uint64(lease.Epoch), LeaseID: lease.LeaseId}, Regions: []string{"gru", "sfo", "fra"}, Clock: func() time.Time { return now }}
	coordinator, err := NewProduction(config)
	if err != nil {
		t.Fatal(err)
	}
	first, err := coordinator.Reconcile(ctx, 15*time.Minute)
	if err != nil || first.Phase != security.PhaseActive || first.Generation != 1 || first.CurrentKeyID != "capability-1" {
		t.Fatalf("initial real coordinator rotation: %+v %v", first, err)
	}
	observer := newRotationTestSession(t, connection, lease)
	state, err := observer.Load(ctx)
	if err != nil || !security.ValidCurrentRotationState(state) || !state.PublicationCommitted || state.PublicationReceipt.ReceiptID != "publication-1" || state.CurrentVersion != 1 {
		t.Fatalf("initial durable active state: %+v %v", state, err)
	}
	// Drop the old coordinator and its private state cursor. The replacement
	// loads the accepted operation and provider receipt from NATS.
	coordinator, err = NewProduction(config)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := coordinator.Reconcile(ctx, 15*time.Minute)
	if err != nil || replay.OperationID != first.OperationID || replay.Generation != 1 || replay.Phase != security.PhaseActive {
		t.Fatalf("restart reconciliation: %+v %v", replay, err)
	}
	if issuer.issues != 1 || vault.generations != 1 || len(publisher.receipts) != 1 {
		t.Fatal("restart repeated issuance or publication")
	}
	now = first.NewExpiry.Add(-10 * time.Minute)
	next, err := coordinator.Reconcile(ctx, 15*time.Minute)
	if err != nil || next.Generation != 2 || next.Phase != security.PhaseActive || next.CurrentKeyID != "capability-2" || next.PreviousKeyID != "capability-1" {
		t.Fatalf("next legitimate generation: %+v %v", next, err)
	}
	state, err = observer.Load(ctx)
	if err != nil || !security.ValidCurrentRotationState(state) || state.PublicationReceipt.ReceiptID != "publication-2" || state.OldCapabilityRef != "capability-1" {
		t.Fatalf("next generation lost publication or retirement obligations: %+v %v", state, err)
	}
	// Restart once more before retiring the previous generation. This must
	// traverse Retire -> Active without discarding the current publication.
	coordinator, err = NewProduction(config)
	if err != nil {
		t.Fatal(err)
	}
	now = state.OldExpiry.Add(time.Minute)
	retired, err := coordinator.Reconcile(ctx, 15*time.Minute)
	if err != nil || retired.Generation != 2 || retired.Phase != security.PhaseActive || retired.PreviousKeyID != "" {
		t.Fatalf("retirement after restart: %+v %v", retired, err)
	}
	state, err = observer.Load(ctx)
	if err != nil || !security.ValidCurrentRotationState(state) || state.OldVersion != 0 || state.CurrentVersion != 2 || state.PublicationReceipt.ReceiptID != "publication-2" {
		t.Fatalf("final durable rotation state: %+v %v", state, err)
	}
	if issuer.issues != 2 || vault.generations != 2 || len(publisher.receipts) != 2 || len(issuer.retired) != 1 || issuer.retired[0] != "identity-1" || len(vault.retired) != 1 || vault.retired[0] != "capability-1" {
		t.Fatal("coordinator repeated issuance or lost retirement across restart")
	}
}

type coordinatorIntegrationIssuer struct {
	productionIssuer
	materials map[string]security.IdentityMaterial
	issues    int
	retired   []string
}

func (p *coordinatorIntegrationIssuer) Issue(ctx context.Context, request security.IdentityRequest) (security.IdentityMaterial, error) {
	ref := fmt.Sprintf("identity-%d", request.Generation)
	if material, ok := p.materials[ref]; ok {
		return material, nil
	}
	material, err := p.productionIssuer.Issue(ctx, request)
	if err != nil {
		return material, err
	}
	material.Reference = ref
	p.materials[ref] = material
	p.issues++
	return material, nil
}
func (p *coordinatorIntegrationIssuer) Fetch(_ context.Context, ref string) (security.IdentityMaterial, error) {
	material, ok := p.materials[ref]
	if !ok {
		return material, fmt.Errorf("fixture identity reference missing")
	}
	return material, nil
}
func (p *coordinatorIntegrationIssuer) Retire(_ context.Context, ref, _ string) error {
	p.retired = append(p.retired, ref)
	return nil
}

type coordinatorIntegrationVault struct {
	productionVault
	materials   map[string]security.CapabilityMaterial
	generations int
	retired     []string
}

func (p *coordinatorIntegrationVault) Generate(ctx context.Context, request security.CapabilityRequest) (security.CapabilityMaterial, error) {
	ref := fmt.Sprintf("capability-%d", request.Generation)
	if material, ok := p.materials[ref]; ok {
		material.Key = append([]byte(nil), material.Key...)
		return material, nil
	}
	material, err := p.productionVault.Generate(ctx, request)
	if err != nil {
		return material, err
	}
	material.Reference = ref
	material.ID = ref
	stored := material
	stored.Key = append([]byte(nil), material.Key...)
	p.materials[ref] = stored
	p.generations++
	return material, nil
}
func (p *coordinatorIntegrationVault) Fetch(_ context.Context, ref string) (security.CapabilityMaterial, error) {
	material, ok := p.materials[ref]
	if !ok {
		return material, fmt.Errorf("fixture capability reference missing")
	}
	material.Key = append([]byte(nil), material.Key...)
	return material, nil
}
func (p *coordinatorIntegrationVault) Retire(_ context.Context, ref, _ string) error {
	p.retired = append(p.retired, ref)
	return nil
}

type coordinatorIntegrationPublisher struct {
	receipts map[string]security.PublicationReceipt
}

func (p *coordinatorIntegrationPublisher) Publish(_ context.Context, operation string, generation uint64, credentials security.CredentialSet, _ string) (security.PublicationReceipt, error) {
	if prior, ok := p.receipts[operation]; ok {
		return prior, nil
	}
	receipt := security.PublicationReceipt{OperationID: operation, Generation: generation, ReceiptID: fmt.Sprintf("publication-%d", generation), CurrentKeyID: credentials.Capability.ID, PreviousKeyID: credentials.PreviousCapability.ID, Committed: true}
	p.receipts[operation] = receipt
	return receipt, nil
}
func (*coordinatorIntegrationPublisher) RollbackPublication(context.Context, security.PublicationReceipt, string) error {
	return fmt.Errorf("unexpected fixture publication rollback")
}
