package region

import (
	"context"
	"encoding/json/v2"
	"errors"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/oracle/oci-go-sdk/v65/vault"
)

type originalNetBirdState struct {
	grant   FoundationGrant
	record  FoundationRecord
	etag    string
	bundle  RetainedFoundation
	intent  verifiedNetBirdIntent
	manager *OriginalFoundationNetBirdManager
}

func (s originalNetBirdState) target() vaultsecret.Target {
	if s.intent.intent.Material == nil {
		return vaultsecret.Target{}
	}
	target := s.intent.intent.Material.Context.Target
	return vaultsecret.Target{CompartmentID: target.CompartmentOCID, VaultID: target.VaultOCID, KeyID: target.KMSKeyOCID}
}

func (s originalNetBirdState) regionalTarget() vaultsecret.Target {
	if s.record.OriginalFoundationCompartments == nil || s.record.OriginalFoundationCompartments.Regions[0].Vault == nil {
		return vaultsecret.Target{}
	}
	v := s.record.OriginalFoundationCompartments.Regions[0].Vault
	return vaultsecret.Target{CompartmentID: v.ControlCompartmentID, VaultID: originalVaultID(v.Vault.OriginalFoundationKMSCreate), KeyID: originalVaultID(v.Key.OriginalFoundationKMSCreate)}
}

func (s *SignedFootprint) originalNetBirdGrant(ctx context.Context) (bool, error) {
	if s == nil || ctx == nil {
		return false, ErrOriginalSourceProducerHold
	}
	wire, err := s.readGrant(ctx)
	if err != nil {
		return false, err
	}
	grant, _, err := s.verifyOriginalDocument(wire)
	if err != nil {
		return false, err
	}
	return grant.SchemaVersion == 3, nil
}

func (s *SignedFootprint) originalNetBirdState(ctx context.Context, resolver FoundationResolver) (originalNetBirdState, error) {
	if s == nil || ctx == nil || s.retainedGrant != nil {
		return originalNetBirdState{}, ErrOriginalSourceProducerHold
	}
	client, ok := s.client.(foundationDiscoveryObjects)
	if !ok {
		return originalNetBirdState{}, ErrOriginalSourceProducerHold
	}
	bundle, err := readCurrentFoundation(ctx, client, s.tenancy)
	if err != nil {
		return originalNetBirdState{}, err
	}
	bundle.GrantWire, err = s.readGrant(ctx)
	if err != nil {
		return originalNetBirdState{}, err
	}
	return s.originalNetBirdStateFromBundle(ctx, resolver, bundle)
}

// The original operator uses this core before publication; runtime callers
// always read the current public bundle through originalNetBirdState.
func (s *SignedFootprint) originalNetBirdStateFromBundle(ctx context.Context, resolver FoundationResolver, bundle RetainedFoundation) (originalNetBirdState, error) {
	var state originalNetBirdState
	if s == nil || ctx == nil || s.factory == nil || s.factory.Region() != foundationHomeRegion || resolver.Footprint != s || resolver.Store == nil ||
		s.scope.Cell != "GRU" || s.scope.Environment != "production" || s.home.GrantGeneration != 1 || bundle.TenancyID != s.tenancy || bundle.Namespace != s.storage.Namespace ||
		len(bundle.RootChainWire) == 0 || len(bundle.RootChainWire) > trust.MaxRootChainBytes || len(bundle.AnchorWire) == 0 || len(bundle.AnchorWire) > bootstrap.MaxBootstrapAnchorBytes ||
		len(bundle.GrantWire) == 0 || len(bundle.GrantWire) > foundationRecordLimit {
		return state, ErrOriginalSourceProducerHold
	}
	if err := ctx.Err(); err != nil {
		return state, err
	}
	tenancy, err := s.factory.Provider().TenancyOCID()
	if err != nil || tenancy != s.tenancy {
		return state, errors.Join(ErrOriginalSourceProducerHold, err)
	}
	if _, err := trust.DecodeRootChain(bundle.RootChainWire); err != nil {
		return state, err
	}
	anchor, err := verifyDiscoveryAnchor(bundle.AnchorWire, s.roots, s.tenancy, bundle.Namespace)
	if err != nil {
		return state, err
	}
	home, err := anchor.FoundationScope()
	if err != nil || !sameOriginalSourceValue(home, s.home) {
		return state, errors.Join(ErrOriginalSourceProducerHold, err)
	}
	grant, expires, err := s.verifyOriginalDocument(bundle.GrantWire)
	if err != nil || grant.SchemaVersion != 3 || grant.Generation != 1 || len(grant.Regions) != 3 {
		return state, errors.Join(ErrOriginalSourceProducerHold, err)
	}
	if err := validateFoundationNetBirdMaterial(grant); err != nil {
		return state, err
	}
	if err := validateNetBirdComponentIntents(grant, s.roots, s.storage, time.Now()); err != nil {
		return state, err
	}
	intent, err := verifyOriginalNetBirdIntent(ctx, s, grant, expires, netBirdMaterialSHA(bundle.GrantWire))
	if err != nil || intent.intent.Material == nil {
		return state, errors.Join(ErrOriginalSourceProducerHold, err)
	}
	record, etag, err := resolver.Store.Load(ctx, "GRU")
	if err != nil {
		return state, err
	}
	manager, err := originalNetBirdManagerState(record)
	if err != nil {
		return state, err
	}
	homeDigest := ""
	for _, regional := range grant.Regions {
		if regional.Plan["cell"] != "GRU" {
			continue
		}
		if homeDigest != "" || regional.Generation != 1 {
			return state, ErrOriginalSourceProducerHold
		}
		homeDigest, err = FoundationIntentDigest(regional)
		if err != nil {
			return state, err
		}
	}
	retained, err := json.Marshal(bundle, json.Deterministic(true))
	if err != nil {
		return state, err
	}
	material := record.NetBirdMaterial
	if material == nil || !material.Complete || material.Authority != *intent.intent.Material || record.validateNetBirdMaterial() != nil ||
		material.OriginalGrantSHA256 != intent.grantDigest || material.OriginalBundleSHA256 != netBirdMaterialSHA(retained) ||
		record.GrantSHA256 != intent.grantDigest || record.Generation != 1 || record.TenancyID != tenancy || record.OCIRegion != foundationHomeRegion ||
		homeDigest == "" || record.IntentDigest != homeDigest || manager.IntentSHA256 != homeDigest || manager.GrantSHA256 != intent.grantDigest ||
		manager.BundleSHA256 != material.OriginalBundleSHA256 || !sameOriginalSourceValue(manager.Intent, intent.intent) ||
		grant.InfrastructureSpend == nil || grant.InfrastructureSpend.Bootstrap == nil {
		return state, ErrOriginalSourceProducerHold
	}
	matches := 0
	for _, slot := range grant.InfrastructureSpend.Bootstrap.Slots {
		if slot.SlotID == manager.Allocation.SlotID {
			if slot != manager.Allocation {
				return state, ErrOriginalSourceProducerHold
			}
			matches++
		}
	}
	if matches != 1 {
		return state, ErrOriginalSourceProducerHold
	}
	if err := validateOriginalNetBirdAllocation(grant, record, intent, time.Now()); err != nil {
		return state, err
	}
	management, err := vault.NewVaultsClientWithConfigurationProvider(s.factory.Provider())
	if err != nil {
		return state, err
	}
	management.SetRegion(foundationHomeRegion)
	s.factory.Configure(&management.BaseClient, ociclient.ServiceKMS)
	for index, create := range material.Creates {
		if create.Version != 1 || create.HoldReason != "" {
			return state, ErrOriginalSourceProducerHold
		}
		if err := checkOriginalNetBirdMaterialMetadata(ctx, &management, material.Authority, index, create); err != nil {
			return state, err
		}
	}
	if !time.Now().Before(intent.expires) {
		return state, ErrOriginalSourceProducerHold
	}
	if err := ctx.Err(); err != nil {
		return state, err
	}
	return originalNetBirdState{grant: grant, record: record, etag: etag, bundle: bundle, intent: intent, manager: manager}, nil
}

func checkOriginalNetBirdMaterialMetadata(ctx context.Context, client *vault.VaultsClient, authority NetBirdMaterialAuthority, index int, create NetBirdMaterialCreate) error {
	metadata, err := client.GetSecret(ociclient.RequestContext(ctx), vault.GetSecretRequest{SecretId: new(create.SecretID)})
	if err != nil || deref(metadata.Id) != create.SecretID || deref(metadata.SecretName) != authority.Names[index] ||
		deref(metadata.CompartmentId) != authority.Context.Target.CompartmentOCID || deref(metadata.VaultId) != authority.Context.Target.VaultOCID || deref(metadata.KeyId) != authority.Context.Target.KMSKeyOCID ||
		metadata.LifecycleState != vault.SecretLifecycleStateActive || metadata.CurrentVersionNumber == nil || *metadata.CurrentVersionNumber != 1 ||
		metadata.RotationConfig != nil || metadata.ReplicationConfig != nil || metadata.TimeOfDeletion != nil || metadata.LastRotationTime != nil || metadata.NextRotationTime != nil ||
		metadata.TimeOfCurrentVersionExpiry != nil || len(metadata.SecretRules) != 0 || metadata.IsReplica != nil && *metadata.IsReplica {
		return errors.Join(ErrOriginalSourceProducerHold, err)
	}
	if index == 0 {
		generation, ok := metadata.SecretGenerationContext.(vault.BytesGenerationContext)
		if !ok || generation.GenerationTemplate != vault.BytesGenerationContextGenerationTemplate512 || generation.SecretTemplate != nil || metadata.IsAutoGenerationEnabled == nil || !*metadata.IsAutoGenerationEnabled {
			return ErrOriginalSourceProducerHold
		}
	} else if metadata.SecretGenerationContext != nil || metadata.IsAutoGenerationEnabled != nil && *metadata.IsAutoGenerationEnabled {
		return ErrOriginalSourceProducerHold
	}
	return nil
}
