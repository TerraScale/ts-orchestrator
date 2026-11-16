package region

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/capacityledger"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/capacityinventory"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/foundation"
	"github.com/oracle/oci-go-sdk/v65/core"
)

// OriginalFoundationActorLaunch retains a finite physical prerequisite, never
// local actor custody, source IAM, admitted startup or runtime authority.
type OriginalFoundationActorLaunch struct {
	Startup              bootstrap.StartupTemplate     `json:"startup"`
	Config               bootstrapmaterial.Config      `json:"config"`
	ControlCompartmentID string                        `json:"controlCompartmentId"`
	NetworkProofSHA256   string                        `json:"networkProofSha256"`
	VaultProofSHA256     string                        `json:"vaultProofSha256"`
	Request              core.LaunchInstanceDetails    `json:"request"`
	Pending              *PendingFoundationCreate      `json:"pending,omitempty"`
	OriginalQuote        *capacityledger.Quote         `json:"originalQuote,omitempty"`
	Provenance           *FoundationResourceProvenance `json:"provenance,omitempty"`
	BootVolumeID         string                        `json:"bootVolumeId,omitempty"`
	PrimaryVNICID        string                        `json:"primaryVnicId,omitempty"`
	ReadbackSHA256       string                        `json:"readbackSha256,omitempty"`
	VerifiedAt           time.Time                     `json:"verifiedAt,omitzero"`
	HoldReason           string                        `json:"holdReason,omitempty"`
}

// originalActorPrerequisites requires complete original compartments, network
// and Vault in the journal. With fresh it also re-reads every Vault and network
// resource; stage entry points do that once per run, while per-effect checks and
// later stages rely on the validated journal.
func originalActorPrerequisites(ctx context.Context, authority *HomeIAMAuthority, fresh bool) (FoundationRecord, string, FoundationGrant, time.Time, error) {
	var empty FoundationGrant
	lease, ok := ctx.Value(homeIAMLeaseKey{}).(*homeIAMLease)
	if !ok || lease == nil || lease.authority != authority {
		return FoundationRecord{}, "", empty, time.Time{}, ErrOriginalSourceProducerHold
	}
	// One NetBird manager reconciliation verifies the compartment scope once;
	// every call still loads and validates its exact journal below.
	memo, _ := ctx.Value(originalNetBirdAuthorityMemoKey{}).(*originalNetBirdAuthorityMemo)
	if fresh || !memo.scopeVerified() {
		if _, err := originalCompartmentScope(ctx, authority); err != nil {
			return FoundationRecord{}, "", empty, time.Time{}, err
		}
		record, _, err := authority.resolver.Store.Load(ctx, "GRU")
		if err != nil {
			return record, "", empty, time.Time{}, err
		}
		if err := originalActorPrerequisiteRecord(record); err != nil {
			return record, "", empty, time.Time{}, err
		}
		// Complete prerequisite components repeat exact authenticated reads only.
		if fresh {
			if err := retainOriginalFoundationVault(ctx, authority); err != nil {
				return record, "", empty, time.Time{}, err
			}
		}
		memo.markScopeVerified()
	}
	record, etag, err := authority.resolver.Store.Load(ctx, "GRU")
	if err != nil {
		return record, "", empty, time.Time{}, err
	}
	if err := originalActorPrerequisiteRecord(record); err != nil {
		return record, "", empty, time.Time{}, err
	}
	reader, ok := authority.resolver.Footprint.(*SignedFootprint)
	if !ok {
		return record, "", empty, time.Time{}, ErrOriginalSourceProducerHold
	}
	grant, expires, err := reader.verifyOriginalDocument(authority.operator.bundle.GrantWire)
	if err != nil {
		return record, "", empty, time.Time{}, err
	}
	if grant.SchemaVersion != 3 || grant.Generation != 1 || digestSource(authority.operator.bundle.GrantWire) != record.OriginalFoundationCompartments.GrantSHA256 {
		return record, "", empty, time.Time{}, ErrOriginalSourceProducerHold
	}
	if err := reader.validatePreparedOriginalDocument(authority.operator.bundle.GrantWire, grant); err != nil {
		return record, "", empty, time.Time{}, err
	}
	logical, err := originalActorSignedScope(record)
	if err != nil || grant.InfrastructureSpend == nil || grant.InfrastructureSpend.ScopeSHA256 != logical.SHA256 {
		return record, "", empty, time.Time{}, errors.Join(ErrOriginalSourceProducerHold, err)
	}
	return record, etag, grant, expires, nil
}

func originalActorPrerequisiteRecord(record FoundationRecord) error {
	return rememberOriginalRecordCheck("actor-prerequisites", record, originalActorPrerequisiteRecordChecked)
}

func originalActorPrerequisiteRecordChecked(record FoundationRecord) error {
	root := record.OriginalFoundationCompartments
	if root == nil || record.OriginalSourceProducers == nil || record.Stage != "original-foundation" || !record.netBirdMaterialOnly() {
		return ErrOriginalSourceProducerHold
	}
	if err := record.validateOriginalFoundationNetwork(); err != nil {
		return err
	}
	if err := record.validateOriginalFoundationVault(); err != nil {
		return err
	}
	return originalActorPrerequisiteRecordFromValidatedNetworkAndVault(record)
}

func originalActorPrerequisiteRecordFromValidatedNetworkAndVault(record FoundationRecord) error {
	root := record.OriginalFoundationCompartments
	if root == nil || record.OriginalSourceProducers == nil || record.Stage != "original-foundation" || !record.netBirdMaterialOnly() {
		return ErrOriginalSourceProducerHold
	}
	for _, region := range root.Regions {
		for _, compartment := range region.Compartments {
			if compartment.VerifiedAt.IsZero() || compartment.ReadbackSHA256 == "" || compartment.HoldReason != "" {
				return ErrOriginalSourceProducerHold
			}
		}
		if region.Network == nil || !region.Network.Complete || region.Vault == nil {
			return ErrOriginalSourceProducerHold
		}
		for slot := range 2 {
			entry := originalVaultEntry(region.Vault, slot)
			if entry.VerifiedAt.IsZero() || entry.ReadbackSHA256 == "" || entry.HoldReason != "" {
				return ErrOriginalSourceProducerHold
			}
		}
	}
	return nil
}

func originalActorScope(record FoundationRecord, index int, startup bootstrap.StartupTemplate, config bootstrapmaterial.Config) (OriginalFoundationActorLaunch, error) {
	var scope OriginalFoundationActorLaunch
	if index < 0 || index >= 3 || originalActorPrerequisiteRecord(record) != nil {
		return scope, ErrOriginalSourceProducerHold
	}
	return originalActorScopeFromPrerequisites(record, index, startup, config)
}

func originalActorScopeFromPrerequisites(record FoundationRecord, index int, startup bootstrap.StartupTemplate, config bootstrapmaterial.Config) (OriginalFoundationActorLaunch, error) {
	var scope OriginalFoundationActorLaunch
	region := record.OriginalFoundationCompartments.Regions[index]
	q := (*record.OriginalSourceProducers)[index].Intent
	startupDigest, err := ControllerBootstrapRecipeDigest(startup)
	if err != nil || startup.ValidateFoundation(region.Cell) != nil || startup.SeedSlot != "controller-a" || startupDigest != q.Allocation.RecipeSHA256 || startup.FounderResources == nil || !startup.FounderResources.LaunchDeadline.Equal(q.LaunchDeadline) {
		return scope, errors.Join(ErrOriginalSourceProducerHold, err)
	}
	configWire, err := json.Marshal(config, json.Deterministic(true))
	if err != nil || config.Validate() != nil || digestSource(configWire) != q.PlanSHA256 || config.Region != region.OCIRegion || config.Cell != strings.ToLower(region.Cell) || config.Environment != q.Environment || config.DeploymentID != q.DeploymentID || config.ClusterID != q.ClusterID {
		return scope, errors.Join(ErrOriginalSourceProducerHold, err)
	}
	var profile bootstrap.LaunchProfile
	var resources bootstrap.StartupSlotResources
	for _, candidate := range startup.Profiles {
		if candidate.Slot == startup.SeedSlot {
			profile = candidate
		}
	}
	for _, candidate := range startup.FounderResources.Slots {
		if candidate.Slot == startup.SeedSlot {
			resources = candidate
		}
	}
	profileDigest, err := ControllerBootstrapProfileDigest(profile)
	slot := q.Allocation
	if err != nil || !sameOriginalSourceValue(profile, q.Profile) || profileDigest != slot.ProfileSHA256 || slot.Cell != region.Cell || slot.Role != "controller" || slot.Slot != startup.SeedSlot || slot.CompartmentID != profile.CompartmentOCID || slot.Shape != profile.Shape || slot.SlotID != BootstrapSlotID(q.InstallationID, region.Cell, "controller", startup.SeedSlot) || q.OperationID != BootstrapOperationID(q.InstallationID, slot.SlotID) || slot.MonthlyLimitMinor <= 0 ||
		resources.WholeOCPUs == 0 || resources.WholeOCPUs > 1<<24 || resources.MemoryInGB == 0 || resources.MemoryInGB > 1<<24 || slot.OCPUs != float64(resources.WholeOCPUs) || slot.MemoryGB != float64(resources.MemoryInGB) || slot.BootGB != float64(resources.BootVolumeGB) || float64(float32(resources.WholeOCPUs)) != slot.OCPUs || float64(float32(resources.MemoryInGB)) != slot.MemoryGB || resources.BootVolumeTier != bootstrap.FounderBootVolumeTierBalanced || startup.ImageOCID != q.ImageOCID || digestSource(startup.ReleaseImageReceiptWire) != q.ImageReceiptSHA256 || digestSource(startup.ReleaseDelegationWire) != q.ImageDelegationSHA256 {
		return scope, errors.Join(ErrOriginalSourceProducerHold, err)
	}
	control := originalCompartmentID(region.Compartments[0])
	if !originalActorRole(region.Cell, "control_compartment", profile.CompartmentOCID, control) || region.Network.Creates[4].Provenance == nil || region.Network.Creates[5].Provenance == nil {
		return scope, ErrOriginalSourceProducerHold
	}
	subnet, nsg := region.Network.Creates[4].Provenance.ResourceID, region.Network.Creates[5].Provenance.ResourceID
	if !originalActorRole(region.Cell, "subnet", profile.SubnetOCID, subnet) || len(profile.NetworkSecurityGroupOCIDs) != 1 || !originalActorRole(region.Cell, "network_security_group", profile.NetworkSecurityGroupOCIDs[0], nsg) {
		return scope, ErrOriginalSourceProducerHold
	}
	if _, err := originalActorImageCompartment(region.Cell, resources.ImageCompartmentOCID, control); err != nil {
		return scope, err
	}
	privateIP := ""
	for _, candidate := range config.Slots {
		if candidate.Name == startup.SeedSlot {
			privateIP = candidate.PrivateIP
		}
	}
	if privateIP == "" {
		return scope, ErrOriginalSourceProducerHold
	}
	networkWire, err := json.Marshal(region.Network, json.Deterministic(true))
	if err != nil {
		return scope, err
	}
	vaultWire, err := json.Marshal(region.Vault, json.Deterministic(true))
	if err != nil {
		return scope, err
	}
	scope.Startup, scope.Config = startup.Clone(), config
	scope.Config.Slots = slices.Clone(config.Slots)
	scope.ControlCompartmentID, scope.NetworkProofSHA256, scope.VaultProofSHA256 = control, digestSource(networkWire), digestSource(vaultWire)
	scope.Request = core.LaunchInstanceDetails{
		AvailabilityDomain: new(profile.AvailabilityDomain), CompartmentId: new(control), FaultDomain: new(profile.FaultDomain), DisplayName: new(strings.ToLower(region.Cell) + "-1-" + startup.SeedSlot), Shape: new(profile.Shape), Metadata: map[string]string{"terrascale-bootstrap": fmt.Sprintf(`{"schemaVersion":1,"slot":%q,"originalBundleSha256":%q}`, startup.SeedSlot, record.OriginalFoundationCompartments.BundleSHA256)},
		LaunchVolumeAttachments: []core.LaunchAttachVolumeDetails{}, LicensingConfigs: []core.LaunchInstanceLicensingConfig{}, DefinedTags: map[string]map[string]any{}, SecurityAttributes: map[string]map[string]any{}, ExtendedMetadata: map[string]any{}, FreeformTags: map[string]string{},
		ShapeConfig:       &core.LaunchInstanceShapeConfigDetails{Ocpus: new(float32(resources.WholeOCPUs)), MemoryInGBs: new(float32(resources.MemoryInGB))},
		SourceDetails:     core.InstanceSourceViaImageDetails{ImageId: new(startup.ImageOCID), BootVolumeSizeInGBs: new(int64(resources.BootVolumeGB)), BootVolumeVpusPerGB: new(int64(10))},
		CreateVnicDetails: &core.CreateVnicDetails{SubnetId: new(subnet), NsgIds: []string{nsg}, PrivateIp: new(privateIP), AssignPublicIp: new(false), DefinedTags: map[string]map[string]any{}, FreeformTags: map[string]string{}, SecurityAttributes: map[string]map[string]any{}, Ipv6AddressIpv6SubnetCidrPairDetails: []core.Ipv6AddressIpv6SubnetCidrPairDetails{}},
	}
	return scope, nil
}

func originalActorRole(cell, role, signed, actual string) bool {
	reference, err := FoundationResourceReference(cell, role)
	return err == nil && actual != "" && (signed == actual || signed == reference)
}

func originalActorImageCompartment(cell, signed, control string) (string, error) {
	if sourceCompartmentPattern.MatchString(signed) && len(signed) <= 512 {
		return signed, nil
	}
	if originalActorRole(cell, "control_compartment", signed, control) {
		return control, nil
	}
	return "", ErrOriginalSourceProducerHold
}

func originalActorSignedScope(record FoundationRecord) (capacityinventory.Scope, error) {
	if record.OriginalFoundationCompartments == nil {
		return capacityinventory.Scope{}, ErrOriginalSourceProducerHold
	}
	grant := FoundationGrant{SchemaVersion: 3, TenancyID: record.TenancyID, ParentCompartmentID: record.ParentCompartmentID, SharedCompartmentID: record.SharedCompartmentID, Currency: record.OriginalFoundationCompartments.Currency}
	for _, region := range record.OriginalFoundationCompartments.Regions {
		if region.Network == nil {
			return capacityinventory.Scope{}, ErrOriginalSourceProducerHold
		}
		grant.Regions = append(grant.Regions, FoundationIntent{Generation: region.Generation, Plan: region.Network.Plan})
	}
	return infrastructureScope(grant)
}

func originalActorPhysicalScope(record FoundationRecord, index int, expires time.Time) (capacityinventory.Scope, error) {
	if index < 0 || index >= 3 || record.OriginalSourceProducers == nil || record.OriginalFoundationCompartments == nil {
		return capacityinventory.Scope{}, ErrOriginalSourceProducerHold
	}
	logical, err := originalActorSignedScope(record)
	if err != nil {
		return capacityinventory.Scope{}, err
	}
	region := record.OriginalFoundationCompartments.Regions[index]
	control := originalCompartmentID(region.Compartments[0])
	if !originalActorRole(region.Cell, "control_compartment", (*record.OriginalSourceProducers)[index].Intent.Allocation.CompartmentID, control) {
		return capacityinventory.Scope{}, ErrOriginalSourceProducerHold
	}
	physical := capacityinventory.Scope{TenancyID: record.TenancyID, Currency: logical.Currency, ExpiresAt: expires, Regions: []capacityinventory.RegionScope{{Cell: region.Cell, OCIRegion: region.OCIRegion, CompartmentIDs: []string{control}}}}
	wire, err := json.Marshal(struct {
		SignedScopeSHA256   string
		TenancyID, Currency string
		Regions             []capacityinventory.RegionScope
	}{logical.SHA256, physical.TenancyID, physical.Currency, physical.Regions}, json.Deterministic(true))
	if err != nil {
		return capacityinventory.Scope{}, err
	}
	physical.SHA256 = digestSource(wire)
	return physical, nil
}

func (actor OriginalFoundationActorLaunch) scopeOnly() OriginalFoundationActorLaunch {
	actor.Pending, actor.OriginalQuote, actor.Provenance = nil, nil, nil
	actor.BootVolumeID, actor.PrimaryVNICID, actor.ReadbackSHA256, actor.HoldReason, actor.VerifiedAt = "", "", "", "", time.Time{}
	return actor
}

func originalActorID(actor *OriginalFoundationActorLaunch) string {
	if actor != nil && actor.Provenance != nil {
		return actor.Provenance.ResourceID
	}
	return ""
}

func originalActorCreateIdentity(record FoundationRecord, index int, digest string) foundation.CreateIdentity {
	region := record.OriginalFoundationCompartments.Regions[index]
	return foundation.CreateIdentity{Key: "controller-a", Region: region.OCIRegion, RequestDigest: digest, RetryToken: BootstrapRetryToken((*record.OriginalSourceProducers)[index].Intent.OperationID, digest)}
}

func originalActorResources(startup bootstrap.StartupTemplate) bootstrap.StartupSlotResources {
	if startup.FounderResources != nil {
		for _, resources := range startup.FounderResources.Slots {
			if resources.Slot == startup.SeedSlot {
				return resources
			}
		}
	}
	return bootstrap.StartupSlotResources{}
}

func validOriginalActorID(kind, region, id string) bool {
	if !slices.Contains([]string{"instance", "vnic", "bootvolume", "vnicattachment", "bootvolumeattachment"}, kind) || len(id) > 512 {
		return false
	}
	suffix, ok := strings.CutPrefix(id, "ocid1."+kind+".oc1."+region+".")
	if !ok || suffix == "" {
		return false
	}
	for _, component := range strings.Split(suffix, ".") {
		if component == "" {
			return false
		}
		for _, ch := range component {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9') {
				return false
			}
		}
	}
	return true
}

func originalActorDeadline(deadlines ...time.Time) time.Time {
	var earliest time.Time
	for _, deadline := range deadlines {
		if deadline.IsZero() {
			return time.Time{}
		}
		if earliest.IsZero() || deadline.Before(earliest) {
			earliest = deadline
		}
	}
	return earliest
}

func originalActorReadback(actor *OriginalFoundationActorLaunch, boot, vnic string) (string, error) {
	if actor == nil || actor.Pending == nil || actor.Provenance == nil {
		return "", ErrOriginalSourceProducerHold
	}
	wire, err := json.Marshal([]string{originalActorID(actor), actor.Pending.Request.RequestDigest, boot, vnic, "RUNNING", "AVAILABLE"}, json.Deterministic(true))
	if err != nil {
		return "", err
	}
	return digestSource(wire), nil
}

func (record FoundationRecord) validateOriginalFoundationActors() error {
	root := record.OriginalFoundationCompartments
	if root == nil {
		return nil
	}
	attached := 0
	for _, region := range root.Regions {
		if region.Actor != nil {
			attached++
		}
	}
	if attached == 0 {
		return nil
	}
	if attached != 3 {
		return ErrOriginalSourceProducerHold
	}
	if err := originalActorPrerequisiteRecord(record); err != nil {
		return err
	}
	return record.validateOriginalFoundationActorsFromValidatedNetworkAndVault()
}

func (record FoundationRecord) validateOriginalFoundationActorsFromValidatedNetworkAndVault() error {
	root := record.OriginalFoundationCompartments
	if root == nil {
		return nil
	}
	attached := 0
	for _, region := range root.Regions {
		if region.Actor != nil {
			attached++
		}
	}
	if attached == 0 {
		return nil
	}
	if attached != 3 {
		return ErrOriginalSourceProducerHold
	}
	if err := originalActorPrerequisiteRecordFromValidatedNetworkAndVault(record); err != nil {
		return err
	}
	notBefore := root.BornAt
	for _, region := range root.Regions {
		for slot := range 2 {
			if originalVaultEntry(region.Vault, slot).VerifiedAt.After(notBefore) {
				notBefore = originalVaultEntry(region.Vault, slot).VerifiedAt
			}
		}
	}
	seen := map[string]bool{}
	for index, region := range root.Regions {
		actor := region.Actor
		q := (*record.OriginalSourceProducers)[index].Intent
		expected, err := originalActorScopeFromPrerequisites(record, index, actor.Startup, actor.Config)
		if err != nil || !sameOriginalSourceValue(actor.scopeOnly(), expected) {
			return errors.Join(ErrOriginalSourceProducerHold, err)
		}
		if actor.Pending == nil {
			if actor.OriginalQuote != nil || actor.Provenance != nil || actor.BootVolumeID != "" || actor.PrimaryVNICID != "" || actor.ReadbackSHA256 != "" || !actor.VerifiedAt.IsZero() || actor.HoldReason != "" {
				return ErrOriginalSourceProducerHold
			}
			continue
		}
		pending := *actor.Pending
		digest, err := netBirdRequestDigest(actor.Request)
		if err != nil || pending.OperationID != q.OperationID || pending.IntentDigest != region.IntentSHA256 || pending.Request != originalActorCreateIdentity(record, index, digest) || pending.FirstAttemptAt.IsZero() || pending.FirstAttemptAt.Before(notBefore) || pending.FirstAttemptAt.After(record.UpdatedAt) || !pending.FirstAttemptAt.Before(q.LaunchDeadline) {
			return errors.Join(ErrOriginalSourceProducerHold, err)
		}
		physical, err := originalActorPhysicalScope(record, index, time.Time{})
		if err != nil {
			return err
		}
		quote := actor.OriginalQuote
		if quote == nil || quote.Validate() != nil || quote.ScopeSHA256 != physical.SHA256 || quote.Cell != region.Cell || quote.CompartmentID != actor.ControlCompartmentID || quote.Shape != q.Allocation.Shape || quote.Currency != root.Currency || quote.OCPUs != q.Allocation.OCPUs || quote.MemoryGB != q.Allocation.MemoryGB || quote.BootGB != q.Allocation.BootGB || quote.MonthlyCents == 0 || quote.MonthlyCents > uint64(q.Allocation.MonthlyLimitMinor) || quote.IssuedAt.Before(pending.FirstAttemptAt) || quote.IssuedAt.After(record.UpdatedAt) || quote.ExpiresAt.After(q.LaunchDeadline) {
			return ErrOriginalSourceProducerHold
		}
		if actor.HoldReason != "" && (actor.Provenance != nil || !slices.Contains([]string{"create-refused", "create-unresolved", "retry-expired"}, actor.HoldReason)) {
			return ErrOriginalSourceProducerHold
		}
		if actor.Provenance != nil {
			proof := actor.Provenance
			if !sameOriginalSourceValue(proof.Create, pending) || proof.Generation != region.Generation || proof.GrantSHA256 != root.GrantSHA256 || !validOriginalActorID("instance", region.OCIRegion, proof.ResourceID) || seen[proof.ResourceID] {
				return ErrOriginalSourceProducerHold
			}
			seen[proof.ResourceID] = true
		}
		if actor.VerifiedAt.IsZero() {
			if actor.BootVolumeID != "" || actor.PrimaryVNICID != "" || actor.ReadbackSHA256 != "" {
				return ErrOriginalSourceProducerHold
			}
			continue
		}
		if actor.Provenance == nil || actor.ReadbackSHA256 == "" || actor.HoldReason != "" || actor.VerifiedAt.Before(pending.FirstAttemptAt) || actor.VerifiedAt.Before(quote.IssuedAt) || actor.VerifiedAt.After(record.UpdatedAt) || !validOriginalActorID("bootvolume", region.OCIRegion, actor.BootVolumeID) || !validOriginalActorID("vnic", region.OCIRegion, actor.PrimaryVNICID) || seen[actor.BootVolumeID] || seen[actor.PrimaryVNICID] {
			return ErrOriginalSourceProducerHold
		}
		seen[actor.BootVolumeID], seen[actor.PrimaryVNICID] = true, true
		readback, err := originalActorReadback(actor, actor.BootVolumeID, actor.PrimaryVNICID)
		if err != nil || actor.ReadbackSHA256 != readback {
			return errors.Join(ErrOriginalSourceProducerHold, err)
		}
	}
	return nil
}

func (next FoundationRecord) retainOriginalFoundationActors(previous FoundationRecord) error {
	before, after := previous.OriginalFoundationCompartments, next.OriginalFoundationCompartments
	if before == nil {
		if after != nil {
			for _, region := range after.Regions {
				if region.Actor != nil {
					return ErrOriginalSourceProducerHold
				}
			}
		}
		return nil
	}
	for index, region := range before.Regions {
		old := region.Actor
		if after == nil {
			if old != nil {
				return ErrOriginalSourceProducerHold
			}
			continue
		}
		current := after.Regions[index].Actor
		if old == nil {
			if current != nil {
				expected, err := originalActorScope(next, index, current.Startup, current.Config)
				if err != nil || !sameOriginalSourceValue(current, expected) {
					return errors.Join(ErrOriginalSourceProducerHold, err)
				}
			}
			continue
		}
		if current == nil || !sameOriginalSourceValue(old.scopeOnly(), current.scopeOnly()) || old.Pending != nil && !sameOriginalSourceValue(old.Pending, current.Pending) || old.OriginalQuote != nil && !sameOriginalSourceValue(old.OriginalQuote, current.OriginalQuote) || old.Provenance != nil && !sameOriginalSourceValue(old.Provenance, current.Provenance) || old.BootVolumeID != "" && old.BootVolumeID != current.BootVolumeID || old.PrimaryVNICID != "" && old.PrimaryVNICID != current.PrimaryVNICID || old.ReadbackSHA256 != "" && old.ReadbackSHA256 != current.ReadbackSHA256 || !old.VerifiedAt.IsZero() && !old.VerifiedAt.Equal(current.VerifiedAt) || old.HoldReason != "" && old.HoldReason != current.HoldReason {
			return ErrOriginalSourceProducerHold
		}
	}
	return nil
}
