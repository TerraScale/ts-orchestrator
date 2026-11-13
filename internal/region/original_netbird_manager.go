package region

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/capacityinventory"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/oracle/oci-go-sdk/v65/core"
)

// This allocation is sealed only by the original full grant and its original
// producer journal. It never becomes generic infrastructure spending authority.
type originalNetBirdAllocation struct {
	intent           verifiedNetBirdIntent
	slot             BootstrapSlotIntent
	scope            capacityinventory.Scope
	logical, binding string
	currency         string
	check            func(context.Context) error
}

func (a originalNetBirdAllocation) Slot() BootstrapSlotIntent { return a.slot }
func (a originalNetBirdAllocation) IsVerified() bool {
	return a.check != nil && a.intent.grantDigest != ""
}
func (a originalNetBirdAllocation) InstallationID() string      { return a.intent.installationID }
func (a originalNetBirdAllocation) Generation() uint64          { return a.intent.generation }
func (a originalNetBirdAllocation) GrantDigest() string         { return a.intent.grantDigest }
func (a originalNetBirdAllocation) BindingDigest() string       { return a.binding }
func (a originalNetBirdAllocation) ScopeDigest() string         { return a.logical }
func (a originalNetBirdAllocation) PhysicalScopeDigest() string { return a.scope.SHA256 }
func (a originalNetBirdAllocation) OperationID() string {
	return BootstrapOperationID(a.InstallationID(), a.slot.SlotID)
}
func (a originalNetBirdAllocation) ExpiresAt() time.Time               { return a.scope.ExpiresAt }
func (a originalNetBirdAllocation) Footprint() capacityinventory.Scope { return a.scope }
func (a originalNetBirdAllocation) Revalidate(ctx context.Context) error {
	if !a.IsVerified() {
		return ErrOriginalSourceProducerHold
	}
	return a.check(ctx)
}
func (a originalNetBirdAllocation) Validate(r BootstrapLaunchRequest, q capacityinventory.Quote, now time.Time) error {
	s := a.slot
	if !a.IsVerified() || !now.Before(a.ExpiresAt()) || r.SlotID != s.SlotID || r.OperationID != a.OperationID() || r.Cell != s.Cell || r.CompartmentID != s.CompartmentID ||
		r.ProfileSHA256 != s.ProfileSHA256 || r.RecipeSHA256 != s.RecipeSHA256 || r.Shape != s.Shape || r.OCPUs != s.OCPUs || r.MemoryGB != s.MemoryGB || r.BootGB != s.BootGB ||
		!bootstrapSHA256.MatchString(r.RequestSHA256) || r.RetryToken != BootstrapRetryToken(r.OperationID, r.RequestSHA256) || r.StartedAt.IsZero() || r.StartedAt.After(now) || !now.Before(r.StartedAt.Add(bootstrapRetryLifetime)) {
		return ErrOriginalSourceProducerHold
	}
	if err := q.Validate(a.scope, s.Cell, s.CompartmentID, s.Shape, s.OCPUs, s.MemoryGB, s.BootGB, now); err != nil {
		return err
	}
	if q.Currency() != a.currency || q.MonthlyCents() == 0 || s.MonthlyLimitMinor <= 0 || q.MonthlyCents() > uint64(s.MonthlyLimitMinor) {
		return ErrOriginalSourceProducerHold
	}
	return nil
}

func verifyOriginalNetBirdIntent(ctx context.Context, reader *SignedFootprint, grant FoundationGrant, expires time.Time, grantDigest string) (verifiedNetBirdIntent, error) {
	var empty verifiedNetBirdIntent
	if reader == nil || grant.SchemaVersion != 3 || grant.Generation != 1 || !validFoundationDigest(grantDigest) || ValidatePreparedFoundation(grant) != nil {
		return empty, ErrOriginalSourceProducerHold
	}
	var selected *NetBirdManagerIntent
	for _, region := range grant.Regions {
		if region.NetBirdManager == nil {
			continue
		}
		if selected != nil || region.Plan["cell"] != "GRU" {
			return empty, ErrOriginalSourceProducerHold
		}
		selected = region.NetBirdManager
	}
	if selected == nil || selected.validate() != nil || selected.Material == nil || selected.Material.validate() != nil {
		return empty, ErrOriginalSourceProducerHold
	}
	i := *selected
	image, err := release.VerifyNetBirdImageCurrent(i.ImageReceiptWire, i.ImageDelegationWire, reader.roots,
		release.ImageExpectation{Environment: reader.scope.Environment, LogicalRegion: "GRU", OCIImageOCID: i.ImageOCID, Architecture: i.Architecture}, time.Now())
	if err != nil {
		return empty, err
	}
	receipt := image.Receipt()
	deadline, err := release.VerifyRetainedProductionCurrent(ctx, release.ProductionProof{Qualification: i.QualificationWire, Delegation: i.QualificationDelegationWire}, reader.roots,
		release.ProductionExpectation{SourceRevision: receipt.SourceRevision, ArtifactSHA256: receipt.ImageSHA256, QualificationSHA256: receipt.QualificationSHA256,
			Cell: "GRU", Environment: reader.scope.Environment, Runtime: release.NetBirdProductionRuntime, Architecture: "arm64", Role: NetBirdManagerRole}, reader.openNetBirdEvidence, time.Now())
	if err != nil {
		return empty, err
	}
	profile, err := NetBirdManagerProfileDigest(i.Profile)
	if err != nil {
		return empty, err
	}
	recipe, err := NetBirdManagerRecipeDigest(i, receipt.ImageSHA256)
	if err != nil {
		return empty, err
	}
	return verifiedNetBirdIntent{intent: i, installationID: grant.InstallationID, generation: grant.Generation,
		expires: originalActorDeadline(expires, image.ExpiresAt(), deadline), image: image, profileDigest: profile, recipeDigest: recipe, grantDigest: grantDigest}, nil
}

func originalNetBirdSignedSlot(grant FoundationGrant) (BootstrapSlotIntent, error) {
	if grant.InfrastructureSpend == nil || grant.InfrastructureSpend.Bootstrap == nil {
		return BootstrapSlotIntent{}, ErrOriginalSourceProducerHold
	}
	var selected BootstrapSlotIntent
	for _, slot := range grant.InfrastructureSpend.Bootstrap.Slots {
		if slot.Role != NetBirdManagerRole {
			continue
		}
		if selected.SlotID != "" || slot.Cell != "GRU" || slot.Slot != NetBirdManagerRole {
			return BootstrapSlotIntent{}, ErrOriginalSourceProducerHold
		}
		selected = slot
	}
	if selected.SlotID == "" {
		return selected, ErrOriginalSourceProducerHold
	}
	return selected, nil
}

func originalNetBirdAuthority(ctx context.Context, authority *HomeIAMAuthority) (FoundationRecord, string, verifiedNetBirdIntent, originalNetBirdAllocation, error) {
	record, etag, grant, expires, err := originalActorPrerequisites(ctx, authority, false)
	if err != nil {
		return record, etag, verifiedNetBirdIntent{}, originalNetBirdAllocation{}, err
	}
	reader, ok := authority.resolver.Footprint.(*SignedFootprint)
	if !ok {
		return record, etag, verifiedNetBirdIntent{}, originalNetBirdAllocation{}, ErrOriginalSourceProducerHold
	}
	intent, err := verifyOriginalNetBirdIntent(ctx, reader, grant, expires, record.OriginalFoundationCompartments.GrantSHA256)
	if err != nil {
		return record, etag, intent, originalNetBirdAllocation{}, err
	}
	slot, err := originalNetBirdSignedSlot(grant)
	if err != nil {
		return record, etag, intent, originalNetBirdAllocation{}, err
	}
	scope, err := originalNetBirdManagerScope(record, intent.intent, slot)
	if err != nil {
		return record, etag, intent, originalNetBirdAllocation{}, err
	}
	compute, err := authority.factory.Compute()
	if err != nil {
		return record, etag, intent, originalNetBirdAllocation{}, err
	}
	image, err := compute.GetImage(ociclient.RequestContext(ctx), core.GetImageRequest{ImageId: new(intent.intent.ImageOCID)})
	if err != nil || value(image.Id) != intent.intent.ImageOCID || image.LifecycleState != core.ImageLifecycleStateAvailable {
		return record, etag, intent, originalNetBirdAllocation{}, errors.Join(ErrOriginalSourceProducerHold, err)
	}
	if current := record.OriginalFoundationCompartments.Regions[0].NetBirdManager; current != nil && !sameOriginalSourceValue(current.scopeOnly(), scope) {
		return record, etag, intent, originalNetBirdAllocation{}, ErrOriginalSourceProducerHold
	}
	physical, err := originalActorPhysicalScope(record, 0, originalActorDeadline(intent.expires, authority.operator.deadline))
	if err != nil {
		return record, etag, intent, originalNetBirdAllocation{}, err
	}
	logical, err := infrastructureScope(grant)
	if err != nil || logical.SHA256 != grant.InfrastructureSpend.ScopeSHA256 {
		return record, etag, intent, originalNetBirdAllocation{}, errors.Join(ErrOriginalSourceProducerHold, err)
	}
	wire, err := json.Marshal(scope, json.Deterministic(true))
	if err != nil {
		return record, etag, intent, originalNetBirdAllocation{}, err
	}
	allocation := originalNetBirdAllocation{intent: intent, slot: slot, scope: physical, logical: logical.SHA256, binding: digestSource(wire), currency: grant.Currency}
	allocation.slot.CompartmentID = scope.ControlCompartmentID
	allocation.check = func(ctx context.Context) error {
		current, _, _, _, err := originalActorPrerequisites(ctx, authority, false)
		if err != nil {
			return err
		}
		manager := current.OriginalFoundationCompartments.Regions[0].NetBirdManager
		if manager == nil || !sameOriginalSourceValue(manager.scopeOnly(), scope) {
			return ErrOriginalSourceProducerHold
		}
		return authority.Guard(ctx, 0)
	}
	if err := validateNetBirdAllocation(allocation, intent, scope.ControlCompartmentID); err != nil {
		return record, etag, intent, originalNetBirdAllocation{}, err
	}
	return record, etag, intent, allocation, nil
}

type originalNetBirdAuthorityMemoKey struct{}

// originalNetBirdAuthorityMemo holds the read-only verified manager authority
// of one manager reconciliation.
type originalNetBirdAuthorityMemo struct {
	mu         sync.Mutex
	verified   bool
	intent     verifiedNetBirdIntent
	allocation originalNetBirdAllocation
	scope      bool
}

func (m *originalNetBirdAuthorityMemo) scopeVerified() bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.scope
}

func (m *originalNetBirdAuthorityMemo) markScopeVerified() {
	if m != nil {
		m.mu.Lock()
		m.scope = true
		m.mu.Unlock()
	}
}

type originalNetBirdNetworkJournal struct{ authority *HomeIAMAuthority }

func (j *originalNetBirdNetworkJournal) entry(ctx context.Context, key string) (FoundationRecord, string, *OriginalFoundationNetworkCreate, error) {
	record, etag, _, _, err := originalNetBirdAuthority(ctx, j.authority)
	if err != nil {
		return record, etag, nil, err
	}
	m := record.OriginalFoundationCompartments.Regions[0].NetBirdManager
	if m == nil || m.HoldReason != "" {
		return record, etag, nil, ErrOriginalSourceProducerHold
	}
	for i := range m.Creates {
		if m.Creates[i].Key == key {
			return record, etag, &m.Creates[i], nil
		}
	}
	return record, etag, nil, ErrOriginalSourceProducerHold
}

func originalNetBirdNetworkToken(operation, key, digest string) string {
	sum := sha256.Sum256([]byte(operation + "\x00" + key + "\x00" + digest))
	return hex.EncodeToString(sum[:])
}

func (j *originalNetBirdNetworkJournal) dispatch(ctx context.Context, key, digest, token string) error {
	_, _, entry, err := j.entry(ociclient.CheckpointContext(ctx), key)
	if err != nil {
		return err
	}
	if entry.Pending == nil || entry.Provenance != nil || entry.HoldReason != "" || entry.Pending.Request.RequestDigest != digest || entry.Pending.Request.RetryToken != token {
		return ErrOriginalSourceProducerHold
	}
	if err := j.authority.Guard(ociclient.CheckpointContext(ctx), 0); err != nil {
		return err
	}
	for _, deadline := range []time.Time{entry.Pending.FirstAttemptAt.Add(bootstrapRetryLifetime), j.authority.operator.deadline} {
		if err := ociclient.LimitAdmission(ctx, deadline); err != nil {
			return err
		}
	}
	return nil
}

func (j *originalNetBirdNetworkJournal) observed(ctx context.Context, key, id, digest string) error {
	record, etag, entry, err := j.entry(ctx, key)
	if err != nil {
		return err
	}
	if entry.Provenance == nil || entry.Provenance.ResourceID != id || entry.Pending == nil || entry.Pending.Request.RequestDigest != digest || entry.HoldReason != "" {
		return ErrOriginalSourceProducerHold
	}
	wire, err := json.Marshal([]string{id, digest, "AVAILABLE"}, json.Deterministic(true))
	if err != nil {
		return err
	}
	if entry.ReadbackSHA256 != "" && entry.ReadbackSHA256 != digestSource(wire) {
		return ErrOriginalSourceProducerHold
	}
	if !entry.VerifiedAt.IsZero() {
		return nil
	}
	entry.ReadbackSHA256, entry.VerifiedAt = digestSource(wire), time.Now().UTC()
	return checkpointOriginalCompartments(ctx, j.authority, &record, &etag)
}

func (j *originalNetBirdNetworkJournal) hold(ctx context.Context, key, reason string) error {
	record, etag, entry, err := j.entry(ctx, key)
	if err != nil {
		return err
	}
	if entry.Pending == nil || entry.Provenance != nil || !slices.Contains([]string{"retry-expired", "create-refused", "create-unresolved"}, reason) {
		return ErrOriginalSourceProducerHold
	}
	entry.HoldReason = reason
	return errors.Join(ErrOriginalSourceProducerHold, checkpointOriginalCompartments(ctx, j.authority, &record, &etag))
}
