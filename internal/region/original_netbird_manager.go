package region

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/capacityinventory"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/foundation"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
)

var ErrOriginalNetBirdFoundationPending = fmt.Errorf("%w: original NetBird physical prerequisites retained; local actor custody and runtime admission remain unavailable", ErrOriginalSourceProducerHold)

// ProvisionOriginalNetBirdFoundation authenticates successful actor facts from
// the original journal; a lower producer's pending error never admits this stage.
func ProvisionOriginalNetBirdFoundation(ctx context.Context, factory *ociclient.Factory, roots trust.Keyring, bundle RetainedFoundation) error {
	stage, err := provisionFoundationMaterial(ctx, factory, roots, bundle)
	if err != nil {
		return err
	}
	defer stage.cancel()
	ctx, release, err := stage.authority.HomeWrite(stage.ctx, 0)
	if err != nil {
		return err
	}
	defer release()
	record, _, grant, _, err := originalActorPrerequisites(ctx, stage.authority, true)
	if err != nil {
		return err
	}
	if grant.SchemaVersion != 3 || grant.Generation != 1 || record.validateOriginalFoundationActors() != nil {
		return ErrOriginalSourceProducerHold
	}
	for index, region := range record.OriginalFoundationCompartments.Regions {
		actor := region.Actor
		if actor == nil || actor.Provenance == nil || actor.BootVolumeID == "" || actor.PrimaryVNICID == "" || actor.ReadbackSHA256 == "" || actor.VerifiedAt.IsZero() || actor.HoldReason != "" {
			return ErrOriginalSourceProducerHold
		}
		if err := retainOriginalActorReadback(ctx, stage.authority, record, index); err != nil {
			return err
		}
	}
	if err := retainOriginalNetBirdManager(ctx, stage.authority); err != nil {
		return err
	}
	if err := retainOriginalNetBirdBackup(ctx, stage.authority); err != nil {
		return err
	}
	return ErrOriginalNetBirdFoundationPending
}

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
}

// verifiedOriginalNetBirdAuthority serves read-only write guards. Within one
// manager reconciliation it verifies the original authority once; every
// journal step still reads and fully verifies its own write base.
func verifiedOriginalNetBirdAuthority(ctx context.Context, authority *HomeIAMAuthority) (verifiedNetBirdIntent, originalNetBirdAllocation, error) {
	memo, _ := ctx.Value(originalNetBirdAuthorityMemoKey{}).(*originalNetBirdAuthorityMemo)
	if memo != nil {
		memo.mu.Lock()
		verified, intent, allocation := memo.verified, memo.intent, memo.allocation
		memo.mu.Unlock()
		if verified {
			return intent, allocation, nil
		}
	}
	_, _, intent, allocation, err := originalNetBirdAuthority(ctx, authority)
	if err == nil && memo != nil {
		memo.mu.Lock()
		memo.verified, memo.intent, memo.allocation = true, intent, allocation
		memo.mu.Unlock()
	}
	return intent, allocation, err
}

func retainOriginalNetBirdManager(ctx context.Context, authority *HomeIAMAuthority) error {
	ctx = context.WithValue(ctx, originalNetBirdAuthorityMemoKey{}, &originalNetBirdAuthorityMemo{})
	record, etag, intent, allocation, err := originalNetBirdAuthority(ctx, authority)
	if err != nil {
		return err
	}
	manager := record.OriginalFoundationCompartments.Regions[0].NetBirdManager
	if manager == nil {
		grant, err := authority.originalMaterialGrant()
		if err != nil {
			return err
		}
		slot, err := originalNetBirdSignedSlot(grant)
		if err != nil {
			return err
		}
		scope, err := originalNetBirdManagerScope(record, intent.intent, slot)
		if err != nil {
			return err
		}
		record.OriginalFoundationCompartments.Regions[0].NetBirdManager = &scope
		if err := checkpointOriginalCompartments(ctx, authority, &record, &etag); err != nil {
			return err
		}
		manager = &scope
	}
	if manager.HoldReason != "" {
		return ErrOriginalSourceProducerHold
	}
	journal := &originalNetBirdNetworkJournal{authority: authority}
	progress := FoundationProgress{OperationID: allocation.OperationID(), AuxiliaryIDs: originalNetBirdManagerIDs(manager), NetBirdManager: manager.Launch,
		ManagerAuthority: func(ctx context.Context) (verifiedNetBirdIntent, error) {
			current, _, err := verifiedOriginalNetBirdAuthority(ctx, authority)
			return current, err
		},
		BeforeWrite: func(ctx context.Context, _ bool) (context.Context, func(), error) {
			current, currentAllocation, err := verifiedOriginalNetBirdAuthority(ctx, authority)
			if err != nil {
				return ctx, nil, err
			}
			if err := currentAllocation.Revalidate(ctx); err != nil {
				return ctx, nil, err
			}
			lease, ok := ctx.Value(homeIAMLeaseKey{}).(*homeIAMLease)
			if !ok || lease == nil || lease.authority != authority {
				return ctx, nil, ErrOriginalSourceProducerHold
			}
			lease.mu.Lock()
			leaseExpires := lease.record.ExpiresAt
			lease.mu.Unlock()
			for _, deadline := range []time.Time{leaseExpires, authority.operator.deadline, current.expires} {
				if err := ociclient.LimitAdmission(ctx, deadline); err != nil {
					return ctx, nil, err
				}
			}
			return ctx, func() {}, nil
		}, PrepareCreate: journal.prepare, CheckpointAuxiliary: journal.created,
		CheckpointManager: func(ctx context.Context, launch NetBirdManagerLaunch) error {
			saved, etag, _, _, err := originalNetBirdAuthority(ctx, authority)
			if err != nil {
				return err
			}
			m := saved.OriginalFoundationCompartments.Regions[0].NetBirdManager
			if m == nil || m.HoldReason != "" || launch.OriginalQuote == nil {
				return ErrOriginalSourceProducerHold
			}
			if launch.InstanceID != "" && !validOriginalActorID("instance", foundationHomeRegion, launch.InstanceID) {
				return journal.managerHold(ctx, "create-unresolved")
			}
			before, err := json.Marshal(m, json.Deterministic(true))
			if err != nil {
				return err
			}
			m.Launch = &launch
			if launch.BootVolumeID != "" {
				boot, vnic, err := observeNetBirdManagerGeometry(ctx, authority.factory, m.Intent, launch, m.ControlCompartmentID)
				if err != nil || boot != launch.BootVolumeID {
					return errors.Join(ErrOriginalSourceProducerHold, err)
				}
				readback, err := originalNetBirdManagerReadback(m, boot, vnic)
				if err != nil || m.ReadbackSHA256 != "" && m.ReadbackSHA256 != readback || m.PrimaryVNICID != "" && m.PrimaryVNICID != vnic {
					return errors.Join(ErrOriginalSourceProducerHold, err)
				}
				m.PrimaryVNICID, m.ReadbackSHA256 = vnic, readback
				if m.VerifiedAt.IsZero() {
					m.VerifiedAt = time.Now().UTC()
				}
			}
			// A reopened ready manager re-observes the same launch; do not rewrite it.
			if after, err := json.Marshal(m, json.Deterministic(true)); err != nil || bytes.Equal(before, after) {
				return err
			}
			return checkpointOriginalCompartments(ctx, authority, &saved, &etag)
		}}
	if manager.Launch != nil && manager.Launch.InstanceID == "" && !time.Now().Before(manager.Launch.StartedAt.Add(bootstrapRetryLifetime)) {
		return journal.managerHold(ctx, "retry-expired")
	}
	err = reconcileNetBirdManagerAllocation(ctx, authority.factory, originalNetBirdManagerPlan(manager), progress,
		func(ctx context.Context, slot string) (netBirdManagerAllocation, error) {
			_, current, err := verifiedOriginalNetBirdAuthority(ctx, authority)
			if err == nil && current.slot.SlotID != slot {
				err = ErrOriginalSourceProducerHold
			}
			return current, err
		}, func(ctx context.Context, factory *ociclient.Factory, plan map[string]any, profile NetBirdManagerProfile, p FoundationProgress) (string, string, error) {
			return reconcileNetBirdNetwork(ctx, factory, plan, profile, p, journal)
		}, func(ctx context.Context, err error) error {
			if errors.Is(err, errNetBirdManagerLaunchIdentity) {
				return errors.Join(err, journal.managerHold(ctx, "create-unresolved"))
			}
			if service, ok := common.IsServiceError(err); ok && service.GetHTTPStatusCode() >= 400 && service.GetHTTPStatusCode() < 500 && service.GetHTTPStatusCode() != 408 && service.GetHTTPStatusCode() != 429 {
				return errors.Join(err, journal.managerHold(ctx, "create-refused"))
			}
			return err
		})
	return err
}

func originalNetBirdManagerPlan(manager *OriginalFoundationNetBirdManager) map[string]any {
	plan := maps.Clone(manager.Plan)
	ids, _ := plan["resource_ids"].(map[string]any)
	ids = maps.Clone(ids)
	if ids == nil {
		ids = map[string]any{}
	}
	ids["control_compartment"], ids["network_compartment"] = manager.ControlCompartmentID, manager.NetworkCompartmentID
	plan["resource_ids"] = ids
	return plan
}

func checkOriginalNetBirdManagerNetwork(ctx context.Context, factory *ociclient.Factory, manager *OriginalFoundationNetBirdManager) error {
	if manager == nil || manager.Launch == nil {
		return ErrOriginalSourceProducerHold
	}
	progress := FoundationProgress{OperationID: manager.Launch.OperationID, AuxiliaryIDs: originalNetBirdManagerIDs(manager),
		BeforeWrite: func(ctx context.Context, _ bool) (context.Context, func(), error) {
			return ctx, nil, ErrOriginalSourceProducerHold
		},
		PrepareCreate:       func(context.Context, foundation.CreateIdentity, bool) error { return ErrOriginalSourceProducerHold },
		CheckpointAuxiliary: func(context.Context, string, string) error { return ErrOriginalSourceProducerHold }}
	_, _, err := ReconcileNetBirdNetwork(ctx, factory, originalNetBirdManagerPlan(manager), manager.Intent.Profile, progress)
	return err
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

func (j *originalNetBirdNetworkJournal) prepare(ctx context.Context, request foundation.CreateIdentity, home bool) error {
	record, etag, entry, err := j.entry(ctx, request.Key)
	if err != nil {
		return err
	}
	a := record.NetBirdMaterial.Authority.Context
	if home || request.Region != foundationHomeRegion || !validFoundationDigest(request.RequestDigest) || request.RetryToken != originalNetBirdNetworkToken(a.ManagerOperationID, request.Key, request.RequestDigest) || entry.Provenance != nil || entry.HoldReason != "" {
		return ErrOriginalSourceProducerHold
	}
	if entry.Pending == nil {
		entry.Pending = &PendingFoundationCreate{OperationID: a.ManagerOperationID, IntentDigest: record.IntentDigest, FirstAttemptAt: time.Now().UTC(), Request: request}
		if err := checkpointOriginalCompartments(ctx, j.authority, &record, &etag); err != nil {
			return err
		}
	}
	if entry.Pending.Request != request {
		return ErrOriginalSourceProducerHold
	}
	if !time.Now().Before(entry.Pending.FirstAttemptAt.Add(bootstrapRetryLifetime)) {
		return j.hold(ctx, request.Key, "retry-expired")
	}
	return ociclient.LimitAdmission(ctx, entry.Pending.FirstAttemptAt.Add(bootstrapRetryLifetime))
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

func (j *originalNetBirdNetworkJournal) created(ctx context.Context, key, id string) error {
	record, etag, entry, err := j.entry(ctx, key)
	if err != nil {
		return err
	}
	if !validOriginalNetBirdNetworkID(key, id) {
		return j.hold(ctx, key, "create-unresolved")
	}
	if entry.Pending == nil || entry.Provenance != nil || entry.HoldReason != "" {
		return ErrOriginalSourceProducerHold
	}
	entry.Provenance = &FoundationResourceProvenance{Create: *entry.Pending, ResourceID: id, Generation: record.Generation, GrantSHA256: record.GrantSHA256}
	return checkpointOriginalCompartments(ctx, j.authority, &record, &etag)
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

func (j *originalNetBirdNetworkJournal) managerHold(ctx context.Context, reason string) error {
	record, etag, err := j.authority.resolver.Store.Load(ociclient.CheckpointContext(ctx), "GRU")
	if err != nil {
		return err
	}
	if record.OriginalFoundationCompartments == nil {
		return ErrOriginalSourceProducerHold
	}
	m := record.OriginalFoundationCompartments.Regions[0].NetBirdManager
	if m == nil || m.Launch == nil || m.Launch.InstanceID != "" || !slices.Contains([]string{"retry-expired", "create-refused", "create-unresolved"}, reason) {
		return ErrOriginalSourceProducerHold
	}
	m.HoldReason = reason
	return errors.Join(ErrOriginalSourceProducerHold, checkpointOriginalCompartments(ctx, j.authority, &record, &etag))
}
