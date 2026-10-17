package region

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"strings"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/capacityledger"
	"github.com/TerraScale/ts-orchestrator/internal/drainwire"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/foundation"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
)

const foundationLease = 45 * time.Second

var (
	ErrFoundationBusy     = errors.New("regional foundation has an active owner")
	ErrFoundationFenced   = errors.New("regional foundation owner was fenced")
	ErrFoundationMissing  = errors.New("regional foundation record does not exist")
	ErrFoundationConflict = errors.New("regional foundation record changed concurrently")
)

// Footprint is supplied by the authenticated initial tenancy grant producer.
// Discovery, subscriptions and serving health do not implement this authority.
type Footprint interface {
	AuthorizedRegions(context.Context) (ApprovedFootprint, error)
}

// ApprovedFootprint contains only reviewed scope. The producer must verify the
// grant's authenticity and spend authority before returning these plans.
type ApprovedFootprint struct {
	GrantSHA256         string
	TenancyID           string
	ParentCompartmentID string
	SharedCompartmentID string
	Regions             []FoundationIntent
}

type FoundationIntent struct {
	Generation        uint64                   `json:"generation"`
	Plan              map[string]any           `json:"plan"`
	BootstrapMaterial *BootstrapMaterialIntent `json:"bootstrapMaterial,omitempty"`
	ReadAccess        *ReadAccessIntent        `json:"readAccess,omitempty"`
	NetBirdManager    *NetBirdManagerIntent    `json:"netbirdManager,omitempty"`
}

// FoundationIntentDigest binds every signed authority field to its generation.
func FoundationIntentDigest(intent FoundationIntent) (string, error) {
	wire, err := json.Marshal(intent, json.Deterministic(true))
	if err != nil {
		return "", err
	}
	// Independent verifiers read the signed JSON as objects, so normalize struct
	// field order to the same recursively sorted representation before hashing.
	var object map[string]any
	if err := json.Unmarshal(wire, &object); err != nil {
		return "", err
	}
	wire, err = json.Marshal(object, json.Deterministic(true))
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(wire)
	return hex.EncodeToString(sum[:]), nil
}

// FoundationAuthority is the existing scoped foundation authority. HomeWrite
// serializes tenancy-wide IAM across all regional operations, including GRU.
type FoundationAuthority interface {
	Guard(context.Context, uint64) error
	HomeWrite(context.Context, uint64) (context.Context, func(), error)
}

// Foundations is the typed OCI foundation boundary; implementations observe
// actual resources on every call and check beforeWrite before every API write.
type Foundations interface {
	ReconcileFoundation(context.Context, map[string]any, FoundationProgress) (map[string]any, error)
}

// FoundationProgress connects provider effects to the same durable scoped
// attempt. The snapshot IDs are authenticated journal values, never discovery.
type FoundationProgress struct {
	homeStorageDomain   bootstrap.StorageDomain
	OperationID         string
	BeforeWrite         func(context.Context, bool) (context.Context, func(), error)
	Checkpoint          func(context.Context, string, string) error
	AuxiliaryIDs        map[string]string
	CheckpointAuxiliary func(context.Context, string, string) error
	PrepareCreate       func(context.Context, foundation.CreateIdentity, bool) error
	NetBirdManager      *NetBirdManagerLaunch
	ManagerAuthority    func(context.Context) (verifiedNetBirdIntent, error)
	ManagerAllocation   func(context.Context, string) (VerifiedBootstrapAllocation, error)
	CheckpointManager   func(context.Context, NetBirdManagerLaunch) error
}

type PendingFoundationCreate struct {
	OperationID    string                    `json:"operationId"`
	IntentDigest   string                    `json:"intentDigest"`
	Request        foundation.CreateIdentity `json:"request"`
	FirstAttemptAt time.Time                 `json:"firstAttemptAt"`
}

// FoundationResourceProvenance preserves the original accepted create after its
// pending entry is cleared; later grants cannot manufacture resource ownership.
type FoundationResourceProvenance struct {
	Create      PendingFoundationCreate `json:"create"`
	ResourceID  string                  `json:"resourceId"`
	Generation  uint64                  `json:"generation"`
	GrantSHA256 string                  `json:"grantSha256"`
}

// FoundationRecord is bootstrap inventory, never serving or membership truth.
// ResourceIDs contain verified OCIDs, never credential payloads.
type FoundationRecord struct {
	NetBirdMaterial     *NetBirdMaterialJournal                 `json:"netBirdMaterial,omitempty"`
	FoundationWriter    *FoundationWriterRecord                 `json:"foundationWriter,omitempty"`
	GrantSHA256         string                                  `json:"grantSha256,omitempty"`
	ResourceProvenance  map[string]FoundationResourceProvenance `json:"resourceProvenance,omitempty"`
	SchemaVersion       int                                     `json:"schemaVersion"`
	Cell                string                                  `json:"cell"`
	OCIRegion           string                                  `json:"ociRegion"`
	TenancyID           string                                  `json:"tenancyId"`
	ParentCompartmentID string                                  `json:"parentCompartmentId"`
	SharedCompartmentID string                                  `json:"sharedCompartmentId"`
	Generation          uint64                                  `json:"generation"`
	IntentDigest        string                                  `json:"intentDigest"`
	OperationID         string                                  `json:"operationId"`
	Epoch               uint64                                  `json:"epoch"`
	LeaseID             string                                  `json:"leaseId,omitempty"`
	ExpiresAt           time.Time                               `json:"expiresAt,omitzero"`
	Stage               string                                  `json:"stage"`
	BlockedReason       string                                  `json:"blockedReason,omitempty"`
	StartedAt           time.Time                               `json:"startedAt"`
	UpdatedAt           time.Time                               `json:"updatedAt"`
	CompletedAt         time.Time                               `json:"completedAt,omitzero"`
	ResourceIDs         map[string]string                       `json:"resourceIds"`
	AuxiliaryIDs        map[string]string                       `json:"auxiliaryIds,omitempty"`
	PendingCreates      map[string]PendingFoundationCreate      `json:"pendingCreates,omitempty"`
	SourcePolicyIDs     map[string]SourcePolicyRecord           `json:"sourcePolicyIds,omitempty"`
	NetBirdManager      *NetBirdManagerLaunch                   `json:"netbirdManager,omitempty"`
	WorkerPolicyIDs     map[string]WorkerPolicyRecord           `json:"workerPolicyIds,omitempty"`
	OCIRIssuances       map[string]OCIRIssuanceEntry            `json:"ocirIssuances,omitempty"`
	OCIResources        *ociresource.ProtectedJournal           `json:"ociResources,omitempty"`
	CapacityLedger      *capacityledger.Ledger                  `json:"capacityLedger,omitempty"`
	CapacityCreates     map[string]PoolCreateRecord             `json:"capacityCreates,omitempty"`
	CapacityPools       map[string]PoolResourceRecord           `json:"capacityPools,omitempty"`
	PoolChildren        map[string]PoolChildRecord              `json:"poolChildren,omitempty"`
	PoolDrains          map[string]drainwire.PoolReceipt        `json:"poolDrains,omitempty"`
	PoolQuarantines     map[string]PoolQuarantineRecord         `json:"poolQuarantines,omitempty"`
}

// FoundationStore uses conditional writes in an already-authorized durable home
// bucket. It must not create that bucket or manufacture bootstrap authority.
type FoundationStore interface {
	Load(context.Context, string) (FoundationRecord, string, error)
	CompareAndSwap(context.Context, FoundationRecord, string) (string, error)
}

type FoundationResult struct {
	Cell   string           `json:"cell"`
	Record FoundationRecord `json:"record"`
	Err    error            `json:"-"`
}

// FoundationController reconciles approved foundations independently, including
// GRU before overlay, regional NATS, SwarmKit or Atlas exist.
type FoundationController struct {
	Footprint   Footprint
	Authority   FoundationAuthority
	Store       FoundationStore
	Foundations Foundations
	// Only the private initial operator path supplies authenticated home buckets.
	initialGRUAuxiliary map[string]string
}

// ReconcileCell selects one authenticated intent without accepting a caller's
// plan, resource identifiers or provider checkpoints.
func (c *FoundationController) ReconcileCell(ctx context.Context, cell string, epoch uint64) (FoundationRecord, error) {
	if c == nil || c.Footprint == nil || c.Authority == nil || c.Store == nil || c.Foundations == nil || epoch == 0 {
		return FoundationRecord{}, errors.New("regional foundation requires authenticated footprint, authority, durable store and OCI provider")
	}
	if err := c.Authority.Guard(ctx, epoch); err != nil {
		return FoundationRecord{}, err
	}
	footprint, err := c.Footprint.AuthorizedRegions(ctx)
	if err != nil {
		return FoundationRecord{}, err
	}
	if err := validateFootprint(footprint); err != nil {
		return FoundationRecord{}, err
	}
	for _, intent := range footprint.Regions {
		if intent.Plan["cell"] == cell {
			return c.reconcile(ctx, epoch, footprint, intent)
		}
	}
	return FoundationRecord{}, errors.New("region is outside authenticated foundation footprint")
}

func (c *FoundationController) Reconcile(ctx context.Context, epoch uint64) ([]FoundationResult, error) {
	if c.Footprint == nil || c.Authority == nil || c.Store == nil || c.Foundations == nil || epoch == 0 {
		return nil, errors.New("regional foundations require authenticated footprint, authority, durable store and OCI provider")
	}
	if err := c.Authority.Guard(ctx, epoch); err != nil {
		return nil, err
	}
	footprint, err := c.Footprint.AuthorizedRegions(ctx)
	if err != nil {
		return nil, fmt.Errorf("read authorized regional footprint: %w", err)
	}
	if err := validateFootprint(footprint); err != nil {
		return nil, err
	}
	results := make([]FoundationResult, len(footprint.Regions))
	jobs := make(chan int)
	var workers sync.WaitGroup
	for range min(3, len(results)) {
		workers.Go(func() {
			for i := range jobs {
				intent := footprint.Regions[i]
				cell := intent.Plan["cell"].(string)
				record, err := c.reconcile(ctx, epoch, footprint, intent)
				results[i] = FoundationResult{Cell: cell, Record: record, Err: err}
			}
		})
	}
	for i := range results {
		jobs <- i
	}
	close(jobs)
	workers.Wait()
	var failures []error
	for _, result := range results {
		if result.Err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", result.Cell, result.Err))
		}
	}
	return results, errors.Join(failures...)
}

func validateFootprint(f ApprovedFootprint) error {
	if !strings.HasPrefix(f.TenancyID, "ocid1.tenancy.") || !strings.HasPrefix(f.ParentCompartmentID, "ocid1.compartment.") ||
		!strings.HasPrefix(f.SharedCompartmentID, "ocid1.compartment.") || len(f.Regions) == 0 || len(f.Regions) > len(catalog.Entries()) {
		return errors.New("authorized regional footprint lacks tenancy, compartments or reviewed regions")
	}
	seen := map[string]bool{}
	for _, intent := range f.Regions {
		p := intent.Plan
		cell, _ := p["cell"].(string)
		entry, ok := catalog.Lookup(cell)
		if !ok || seen[cell] || intent.Generation == 0 || p["region"] != entry.OCIRegion ||
			p["tenancy_id"] != f.TenancyID || p["parent_compartment_id"] != f.ParentCompartmentID || p["shared_compartment_id"] != f.SharedCompartmentID {
			return errors.New("regional plan is outside authenticated footprint or repeats a region")
		}
		if _, ok := p["resource_ids"].(map[string]any); !ok {
			return errors.New("regional plan lacks resource identities")
		}
		seen[cell] = true
	}
	return nil
}

// foundationAttempt serializes local renewals/checkpoints; object ETags fence
// other processes and the authority epoch fences older leaders.
type foundationAttempt struct {
	controller *FoundationController
	mu         sync.Mutex
	record     FoundationRecord
	etag       string
	leaseID    string
	epoch      uint64
	cancel     context.CancelCauseFunc
}

func (c *FoundationController) reconcile(ctx context.Context, epoch uint64, footprint ApprovedFootprint, intent FoundationIntent) (FoundationRecord, error) {
	wire, err := json.Marshal(intent.Plan, json.Deterministic(true))
	if err != nil {
		return FoundationRecord{}, err
	}
	var plan map[string]any
	if err := json.Unmarshal(wire, &plan); err != nil {
		return FoundationRecord{}, err
	}
	delete(plan, "_source_path")
	cell := plan["cell"].(string)
	digest, err := FoundationIntentDigest(intent)
	if err != nil {
		return FoundationRecord{}, err
	}
	current, etag, err := c.Store.Load(ctx, cell)
	if err != nil && !errors.Is(err, ErrFoundationMissing) {
		return FoundationRecord{}, err
	}
	now := time.Now().UTC()
	if errors.Is(err, ErrFoundationMissing) {
		current = FoundationRecord{SchemaVersion: 1, Cell: cell, OCIRegion: plan["region"].(string), TenancyID: footprint.TenancyID,
			ParentCompartmentID: footprint.ParentCompartmentID, SharedCompartmentID: footprint.SharedCompartmentID,
			Generation: intent.Generation, IntentDigest: digest, GrantSHA256: footprint.GrantSHA256, OperationID: entityid.Derive("regional-foundation", footprint.TenancyID, cell, fmt.Sprint(intent.Generation)),
			StartedAt: now, ResourceIDs: map[string]string{}}
		if cell == "GRU" {
			current.AuxiliaryIDs = maps.Clone(c.initialGRUAuxiliary)
		}
	} else {
		if cell == "GRU" {
			for key, id := range c.initialGRUAuxiliary {
				if current.AuxiliaryIDs[key] != id {
					return current, errors.New("existing home journal differs from authenticated initial bucket prerequisites")
				}
			}
		}
		if current.TenancyID != footprint.TenancyID || current.ParentCompartmentID != footprint.ParentCompartmentID || current.SharedCompartmentID != footprint.SharedCompartmentID {
			return current, errors.New("foundation record belongs to another authorized scope")
		}
		if epoch < current.Epoch || intent.Generation < current.Generation || intent.Generation == current.Generation && digest != current.IntentDigest {
			return current, fmt.Errorf("%w: signed generation or full intent differs from the protected record; preserve the journal and follow docs/foundation-binding-recovery.md", ErrFoundationFenced)
		}
		if current.LeaseID != "" && now.Before(current.ExpiresAt) && epoch <= current.Epoch {
			return current, ErrFoundationBusy
		}
		if intent.Generation > current.Generation {
			if len(current.PendingCreates) != 0 {
				return current, errors.New("previous foundation intent has unresolved accepted creates")
			}
			current.Generation, current.IntentDigest, current.GrantSHA256 = intent.Generation, digest, footprint.GrantSHA256
			current.OperationID = entityid.Derive("regional-foundation", footprint.TenancyID, cell, fmt.Sprint(intent.Generation))
			current.StartedAt = now
		}
	}
	if current.GrantSHA256 != "" && current.GrantSHA256 != footprint.GrantSHA256 {
		return current, errors.New("foundation grant differs from persisted generation authority")
	}
	current.GrantSHA256 = footprint.GrantSHA256
	if current.ResourceProvenance == nil {
		current.ResourceProvenance = map[string]FoundationResourceProvenance{}
	}
	if current.ResourceIDs == nil {
		current.ResourceIDs = map[string]string{}
	}
	if current.AuxiliaryIDs == nil {
		current.AuxiliaryIDs = map[string]string{}
	}
	if current.PendingCreates == nil {
		current.PendingCreates = map[string]PendingFoundationCreate{}
	}
	ids := plan["resource_ids"].(map[string]any)
	for key, id := range current.ResourceIDs {
		if pinned := ids[key]; pinned != nil && pinned != id {
			return current, errors.New("approved plan conflicts with persisted foundation identity")
		}
		ids[key] = id
	}
	leaseID := entityid.New()
	current.Epoch, current.LeaseID, current.ExpiresAt = epoch, leaseID, now.Add(foundationLease)
	current.Stage, current.BlockedReason, current.CompletedAt, current.UpdatedAt = "foundation", "", time.Time{}, now
	if err := c.Authority.Guard(ctx, epoch); err != nil {
		return current, err
	}
	etag, err = c.Store.CompareAndSwap(ctx, current, etag)
	if err != nil {
		return current, err
	}
	workCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	attempt := &foundationAttempt{controller: c, record: current, etag: etag, leaseID: leaseID, epoch: epoch, cancel: cancel}
	stopped := make(chan struct{})
	renewed := make(chan struct{})
	go func() {
		defer close(renewed)
		ticker := time.NewTicker(foundationLease / 3)
		defer ticker.Stop()
		for {
			select {
			case <-stopped:
				return
			case <-workCtx.Done():
				return
			case <-ticker.C:
				if err := attempt.renew(workCtx); err != nil {
					cancel(err)
					return
				}
			}
		}
	}()
	progress := FoundationProgress{OperationID: current.OperationID, BeforeWrite: attempt.beforeWrite, Checkpoint: attempt.checkpoint,
		AuxiliaryIDs: maps.Clone(current.AuxiliaryIDs), CheckpointAuxiliary: attempt.checkpointAuxiliary, PrepareCreate: attempt.prepareCreate}
	if reader, ok := c.Footprint.(*SignedFootprint); ok && cell == "GRU" {
		progress.homeStorageDomain = reader.storage
	}
	if intent.NetBirdManager != nil {
		reader, ok := c.Footprint.(*SignedFootprint)
		if !ok || cell != "GRU" {
			close(stopped)
			<-renewed
			return attempt.finish(ctx, errors.New("NetBird manager requires the same signed GRU foundation grant"))
		}
		resolver := FoundationResolver{Footprint: c.Footprint, Store: c.Store}
		progress.ManagerAuthority, progress.ManagerAllocation = reader.authorizedNetBirdManager, resolver.BootstrapAllocation
		progress.NetBirdManager, progress.CheckpointManager = current.NetBirdManager, attempt.checkpointManager
	}
	bound, providerErr := c.Foundations.ReconcileFoundation(workCtx, plan, progress)
	close(stopped)
	<-renewed
	if cause := context.Cause(workCtx); cause != nil {
		providerErr = errors.Join(providerErr, cause)
	}
	if providerErr == nil {
		boundIDs, ok := bound["resource_ids"].(map[string]any)
		if !ok {
			providerErr = errors.New("foundation returned no resource identities")
		} else {
			for key, raw := range boundIDs {
				if key == "instances" || key == "boot_volumes" || key == "data_volumes" {
					expected, valid := ids[key].(map[string]any)
					observed, ok := raw.(map[string]any)
					if !valid || !ok || !maps.Equal(expected, observed) {
						providerErr = errors.New("foundation changed signed host resource bindings")
						break
					}
					continue
				}
				if raw == nil {
					continue
				}
				id, ok := raw.(string)
				if !ok {
					providerErr = errors.New("foundation returned invalid resource identity")
					break
				}
				if err := attempt.checkpoint(workCtx, key, id); err != nil {
					providerErr = err
					break
				}
			}
		}
	}
	return attempt.finish(ctx, providerErr)
}

func (a *foundationAttempt) guard(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := a.controller.Authority.Guard(ctx, a.epoch); err != nil {
		return fmt.Errorf("%w: %w", ErrFoundationFenced, err)
	}
	latest, _, err := a.controller.Store.Load(ctx, a.record.Cell)
	if err != nil {
		return err
	}
	if latest.LeaseID != a.leaseID || latest.Epoch != a.epoch || !time.Now().Before(latest.ExpiresAt) {
		return ErrFoundationFenced
	}
	return nil
}

func (a *foundationAttempt) beforeWrite(ctx context.Context, home bool) (context.Context, func(), error) {
	if err := a.guard(ctx); err != nil {
		a.cancel(err)
		return ctx, nil, err
	}
	release := func() {}
	if home {
		var err error
		ctx, release, err = a.controller.Authority.HomeWrite(ctx, a.epoch)
		if err != nil {
			return ctx, nil, err
		}
		if ctx == nil || release == nil {
			if release != nil {
				release()
			}
			return ctx, nil, errors.New("home IAM authority did not return its release")
		}
	}
	if err := a.guard(ctx); err != nil {
		release()
		a.cancel(err)
		return ctx, nil, err
	}
	return ctx, release, nil
}

func (a *foundationAttempt) update(ctx context.Context) error {
	if err := a.guard(ctx); err != nil {
		return err
	}
	a.record.UpdatedAt = time.Now().UTC()
	etag, err := a.controller.Store.CompareAndSwap(ctx, a.record, a.etag)
	if err != nil {
		a.cancel(err)
		return err
	}
	a.etag = etag
	return nil
}

func (a *foundationAttempt) renew(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.record.ExpiresAt = time.Now().UTC().Add(foundationLease)
	return a.update(ctx)
}

func (a *foundationAttempt) checkpoint(ctx context.Context, key, id string) error {
	if key == "" || !strings.HasPrefix(id, "ocid1.") {
		return errors.New("foundation checkpoint requires resource name and OCID")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if old := a.record.ResourceIDs[key]; old != "" && old != id {
		return errors.New("foundation resource identity cannot be silently replaced")
	}
	a.record.ResourceIDs[key] = id
	if err := a.completeCreate(key, id); err != nil {
		return err
	}
	return a.update(ctx)
}

func (a *foundationAttempt) checkpointAuxiliary(ctx context.Context, key, id string) error {
	if !validAuxiliaryID(key, id, a.record.OCIRegion) {
		return errors.New("auxiliary foundation checkpoint has invalid resource scope")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if old := a.record.AuxiliaryIDs[key]; old != "" && old != id {
		return errors.New("auxiliary foundation identity cannot be silently replaced")
	}
	a.record.AuxiliaryIDs[key] = id
	if err := a.completeCreate(key, id); err != nil {
		return err
	}
	return a.update(ctx)
}

func (a *foundationAttempt) checkpointManager(ctx context.Context, next NetBirdManagerLaunch) error {
	if err := next.validate(); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if old := a.record.NetBirdManager; old != nil {
		previous := *old
		if previous.InstanceID != "" && previous.InstanceID != next.InstanceID || previous.BootVolumeID != "" && previous.BootVolumeID != next.BootVolumeID {
			return errors.New("dedicated manager singleton identity cannot be replaced")
		}
		previous.InstanceID, previous.BootVolumeID = next.InstanceID, next.BootVolumeID
		if !sameCapacityValue(previous, next) {
			return errors.New("dedicated manager immutable reservation changed")
		}
	}
	a.record.NetBirdManager = &next
	return a.update(ctx)
}

func (a *foundationAttempt) completeCreate(key, id string) error {
	if original, exists := a.record.ResourceProvenance[key]; exists {
		if original.ResourceID != id {
			return errors.New("foundation create provenance cannot be replaced")
		}
		return nil
	}
	if pending, exists := a.record.PendingCreates[key]; exists {
		if validFoundationDigest(a.record.GrantSHA256) {
			if a.record.ResourceProvenance == nil {
				a.record.ResourceProvenance = map[string]FoundationResourceProvenance{}
			}
			a.record.ResourceProvenance[key] = FoundationResourceProvenance{Create: pending, ResourceID: id, Generation: a.record.Generation, GrantSHA256: a.record.GrantSHA256}
		}
		delete(a.record.PendingCreates, key)
	}
	return nil
}

func (a *foundationAttempt) prepareCreate(ctx context.Context, request foundation.CreateIdentity, recovery bool) error {
	if err := request.Validate(); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.guard(ctx); err != nil {
		return err
	}
	if pending, exists := a.record.PendingCreates[request.Key]; exists {
		now := time.Now().UTC()
		if pending.OperationID != a.record.OperationID || pending.IntentDigest != a.record.IntentDigest || pending.Request != request ||
			pending.FirstAttemptAt.After(now) || !now.Before(pending.FirstAttemptAt.Add(23*time.Hour)) {
			return errors.New("foundation create cannot replay a changed or expired pending request")
		}
		if request.RetryToken == "" {
			return errors.New("pending OCI create has no replay token; exact provider observation is required")
		}
		return nil
	}
	if recovery {
		return errors.New("unrecorded OCI resource has no durable pending create")
	}
	a.record.PendingCreates[request.Key] = PendingFoundationCreate{OperationID: a.record.OperationID, IntentDigest: a.record.IntentDigest,
		Request: request, FirstAttemptAt: time.Now().UTC()}
	return a.update(ctx)
}

func (a *foundationAttempt) finish(ctx context.Context, providerErr error) (FoundationRecord, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.guard(ctx); err != nil {
		return a.record, errors.Join(providerErr, err)
	}
	a.record.LeaseID, a.record.ExpiresAt = "", time.Time{}
	if providerErr == nil {
		if len(a.record.PendingCreates) != 0 {
			providerErr = errors.New("foundation still has unresolved creates")
		}
	}
	if providerErr == nil {
		a.record.Stage, a.record.CompletedAt = "reconciled", time.Now().UTC()
	} else {
		a.record.Stage, a.record.BlockedReason = "blocked", "foundation-unavailable"
	}
	// Do not persist arbitrary provider errors: SDK responses can contain values.
	a.record.UpdatedAt = time.Now().UTC()
	etag, err := a.controller.Store.CompareAndSwap(ctx, a.record, a.etag)
	if err == nil {
		a.etag = etag
	}
	result := a.record
	result.ResourceIDs = maps.Clone(result.ResourceIDs)
	result.AuxiliaryIDs = maps.Clone(result.AuxiliaryIDs)
	result.PendingCreates = maps.Clone(result.PendingCreates)
	result.SourcePolicyIDs = cloneSourcePolicies(result.SourcePolicyIDs)
	result.WorkerPolicyIDs = maps.Clone(result.WorkerPolicyIDs)
	result.ResourceProvenance = maps.Clone(result.ResourceProvenance)
	result.cloneCapacity()
	result.clonePoolDrains()
	return result, errors.Join(providerErr, err)
}
