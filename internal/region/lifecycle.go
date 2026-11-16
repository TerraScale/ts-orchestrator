package region

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/capacityledger"
	"github.com/TerraScale/ts-orchestrator/internal/drainwire"
	"github.com/TerraScale/ts-orchestrator/internal/foundationbinding"
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
	// Independent verifiers read the signed JSON as objects.
	return foundationbinding.CanonicalDigest(intent)
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
	OriginalFoundationCompartments *OriginalFoundationCompartments         `json:"originalFoundationCompartments,omitempty"`
	OriginalSourceProducers        *[3]OriginalSourceProducerBirth         `json:"originalSourceProducers,omitempty"`
	NetBirdMaterial                *NetBirdMaterialJournal                 `json:"netBirdMaterial,omitempty"`
	FoundationWriter               *FoundationWriterRecord                 `json:"foundationWriter,omitempty"`
	GrantSHA256                    string                                  `json:"grantSha256,omitempty"`
	ResourceProvenance             map[string]FoundationResourceProvenance `json:"resourceProvenance,omitempty"`
	SchemaVersion                  int                                     `json:"schemaVersion"`
	Cell                           string                                  `json:"cell"`
	OCIRegion                      string                                  `json:"ociRegion"`
	TenancyID                      string                                  `json:"tenancyId"`
	ParentCompartmentID            string                                  `json:"parentCompartmentId"`
	SharedCompartmentID            string                                  `json:"sharedCompartmentId"`
	Generation                     uint64                                  `json:"generation"`
	IntentDigest                   string                                  `json:"intentDigest"`
	OperationID                    string                                  `json:"operationId"`
	Epoch                          uint64                                  `json:"epoch"`
	LeaseID                        string                                  `json:"leaseId,omitempty"`
	ExpiresAt                      time.Time                               `json:"expiresAt,omitzero"`
	Stage                          string                                  `json:"stage"`
	BlockedReason                  string                                  `json:"blockedReason,omitempty"`
	StartedAt                      time.Time                               `json:"startedAt"`
	UpdatedAt                      time.Time                               `json:"updatedAt"`
	CompletedAt                    time.Time                               `json:"completedAt,omitzero"`
	ResourceIDs                    map[string]string                       `json:"resourceIds"`
	AuxiliaryIDs                   map[string]string                       `json:"auxiliaryIds,omitempty"`
	PendingCreates                 map[string]PendingFoundationCreate      `json:"pendingCreates,omitempty"`
	SourcePolicyIDs                map[string]SourcePolicyRecord           `json:"sourcePolicyIds,omitempty"`
	NetBirdManager                 *NetBirdManagerLaunch                   `json:"netbirdManager,omitempty"`
	WorkerPolicyIDs                map[string]WorkerPolicyRecord           `json:"workerPolicyIds,omitempty"`
	OCIRIssuances                  map[string]OCIRIssuanceEntry            `json:"ocirIssuances,omitempty"`
	OCIResources                   *ociresource.ProtectedJournal           `json:"ociResources,omitempty"`
	CapacityLedger                 *capacityledger.Ledger                  `json:"capacityLedger,omitempty"`
	CapacityCreates                map[string]PoolCreateRecord             `json:"capacityCreates,omitempty"`
	CapacityPools                  map[string]PoolResourceRecord           `json:"capacityPools,omitempty"`
	PoolChildren                   map[string]PoolChildRecord              `json:"poolChildren,omitempty"`
	PoolDrains                     map[string]drainwire.PoolReceipt        `json:"poolDrains,omitempty"`
	PoolQuarantines                map[string]PoolQuarantineRecord         `json:"poolQuarantines,omitempty"`
}

// FoundationStore uses conditional writes in an already-authorized durable home
// bucket. It must not create that bucket or manufacture bootstrap authority.
type FoundationStore interface {
	Load(context.Context, string) (FoundationRecord, string, error)
	CompareAndSwap(context.Context, FoundationRecord, string) (string, error)
}

// FoundationController reconciles approved foundations independently, including
type FoundationController struct {
	Footprint   Footprint
	Authority   FoundationAuthority
	Store       FoundationStore
	Foundations Foundations
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
