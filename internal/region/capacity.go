package region

import (
	"errors"
	"maps"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/capacityledger"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

// PoolWireRecord retains the original request across retries and grants. A
// later rejection never clears EverUnknown; a positive original result resolves it.
type PoolWireRecord struct {
	RequestSHA256    string    `json:"requestSha256"`
	RetryToken       string    `json:"retryToken"`
	IfMatch          string    `json:"ifMatch,omitempty"`
	FirstAttemptAt   time.Time `json:"firstAttemptAt"`
	LastAttemptAt    time.Time `json:"lastAttemptAt"`
	Attempts         uint64    `json:"attempts"`
	EverUnknown      bool      `json:"everUnknown,omitzero"`
	TokenInvalidated bool      `json:"tokenInvalidated,omitzero"`
	AcceptedAt       time.Time `json:"acceptedAt,omitzero"`
	OpcRequestID     string    `json:"opcRequestId,omitempty"`
	WorkRequestID    string    `json:"workRequestId,omitempty"`
	WorkCompletedAt  time.Time `json:"workCompletedAt,omitzero"`
}

// PoolCreateRecord checkpoints before a configuration or pool ID exists. It
// remains after success so unknown creates cannot be replaced by discovery.
type PoolCreateRecord struct {
	OperationID         string         `json:"operationId"`
	Kind                string         `json:"kind"`
	RecipeSHA256        string         `json:"recipeSha256"`
	GrantSHA256         string         `json:"grantSha256"`
	Generation          uint64         `json:"generation"`
	ConfigurationID     string         `json:"configurationId,omitempty"`
	ConfigurationSHA256 string         `json:"configurationSha256"`
	PlacementSHA256     string         `json:"placementSha256,omitempty"`
	ResourceID          string         `json:"resourceId,omitempty"`
	Request             PoolWireRecord `json:"request"`
}

type PoolConfigurationRecord struct {
	ConfigurationID     string         `json:"configurationId"`
	OperationID         string         `json:"operationId"`
	RecipeSHA256        string         `json:"recipeSha256"`
	ConfigurationSHA256 string         `json:"configurationSha256"`
	GrantSHA256         string         `json:"grantSha256"`
	Generation          uint64         `json:"generation"`
	Create              PoolWireRecord `json:"create"`
}

// PoolResourceRecord is original provider provenance, not tag-based discovery.
// An unresolved lifecycle keeps ActiveOperationID until positively completed.
type PoolResourceRecord struct {
	PoolID                 string                             `json:"poolId"`
	CompartmentID          string                             `json:"compartmentId"`
	OperationID            string                             `json:"operationId"`
	GrantSHA256            string                             `json:"grantSha256"`
	Generation             uint64                             `json:"generation"`
	Create                 PoolWireRecord                     `json:"create"`
	Configurations         map[string]PoolConfigurationRecord `json:"configurations"`
	CurrentConfigurationID string                             `json:"currentConfigurationId"`
	ActiveOperationID      string                             `json:"activeOperationId,omitempty"`
	LeaseID                string                             `json:"leaseId,omitempty"`
	Epoch                  uint64                             `json:"epoch"`
	LeaseExpiresAt         time.Time                          `json:"leaseExpiresAt,omitzero"`
}

type PoolChildStage string

const (
	PoolChildReserved       PoolChildStage = "reserved"
	PoolChildLaunchPrepared PoolChildStage = "launch-prepared"
	PoolChildLaunchUnknown  PoolChildStage = "launch-unknown"
	PoolChildBorn           PoolChildStage = "born"
	PoolChildAttachPrepared PoolChildStage = "attach-prepared"
	PoolChildAttachUnknown  PoolChildStage = "attach-unknown"
	PoolChildAttached       PoolChildStage = "attached"
	PoolChildReady          PoolChildStage = "ready"
	PoolChildDraining       PoolChildStage = "draining"
	PoolChildDetachPrepared PoolChildStage = "detach-prepared"
	PoolChildDetachUnknown  PoolChildStage = "detach-unknown"
	PoolChildDetaching      PoolChildStage = "detaching"
	PoolChildDetached       PoolChildStage = "detached"
	PoolChildTerminating    PoolChildStage = "terminating"
	PoolChildRetired        PoolChildStage = "retired"
)

// PoolChildRecord binds exactly one original launch response to its lifecycle.
// Serialized data alone is never an enrollment or termination capability.
type PoolChildRecord struct {
	OperationID          string          `json:"operationId"`
	RecipeSHA256         string          `json:"recipeSha256"`
	PoolID               string          `json:"poolId"`
	ConfigurationID      string          `json:"configurationId"`
	TargetFrom           int             `json:"targetFrom"`
	AvailabilityDomain   string          `json:"availabilityDomain"`
	SubnetID             string          `json:"subnetId"`
	Stage                PoolChildStage  `json:"stage"`
	Launch               *PoolWireRecord `json:"launch,omitempty"`
	InstanceID           string          `json:"instanceId,omitempty"`
	BornAt               time.Time       `json:"bornAt,omitzero"`
	BootVolumeID         string          `json:"bootVolumeId,omitempty"`
	BootAttachmentID     string          `json:"bootAttachmentId,omitempty"`
	Attach               *PoolWireRecord `json:"attach,omitempty"`
	ReadyAt              time.Time       `json:"readyAt,omitzero"`
	RemovalOperationID   string          `json:"removalOperationId,omitempty"`
	DrainAuthoritySHA256 string          `json:"drainAuthoritySha256,omitempty"`
	Detach               *PoolWireRecord `json:"detach,omitempty"`
	DetachedAt           time.Time       `json:"detachedAt,omitzero"`
	Terminate            *PoolWireRecord `json:"terminate,omitempty"`
	DeleteBoot           *PoolWireRecord `json:"deleteBoot,omitempty"`
	InstanceRetiredAt    time.Time       `json:"instanceRetiredAt,omitzero"`
	BootRetiredAt        time.Time       `json:"bootRetiredAt,omitzero"`
}

// PoolQuarantineRecord removes only membership; it grants no birth or deletion.
type PoolQuarantineRecord struct {
	OperationID   string          `json:"operationId"`
	PoolID        string          `json:"poolId"`
	InstanceID    string          `json:"instanceId"`
	PurposeSHA256 string          `json:"purposeSha256"`
	GrantSHA256   string          `json:"grantSha256"`
	Generation    uint64          `json:"generation"`
	Detach        *PoolWireRecord `json:"detach,omitempty"`
	DetachedAt    time.Time       `json:"detachedAt,omitzero"`
}

func (w PoolWireRecord) validate(updated time.Time) error {
	if !validFoundationDigest(w.RequestSHA256) || len(w.RetryToken) > 64 ||
		strings.ContainsAny(w.RetryToken+w.IfMatch+w.OpcRequestID, "\r\n") || len(w.IfMatch) > 512 || len(w.OpcRequestID) > 512 ||
		w.FirstAttemptAt.IsZero() || w.LastAttemptAt.Before(w.FirstAttemptAt) || w.LastAttemptAt.After(updated) || w.Attempts == 0 ||
		!w.AcceptedAt.IsZero() && (w.AcceptedAt.Before(w.FirstAttemptAt) || w.AcceptedAt.After(updated)) ||
		w.WorkRequestID != "" && !capacityOCID(w.WorkRequestID, "workrequest") ||
		!w.WorkCompletedAt.IsZero() && (w.AcceptedAt.IsZero() || w.WorkRequestID == "" || w.WorkCompletedAt.Before(w.AcceptedAt) || w.WorkCompletedAt.After(updated)) {
		return errors.New("protected pool request has invalid original identity, attempt or provider outcome")
	}
	return nil
}

func (r FoundationRecord) validateCapacity() error {
	if len(r.CapacityCreates) > 1024 || len(r.CapacityPools) > 64 || len(r.PoolChildren) > 1024 || len(r.PoolQuarantines) > 1024 {
		return errors.New("protected capacity history exceeds its retained bound")
	}
	for key, create := range r.CapacityCreates {
		kind := "instanceconfiguration"
		if create.Kind == "pool" {
			kind = "instancepool"
		}
		if key != create.OperationID+":"+create.Kind || !entityid.Valid(create.OperationID) || create.Kind != "configuration" && create.Kind != "pool" ||
			!validFoundationDigest(create.RecipeSHA256) || !validFoundationDigest(create.GrantSHA256) || !validFoundationDigest(create.ConfigurationSHA256) ||
			create.Generation == 0 || create.Generation > r.Generation || create.Request.validate(r.UpdatedAt) != nil || create.Request.RetryToken == "" ||
			create.Kind == "pool" && (!capacityOCID(create.ConfigurationID, "instanceconfiguration") || !validFoundationDigest(create.PlacementSHA256)) ||
			create.ResourceID != "" && (!capacityOCID(create.ResourceID, kind) || create.Request.AcceptedAt.IsZero()) || create.ResourceID == "" && !create.Request.AcceptedAt.IsZero() {
			return errors.New("capacity resource create lacks exact original preparation or SDK result")
		}
	}
	if r.CapacityLedger != nil {
		if err := r.CapacityLedger.Validate(); err != nil {
			return err
		}
	}
	for key, pool := range r.CapacityPools {
		if key != pool.PoolID || !capacityOCID(pool.PoolID, "instancepool") || !capacityOCID(pool.CompartmentID, "compartment") ||
			!entityid.Valid(pool.OperationID) || !validFoundationDigest(pool.GrantSHA256) || pool.Generation == 0 || pool.Generation > r.Generation ||
			pool.Create.validate(r.UpdatedAt) != nil || pool.Create.RetryToken == "" || pool.Create.AcceptedAt.IsZero() || len(pool.Configurations) == 0 || len(pool.Configurations) > 128 ||
			pool.Epoch == 0 {
			return errors.New("capacity pool lacks its exact protected original create")
		}
		if _, exists := pool.Configurations[pool.CurrentConfigurationID]; !exists {
			return errors.New("capacity pool references an unproven configuration")
		}
		for id, config := range pool.Configurations {
			if id != config.ConfigurationID || !capacityOCID(id, "instanceconfiguration") || !entityid.Valid(config.OperationID) ||
				!validFoundationDigest(config.RecipeSHA256) || !validFoundationDigest(config.ConfigurationSHA256) || !validFoundationDigest(config.GrantSHA256) ||
				config.Generation == 0 || config.Generation > r.Generation || config.Create.validate(r.UpdatedAt) != nil || config.Create.RetryToken == "" || config.Create.AcceptedAt.IsZero() {
				return errors.New("capacity configuration lacks its exact protected original create")
			}
		}
		if pool.ActiveOperationID != "" && !entityid.Valid(pool.ActiveOperationID) ||
			pool.LeaseID != "" && (!entityid.Valid(pool.LeaseID) || pool.ActiveOperationID == "" || pool.LeaseExpiresAt.IsZero()) ||
			pool.LeaseID == "" && !pool.LeaseExpiresAt.IsZero() {
			return errors.New("capacity pool lifecycle owner has an invalid operation or lease")
		}
	}
	hosts := map[string]capacityledger.Host{}
	if r.CapacityLedger != nil {
		for _, host := range r.CapacityLedger.Hosts {
			if host.Receipt.TenancyID != r.TenancyID || host.Receipt.Quote.Cell != r.Cell || host.Receipt.GrantGeneration > r.Generation {
				return errors.New("capacity liability differs from its protected home scope")
			}
			hosts[host.Receipt.OperationID] = host
		}
	}
	instances := map[string]bool{}
	for key, child := range r.PoolChildren {
		pool, poolExists := r.CapacityPools[child.PoolID]
		config, configExists := pool.Configurations[child.ConfigurationID]
		host, reserved := hosts[key]
		if key != child.OperationID || !entityid.Valid(key) || !poolExists || !configExists || !reserved ||
			child.RecipeSHA256 != host.Receipt.RecipeSHA256 || child.RecipeSHA256 != config.RecipeSHA256 ||
			pool.CompartmentID != host.Receipt.Quote.CompartmentID || child.TargetFrom < 0 || child.TargetFrom >= 1024 ||
			child.AvailabilityDomain == "" || len(child.AvailabilityDomain) > 128 || !capacityOCID(child.SubnetID, "subnet") {
			return errors.New("pool child differs from its original protected reservation, configuration or placement")
		}
		if err := child.validate(host, r.UpdatedAt); err != nil {
			return err
		}
		if child.InstanceID != "" {
			if instances[child.InstanceID] {
				return errors.New("protected pool children repeat an original instance identity")
			}
			instances[child.InstanceID] = true
		}
	}
	for key, quarantine := range r.PoolQuarantines {
		_, poolExists := r.CapacityPools[quarantine.PoolID]
		if key != quarantine.OperationID || !entityid.Valid(key) || !poolExists || !capacityOCID(quarantine.InstanceID, "instance") ||
			!validFoundationDigest(quarantine.PurposeSHA256) || !validFoundationDigest(quarantine.GrantSHA256) ||
			quarantine.Generation == 0 || quarantine.Generation > r.Generation {
			return errors.New("pool quarantine lacks exact protected membership purpose")
		}
		if quarantine.Detach != nil && (quarantine.Detach.validate(r.UpdatedAt) != nil || quarantine.Detach.RetryToken == "") ||
			!quarantine.DetachedAt.IsZero() && (quarantine.Detach == nil || quarantine.Detach.AcceptedAt.IsZero() || quarantine.Detach.WorkCompletedAt.IsZero() ||
				quarantine.DetachedAt.Before(quarantine.Detach.WorkCompletedAt) || quarantine.DetachedAt.After(r.UpdatedAt)) {
			return errors.New("pool quarantine lacks positive exact detach completion")
		}
	}
	return nil
}

func (c PoolChildRecord) validate(host capacityledger.Host, updated time.Time) error {
	rank := map[PoolChildStage]int{
		PoolChildReserved: 0, PoolChildLaunchPrepared: 1, PoolChildLaunchUnknown: 1, PoolChildBorn: 2,
		PoolChildAttachPrepared: 3, PoolChildAttachUnknown: 3, PoolChildAttached: 4, PoolChildReady: 5,
		PoolChildDraining: 6, PoolChildDetachPrepared: 7, PoolChildDetachUnknown: 7,
		PoolChildDetaching: 7, PoolChildDetached: 8, PoolChildTerminating: 9, PoolChildRetired: 10,
	}
	step, validStage := rank[c.Stage]
	if !validStage || step < 2 && (c.InstanceID != "" || !c.BornAt.IsZero() || c.BootVolumeID != "" || c.BootAttachmentID != "") ||
		step < 3 && c.Attach != nil || step < 5 && !c.ReadyAt.IsZero() ||
		step < 6 && (c.RemovalOperationID != "" || c.DrainAuthoritySHA256 != "") || step < 7 && c.Detach != nil ||
		step < 8 && !c.DetachedAt.IsZero() || step < 9 && (c.Terminate != nil || c.DeleteBoot != nil || !c.InstanceRetiredAt.IsZero() || !c.BootRetiredAt.IsZero()) {
		return errors.New("pool child has effects outside its protected lifecycle stage")
	}
	for _, wire := range []*PoolWireRecord{c.Launch, c.Attach, c.Detach, c.Terminate, c.DeleteBoot} {
		if wire != nil && wire.validate(updated) != nil {
			return errors.New("pool child contains an invalid protected request")
		}
	}
	if c.Attach != nil && c.Attach.RetryToken == "" || c.Detach != nil && c.Detach.RetryToken == "" {
		return errors.New("pool membership mutation lacks its original replay token")
	}
	if c.Launch == nil {
		if c.Stage != PoolChildReserved || host.RequestSHA256 != "" || c.InstanceID != "" || !c.BornAt.IsZero() || c.BootVolumeID != "" || c.BootAttachmentID != "" ||
			c.Attach != nil || !c.ReadyAt.IsZero() || c.RemovalOperationID != "" || c.DrainAuthoritySHA256 != "" || c.Detach != nil || !c.DetachedAt.IsZero() ||
			c.Terminate != nil || c.DeleteBoot != nil || !c.InstanceRetiredAt.IsZero() || !c.BootRetiredAt.IsZero() {
			return errors.New("pool child has effects without its original prepared launch")
		}
		return nil
	}
	if c.Launch.RetryToken == "" || c.Launch.RequestSHA256 != host.RequestSHA256 || !c.Launch.FirstAttemptAt.Equal(host.StartedAt) {
		return errors.New("pool child launch differs from its original financial request")
	}
	if c.InstanceID == "" {
		if c.Stage != PoolChildLaunchPrepared && c.Stage != PoolChildLaunchUnknown || !c.Launch.AcceptedAt.IsZero() ||
			!c.BornAt.IsZero() || c.BootVolumeID != "" || c.BootAttachmentID != "" || c.Attach != nil || c.Detach != nil || c.Terminate != nil || c.DeleteBoot != nil ||
			c.Stage == PoolChildLaunchUnknown && !c.Launch.EverUnknown {
			return errors.New("unborn pool child contains inferred or conflicting provider effects")
		}
		return nil
	}
	if !capacityOCID(c.InstanceID, "instance") || c.Launch.AcceptedAt.IsZero() || !c.BornAt.Equal(c.Launch.AcceptedAt) ||
		c.BootVolumeID != "" && !capacityOCID(c.BootVolumeID, "bootvolume") || c.BootAttachmentID != "" && !capacityOCID(c.BootAttachmentID, "bootvolumeattachment") ||
		(c.BootVolumeID == "") != (c.BootAttachmentID == "") {
		return errors.New("pool child lacks its positive original SDK birth and exact boot attachment")
	}
	if c.BootVolumeID == "" {
		if c.Stage != PoolChildBorn || c.Attach != nil || host.InstanceID != "" {
			return errors.New("pool child cannot advance before its exact boot observation")
		}
		return nil
	}
	if host.InstanceID != c.InstanceID || host.BootVolumeID != c.BootVolumeID || !host.BornAt.Equal(c.BornAt) ||
		!host.InstanceRetiredAt.Equal(c.InstanceRetiredAt) || !host.BootRetiredAt.Equal(c.BootRetiredAt) {
		return errors.New("pool child resources differ from their immutable original liabilities")
	}
	switch c.Stage {
	case PoolChildBorn:
		if c.Attach != nil {
			return errors.New("born child already has an attach request")
		}
	case PoolChildAttachPrepared, PoolChildAttachUnknown:
		if c.Attach == nil || c.Attach.RetryToken == "" || !c.Attach.AcceptedAt.IsZero() || c.Stage == PoolChildAttachUnknown && !c.Attach.EverUnknown {
			return errors.New("pool child attach outcome is inconsistent")
		}
	case PoolChildAttached:
		if c.Attach == nil || c.Attach.AcceptedAt.IsZero() {
			return errors.New("attached child lacks an original positive attach result")
		}
	case PoolChildReady, PoolChildDraining, PoolChildDetachPrepared, PoolChildDetachUnknown, PoolChildDetaching, PoolChildDetached, PoolChildTerminating, PoolChildRetired:
		if c.Attach == nil || c.Attach.AcceptedAt.IsZero() || c.Attach.WorkCompletedAt.IsZero() || c.ReadyAt.Before(c.Attach.WorkCompletedAt) || c.ReadyAt.After(updated) {
			return errors.New("ready child lacks completed exact attach and fresh readiness facts")
		}
	default:
		return errors.New("pool child has an unknown or regressed lifecycle stage")
	}
	retiring := c.Stage == PoolChildDraining || c.Stage == PoolChildDetachPrepared || c.Stage == PoolChildDetachUnknown || c.Stage == PoolChildDetaching || c.Stage == PoolChildDetached || c.Stage == PoolChildTerminating || c.Stage == PoolChildRetired
	if retiring && (!entityid.Valid(c.RemovalOperationID) || !validFoundationDigest(c.DrainAuthoritySHA256)) {
		return errors.New("pool child removal lacks its distinct protected runtime drain authority")
	}
	if (c.Stage == PoolChildDetachPrepared || c.Stage == PoolChildDetachUnknown) && (c.Detach == nil || c.Detach.RetryToken == "" || !c.Detach.AcceptedAt.IsZero() || c.Stage == PoolChildDetachUnknown && !c.Detach.EverUnknown) {
		return errors.New("pool child detach outcome is inconsistent")
	}
	if c.Stage == PoolChildDetaching && (c.Detach == nil || c.Detach.AcceptedAt.IsZero()) {
		return errors.New("detaching child lacks its original positive nonterminating detach result")
	}
	if c.Stage == PoolChildDetached || c.Stage == PoolChildTerminating || c.Stage == PoolChildRetired {
		if c.Detach == nil || c.Detach.AcceptedAt.IsZero() || c.Detach.WorkCompletedAt.IsZero() || c.DetachedAt.Before(c.Detach.WorkCompletedAt) || c.DetachedAt.After(updated) {
			return errors.New("pool child termination requires completed nonterminating detach and fresh exact removal")
		}
	}
	if c.Stage == PoolChildTerminating && c.Terminate == nil || c.Stage == PoolChildRetired && (c.Terminate == nil || c.InstanceRetiredAt.IsZero() || c.BootRetiredAt.IsZero()) {
		return errors.New("retired pool child lacks separate termination and positive terminal observations")
	}
	return nil
}

func capacityOCID(id, kind string) bool {
	return strings.HasPrefix(id, "ocid1."+kind+".") && len(id) <= 512 && !strings.ContainsAny(id, "\r\n\t ")
}

func (r *FoundationRecord) cloneCapacity() {
	if r.CapacityLedger != nil {
		r.CapacityLedger = new(r.CapacityLedger.Clone())
	}
	r.CapacityCreates = maps.Clone(r.CapacityCreates)
	r.CapacityPools = maps.Clone(r.CapacityPools)
	for id, pool := range r.CapacityPools {
		pool.Configurations = maps.Clone(pool.Configurations)
		r.CapacityPools[id] = pool
	}
	r.PoolChildren = maps.Clone(r.PoolChildren)
	for id, child := range r.PoolChildren {
		child.Launch, child.Attach, child.Detach = clonePoolWire(child.Launch), clonePoolWire(child.Attach), clonePoolWire(child.Detach)
		child.Terminate, child.DeleteBoot = clonePoolWire(child.Terminate), clonePoolWire(child.DeleteBoot)
		r.PoolChildren[id] = child
	}
	r.PoolQuarantines = maps.Clone(r.PoolQuarantines)
	for id, quarantine := range r.PoolQuarantines {
		quarantine.Detach = clonePoolWire(quarantine.Detach)
		r.PoolQuarantines[id] = quarantine
	}
}

func clonePoolWire(wire *PoolWireRecord) *PoolWireRecord {
	if wire == nil {
		return nil
	}
	return new(*wire)
}
