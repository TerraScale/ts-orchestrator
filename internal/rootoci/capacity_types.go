package rootoci

import (
	"context"
	"time"
)

// Pool requests select existing authority. The root derives provider payloads,
// original reservations and lifecycle evidence independently of these fields.
type Pool interface {
	AdvancePoolChild(context.Context, Call, PoolChildExpectation) (PoolChildView, error)
	RetirePoolChild(context.Context, Call, PoolRetirementExpectation) (PoolRetirementView, error)
	QuarantinePoolChild(context.Context, Call, PoolQuarantineExpectation) (PoolQuarantineView, error)
	ObservePoolChild(context.Context, Call, PoolChildObservation) (PoolChildView, error)
}

type PoolChildExpectation struct {
	Cell          string `json:"cell"`
	OperationID   string `json:"operation_id"`
	ReservationID string `json:"reservation_id"`
	RecipeSHA256  string `json:"recipe_sha256"`
	// Public recipe selectors are independently checked against the signed source.
	PublicCAPEM         []byte   `json:"public_ca_pem"`
	AvailabilityDomains []string `json:"availability_domains"`
	PoolID              string   `json:"pool_id,omitempty"`
	ConfigurationID     string   `json:"configuration_id,omitempty"`
	GrantSHA256         string   `json:"grant_sha256"`
	Generation          uint64   `json:"generation"`
	Epoch               uint64   `json:"epoch"`
}

type PoolRetirementExpectation struct {
	Child              PoolChildExpectation `json:"child"`
	InstanceID         string               `json:"instance_id"`
	RemovalOperationID string               `json:"removal_operation_id"`
	DrainSHA256        string               `json:"drain_sha256"`
}

type PoolQuarantineExpectation struct {
	Cell          string `json:"cell"`
	PoolID        string `json:"pool_id"`
	InstanceID    string `json:"instance_id"`
	OperationID   string `json:"operation_id"`
	PurposeSHA256 string `json:"purpose_sha256"`
	GrantSHA256   string `json:"grant_sha256"`
	Generation    uint64 `json:"generation"`
	Epoch         uint64 `json:"epoch"`
}

type PoolChildObservation struct {
	Cell            string `json:"cell"`
	InstanceID      string `json:"instance_id"`
	OperationID     string `json:"operation_id,omitempty"`
	RecipeSHA256    string `json:"recipe_sha256,omitempty"`
	PoolID          string `json:"pool_id,omitempty"`
	ConfigurationID string `json:"configuration_id,omitempty"`
	GrantSHA256     string `json:"grant_sha256,omitempty"`
	Generation      uint64 `json:"generation,omitzero"`
}

// PoolChildView is descriptive. Only the concrete authenticated root client
// can turn a current admission response into an opaque VerifiedPoolChild.
type PoolChildView struct {
	Cell                 string    `json:"cell"`
	Stage                string    `json:"stage"`
	OperationID          string    `json:"operation_id"`
	ReservationID        string    `json:"reservation_id"`
	InstanceID           string    `json:"instance_id,omitempty"`
	PoolID               string    `json:"pool_id"`
	ConfigurationID      string    `json:"configuration_id"`
	BootVolumeIDs        []string  `json:"boot_volume_ids,omitempty"`
	RecipeSHA256         string    `json:"recipe_sha256"`
	GrantSHA256          string    `json:"grant_sha256"`
	ProfileSHA256        string    `json:"profile_sha256"`
	SourceSHA256         string    `json:"source_sha256"`
	SlotID               string    `json:"slot_id"`
	BirthSHA256          string    `json:"birth_sha256"`
	AttachSHA256         string    `json:"attach_sha256,omitempty"`
	SessionBindingSHA256 string    `json:"session_binding_sha256"`
	Generation           uint64    `json:"generation"`
	Epoch                uint64    `json:"epoch"`
	Node                 string    `json:"node,omitempty"`
	PrivateIP            string    `json:"private_ip,omitempty"`
	CompartmentID        string    `json:"compartment_id"`
	AvailabilityDomain   string    `json:"availability_domain"`
	FaultDomain          string    `json:"fault_domain"`
	ImageID              string    `json:"image_id"`
	Shape                string    `json:"shape"`
	OCPUs                float32   `json:"ocpus"`
	MemoryGB             float32   `json:"memory_gb"`
	BootGB               int64     `json:"boot_gb"`
	Role                 string    `json:"role"`
	Architecture         string    `json:"architecture"`
	Descriptor           string    `json:"descriptor,omitempty"`
	ObservedAt           time.Time `json:"observed_at"`
	ExpiresAt            time.Time `json:"expires_at"`
	OriginalDeadline     time.Time `json:"original_deadline"`
}

type PoolRetirementView struct {
	Cell               string   `json:"cell"`
	InstanceID         string   `json:"instance_id"`
	RemovalOperationID string   `json:"removal_operation_id"`
	Stage              string   `json:"stage"`
	BootVolumeIDs      []string `json:"boot_volume_ids"`
	RecordSHA256       string   `json:"record_sha256"`
}

type PoolQuarantineView struct {
	Cell         string `json:"cell"`
	PoolID       string `json:"pool_id"`
	InstanceID   string `json:"instance_id"`
	OperationID  string `json:"operation_id"`
	Stage        string `json:"stage"`
	RecordSHA256 string `json:"record_sha256"`
}
