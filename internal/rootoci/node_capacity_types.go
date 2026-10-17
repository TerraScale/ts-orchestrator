package rootoci

import "time"

// NodeCapacityObservation is descriptive current provider evidence. It grants
// neither a purchase nor accounting completeness, and cannot replace a birth.
type NodeCapacityObservation struct {
	Cell, OCIRegion, GrantSHA256, WorkerCompartmentID string
	Generation                                        uint64
	ObservedAt, ExpiresAt                             time.Time
	Pools                                             []NodePoolObservation
	Candidates                                        []NodeCandidateObservation
	Pending                                           []string
}

type NodePoolObservation struct {
	ID, Name, ConfigurationID, LifecycleState string
	Role, Architecture, Shape                 string
	Size                                      int
	Legacy                                    bool
	Configuration                             *NodeConfigurationObservation
	Members                                   []NodeMemberObservation
	Pending                                   []string
}

type NodeConfigurationObservation struct {
	ID, Name, Shape, ImageID string
	OCPUs, MemoryGB          *float32
	BootGB                   *int64
	LegacyIMDSDisabled       *bool
}

type NodeMemberObservation struct {
	ID, Name, State, PrivateIP, AvailabilityDomain, FaultDomain string
	Created                                                     time.Time
	LegacyIMDSDisabled                                          *bool
}

type NodeCandidateObservation struct {
	Role, Architecture, Shape, ImageID, ImageSHA256, AvailabilityDomain string
	OCPUs, MemoryGB                                                     float32
	BootGB                                                              int
	ExpiresAt                                                           time.Time
	Quotas                                                              []NodeQuotaObservation
	AvailableCount                                                      int64
}

type NodeQuotaObservation struct {
	Name, Scope         string
	Required, Available float64
}

// NodeProbeRegionObservation is the finite OCI region catalog for RTT probes.
// These names authorize no deployment or resource access.
type NodeProbeRegionObservation struct {
	Cell, OCIRegion, GrantSHA256 string
	ObservedAt, ExpiresAt        time.Time
	Regions                      []string
}
