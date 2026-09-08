package vmqual

import (
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/control/authority"
	"terrascale.tech/orchestrator/src/orchestrator/control/directory"
)

// InitialControlObservation is finite GRU admission evidence. Lease terms are
// election observations and never stand in for topology epochs or generations.
type InitialControlObservation struct {
	SourceHost       string                                   `json:"sourceHost"`
	GrantSHA256      map[string]string                        `json:"grantSha256"`
	ManifestSHA256   map[string]string                        `json:"manifestSha256"`
	RegionalLease    authority.RegionalAuthorityLeaseDocument `json:"regionalLease"`
	GlobalLease      authority.RegionalAuthorityLeaseDocument `json:"globalLease"`
	Membership       directory.RegionalRuntimeMember          `json:"membership"`
	RegionalRevision uint64                                   `json:"regionalRevision"`
	GlobalRevision   uint64                                   `json:"globalRevision"`
	ObservedAt       time.Time                                `json:"observedAt"`
	JournalPath      string                                   `json:"journalPath"`
}
