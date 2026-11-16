package releasechannel

import (
	"time"
)

// A service release channel (TS-610) carries one release of a native role
// such as terrabase or ts-auth: CI uploads the binary under its digest and
// replaces release.json with the delivery artifact claim it signed with the
// role's scoped release key. The region's authority leader admits the claim
// and rolls the role out through the release gate; it reports in
// status.json, which CI polls.
const (
	ServiceStatusSchema = "terrascale.orchestrator.service-release-status"
	servicePrefix       = "releases/services/"
	// MaxServiceClaimBytes bounds release.json: one signed artifact claim.
	MaxServiceClaimBytes = 8 << 10
	// MaxServiceBinaryBytes bounds a service binary, the artifact store's
	// own bound.
	MaxServiceBinaryBytes = 512 << 20
)

// ClaimClockSkew bounds how far ahead of a reader's clock a claim may be
// issued. A leader refuses a claim issued later; a publisher never keeps
// one as the channel's ordering floor.
const ClaimClockSkew = 5 * time.Minute

// ServiceStatus is the region leader's report on a role's release: the
// release is the claim's digest and issuance instant.
type ServiceStatus struct {
	ReleaseSequence uint64               `json:"release_sequence,omitzero"`
	SourceRevision  string               `json:"source_revision,omitempty"`
	Schema          string               `json:"schema"`
	Cell            string               `json:"cell"`
	Role            string               `json:"role"`
	Digest          string               `json:"digest"`
	IssuedAt        time.Time            `json:"issued_at"`
	State           State                `json:"state"`
	Reason          string               `json:"reason,omitempty"`
	UpdatedAt       time.Time            `json:"updated_at"`
	Pins            *ReleasePins         `json:"pins,omitempty"`
	Replicas        []ReplicaObservation `json:"replicas,omitempty"`
}

type ReplicaObservation struct {
	Node          string    `json:"node"`
	RunningDigest string    `json:"running_digest,omitempty"`
	State         string    `json:"state"`
	ObservedAt    time.Time `json:"observed_at"`
}
