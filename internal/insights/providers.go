package insights

import (
	"context"
	"time"
)

// The optional providers below are owned by slices that are being built in
// parallel. Each has a small value type with only what a rule needs. A nil
// provider keeps its rules silent; a provider error is reported in
// Evaluation.Unavailable and also keeps them silent.

// RolloutProvider lists rollouts with their deadlines (rollout slice).
type RolloutProvider interface {
	Rollouts(ctx context.Context) ([]Rollout, error)
}

// Rollout is one release rollout as the rollout slice sees it.
type Rollout struct {
	ID      string `json:"id"`
	Release string `json:"release"`
	// Phase is the rollout state machine's phase: pending, preflight,
	// canary, canary-soak, batch, batch-soak, complete, rolling-back,
	// frozen, aborted or rolled-back.
	Phase string `json:"phase"`
	// PhaseStarted is when the current phase began and PhaseDeadline when
	// it should have ended; a zero deadline means none.
	PhaseStarted  time.Time `json:"phase_started"`
	PhaseDeadline time.Time `json:"phase_deadline,omitzero"`
	Done          bool      `json:"done"`
}

// VolumeProvider lists block volumes and their attachment state (storage
// slice).
type VolumeProvider interface {
	Volumes(ctx context.Context) ([]Volume, error)
}

// Volume is one block volume.
type Volume struct {
	ID   string `json:"id"`
	Host string `json:"host,omitempty"`
	// State is attached, available, attaching or detaching.
	State string `json:"state"`
	// Detail optionally names the provider's own finer state, for example
	// the placement stage behind an attached volume.
	Detail string `json:"detail,omitempty"`
	// StateSince is when the volume entered State.
	StateSince time.Time `json:"state_since"`
}

// CertificateProvider lists certificates and signing delegations that
// expire (trust and natscell slices).
type CertificateProvider interface {
	Certificates(ctx context.Context) ([]Certificate, error)
}

// Certificate is one expiring credential.
type Certificate struct {
	Name string `json:"name"`
	// Kind is tls, delegation, nats-jwt or netbird-setup-key.
	Kind     string    `json:"kind"`
	NotAfter time.Time `json:"not_after"`
}

// NetBirdProvider lists NetBird peers of the region (netbird slice).
type NetBirdProvider interface {
	Peers(ctx context.Context) ([]NetBirdPeer, error)
}

// NetBirdPeer is one overlay peer.
type NetBirdPeer struct {
	Name      string    `json:"name"`
	Connected bool      `json:"connected"`
	Relayed   bool      `json:"relayed"`
	LastSeen  time.Time `json:"last_seen,omitzero"`
}

// AutoscalerProvider lists autoscaled targets (autoscale slice).
type AutoscalerProvider interface {
	Autoscalers(ctx context.Context) ([]Autoscaler, error)
}

// Autoscaler is one autoscaled target.
type Autoscaler struct {
	Name    string `json:"name"`
	Current int    `json:"current"`
	Max     int    `json:"max"`
	// AtMaxSince is when Current reached Max; zero when below.
	AtMaxSince time.Time `json:"at_max_since,omitzero"`
}

// BudgetProvider lists spending or quota budgets.
type BudgetProvider interface {
	Budgets(ctx context.Context) ([]Budget, error)
}

// Budget is one ceiling and its use.
type Budget struct {
	Name    string  `json:"name"`
	Used    float64 `json:"used"`
	Ceiling float64 `json:"ceiling"`
	Unit    string  `json:"unit,omitempty"`
}

// ReachabilityProvider reports which other regions answer (regionview).
type ReachabilityProvider interface {
	Reachability(ctx context.Context) []RegionReach
}

// RegionReach is one region's reachability from this member.
type RegionReach struct {
	Region string `json:"region"`
	// State is ok, unreachable, error or not_linked; only a linked region
	// that stops answering raises an insight.
	State    string    `json:"state"`
	LastSeen time.Time `json:"last_seen,omitzero"`
	WAN      string    `json:"wan,omitempty"`
	Detail   string    `json:"detail,omitempty"`
}

// HoldProvider reports placement holds currently being re-asserted by the
// reconciler (placement slice, through the app wiring).
type HoldProvider interface {
	Holds(now time.Time) []Hold
}

// Hold is one active placement hold.
type Hold struct {
	Reason    string    `json:"reason"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// OCIResourceProvider supplies the declarative OCI reconcile's last
// observation of every desired resource in the region.
type OCIResourceProvider interface {
	OCIResources(ctx context.Context) ([]OCIResource, error)
}

// OCIResource is one desired OCI resource as the reconcile last saw it.
type OCIResource struct {
	// Key is <CELL>/<kind>/<name>.
	Key  string `json:"key"`
	Kind string `json:"kind"`
	// Policy is enforce or report.
	Policy  string `json:"policy"`
	Found   bool   `json:"found"`
	InSync  bool   `json:"in_sync"`
	Foreign bool   `json:"foreign,omitempty"`
	// Applied is set when this observation's pass applied a change; its
	// drift is what was just corrected, not evidence of drift.
	Applied bool `json:"applied,omitempty"`
	// Drift lists the pending changes, one "<op> <detail>" each.
	Drift      []string  `json:"drift,omitempty"`
	Error      string    `json:"error,omitempty"`
	ObservedAt time.Time `json:"observed_at"`
}
