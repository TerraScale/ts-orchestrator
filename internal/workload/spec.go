// Package workload owns the desired state of generic regional services: the
// operator-signed ServiceSpec, the observation of committed host allocations
// and a level-triggered reconciler that keeps the replica set converged and
// applies autoscaling decisions. Artifact admission and release intents stay
// in internal/delivery; TerraBase member lifecycle stays in internal/placement.
package workload

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/TerraScale/ts-orchestrator/internal/autoscale"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
)

var (
	ErrInvalidSpec = errors.New("invalid workload service spec")
	nameRE         = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
)

// Kind separates replaceable stateless replicas from members that own data.
type Kind string

const (
	KindStateless Kind = "stateless"
	KindStateful  Kind = "stateful"
)

// ReplicaBounds are the operator-signed replica limits. The first release of
// a service without running replicas starts at its intent's replica count,
// clamped to these bounds; later releases keep the current scale.
type ReplicaBounds struct {
	Min int `json:"min"`
	Max int `json:"max"`
}

func (b ReplicaBounds) bounds() autoscale.Bounds { return autoscale.Bounds{Min: b.Min, Max: b.Max} }

// Constraints are hard placement rules checked after the solver chooses hosts.
// NodePool names the capacity pool asked for more hosts when placement lacks
// capacity. MaxPerFailureDomain of zero disables the per-domain cap.
type Constraints struct {
	NodePool            string `json:"node_pool,omitempty"`
	MaxPerFailureDomain int    `json:"max_per_failure_domain,omitzero"`
}

// Rollout bounds how much one reconciliation step may change. MaxSurge is the
// number of new replicas started per step and MaxUnavailable the number of
// ready replicas withdrawn per step; zero means one.
type Rollout struct {
	MaxSurge       int `json:"max_surge,omitzero"`
	MaxUnavailable int `json:"max_unavailable,omitzero"`
}

func (r Rollout) surge() int       { return max(r.MaxSurge, 1) }
func (r Rollout) unavailable() int { return max(r.MaxUnavailable, 1) }

// VolumeRetention decides what happens to a retired stateful member's volume.
type VolumeRetention string

const (
	// RetainVolume keeps the detached volume for an explicit later decision.
	RetainVolume VolumeRetention = "retain"
)

// StatefulPolicy constrains topology changes of data-owning members. Today it
// only gates TerraBase scale-in; see StatefulScaleDown.
type StatefulPolicy struct {
	QuorumFloorPerRegion int             `json:"quorum_floor_per_region"`
	MaxConcurrentChanges int             `json:"max_concurrent_changes"`
	DrainTimeoutSeconds  int             `json:"drain_timeout_seconds"`
	MaxLagForScaleDown   uint64          `json:"max_lag_for_scale_down"`
	VolumeRetention      VolumeRetention `json:"volume_retention"`
}

// MinQuorumFloor matches placement's retirement topology floor: two serving
// members on distinct failure domains in every region.
const MinQuorumFloor = 2

func (p StatefulPolicy) validate() error {
	if p.QuorumFloorPerRegion < MinQuorumFloor || p.QuorumFloorPerRegion > autoscale.MaxReplicas {
		return fmt.Errorf("%w: quorum floor must be at least %d", ErrInvalidSpec, MinQuorumFloor)
	}
	// Placement performs one persisted member transition per tick; concurrent
	// topology changes would race its retirement evidence.
	if p.MaxConcurrentChanges != 1 {
		return fmt.Errorf("%w: stateful services allow exactly one concurrent topology change", ErrInvalidSpec)
	}
	if p.DrainTimeoutSeconds <= 0 || p.DrainTimeoutSeconds > 24*60*60 {
		return fmt.Errorf("%w: drain timeout must be within 1..86400 seconds", ErrInvalidSpec)
	}
	// Lag is a sequence-count difference: zero would demand perfectly
	// caught-up replicas and silently block every scale-down.
	if p.MaxLagForScaleDown == 0 {
		return fmt.Errorf("%w: max lag for scale down must be positive", ErrInvalidSpec)
	}
	if p.VolumeRetention != RetainVolume {
		return fmt.Errorf("%w: only retained volumes are supported", ErrInvalidSpec)
	}
	return nil
}

// ServiceSpec is the operator-signed desired shape of one regional service.
// Resources of zero inherit the controller's signed workload profile.
type ServiceSpec struct {
	Role        string              `json:"role"`
	Environment string              `json:"environment"`
	Kind        Kind                `json:"kind"`
	Replicas    ReplicaBounds       `json:"replicas"`
	Resources   placement.Resources `json:"resources,omitzero"`
	Placement   Constraints         `json:"placement,omitzero"`
	Rollout     Rollout             `json:"rollout,omitzero"`
	Scaling     *autoscale.Policy   `json:"scaling,omitempty"`
	Stateful    *StatefulPolicy     `json:"stateful,omitempty"`
}

// Validate checks the spec in isolation.
func (s ServiceSpec) Validate() error {
	if !nameRE.MatchString(s.Role) || !nameRE.MatchString(s.Environment) {
		return fmt.Errorf("%w: role or environment", ErrInvalidSpec)
	}
	if err := s.Replicas.bounds().Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidSpec, err)
	}
	if s.Resources != (placement.Resources{}) &&
		(s.Resources.CPU <= 0 || s.Resources.MemoryBytes <= 0 || s.Resources.DiskBytes <= 0) {
		return fmt.Errorf("%w: resources must be all positive or inherited", ErrInvalidSpec)
	}
	if s.Placement.NodePool != "" && !nameRE.MatchString(s.Placement.NodePool) ||
		s.Placement.MaxPerFailureDomain < 0 || s.Placement.MaxPerFailureDomain > autoscale.MaxReplicas {
		return fmt.Errorf("%w: placement constraints", ErrInvalidSpec)
	}
	if s.Rollout.MaxSurge < 0 || s.Rollout.MaxSurge > autoscale.MaxReplicas ||
		s.Rollout.MaxUnavailable < 0 || s.Rollout.MaxUnavailable > autoscale.MaxReplicas {
		return fmt.Errorf("%w: rollout limits", ErrInvalidSpec)
	}
	if s.Scaling != nil {
		if err := s.Scaling.Validate(); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidSpec, err)
		}
	}
	switch s.Kind {
	case KindStateless:
		if s.Stateful != nil {
			return fmt.Errorf("%w: stateless service has a stateful policy", ErrInvalidSpec)
		}
	case KindStateful:
		if s.Stateful == nil {
			return fmt.Errorf("%w: stateful service lacks a stateful policy", ErrInvalidSpec)
		}
		if err := s.Stateful.validate(); err != nil {
			return err
		}
		if s.Replicas.Min < s.Stateful.QuorumFloorPerRegion {
			return fmt.Errorf("%w: minimum replicas below the quorum floor", ErrInvalidSpec)
		}
	default:
		return fmt.Errorf("%w: unknown kind %q", ErrInvalidSpec, s.Kind)
	}
	return nil
}

// ValidateSpecs checks a spec set and rejects two specs for one role.
func ValidateSpecs(specs []ServiceSpec) error {
	seen := make(map[string]struct{}, len(specs))
	for _, spec := range specs {
		if err := spec.Validate(); err != nil {
			return fmt.Errorf("service %q: %w", spec.Role, err)
		}
		if _, exists := seen[spec.Role]; exists {
			return fmt.Errorf("%w: repeated role %q", ErrInvalidSpec, spec.Role)
		}
		seen[spec.Role] = struct{}{}
	}
	return nil
}
