// Package autoscale evaluates authenticated member observations into durable,
// scaling targets. Provider creation remains owned by OCI reconcile.
package autoscale

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"math"
	"slices"
	"strings"
	"time"
)

var ErrUnavailable = errors.New("autoscale: observation source unavailable")
var ErrConflict = errors.New("autoscale: target compare-and-swap conflict")

type Observation struct {
	MemberSlot         int
	ProviderResourceID string
	ProviderGeneration uint64
	HostID             string
	EngineID           string
	Sequence           int64
	Incarnation        string
	ObservedAt         time.Time
	CPUPercent         float64
	MemoryPercent      float64
	QueueDepth         int
	QueueCapacity      int
	Healthy            bool
	Authenticated      bool
	Proof              ProofSnapshot
}

// ProofSnapshot carries only facts observed in the authenticated engine
// report. Missing producers remain false; consumers must fail closed.
type ProofSnapshot struct {
	Removal *RemovalProof

	HeadroomMeasured  bool
	ResidencyVerified bool
	QuorumVerified    bool
	Databases         []DatabaseProof
}

// RemovalProof is supplied by the lease-owned placement/provider producer.
// Empty telemetry alone never proves that a member has no assigned databases.
type RemovalMember struct {
	HostID, EngineID, ResourceID, Incarnation string
	Generation                                uint64
	Slot                                      int
}
type RemovalProof struct {
	ScopeID, HeadDigest, InventoryDigest, LeaseID string
	AuthorityEpoch                                uint64
	Member                                        RemovalMember
	Survivors                                     []RemovalMember
	NoAssignedData                                bool
}

type DatabaseProof struct {
	Tenant, Project, Database                     string
	RegionalCaughtUp                              bool
	CausalCaughtUp                                bool
	BackupCaughtUp                                bool
	SourceSequence, RegionalSequence              uint64
	BackupSourceSequence, BackupProtectedSequence uint64
}

type ObservationSource interface {
	Observe(context.Context, string) ([]Observation, error)
}

type CompletedRemoval struct {
	OperationID string
	ResourceID  string
}

type Target struct {
	CompletedRemovals      map[int]CompletedRemoval
	Region                 string
	Members                int
	ConsecutiveHighSamples int
	ConsecutiveLowSamples  int
	LastObservation        int64
	LastScaleAt            time.Time
	OperationID            string
	RemovalOperationID     string
	RemovalSlot            int
	RemovalResourceID      string
	RemovalHostID          string
	RemovalIncarnation     string
	RemovalPhase           string
	HostObservedAt         map[string]time.Time
	RetiredIncarnations    map[string]map[string]time.Time
	ActiveHosts            []string
	HostSequences          map[string]int64
	HostIncarnations       map[string]string
}

type TargetStore interface {
	Load(context.Context, string) (Target, bool, error)
	CompareAndSwap(context.Context, string, *Target, Target) error
}

type Authority interface {
	Check(context.Context) error
}

type RemovalOutcome string

const (
	RemovalPending   RemovalOutcome = "pending"
	RemovalCompleted RemovalOutcome = "completed"
	RemovalCancelled RemovalOutcome = "cancelled"
)

type Config struct {
	Source ObservationSource
	// RemovalOutcome must verify the exact durable removal journal operation.
	// Unknown provider outcomes must remain pending.
	RemovalOutcome    func(context.Context, Target) (RemovalOutcome, error)
	Targets           TargetStore
	Authority         Authority
	MinMembers        int
	MaxMembers        int
	CPUThreshold      float64
	MemoryThreshold   float64
	QueueThreshold    int
	HighSamples       int
	LowSamples        int
	Cooldown          time.Duration
	ObservationMaxAge time.Duration
	Now               func() time.Time
}

type Plan struct {
	Region             string
	PreviousMembers    int
	DesiredMembers     int
	ObservationSeq     int64
	OperationID        string
	RemovalSlot        int
	RemovalResourceID  string
	RemovalHostID      string
	RemovalIncarnation string
	RemovalPhase       string
}

type Controller struct {
	config Config
}

// Target returns the durable target for a Region. Production composition uses
// this on every reconcile tick so a restarted worker replays an already
// admitted target before waiting for a new observation or scale plan.
func (c *Controller) Target(ctx context.Context, region string) (Target, bool, error) {
	region = strings.ToLower(strings.TrimSpace(region))
	if c == nil || region == "" || region != strings.TrimSpace(region) {
		return Target{}, false, errors.New("autoscale: invalid region")
	}
	if err := c.config.Authority.Check(ctx); err != nil {
		return Target{}, false, err
	}
	return c.config.Targets.Load(ctx, region)
}

func New(config Config) (*Controller, error) {
	if config.Source == nil || config.Targets == nil || config.Authority == nil || config.Now == nil {
		return nil, errors.New("autoscale: incomplete configuration")
	}
	if config.LowSamples == 0 {
		config.LowSamples = 3
	}
	if config.MinMembers < 2 || config.MaxMembers < config.MinMembers || !(config.CPUThreshold > 0 && config.CPUThreshold <= 100) || !(config.MemoryThreshold > 0 && config.MemoryThreshold <= 100) || config.QueueThreshold < 0 || config.HighSamples <= 0 || config.LowSamples <= 0 || config.Cooldown < 0 || config.ObservationMaxAge <= 0 {
		return nil, errors.New("autoscale: invalid bounds")
	}
	return &Controller{config: config}, nil
}

// Evaluate records valid pressure and creates at most one target increment.
// Invalid, stale, contradictory, or unauthorized observations hold state.
func (c *Controller) Evaluate(ctx context.Context, region string) (Plan, bool, error) {
	region = strings.ToLower(strings.TrimSpace(region))
	if c == nil || region == "" || region != strings.TrimSpace(region) {
		return Plan{}, false, errors.New("autoscale: invalid region")
	}
	if err := ctx.Err(); err != nil {
		return Plan{}, false, err
	}
	if err := c.config.Authority.Check(ctx); err != nil {
		return Plan{}, false, err
	}
	// A retained removal is a durable handoff and must be replayable after a
	// restart even when telemetry is temporarily unavailable.
	retained, found, err := c.config.Targets.Load(ctx, region)
	if err != nil {
		return Plan{}, false, err
	}
	if found && retained.Region == region && retained.RemovalOperationID != "" {
		if c.config.RemovalOutcome == nil {
			return removalPlan(region, retained, retained.LastObservation), true, nil
		}
		outcome, err := c.config.RemovalOutcome(ctx, retained)
		if err != nil {
			return Plan{}, false, err
		}
		if outcome == RemovalPending {
			return removalPlan(region, retained, retained.LastObservation), true, nil
		}
		if outcome != RemovalCompleted && outcome != RemovalCancelled {
			return Plan{}, false, errors.New("autoscale: invalid removal outcome")
		}
		if retained.RemovalSlot != retained.Members+1 {
			return Plan{}, false, errors.New("autoscale: invalid retained removal capacity")
		}
		if err := c.config.Authority.Check(ctx); err != nil {
			return Plan{}, false, err
		}
		if err := ctx.Err(); err != nil {
			return Plan{}, false, err
		}
		next := retained
		if outcome == RemovalCancelled {
			// Restore capacity in the same CAS that clears this exact intent.
			// Cancellation never creates a receipt permitting slot reenrollment.
			next.Members = retained.RemovalSlot
			next.OperationID = ""
		} else {
			next.CompletedRemovals = maps.Clone(retained.CompletedRemovals)
			if next.CompletedRemovals == nil {
				next.CompletedRemovals = map[int]CompletedRemoval{}
			}
			next.CompletedRemovals[retained.RemovalSlot] = CompletedRemoval{OperationID: retained.RemovalOperationID, ResourceID: retained.RemovalResourceID}
		}
		next.RemovalOperationID, next.RemovalHostID, next.RemovalIncarnation, next.RemovalPhase = "", "", "", ""
		next.RemovalSlot, next.RemovalResourceID = 0, ""
		next.ConsecutiveHighSamples, next.ConsecutiveLowSamples = 0, 0
		next.LastScaleAt = c.config.Now().UTC()
		if err := c.config.Targets.CompareAndSwap(ctx, region, &retained, next); err != nil {
			if errors.Is(err, ErrConflict) {
				return Plan{}, false, nil
			}
			return Plan{}, false, err
		}
		if outcome == RemovalCancelled {
			return Plan{Region: region, PreviousMembers: retained.Members, DesiredMembers: next.Members, ObservationSeq: next.LastObservation}, true, nil
		}
	}
	observations, err := c.config.Source.Observe(ctx, region)
	if err != nil {
		if errors.Is(err, ErrUnavailable) {
			return Plan{}, false, nil
		}
		return Plan{}, false, err
	}
	now := c.config.Now().UTC()
	if !validObservations(observations, now, c.config.ObservationMaxAge) {
		return Plan{}, false, nil
	}
	if err := c.config.Authority.Check(ctx); err != nil {
		return Plan{}, false, err
	}
	state, found, err := c.config.Targets.Load(ctx, region)
	if err != nil {
		return Plan{}, false, err
	}
	if !found {
		state = Target{Region: region, Members: max(c.config.MinMembers, len(observations))}
	}
	if state.Region != region || state.Members < c.config.MinMembers || state.Members > c.config.MaxMembers {
		return Plan{}, false, nil
	}
	previousState := state
	advanced, bootChanged := observationsAdvance(observations, state, now)
	seq := latestObservationSequence(observations)
	if !advanced {
		if state.RemovalOperationID != "" {
			return removalPlan(region, state, seq), true, nil
		}
		return Plan{}, false, nil
	}
	active := slices.Sorted(maps.Keys(observationSequences(observations)))
	previousHosts := state.ActiveHosts
	if len(previousHosts) == 0 {
		previousHosts = slices.Sorted(maps.Keys(state.HostSequences))
	}
	membershipChanged := len(previousHosts) != 0 && !slices.Equal(active, previousHosts)
	state.ActiveHosts = active
	// Keep high-water marks for removed hosts so re-admission cannot replay
	// a previously consumed sample. Never mutate the loaded CAS expectation.
	state.HostSequences = maps.Clone(state.HostSequences)
	state.HostIncarnations = maps.Clone(state.HostIncarnations)
	state.HostObservedAt = maps.Clone(state.HostObservedAt)
	state.RetiredIncarnations = cloneRetiredIncarnations(state.RetiredIncarnations, now)
	if state.HostSequences == nil {
		state.HostSequences = map[string]int64{}
	}
	if state.HostIncarnations == nil {
		state.HostIncarnations = map[string]string{}
	}
	if state.HostObservedAt == nil {
		state.HostObservedAt = map[string]time.Time{}
	}
	for _, value := range observations {
		if previous := state.HostIncarnations[value.HostID]; previous != "" && previous != value.Incarnation {
			retired := state.RetiredIncarnations[value.HostID]
			if retired == nil {
				retired = map[string]time.Time{}
				state.RetiredIncarnations[value.HostID] = retired
			}
			// Reports from the retired boot were signed before this transition.
			// Once this window expires, their signed time is necessarily stale.
			retired[previous] = now.Add(c.config.ObservationMaxAge)
		}
		state.HostSequences[value.HostID] = value.Sequence
		state.HostIncarnations[value.HostID] = value.Incarnation
		state.HostObservedAt[value.HostID] = value.ObservedAt
	}
	// A retained removal intent is the single durable handoff to the drain
	// owner. Replays must return the same intent and never decrement again.
	if state.RemovalOperationID != "" {
		return removalPlan(region, state, seq), true, nil
	}
	// A changed admitted set or boot establishes a baseline; pressure must
	// then accumulate from fresh samples of that complete set and boot.
	high := !membershipChanged && !bootChanged && anyHigh(observations, c.config)
	low := !membershipChanged && !bootChanged && allLow(observations, c.config) && allRemovalProofs(observations)
	if high {
		state.ConsecutiveHighSamples++
	} else {
		state.ConsecutiveHighSamples = 0
	}
	if low {
		state.ConsecutiveLowSamples++
	} else {
		state.ConsecutiveLowSamples = 0
	}
	state.LastObservation = seq
	if low && state.ConsecutiveLowSamples >= c.config.LowSamples && state.Members > c.config.MinMembers && (state.LastScaleAt.IsZero() || !now.Before(state.LastScaleAt.Add(c.config.Cooldown))) {
		candidate, eligible := removalCandidate(observations, state.Members)
		if !eligible {
			return Plan{}, false, nil
		}
		state.Members--
		state.ConsecutiveLowSamples = 0
		state.LastScaleAt = now
		state.RemovalHostID, state.RemovalIncarnation = candidate.HostID, candidate.Incarnation
		state.RemovalSlot, state.RemovalResourceID = candidate.MemberSlot, candidate.ProviderResourceID
		state.RemovalPhase = "intent"
		state.RemovalOperationID = removalOperationID(region, candidate, state.Members, seq)
		if err := c.config.Authority.Check(ctx); err != nil {
			return Plan{}, false, err
		}
		if err := c.config.Targets.CompareAndSwap(ctx, region, targetExpected(found, previousState), state); err != nil {
			if errors.Is(err, ErrConflict) {
				_, _, _ = c.config.Targets.Load(ctx, region)
				return Plan{}, false, nil
			}
			return Plan{}, false, err
		}
		return Plan{Region: region, PreviousMembers: state.Members + 1, DesiredMembers: state.Members, ObservationSeq: seq,
			RemovalSlot: state.RemovalSlot, RemovalResourceID: state.RemovalResourceID, OperationID: state.RemovalOperationID, RemovalHostID: state.RemovalHostID,
			RemovalIncarnation: state.RemovalIncarnation, RemovalPhase: state.RemovalPhase}, true, nil
	}
	if !high || state.ConsecutiveHighSamples < c.config.HighSamples || state.Members >= c.config.MaxMembers || !state.LastScaleAt.IsZero() && now.Before(state.LastScaleAt.Add(c.config.Cooldown)) {
		if err := c.config.Authority.Check(ctx); err != nil {
			return Plan{}, false, err
		}
		if err := c.config.Targets.CompareAndSwap(ctx, region, targetExpected(found, previousState), state); err != nil {
			if errors.Is(err, ErrConflict) {
				_, _, _ = c.config.Targets.Load(ctx, region)
				return Plan{}, false, nil
			}
			return Plan{}, false, err
		}
		return Plan{}, false, nil
	}
	previous := state.Members
	state.Members++
	state.ConsecutiveHighSamples = 0
	state.LastScaleAt = now
	state.OperationID = operationID(region, previous, state.Members, seq)
	if err := c.config.Authority.Check(ctx); err != nil {
		return Plan{}, false, err
	}
	if err := c.config.Targets.CompareAndSwap(ctx, region, targetExpected(found, previousState), state); err != nil {
		if errors.Is(err, ErrConflict) {
			_, _, _ = c.config.Targets.Load(ctx, region)
			return Plan{}, false, nil
		}
		return Plan{}, false, err
	}
	return Plan{Region: region, PreviousMembers: previous, DesiredMembers: state.Members, ObservationSeq: seq, OperationID: state.OperationID}, true, nil
}

func removalPlan(region string, state Target, sequence int64) Plan {
	return Plan{Region: region, PreviousMembers: state.Members + 1, DesiredMembers: state.Members, ObservationSeq: sequence,
		RemovalSlot: state.RemovalSlot, RemovalResourceID: state.RemovalResourceID, OperationID: state.RemovalOperationID, RemovalHostID: state.RemovalHostID,
		RemovalIncarnation: state.RemovalIncarnation, RemovalPhase: state.RemovalPhase}
}

func targetExpected(found bool, state Target) *Target {
	if !found {
		return nil
	}
	// The caller loaded this exact value; stores compare all fields.
	previous := state
	return &previous
}

func validObservations(values []Observation, now time.Time, maxAge time.Duration) bool {
	if len(values) == 0 {
		return false
	}
	seenHosts, seenEngines := map[string]struct{}{}, map[string]struct{}{}
	for _, value := range values {
		if value.HostID == "" || value.EngineID == "" || value.Incarnation == "" || value.Sequence <= 0 || !value.Authenticated || !value.Healthy || value.ObservedAt.IsZero() || value.ObservedAt.After(now) || now.Sub(value.ObservedAt) > maxAge || value.CPUPercent < 0 || value.CPUPercent > 100 || value.MemoryPercent < 0 || value.MemoryPercent > 100 || value.QueueDepth < 0 || value.QueueCapacity < 0 || value.QueueCapacity == 0 && value.QueueDepth != 0 || value.QueueDepth > value.QueueCapacity || math.IsNaN(value.CPUPercent) || math.IsInf(value.CPUPercent, 0) || math.IsNaN(value.MemoryPercent) || math.IsInf(value.MemoryPercent, 0) {
			return false
		}
		if _, ok := seenHosts[value.HostID]; ok {
			return false
		}
		seenHosts[value.HostID] = struct{}{}
		if _, ok := seenEngines[value.EngineID]; ok {
			return false
		}
		seenEngines[value.EngineID] = struct{}{}
	}
	return true
}

func latestObservationSequence(values []Observation) int64 {
	var latest int64
	for _, value := range values {
		latest = max(latest, value.Sequence)
	}
	return latest
}

// The source authenticates current host reports, including their boot and
// observation time. An unseen boot can establish a baseline, but cannot count
// pressure immediately or revive a retired boot within the freshness window.
func observationsAdvance(values []Observation, state Target, now time.Time) (bool, bool) {
	bootChanged := false
	for _, value := range values {
		previous, known := state.HostSequences[value.HostID]
		if !known {
			continue
		}
		if state.HostIncarnations[value.HostID] != value.Incarnation {
			if expiry, retired := state.RetiredIncarnations[value.HostID][value.Incarnation]; retired && !now.After(expiry) {
				return false, false
			}
			if !value.ObservedAt.After(state.HostObservedAt[value.HostID]) {
				return false, false
			}
			bootChanged = true
		} else if value.Sequence <= previous || value.ObservedAt.Before(state.HostObservedAt[value.HostID]) {
			return false, false
		}
	}
	return true, bootChanged
}

func cloneRetiredIncarnations(previous map[string]map[string]time.Time, now time.Time) map[string]map[string]time.Time {
	result := make(map[string]map[string]time.Time)
	for host, boots := range previous {
		for boot, expiry := range boots {
			if !now.After(expiry) {
				if result[host] == nil {
					result[host] = make(map[string]time.Time)
				}
				result[host][boot] = expiry
			}
		}
	}
	return result
}

func observationSequences(values []Observation) map[string]int64 {
	result := make(map[string]int64, len(values))
	for _, value := range values {
		result[value.HostID] = value.Sequence
	}
	return result
}

// A single saturated resource or hot member can exhaust serving headroom.
// Requiring simultaneous pressure across resources and hosts hides bottlenecks.
// A zero queue threshold disables that optional signal.
func anyHigh(values []Observation, config Config) bool {
	return slices.ContainsFunc(values, func(value Observation) bool {
		return value.CPUPercent >= config.CPUThreshold || value.MemoryPercent >= config.MemoryThreshold || config.QueueThreshold > 0 && value.QueueCapacity > 0 && value.QueueDepth >= config.QueueThreshold
	})
}

func allLow(values []Observation, config Config) bool {
	return !anyHigh(values, config)
}

func allRemovalProofs(values []Observation) bool {
	for _, value := range values {
		if !value.Proof.HeadroomMeasured || !value.Proof.ResidencyVerified || !value.Proof.QuorumVerified || !validRemovalProof(value, values) {
			return false
		}
		for _, database := range value.Proof.Databases {
			if !database.RegionalCaughtUp || !database.CausalCaughtUp || !database.BackupCaughtUp || database.RegionalSequence < database.SourceSequence || database.BackupProtectedSequence < database.BackupSourceSequence {
				return false
			}
		}
	}
	return true
}

func validRemovalProof(value Observation, values []Observation) bool {
	proof := value.Proof.Removal
	if value.ProviderGeneration == 0 || proof == nil || proof.ScopeID == "" || proof.LeaseID == "" || proof.AuthorityEpoch == 0 || len(proof.HeadDigest) != 64 || len(proof.InventoryDigest) != 64 || proof.Member != removalMember(value) || len(proof.Survivors) != len(values)-1 || len(proof.Survivors) < 2 {
		return false
	}
	for _, other := range values {
		if other.Proof.Removal == nil || other.Proof.Removal.ScopeID != proof.ScopeID || other.Proof.Removal.HeadDigest != proof.HeadDigest || other.Proof.Removal.InventoryDigest != proof.InventoryDigest || other.Proof.Removal.AuthorityEpoch != proof.AuthorityEpoch || other.Proof.Removal.LeaseID != proof.LeaseID {
			return false
		}
	}
	if (len(value.Proof.Databases) == 0) != proof.NoAssignedData {
		return false
	}
	seen := map[string]bool{}
	for _, survivor := range proof.Survivors {
		if survivor.HostID == value.HostID || seen[survivor.HostID] || !slices.ContainsFunc(values, func(observed Observation) bool { return removalMember(observed) == survivor }) {
			return false
		}
		seen[survivor.HostID] = true
	}
	return true
}
func removalMember(value Observation) RemovalMember {
	return RemovalMember{HostID: value.HostID, EngineID: value.EngineID, ResourceID: value.ProviderResourceID, Incarnation: value.Incarnation, Generation: value.ProviderGeneration, Slot: value.MemberSlot}
}

// The provider pool consists of contiguous stable slots. A removal may only
// retire the highest slot from a complete, authoritatively bound member set.
func removalCandidate(values []Observation, members int) (Observation, bool) {
	if len(values) != members {
		return Observation{}, false
	}
	seen := make(map[int]bool, members)
	resources := make(map[string]bool, members)
	var candidate Observation
	for _, value := range values {
		if value.MemberSlot < 1 || value.MemberSlot > members || value.ProviderResourceID == "" || seen[value.MemberSlot] || resources[value.ProviderResourceID] {
			return Observation{}, false
		}
		seen[value.MemberSlot], resources[value.ProviderResourceID] = true, true
		if value.MemberSlot == members {
			candidate = value
		}
	}
	return candidate, candidate.MemberSlot == members
}

func operationID(region string, previous, next int, sequence int64) string {
	digest := sha256.Sum256([]byte(fmt.Sprintf("%s/%d/%d/%d", region, previous, next, sequence)))
	return "autoscale-" + hex.EncodeToString(digest[:16])
}

func removalOperationID(region string, candidate Observation, next int, sequence int64) string {
	digest := sha256.Sum256([]byte(fmt.Sprintf("%s/remove/%s/%s/%s/%d/%d", region, candidate.HostID, candidate.Incarnation, candidate.ProviderResourceID, next, sequence)))
	return "autoscale-remove-" + hex.EncodeToString(digest[:16])
}
