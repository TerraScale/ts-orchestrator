// Package autoscale evaluates authenticated member observations into durable,
// scale-out-only targets. Provider creation remains owned by OCI reconcile.
package autoscale

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
)

var ErrUnavailable = errors.New("autoscale: observation source unavailable")
var ErrConflict = errors.New("autoscale: target compare-and-swap conflict")

type Observation struct {
	HostID        string
	EngineID      string
	Sequence      int64
	ObservedAt    time.Time
	CPUPercent    float64
	MemoryPercent float64
	QueueDepth    int
	QueueCapacity int
	Healthy       bool
	Authenticated bool
}

type ObservationSource interface {
	Observe(context.Context, string) ([]Observation, error)
}

type Target struct {
	Region                 string
	Members                int
	ConsecutiveHighSamples int
	LastObservation        int64
	LastScaleAt            time.Time
	OperationID            string
}

type TargetStore interface {
	Load(context.Context, string) (Target, bool, error)
	CompareAndSwap(context.Context, string, *Target, Target) error
}

type Authority interface {
	Check(context.Context) error
}

type Config struct {
	Source            ObservationSource
	Targets           TargetStore
	Authority         Authority
	MinMembers        int
	MaxMembers        int
	CPUThreshold      float64
	MemoryThreshold   float64
	QueueThreshold    int
	HighSamples       int
	Cooldown          time.Duration
	ObservationMaxAge time.Duration
	Now               func() time.Time
}

type Plan struct {
	Region          string
	PreviousMembers int
	DesiredMembers  int
	ObservationSeq  int64
	OperationID     string
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
	if config.MinMembers < 2 || config.MaxMembers < config.MinMembers || config.CPUThreshold <= 0 || config.CPUThreshold > 100 || config.MemoryThreshold <= 0 || config.MemoryThreshold > 100 || config.QueueThreshold < 0 || config.HighSamples <= 0 || config.Cooldown < 0 || config.ObservationMaxAge <= 0 {
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
	if err := c.config.Authority.Check(ctx); err != nil {
		return Plan{}, false, err
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
	seq := latestObservationSequence(observations)
	if seq <= state.LastObservation {
		return Plan{}, false, nil
	}
	high := allHigh(observations, c.config)
	if high {
		state.ConsecutiveHighSamples++
	} else {
		state.ConsecutiveHighSamples = 0
	}
	state.LastObservation = seq
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
		if value.HostID == "" || value.EngineID == "" || value.Sequence <= 0 || !value.Authenticated || !value.Healthy || value.ObservedAt.IsZero() || value.ObservedAt.After(now) || now.Sub(value.ObservedAt) > maxAge || value.CPUPercent < 0 || value.CPUPercent > 100 || value.MemoryPercent < 0 || value.MemoryPercent > 100 || value.QueueDepth < 0 || value.QueueCapacity < 0 || value.QueueCapacity == 0 && value.QueueDepth != 0 || value.QueueDepth > value.QueueCapacity || math.IsNaN(value.CPUPercent) || math.IsInf(value.CPUPercent, 0) || math.IsNaN(value.MemoryPercent) || math.IsInf(value.MemoryPercent, 0) {
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

func allHigh(values []Observation, config Config) bool {
	for _, value := range values {
		if value.CPUPercent < config.CPUThreshold || value.MemoryPercent < config.MemoryThreshold || value.QueueCapacity > 0 && value.QueueDepth < config.QueueThreshold {
			return false
		}
	}
	return true
}

func operationID(region string, previous, next int, sequence int64) string {
	digest := sha256.Sum256([]byte(fmt.Sprintf("%s/%d/%d/%d", region, previous, next, sequence)))
	return "autoscale-" + hex.EncodeToString(digest[:16])
}
