package main

import (
	"context"
	"errors"
	"slices"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/autoscale"
	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
)

// Observe implements the autoscale observation boundary over the same
// authenticated host reports used by regional health. Resource pressure is
// never inferred from health or disk facts; reports without the typed metrics
// are unavailable and therefore hold the durable target.
func (s *observedKVHealthSource) Observe(ctx context.Context, region string) ([]autoscale.Observation, error) {
	if s == nil || ctx == nil || region == "" {
		return nil, autoscale.ErrUnavailable
	}
	config, err := s.configuration()
	if err != nil {
		return nil, err
	}
	for _, entry := range config.Regions {
		if entry.Code != region {
			continue
		}
		reports, err := s.sample(ctx, entry)
		if err != nil {
			return nil, err
		}
		result := make([]autoscale.Observation, 0, len(reports))
		now := time.Now()
		seen := map[string]bool{}
		for _, report := range reports {
			if seen[report.NodeId] || !slices.ContainsFunc(entry.Members, func(member healthMember) bool { return member.ID == report.NodeId }) {
				return nil, autoscale.ErrUnavailable
			}
			seen[report.NodeId] = true
			engine := report.Facts.Engine
			metrics := report.Facts.Metrics
			if !validAutoscaleEngineFacts(engine, now) || report.State != hostagent.NodeStateServing || report.Quiesced || metrics.ObservationSequence <= 0 {
				return nil, autoscale.ErrUnavailable
			}
			result = append(result, autoscale.Observation{
				HostID: report.NodeId, Incarnation: metrics.BootGeneration, Sequence: metrics.ObservationSequence,
				ObservedAt: time.UnixMilli(metrics.ObservedAtUnixMS), CPUPercent: metrics.CPUPercent,
				MemoryPercent: metrics.MemoryPercent, QueueDepth: metrics.QueueDepth,
				QueueCapacity: metrics.QueueCapacity, Healthy: true, Authenticated: true,
				Proof: engineProofWithMetrics(metrics, engine),
			})
		}
		if len(result) != len(entry.Members) {
			return nil, autoscale.ErrUnavailable
		}
		return result, nil
	}
	return nil, errors.New("autoscale: region is not admitted")
}

// validAutoscaleEngineFacts admits only a complete, fresh engine observation
// into the autoscale stream. The authenticated transport is the authority for
// the report; these checks ensure a delayed or incomplete report cannot be
// turned into a scale-down proof by the adapter.
func validAutoscaleEngineFacts(engine hostagent.EngineFacts, now time.Time) bool {
	if !engine.Measured || !engine.Serving || engine.Draining || engine.ObservedAtUnixMS <= 0 {
		return false
	}
	observed := time.UnixMilli(engine.ObservedAtUnixMS)
	if observed.After(now.Add(time.Second)) || now.Sub(observed) > 30*time.Second {
		return false
	}
	// An empty report grants no catch-up or removal authority. The production
	// proof producer must independently prove the exact member has no assignments.
	if len(engine.Databases) == 0 {
		return true
	}
	if !engine.CatchUpComplete || engine.AssignmentRevision == "" || engine.CatchUpObservedAtUnixMS == 0 || len(engine.Databases) == 0 || len(engine.Databases) > 4096 {
		return false
	}
	catchUpObserved := time.UnixMilli(int64(engine.CatchUpObservedAtUnixMS))
	if engine.CatchUpObservedAtUnixMS > uint64(now.Add(time.Second).UnixMilli()) || now.Sub(catchUpObserved) > 30*time.Second {
		return false
	}
	seen := make(map[string]bool, len(engine.Databases))
	for _, database := range engine.Databases {
		key := database.Tenant + "\x00" + database.Project + "\x00" + database.Database
		if database.Tenant == "" || database.Project == "" || database.Database == "" || seen[key] {
			return false
		}
		seen[key] = true
	}
	return true
}

func engineProof(engine hostagent.EngineFacts) autoscale.ProofSnapshot {
	return engineProofWithMetrics(hostagent.HostMetrics{}, engine)
}

func engineProofWithMetrics(metrics hostagent.HostMetrics, engine hostagent.EngineFacts) autoscale.ProofSnapshot {
	proof := autoscale.ProofSnapshot{HeadroomMeasured: metrics.HeadroomValid(), Databases: make([]autoscale.DatabaseProof, 0, len(engine.Databases))}
	for _, database := range engine.Databases {
		proof.Databases = append(proof.Databases, autoscale.DatabaseProof{
			Tenant: database.Tenant, Project: database.Project, Database: database.Database,
			RegionalCaughtUp: database.RegionalMeasured && database.RegionalSequence >= database.SourceSequence,
			CausalCaughtUp:   database.CausalMeasured && database.CausalCaughtUp,
			BackupCaughtUp:   database.BackupMeasured && database.BackupCaughtUp && database.BackupProtectedSequence >= database.BackupSourceSequence,
			SourceSequence:   database.SourceSequence, RegionalSequence: database.RegionalSequence,
			BackupSourceSequence: database.BackupSourceSequence, BackupProtectedSequence: database.BackupProtectedSequence,
		})
	}
	return proof
}
