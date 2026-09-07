package main

import (
	"context"
	"errors"
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
		for _, report := range reports {
			engine := report.Facts.Engine
			metrics := report.Facts.Metrics
			if !validAutoscaleEngineFacts(engine, now) || report.State != hostagent.NodeStateServing || report.Quiesced || metrics.ObservationSequence <= 0 {
				return nil, autoscale.ErrUnavailable
			}
			result = append(result, autoscale.Observation{
				HostID: report.NodeId, EngineID: report.NodeId, Incarnation: metrics.BootGeneration, Sequence: metrics.ObservationSequence,
				ObservedAt: time.UnixMilli(metrics.ObservedAtUnixMS), CPUPercent: metrics.CPUPercent,
				MemoryPercent: metrics.MemoryPercent, QueueDepth: metrics.QueueDepth,
				QueueCapacity: metrics.QueueCapacity, Healthy: true, Authenticated: true,
				Proof: engineProofWithMetrics(metrics, engine),
			})
		}
		if s.proof != nil {
			proof, err := s.proof.Produce(ctx, region, result)
			if err != nil {
				return nil, err
			}
			for index := range result {
				result[index].Proof.ResidencyVerified = proof.ResidencyVerified
				result[index].Proof.QuorumVerified = proof.QuorumVerified
			}
		}
		if len(result) != len(entry.Members) {
			return nil, autoscale.ErrUnavailable
		}
		return result, nil
	}
	return nil, errors.New("autoscale: region is not admitted")
}

// autoscaleProofProducer adds the two region-wide facts that are outside a
// host's authority. Implementations must read the accepted placement catalog
// and live control-membership authority; nil callbacks fail closed.
type autoscaleProofProducer interface {
	Produce(context.Context, string, []autoscale.Observation) (autoscale.ProofSnapshot, error)
}

type productionAutoscaleProofProducer struct {
	residency func(context.Context, string, []autoscale.Observation) (bool, error)
	quorum    func(context.Context, string, []autoscale.Observation) (bool, error)
}

func (p productionAutoscaleProofProducer) Produce(ctx context.Context, region string, observations []autoscale.Observation) (autoscale.ProofSnapshot, error) {
	if p.residency == nil || p.quorum == nil || len(observations) == 0 {
		return autoscale.ProofSnapshot{}, autoscale.ErrUnavailable
	}
	for _, observation := range observations {
		if !observation.Authenticated || len(observation.Proof.Databases) == 0 {
			return autoscale.ProofSnapshot{}, autoscale.ErrUnavailable
		}
		for _, database := range observation.Proof.Databases {
			if !database.RegionalCaughtUp || !database.CausalCaughtUp || !database.BackupCaughtUp || database.RegionalSequence < database.SourceSequence || database.BackupProtectedSequence < database.BackupSourceSequence {
				return autoscale.ProofSnapshot{}, autoscale.ErrUnavailable
			}
		}
	}
	residency, err := p.residency(ctx, region, observations)
	if err != nil {
		return autoscale.ProofSnapshot{}, err
	}
	quorum, err := p.quorum(ctx, region, observations)
	if err != nil {
		return autoscale.ProofSnapshot{}, err
	}
	return autoscale.ProofSnapshot{ResidencyVerified: residency, QuorumVerified: quorum}, nil
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
