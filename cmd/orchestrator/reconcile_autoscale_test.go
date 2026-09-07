package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/autoscale"
	"terrascale.tech/orchestrator/src/orchestrator/estate"
	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
	runtimeplan "terrascale.tech/orchestrator/src/orchestrator/runtime"
)

func TestObservedAutoscaleProofCarriesMeasuredHeadroomAndRejectsEngineGaps(t *testing.T) {
	path := filepath.Join(t.TempDir(), "health.json")
	write := func(engine hostagent.EngineFacts, metrics hostagent.HostMetrics, wantHeadroom bool) error {
		raw, err := json.Marshal(healthObservationConfig{Regions: []healthRegion{{Code: "gru", Latitude: new(0.0), Longitude: new(0.0), Members: []healthMember{{ID: "gru-1", Address: "198.51.100.1", Architecture: new(runtimeplan.HostArchitectureArm64)}}}}})
		if err != nil {
			return err
		}
		if err := os.WriteFile(path, raw, 0600); err != nil {
			return err
		}
		source := &observedKVHealthSource{spec: estate.Spec{Regions: []estate.Region{{Code: "gru"}}}, path: path, sample: func(context.Context, healthRegion) ([]hostagent.NodeStatusReport, error) {
			return []hostagent.NodeStatusReport{{NodeId: "gru-1", State: hostagent.NodeStateServing, Facts: hostagent.HostFacts{State: hostagent.NodeStateServing, Engine: engine, Metrics: metrics}}}, nil
		}}
		observations, err := source.Observe(t.Context(), "gru")
		if err != nil {
			return err
		}
		if len(observations) != 1 || observations[0].Proof.HeadroomMeasured != wantHeadroom {
			return errors.New("autoscale headroom proof mismatch")
		}
		return nil
	}
	now := time.Now()
	engine := hostagent.EngineFacts{Measured: true, Serving: true, ObservedAtUnixMS: now.UnixMilli(), CatchUpComplete: true, AssignmentRevision: "assignment-1", CatchUpObservedAtUnixMS: uint64(now.UnixMilli()), Databases: []hostagent.DatabaseCatchUpFacts{{Tenant: "tenant", Project: "project", Database: "db"}}}
	metrics := hostagent.HostMetrics{ObservationSequence: 1, BootGeneration: "boot-1", ObservedAtUnixMS: now.UnixMilli(), CapacityMeasured: true, CPUCount: 2, CPUBudgetMilli: 2000, AvailableMemoryBytes: 1, AvailableStorageBytes: 1}
	if err := write(engine, metrics, true); err != nil {
		t.Fatal(err)
	}
	invalidMetrics := metrics
	invalidMetrics.CapacityMeasured = false
	if err := write(engine, invalidMetrics, false); err != nil {
		t.Fatal(err)
	}
	stale := engine
	stale.ObservedAtUnixMS = now.Add(-time.Minute).UnixMilli()
	if err := write(stale, metrics, true); err == nil {
		t.Fatal("stale engine observation admitted")
	}
}

func TestEngineProofPreservesMeasuredCatchupAndFailsClosedOnMissingEvidence(t *testing.T) {
	proof := engineProof(hostagent.EngineFacts{Databases: []hostagent.DatabaseCatchUpFacts{
		{Tenant: "tenant", Project: "project", Database: "database", SourceSequence: 4, RegionalSequence: 4, RegionalMeasured: true, BackupSourceSequence: 3, BackupProtectedSequence: 3, BackupMeasured: true, BackupCaughtUp: true},
		{Tenant: "tenant", Project: "project", Database: "foreign", SourceSequence: 4, RegionalSequence: 3, RegionalMeasured: true, BackupSourceSequence: 3, BackupProtectedSequence: 3, BackupMeasured: true, BackupCaughtUp: true},
	}})
	if len(proof.Databases) != 2 || !proof.Databases[0].RegionalCaughtUp || !proof.Databases[0].BackupCaughtUp {
		t.Fatalf("measured proof = %+v", proof)
	}
	if proof.Databases[1].RegionalCaughtUp || !proof.Databases[1].BackupCaughtUp {
		t.Fatalf("invalid proof was accepted = %+v", proof.Databases[1])
	}
	if proof.HeadroomMeasured || proof.ResidencyVerified || proof.QuorumVerified {
		t.Fatal("unprovided scale-down evidence was fabricated")
	}
}

func TestProductionAutoscaleProofProducerRequiresBothAuthorities(t *testing.T) {
	observations := []autoscale.Observation{{HostID: "gru-1", Authenticated: true, Proof: autoscale.ProofSnapshot{Databases: []autoscale.DatabaseProof{{RegionalCaughtUp: true, CausalCaughtUp: true, BackupCaughtUp: true}}}}}
	producer := productionAutoscaleProofProducer{
		residency: func(context.Context, string, []autoscale.Observation) (bool, error) { return true, nil },
		quorum:    func(context.Context, string, []autoscale.Observation) (bool, error) { return true, nil },
	}
	proof, err := producer.Produce(t.Context(), "gru", observations)
	if err != nil || !proof.ResidencyVerified || !proof.QuorumVerified {
		t.Fatalf("proof = %+v, err = %v", proof, err)
	}
	producer.quorum = nil
	if _, err := producer.Produce(t.Context(), "gru", observations); !errors.Is(err, autoscale.ErrUnavailable) {
		t.Fatalf("missing quorum authority err = %v", err)
	}
}

func TestObservedAutoscaleProofProducerKeepsUnknownFactsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "health.json")
	now := time.Now()
	raw, err := json.Marshal(healthObservationConfig{Regions: []healthRegion{{Code: "gru", Latitude: new(0.0), Longitude: new(0.0), Members: []healthMember{{ID: "gru-1", Address: "198.51.100.1", Architecture: new(runtimeplan.HostArchitectureArm64)}}}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	engine := hostagent.EngineFacts{Measured: true, Serving: true, ObservedAtUnixMS: now.UnixMilli(), CatchUpComplete: true, AssignmentRevision: "assignment-1", CatchUpObservedAtUnixMS: uint64(now.UnixMilli()), Databases: []hostagent.DatabaseCatchUpFacts{{Tenant: "tenant", Project: "project", Database: "db", RegionalMeasured: true, CausalMeasured: true, CausalCaughtUp: true, BackupMeasured: true, BackupCaughtUp: true}}}
	metrics := hostagent.HostMetrics{ObservationSequence: 1, BootGeneration: "boot-1", ObservedAtUnixMS: now.UnixMilli(), CapacityMeasured: true, CPUCount: 2, CPUBudgetMilli: 2000, AvailableMemoryBytes: 1, AvailableStorageBytes: 1}
	source := &observedKVHealthSource{spec: estate.Spec{Regions: []estate.Region{{Code: "gru"}}}, path: path, sample: func(context.Context, healthRegion) ([]hostagent.NodeStatusReport, error) {
		return []hostagent.NodeStatusReport{{NodeId: "gru-1", State: hostagent.NodeStateServing, Facts: hostagent.HostFacts{State: hostagent.NodeStateServing, Engine: engine, Metrics: metrics}}}, nil
	}, proof: productionAutoscaleProofProducer{
		residency: func(context.Context, string, []autoscale.Observation) (bool, error) { return false, nil },
		quorum:    func(context.Context, string, []autoscale.Observation) (bool, error) { return true, nil },
	}}
	observations, err := source.Observe(t.Context(), "gru")
	if err != nil || len(observations) != 1 || observations[0].Proof.ResidencyVerified || !observations[0].Proof.QuorumVerified {
		t.Fatalf("observations = %+v, err = %v", observations, err)
	}
}
