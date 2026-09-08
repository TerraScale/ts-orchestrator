package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

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
