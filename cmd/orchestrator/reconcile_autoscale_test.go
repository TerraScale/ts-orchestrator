package main

import (
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
)

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
