package main

import (
	"context"
	"errors"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/autoscale"
	"terrascale.tech/orchestrator/src/orchestrator/hostremoval"
)

func TestAutoscaleCancellationTombstoneSurvivesRestartWithoutCompletingDeletion(t *testing.T) {
	target := autoscale.Target{Region: "gru", Members: 2, RemovalOperationID: "cancelled", RemovalResourceID: "oci-original", RemovalHostID: "host", RemovalIncarnation: "boot", RemovalSlot: 3}
	journal := &runtimeRemovalJournal{found: true, record: hostremoval.Operation{OperationID: target.RemovalOperationID, ResourceID: target.RemovalResourceID, Stage: hostremoval.StageCancelled}}
	construct := func() *productionHostRemoval {
		return &productionHostRemoval{owner: &hostremoval.Owner{Journal: journal}, completed: func(context.Context, string) error {
			t.Fatal("cancelled reservation cannot release a completed deletion fence")
			return nil
		}}
	}
	for range 2 {
		outcome, err := construct().AutoscaleRemovalOutcome(t.Context(), target)
		if err != nil || outcome != autoscale.RemovalCancelled || journal.record.Stage != hostremoval.StageCancelled {
			t.Fatalf("terminal cancellation: %s %v %+v", outcome, err, journal.record)
		}
	}
	for _, dimension := range []string{"operation", "resource"} {
		t.Run(dimension, func(t *testing.T) {
			wrong := target
			if dimension == "operation" {
				wrong.RemovalOperationID = "new-operation"
			} else {
				wrong.RemovalResourceID = "oci-replacement"
			}
			if outcome, err := construct().AutoscaleRemovalOutcome(t.Context(), wrong); !errors.Is(err, hostremoval.ErrConflict) || outcome != autoscale.RemovalPending {
				t.Fatalf("wrong identity cancellation: %s %v", outcome, err)
			}
		})
	}
}
