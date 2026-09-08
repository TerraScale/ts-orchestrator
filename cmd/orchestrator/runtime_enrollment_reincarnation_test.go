package main

import (
	"context"
	"errors"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/autoscale"
	"terrascale.tech/orchestrator/src/orchestrator/enrollment"
	"terrascale.tech/orchestrator/src/orchestrator/hostremoval"
	"terrascale.tech/orchestrator/src/orchestrator/ocireconcile"
)

type runtimeRetirementEnrollment struct{ retired int }

func (s *runtimeRetirementEnrollment) Read(context.Context) (enrollment.State, error) {
	return enrollment.State{}, nil
}
func (s *runtimeRetirementEnrollment) Retire(context.Context, string, int, hostremoval.Operation) error {
	s.retired++
	return nil
}

func TestReenrollmentRequiresExactTerminalProviderAndCompleteRemoval(t *testing.T) {
	for _, scenario := range []string{"terminal", "pending removal", "running", "not found", "wrong resource", "wrong region", "wrong slot", "missing etag"} {
		t.Run(scenario, func(t *testing.T) {
			completed := autoscale.CompletedRemoval{OperationID: "remove", ResourceID: "ocid1.instance.original"}
			journal := &runtimeRetirementEnrollment{}
			removals := &runtimeRemovalJournal{found: true, record: hostremoval.Operation{OperationID: completed.OperationID, ResourceID: completed.ResourceID, Stage: hostremoval.StageComplete}}
			gateway := &runtimeRemovalGateway{current: ocireconcile.ObservedMember{ID: completed.ResourceID, ETag: "terminal-etag", LifecycleState: "RUNNING"}, terminal: true}
			switch scenario {
			case "pending removal":
				removals.record.Stage = hostremoval.StageFenced
			case "running":
				gateway.terminal = false
			case "not found":
				gateway.failure = errors.New("OCI 404: unauthorized or not found")
			case "wrong resource":
				gateway.current.ID = "ocid1.instance.foreign"
			case "wrong region":
				gateway.current.Region = "sfo"
			case "wrong slot":
				gateway.current.Index = 2
			case "missing etag":
				gateway.current.ETag = ""
			}
			projection := &productionEnrollmentProjection{journal: journal, removals: removals, gateways: map[string]ocireconcile.ComputeGateway{"gru": gateway}}
			err := projection.prepareReenrollment(t.Context(), "gru", 3, completed)
			if scenario == "terminal" {
				if err != nil || journal.retired != 1 {
					t.Fatalf("terminal: %v, retired=%d", err, journal.retired)
				}
				return
			}
			if err == nil || journal.retired != 0 {
				t.Fatalf("unsafe %s accepted: %v, retired=%d", scenario, err, journal.retired)
			}
		})
	}
}
