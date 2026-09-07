package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/autoscale"
	"terrascale.tech/orchestrator/src/orchestrator/estate"
	"terrascale.tech/orchestrator/src/orchestrator/hostremoval"
	"terrascale.tech/orchestrator/src/orchestrator/ocireconcile"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
)

type recordingAutoscaleRemoval struct {
	operation string
	calls     int
}

func (o *recordingAutoscaleRemoval) RemoveMember(_ context.Context, operation string, _ ocireconcile.ObservedMember, _ []ocireconcile.ObservedMember) error {
	o.operation = operation
	o.calls++
	return nil
}

func TestAutoscaleRemovalBindsCopiedComputeConfigToExactDurableIntent(t *testing.T) {
	target := autoscale.Target{Region: "gru", Members: 2, RemovalOperationID: "autoscale-original", RemovalHostID: "gru-3", RemovalIncarnation: "boot-3", RemovalSlot: 3, RemovalResourceID: "oci-original"}
	store := &runtimeAutoscaleTargets{target: target, found: true}
	controller, err := autoscale.New(autoscale.Config{Source: &runtimeAutoscaleSource{}, Targets: store, Authority: runtimeAutoscaleAuthority{}, MinMembers: 2, MaxMembers: 5, CPUThreshold: 80, MemoryThreshold: 80, HighSamples: 1, ObservationMaxAge: time.Minute, Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	original := productionGlobalWorkerConfig{ComputeRemovalOwner: &computeRemovalOwnerBinding{}}
	// Like the production ComputeApply closure, this observes the original
	// config while the worker constructor receives and binds a value copy.
	invoke := func(member ocireconcile.ObservedMember) error {
		return original.ComputeRemovalOwner.RemoveMember(t.Context(), "provider-generated", member, nil)
	}
	copyConfig := original
	owner := &recordingAutoscaleRemoval{}
	member := ocireconcile.ObservedMember{ID: "oci-original", Region: "gru", Index: 3}
	if err := invoke(member); err == nil {
		t.Fatal("unbound provider owner admitted removal")
	}
	copyConfig.ComputeRemovalOwner.Bind(&autoscaleRemovalOwner{controller: controller, owner: owner})
	for _, wrong := range []ocireconcile.ObservedMember{{ID: "oci-replacement", Region: "gru", Index: 3}, {ID: "oci-original", Region: "gru", Index: 2}} {
		if err := invoke(wrong); err == nil {
			t.Fatal("wrong removal identity accepted")
		}
	}
	if owner.calls != 0 {
		t.Fatal("wrong identity reached durable owner")
	}
	if err := invoke(member); err != nil {
		t.Fatal(err)
	}
	if owner.operation != target.RemovalOperationID || owner.calls != 1 {
		t.Fatalf("handoff lost durable identity: %+v", owner)
	}
}

func TestAutoscaleRemovalCompletionUsesJournalAcrossUnknownAndTerminalRestart(t *testing.T) {
	target := autoscale.Target{Region: "gru", Members: 2, RemovalOperationID: "autoscale-original", RemovalHostID: "gru-3", RemovalIncarnation: "boot-3", RemovalSlot: 3, RemovalResourceID: "oci-original"}
	member := ocireconcile.ObservedMember{ID: target.RemovalResourceID, ETag: "etag", CompartmentID: "compartment", Region: "gru", Index: 3, LifecycleState: "RUNNING"}
	gateway := &runtimeRemovalGateway{current: member}
	ownership := &runtimeRemovalOwnership{record: provider.ProviderOwnershipRecord{ResourceId: provider.ProviderResourceId{Value: member.ID}, CompartmentId: provider.ProviderCompartmentId{Value: member.CompartmentID}, CellId: provider.ProviderCellId{Value: "gru"}, Generation: provider.ProviderGeneration{Value: 7}, ServerIdentity: "spiffe://terrascale.tech/prod/member/original"}}
	journal := &runtimeRemovalJournal{}
	construct := func() *productionHostRemoval {
		return &productionHostRemoval{observeFn: newProductionDurableMemberObserver(ownership, gateway), terminateFn: newProductionOCITerminator(map[string]ocireconcile.ComputeGateway{"gru": gateway}), owner: &hostremoval.Owner{Journal: journal, Inventory: func(context.Context, hostremoval.RemovalRequest, []hostremoval.Replacement) (uint64, []hostremoval.Replacement, error) {
			return 1, nil, nil
		}, Replace: func(context.Context, hostremoval.Replacement) error { return nil }, Revalidate: func(context.Context, string, string, uint64) error { return nil }, Fence: func(context.Context, string, string, []hostremoval.Replacement) error { return nil }}}
	}
	if complete, err := construct().AutoscaleRemovalComplete(t.Context(), target); err != nil || complete {
		t.Fatalf("missing journal completed: %v %v", complete, err)
	}
	if err := construct().RemoveMember(t.Context(), target.RemovalOperationID, member, nil); err == nil {
		t.Fatal("lost acknowledgement hidden")
	}
	gateway.failure = errors.New("OCI inaccessible")
	if complete, err := construct().AutoscaleRemovalComplete(t.Context(), target); err == nil || complete {
		t.Fatalf("unknown completed: %v %v", complete, err)
	}
	if journal.record.Stage != hostremoval.StageFenced {
		t.Fatal("unknown terminal outcome advanced journal")
	}
	gateway.failure = nil
	// The gateway is terminal after its lost submission response. No ListMembers
	// observation is needed to resume the exact retained journal operation.
	if complete, err := construct().AutoscaleRemovalComplete(t.Context(), target); err != nil || !complete {
		t.Fatalf("terminal restart: %v %v", complete, err)
	}
	if journal.record.Stage != hostremoval.StageComplete || gateway.terminations != 1 {
		t.Fatalf("completion %+v calls=%d", journal.record, gateway.terminations)
	}
	wrong := target
	wrong.RemovalResourceID = "oci-replacement"
	if complete, err := construct().AutoscaleRemovalComplete(t.Context(), wrong); !errors.Is(err, hostremoval.ErrConflict) || complete {
		t.Fatalf("wrong incarnation completed: %v %v", complete, err)
	}
	gateway.failure = errors.New("provider unavailable after completion")
	if complete, err := construct().AutoscaleRemovalComplete(t.Context(), target); err != nil || !complete {
		t.Fatalf("durable completion lost: %v %v", complete, err)
	}
}

func TestEnrollmentTargetProjectionPreservesAdmittedScaleDown(t *testing.T) {
	region := estate.Region{Code: "gru"}
	region.Members.Count = 3
	projection := &productionEnrollmentProjection{targets: func(context.Context) (map[string]autoscale.Target, error) {
		return map[string]autoscale.Target{"gru": {Region: "gru", Members: 2, RemovalOperationID: "remove"}}, nil
	}}
	count, err := projection.TargetCount(t.Context(), region)
	if err != nil || count != 2 {
		t.Fatalf("durable scale-down was replaced by declared floor: %d %v", count, err)
	}
}
