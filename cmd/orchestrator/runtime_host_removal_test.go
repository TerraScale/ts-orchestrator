package main

import (
	"context"
	"errors"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/hostremoval"
	"terrascale.tech/orchestrator/src/orchestrator/ocireconcile"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
)

func TestRemovalRuntimeBindsSPIFFEToExactOCIResourcePerInvocation(t *testing.T) {
	first := ocireconcile.ObservedMember{ID: "ocid1.instance.first", Region: "gru", Index: 1}
	second := ocireconcile.ObservedMember{ID: "ocid1.instance.second", Region: "gru", Index: 2}
	observed := hostremoval.MemberObservation{Identity: "spiffe://terrascale.tech/prod/member/one", Region: "gru", Slot: 1, Generation: 4}
	var terminated string
	runtime := &productionHostRemoval{
		owner: &hostremoval.Owner{Terminate: func(_ context.Context, id string) error { terminated = id; return nil }},
		observeFn: func(_ context.Context, member ocireconcile.ObservedMember) (hostremoval.MemberObservation, error) {
			if member.ID != first.ID {
				t.Fatalf("wrong exact observation: %s", member.ID)
			}
			return observed, nil
		},
	}
	bound := runtime.ownerFor(first, observed)
	other := runtime.ownerFor(second, hostremoval.MemberObservation{Identity: "spiffe://terrascale.tech/prod/member/two", Generation: 4})
	if present, err := bound.Observe(t.Context(), observed.Identity); err != nil || !present {
		t.Fatalf("observation: %v", err)
	}
	if err := bound.Terminate(t.Context(), observed.Identity); err != nil || terminated != first.ID {
		t.Fatalf("termination resource=%s error=%v", terminated, err)
	}
	if err := other.Terminate(t.Context(), observed.Identity); !errors.Is(err, hostremoval.ErrConflict) {
		t.Fatalf("cross invocation identity accepted: %v", err)
	}
	observed.Generation++
	if _, err := bound.Observe(t.Context(), observed.Identity); !errors.Is(err, hostremoval.ErrConflict) {
		t.Fatalf("changed generation accepted: %v", err)
	}
}

type runtimeRemovalJournal struct {
	record hostremoval.Operation
	found  bool
}

func (j *runtimeRemovalJournal) Load(context.Context, string) (hostremoval.Operation, error) {
	if !j.found {
		return hostremoval.Operation{}, hostremoval.ErrMissing
	}
	return j.record, nil
}
func (j *runtimeRemovalJournal) Begin(_ context.Context, op string, m hostremoval.MemberObservation, generation, revision uint64, r []hostremoval.Replacement, s []hostremoval.MemberObservation) (hostremoval.Operation, error) {
	j.record = hostremoval.Operation{OperationID: op, ResourceID: m.ResourceID, MemberIdentity: m.Identity, Generation: generation, InventoryRevision: revision, Replacements: r, Survivors: s, Stage: hostremoval.StageInventoryCaptured}
	j.found = true
	return j.record, nil
}
func (j *runtimeRemovalJournal) Advance(_ context.Context, _ string, stage hostremoval.Stage) (hostremoval.Operation, error) {
	j.record.Stage = stage
	return j.record, nil
}

type runtimeRemovalGateway struct {
	ocireconcile.ComputeGateway
	current      ocireconcile.ObservedMember
	terminal     bool
	failure      error
	terminations int
}

func (g *runtimeRemovalGateway) ObserveMember(_ context.Context, id string) (ocireconcile.ObservedMember, error) {
	if id != g.current.ID {
		return ocireconcile.ObservedMember{}, errors.New("unknown resource")
	}
	if g.failure != nil {
		return ocireconcile.ObservedMember{}, g.failure
	}
	if g.terminal {
		g.current.LifecycleState = "TERMINATED"
		return g.current, ocireconcile.ErrMemberTerminated
	}
	return g.current, nil
}
func (g *runtimeRemovalGateway) TerminateMember(_ context.Context, id string) error {
	if id != g.current.ID {
		return errors.New("wrong resource")
	}
	g.terminations++
	g.terminal = true
	return errors.New("OCI deleted instance but response was lost")
}

type runtimeRemovalOwnership struct {
	provider.DurableOwnershipEvidence
	record provider.ProviderOwnershipRecord
	reads  int
}

func (o *runtimeRemovalOwnership) AuthoritativeDurable() bool { return true }
func (o *runtimeRemovalOwnership) Lookup(_ context.Context, id provider.ProviderResourceId) (provider.ProviderOwnershipRecord, bool, error) {
	o.reads++
	return o.record, id.Value == o.record.ResourceId.Value, nil
}

func TestRemovalRuntimeRestartAfterLostTerminationResponse(t *testing.T) {
	member := ocireconcile.ObservedMember{ID: "ocid1.instance.original", ETag: "etag", CompartmentID: "compartment", Region: "gru", Index: 1, LifecycleState: "RUNNING"}
	gateway := &runtimeRemovalGateway{current: member}
	ownership := &runtimeRemovalOwnership{record: provider.ProviderOwnershipRecord{ResourceId: provider.ProviderResourceId{Value: member.ID}, CompartmentId: provider.ProviderCompartmentId{Value: member.CompartmentID}, CellId: provider.ProviderCellId{Value: "gru"}, Generation: provider.ProviderGeneration{Value: 7}, ServerIdentity: "spiffe://terrascale.tech/prod/member/original"}}
	journal := &runtimeRemovalJournal{}
	construct := func() *productionHostRemoval {
		return &productionHostRemoval{observeFn: newProductionDurableMemberObserver(ownership, gateway), owner: &hostremoval.Owner{Journal: journal,
			Inventory: func(context.Context, hostremoval.RemovalRequest, []hostremoval.Replacement) (uint64, []hostremoval.Replacement, error) {
				return 1, nil, nil
			},
			Replace:    func(context.Context, hostremoval.Replacement) error { return nil },
			Revalidate: func(context.Context, string, string, uint64) error { return nil },
			Fence:      func(context.Context, string, string, []hostremoval.Replacement) error { return nil },
			Terminate:  newProductionOCITerminator(map[string]ocireconcile.ComputeGateway{"gru": gateway}),
		}}
	}
	if err := construct().RemoveMember(t.Context(), "remove", member, nil); err == nil {
		t.Fatal("lost response must remain pending")
	}
	if journal.record.Stage != hostremoval.StageFenced || gateway.terminations != 1 {
		t.Fatalf("first attempt: %+v calls=%d", journal.record, gateway.terminations)
	}
	unavailable := errors.New("OCI 404: unauthorized or not found")
	gateway.failure = unavailable
	if err := construct().RemoveMember(t.Context(), "remove", member, nil); !errors.Is(err, unavailable) {
		t.Fatalf("ambiguous absence accepted: %v", err)
	}
	if journal.record.Stage != hostremoval.StageFenced {
		t.Fatal("unavailable provider completed journal")
	}
	gateway.failure = nil
	ownership.record.Generation.Value++
	if err := construct().RemoveMember(t.Context(), "remove", member, nil); !errors.Is(err, hostremoval.ErrConflict) {
		t.Fatalf("rebound ownership accepted: %v", err)
	}
	ownership.record.Generation.Value--
	if err := construct().RemoveMember(t.Context(), "remove", member, nil); err != nil {
		t.Fatal(err)
	}
	if journal.record.Stage != hostremoval.StageComplete || gateway.terminations != 1 || ownership.reads < 3 {
		t.Fatalf("restart: %+v calls=%d ownership reads=%d", journal.record, gateway.terminations, ownership.reads)
	}
	gateway.failure = unavailable
	if err := construct().RemoveMember(t.Context(), "remove", member, nil); err != nil {
		t.Fatalf("completed journal reread provider: %v", err)
	}
}
