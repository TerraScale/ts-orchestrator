package main

import (
	"context"
	"errors"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/hostremoval"
	"terrascale.tech/orchestrator/src/orchestrator/ocireconcile"
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
