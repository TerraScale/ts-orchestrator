package vmqual

import (
	"context"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
)

func TestLaunchStagesKeepOrdinaryHostsOutOfCandidateWave(t *testing.T) {
	factory := &smokeFakeFactory{}
	stack, err := NewStack(StackConfig{VMFactory: factory, Network: &smokeFakeNetwork{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := stack.Cleanup(context.WithoutCancel(t.Context())); err != nil {
			t.Error(err)
		}
	})
	if err := stack.StartCandidates(t.Context(), vmnet.SFO); err == nil {
		t.Fatal("candidate started before initial GRU")
	}
	if err := stack.StartBootstrap(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(factory.created) != 2 {
		t.Fatal("initial wave did not contain two hosts")
	}
	if err := stack.StartCandidates(t.Context(), vmnet.SFO, vmnet.FRA); err != nil {
		t.Fatal(err)
	}
	if len(factory.created) != 4 {
		t.Fatal("candidate wave started ordinary second hosts")
	}
	for _, vm := range factory.created[2:] {
		if !vm.guest.Control || vm.guest.Region == vmnet.GRU {
			t.Fatal("candidate wave has an ordinary host")
		}
	}
	if err := stack.StartCandidates(t.Context(), vmnet.SFO, vmnet.FRA); err != nil {
		t.Fatal(err)
	}
	if len(factory.created) != 4 {
		t.Fatal("candidate retry created duplicate hosts")
	}
	if err := stack.StartRegions(t.Context(), vmnet.SFO, vmnet.FRA); err != nil {
		t.Fatal(err)
	}
	if len(factory.created) != 6 {
		t.Fatal("ordinary wave did not complete six hosts")
	}
}
