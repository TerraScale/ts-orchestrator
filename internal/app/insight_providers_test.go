package app

import (
	"strings"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/membership"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
)

func TestControllerSlotServerNameMatchesTheBroker(t *testing.T) {
	topology := membership.Topology{Cell: "gru", Slots: []string{"controller-a"}, SeedSlot: "controller-a",
		SelfSlot: "controller-a"}
	if got, want := topology.ServerName("controller-a"), natscell.ServerName("gru", "controller-a"); got != want {
		t.Fatalf("slot server name %q differs from broker server name %q", got, want)
	}
}

func TestVolumeAttachmentStateFeedsTheStuckAttachRule(t *testing.T) {
	for _, stage := range []placement.MemberStage{placement.StagePreparedAttach, placement.StageAwaitingAttach} {
		if state := volumeAttachmentState(stage); !strings.Contains(strings.ToLower(state), "attaching") {
			t.Fatalf("%s maps to %q, want an attaching state", stage, state)
		}
	}
	if state := volumeAttachmentState(placement.StageServing); strings.Contains(strings.ToLower(state), "attaching") {
		t.Fatalf("a serving member's volume must not read as attaching: %q", state)
	}
	// The dashboard keys on the canonical lowercase states.
	for stage, want := range map[placement.MemberStage]string{placement.StageServing: "attached",
		placement.StageAwaitingAttach: "attaching", placement.StagePreparedVolume: "available"} {
		if got := volumeAttachmentState(stage); got != want {
			t.Fatalf("%s maps to %q, want the canonical %q", stage, got, want)
		}
	}
}

func TestNilSliceProvidersStaySilent(t *testing.T) {
	if scalers, err := (workloadAutoscalers{}).Autoscalers(t.Context()); err != nil || scalers != nil {
		t.Fatalf("autoscalers = %v, %v", scalers, err)
	}
	if volumes, err := (placementVolumes{}).Volumes(t.Context()); err != nil || volumes != nil {
		t.Fatalf("volumes = %v, %v", volumes, err)
	}
}
