package app

import (
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/insights"
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
		if state := volumeAttachmentState(placement.MemberState{Stage: stage}); !strings.Contains(strings.ToLower(state), "attaching") {
			t.Fatalf("%s maps to %q, want an attaching state", stage, state)
		}
	}
	if state := volumeAttachmentState(placement.MemberState{Stage: placement.StageServing}); strings.Contains(strings.ToLower(state), "attaching") {
		t.Fatalf("a serving member's volume must not read as attaching: %q", state)
	}
	// The dashboard keys on the canonical lowercase states.
	for stage, want := range map[placement.MemberStage]string{placement.StageServing: "attached",
		placement.StageAwaitingAttach: "attaching", placement.StagePreparedVolume: "available"} {
		if got := volumeAttachmentState(placement.MemberState{Stage: stage, HostNode: "node-a", AttachmentID: "attachment-a"}); got != want {
			t.Fatalf("%s maps to %q, want the canonical %q", stage, got, want)
		}
	}
}

func TestVolumeAttachmentRequiresPlacementEvidence(t *testing.T) {
	for _, member := range []placement.MemberState{
		{Stage: placement.StagePreparedHost, VolumeID: "retained"},
		{Stage: placement.StageServing, HostNode: "node-a", VolumeID: "retained"},
		{Stage: placement.StageServing, VolumeID: "retained", AttachmentID: "attachment-a"},
		{Stage: placement.StageTerminated, HostNode: "node-a", VolumeID: "retained", AttachmentID: "attachment-a"},
	} {
		if got := volumeAttachmentState(member); got != "unknown" {
			t.Errorf("%+v reports unproven attachment as %q", member, got)
		}
	}
}

func TestVolumeAttachAgeUsesTheRequestTime(t *testing.T) {
	requested := time.Now().UTC().Add(-time.Hour)
	store := volumeListStore{intents: []placement.Intent{{DatabaseID: "db", PartitionID: "partition"}},
		members: map[string][]placement.VersionedMemberState{"db/partition": {{State: placement.MemberState{
			VolumeID: "volume", Stage: placement.StageAwaitingAttach, AttachRequestedAt: requested, UpdatedAt: time.Now().UTC(),
		}}}}}
	volumes, err := (placementVolumes{store: store}).Volumes(t.Context())
	if err != nil || len(volumes) != 1 || !volumes[0].StateSince.Equal(requested) {
		t.Fatalf("attach age was reset by a placement write: %+v, %v", volumes, err)
	}
}

func TestVolumeAttachmentTimingReachesTheStuckRule(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name      string
		stage     placement.MemberStage
		requested time.Time
		updated   time.Time
		since     time.Time
		warnings  int
	}{
		{name: "observed attachment", stage: placement.StageAwaitingAttach,
			updated: now.Add(-time.Hour), since: now.Add(-time.Hour), warnings: 1},
		{name: "recent observed attachment", stage: placement.StageAwaitingAttach,
			updated: now.Add(-time.Minute), since: now.Add(-time.Minute)},
		{name: "request before phase entry", stage: placement.StageAwaitingAttach,
			requested: now.Add(-time.Hour), updated: now, since: now.Add(-time.Hour), warnings: 1},
		{name: "prepared without request", stage: placement.StagePreparedAttach, updated: now.Add(-time.Hour)},
		{name: "prepared with request", stage: placement.StagePreparedAttach,
			requested: now.Add(-time.Hour), updated: now, since: now.Add(-time.Hour), warnings: 1},
		{name: "unknown phase time", stage: placement.StageAwaitingAttach},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := volumeListStore{intents: []placement.Intent{{DatabaseID: "db", PartitionID: "partition"}},
				members: map[string][]placement.VersionedMemberState{"db/partition": {{State: placement.MemberState{
					VolumeID: "volume", HostNode: "node-a", AttachmentID: "attachment-a", Stage: test.stage,
					AttachRequestedAt: test.requested, UpdatedAt: test.updated,
				}}}}}
			volumes, err := (placementVolumes{store: store}).Volumes(t.Context())
			if err != nil || len(volumes) != 1 {
				t.Fatalf("volume evidence = %+v, %v", volumes, err)
			}
			var rule insights.Rule
			for _, candidate := range insights.DefaultRules() {
				if candidate.Name == "volume_stuck" {
					rule = candidate
					break
				}
			}
			if rule.Evaluate == nil {
				t.Fatal("stuck volume rule missing")
			}
			warnings := rule.Evaluate(&insights.Inputs{Now: now, Volumes: volumes,
				Thresholds: insights.Thresholds{VolumeAttachStuck: 15 * time.Minute}})
			if len(warnings) != test.warnings {
				t.Fatalf("volume evidence produced %d stuck warnings, want %d: %+v", len(warnings), test.warnings, volumes)
			}
			if !volumes[0].StateSince.Equal(test.since) {
				t.Fatalf("attachment state started at %s, want %s", volumes[0].StateSince, test.since)
			}
		})
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
