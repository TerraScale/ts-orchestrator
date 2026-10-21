package placement

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSummarizeCountsStagesAndRolloutProgress(t *testing.T) {
	t.Parallel()
	prepared := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	member := func(seat string, stage MemberStage, operation string, phase ManagedUpdateSeatPhase, at time.Time) VersionedMemberState {
		state := MemberState{DatabaseID: "0000000000T8H7NEY8XQ530245", PartitionID: "00000000003K6TBW31R91GBDRD", MemberID: seat, Stage: stage, HostNode: "host-" + seat}
		if operation != "" {
			state.ManagedRuntimeTarget = ManagedRuntimeTarget{OperationID: operation, Phase: phase, PreparedAt: at,
				ArtifactDigest: "sha256:new"}
		}
		return VersionedMemberState{State: state, Revision: 1}
	}
	store := &placementMemoryStore{
		intents: []Intent{{DatabaseID: "0000000000T8H7NEY8XQ530245", PartitionID: "00000000003K6TBW31R91GBDRD", Generation: 4,
			CanonicalRoster: CanonicalRoster{Rows: []CanonicalRosterRow{{SeatID: "0000000000NR756QAGVQCJMV00"}, {SeatID: "00000000002CXZ93EYQ224Z7QR"}, {SeatID: "00000000004X8BXAJ3KVRH7WYM"}}}},
			{DatabaseID: "0000000000F6H63RT9R93XQ0MH", PartitionID: "00000000003K6TBW31R91GBDRD", Generation: 1}},
		members: map[string]VersionedMemberState{
			"a": member("a", StageServing, "update-2", ManagedUpdateSeatCanaryServing, prepared.Add(time.Minute)),
			"b": member("b", StageAwaitingHealthy, "update-2", ManagedUpdateSeatPrepared, prepared.Add(2*time.Minute)),
			"c": member("c", StageServing, "update-1", ManagedUpdateSeatCanaryServing, prepared),
		},
	}
	view, err := Summarize(t.Context(), store)
	if err != nil {
		t.Fatal(err)
	}
	if len(view.Databases) != 2 || view.StageCounts["serving"] != 2 || view.StageCounts["awaiting-healthy"] != 1 {
		t.Fatalf("view = %+v", view)
	}
	database := view.Databases[0]
	if database.DesiredSeats != 3 || database.Serving != 0 || database.Readiness != "unknown" || database.ReadinessReason == "" || database.Generation != 4 || len(database.Members) != 3 {
		t.Fatalf("database = %+v", database)
	}
	rollout := database.Rollout
	// The latest operation targets a and b; c finished an older one.
	if rollout == nil || rollout.OperationID != "update-2" || rollout.Seats != 2 || rollout.Completed != 1 ||
		rollout.Phases["prepared"] != 1 || rollout.Phases["canary-serving"] != 1 {
		t.Fatalf("rollout = %+v", rollout)
	}
	if view.Databases[1].Rollout != nil || view.Databases[1].DesiredSeats != 0 {
		t.Fatalf("idle partition = %+v", view.Databases[1])
	}
	if _, err := Summarize(t.Context(), nil); err == nil {
		t.Fatal("nil store was accepted")
	}
}

func TestReconcileMetricsSeparateStandbyFromErrors(t *testing.T) {
	before := reconcileError.Get()
	standbyBefore := reconcileStandby.Get()
	recordReconcile(time.Now(), true, errors.New("ignored while standby"))
	recordReconcile(time.Now(), false, errors.New("observe failed"))
	recordReconcile(time.Now(), false, nil)
	if reconcileError.Get() != before+1 || reconcileStandby.Get() != standbyBefore+1 {
		t.Fatalf("errors %d->%d, standby %d->%d", before, reconcileError.Get(), standbyBefore, reconcileStandby.Get())
	}
	var output bytes.Buffer
	Metrics.WritePrometheus(&output)
	if !strings.Contains(output.String(), `ts_orch_reconcile_total{loop="placement",result="ok"}`) ||
		strings.Contains(output.String(), `reconcile_last_success_timestamp_seconds{loop="placement"} NaN`) {
		t.Fatalf("placement metrics = %s", output.String())
	}
}
