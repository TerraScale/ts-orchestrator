package cellscale

import (
	"slices"
	"testing"
	"time"
)

func TestScaleInWaitsForFullReplicaConvergence(t *testing.T) {
	for _, evacuation := range []time.Duration{time.Second, MaxPressureAge + time.Second} {
		t.Run(evacuation.String(), func(t *testing.T) {
			captureJournal(t)
			policy := testPolicy()
			policy.SustainDownSeconds, policy.CooldownSeconds, policy.ScaleDownCooldownSeconds = 0, 0, 0
			policy.MaxFailures = 1
			cell := newFakeCell(4, small, 2, 150)
			s := newSim(t, policy, cell, time.Minute)
			postDrainReads := 0
			cell.replicas = func() (ReplicaSnapshot, error) {
				if !s.now.After(s.controller.replicasAfter) {
					s.now = s.controller.replicasAfter.Add(time.Second)
				}
				if cell.state["gru-1-db-4"] == StateDrained {
					postDrainReads++
					if postDrainReads == 1 {
						s.now = s.now.Add(evacuation)
					} else {
						s.now = s.now.Add(time.Second)
					}
				}
				snapshot := safeReplicaSnapshot(s.now, cell)
				if postDrainReads > 0 && postDrainReads <= 2 {
					for i := range snapshot.Placements {
						snapshot.Placements[i].LiveReplicas = snapshot.Placements[i].LiveReplicas[:2]
					}
				}
				return snapshot, nil
			}
			action, err := s.controller.Tick(t.Context())
			if err != nil || s.controller.History().Paused || postDrainReads < 3 ||
				!slices.Equal(cell.callLog(), []string{"drain gru-1-db-4", "terminate gru-1-db-4"}) {
				t.Fatalf("transient evacuation failed: action=%+v err=%v paused=%v reads=%d calls=%v",
					action, err, s.controller.History().Paused, postDrainReads, cell.callLog())
			}
		})
	}
}
