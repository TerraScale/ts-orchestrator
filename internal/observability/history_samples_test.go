package observability

import (
	"errors"
	"testing"
)

func TestSnapshotSamplerOmitsUnavailableFilesystemGauges(t *testing.T) {
	t.Parallel()
	root := writeProcFixture(t)
	sampler := &SnapshotSampler{}
	for index, unavailable := range []bool{false, true, false} {
		view, err := readSystem(root, []FilesystemRole{{Role: "nats", Path: "/data"}, {Role: "store", Path: "/store"}},
			func(path string) (FilesystemView, error) {
				if path == "/store" && unavailable {
					return FilesystemView{}, errors.New("statfs failed")
				}
				return FilesystemView{SizeBytes: 100, AvailBytes: 40}, nil
			})
		if err != nil {
			t.Fatal(err)
		}
		// Keep CPU counters growing even when one filesystem is unavailable.
		view.CPUSeconds.User += float64(index) * 10
		view.CPUSeconds.Idle += float64(index) * 10
		samples := sampler.Samples(ClusterSnapshot{Members: []MemberSnapshot{{Member: "c1", System: &view}}})
		values := historySampleValues(t, samples)
		for _, role := range []string{"nats", "store"} {
			for metric, want := range map[string]float64{HistFSUsed: 60, HistFSSize: 100, HistFSRatio: 0.6} {
				got, present := values[Series(metric, "member", "c1", "role", role)]
				if unavailable && role == "store" {
					if present {
						t.Errorf("%s for unavailable store = %v", metric, got)
					}
				} else if !present || got != want {
					t.Errorf("%s for %s = %v (present %v), want %v", metric, role, got, present, want)
				}
			}
		}
		for metric, want := range map[string]float64{HistLoad1: 0.5, HistMemoryRatio: 0.5} {
			if got, present := values[Series(metric, "member", "c1")]; !present || got != want {
				t.Errorf("%s = %v (present %v), want %v", metric, got, present, want)
			}
		}
		if unavailable {
			if got, present := values[Series(HistCPUUtilization, "member", "c1")]; !present || got != 0.5 {
				t.Errorf("CPU utilization with store unavailable = %v (present %v)", got, present)
			}
		}
	}
}

func TestSnapshotSamplerExcludesTerminalPartitionsFromActiveGauges(t *testing.T) {
	t.Parallel()
	placement := &PlacementView{Databases: []DatabaseView{
		{DatabaseID: "orders", PartitionID: "p0", DesiredSeats: 3, Serving: 2, Stages: map[string]int{"serving": 2},
			Rollout: &RolloutView{OperationID: "active-update", Seats: 2, Completed: 1}},
		{DatabaseID: "orders", PartitionID: "p1", DesiredSeats: 2, Serving: 1, Stages: map[string]int{"serving": 1}},
		{DatabaseID: "archived", PartitionID: "p0", Terminal: true, DesiredSeats: 7, Serving: 7,
			Stages:  map[string]int{"serving": 7, "retired": 1},
			Rollout: &RolloutView{OperationID: "retired-update", Seats: 7}},
	}, StageCounts: map[string]int{"serving": 10, "retired": 1}}
	sampler := &SnapshotSampler{}
	cluster := ClusterSnapshot{Members: []MemberSnapshot{{Member: "c1", Placement: placement}}}
	for range 2 {
		samples := sampler.Samples(cluster)
		values := historySampleValues(t, samples)
		for key, want := range map[string]float64{
			HistDatabases: 2, HistSeatsDesired: 5, HistSeatsServing: 3,
			Series(HistStageMembers, "stage", "serving"):                            3,
			Series(HistStageMembers, "stage", "retired"):                            0,
			Series(HistRolloutProgress, "operation", "active-update"):               0.5,
			Series(HistPartitionDesired, "database", "archived", "partition", "p0"): 7,
			Series(HistPartitionServing, "database", "archived", "partition", "p0"): 7,
		} {
			if got, present := values[key]; !present || got != want {
				t.Errorf("%s = %v (present %v), want %v", key, got, present, want)
			}
		}
		if _, present := values[Series(HistRolloutProgress, "operation", "retired-update")]; present {
			t.Error("terminal partition produced active rollout progress")
		}
	}
	if placement.StageCounts["serving"] != 10 || placement.StageCounts["retired"] != 1 {
		t.Fatalf("sampling mutated the placement stages: %v", placement.StageCounts)
	}
	for index := range placement.Databases {
		placement.Databases[index].Terminal = true
	}
	for _, sample := range sampler.Samples(cluster) {
		switch sample.Metric {
		case HistDatabases, HistSeatsDesired, HistSeatsServing, HistStageMembers:
			if sample.Value != 0 {
				t.Errorf("%s with all partitions terminal = %v, want 0", sample.Metric, sample.Value)
			}
		case HistRolloutProgress:
			t.Error("all-terminal placement produced active rollout progress")
		}
	}
}
