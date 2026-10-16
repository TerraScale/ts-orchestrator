package devfake

import (
	"context"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/decisionlog"
)

// The fake world is a pure function of the sample time and the fixed world
// start: live samples must keep moving like the backfill, whatever the wall
// clock says when they are taken.

func testRegion(t *testing.T, name string) *region {
	t.Helper()
	world := New()
	for _, region := range world.regions {
		if region.name == name {
			return region
		}
	}
	t.Fatalf("no region %s", name)
	return nil
}

func TestFillingDiskKeepsGrowingAfterTheWorldStarts(t *testing.T) {
	t.Parallel()
	gru := testRegion(t, "gru")
	start := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	used := func(at time.Time) float64 {
		for _, filesystem := range gru.filesystems(gru.fullDisk, at, start) {
			if filesystem.Role == "nats" {
				return 1 - float64(filesystem.AvailBytes)/float64(filesystem.SizeBytes)
			}
		}
		t.Fatal("no nats filesystem")
		return 0
	}
	// Anchored to the world start, not the wall clock: ten hours after the
	// start the disk is 34 hours of growth above its 71.5% origin.
	if got, want := used(start.Add(10*time.Hour)), 0.715+fullDiskRate*34; got < want-0.001 || got > want+0.001 {
		t.Fatalf("used 10h after the start = %.4f, want %.4f", got, want)
	}
	previous := used(start.Add(-24 * time.Hour))
	for hours := -23; hours <= 48; hours++ {
		current := used(start.Add(time.Duration(hours) * time.Hour))
		if growth := current - previous; current < 0.999 && (growth < fullDiskRate*0.9 || growth > fullDiskRate*1.1) {
			t.Fatalf("hour %d grew %.5f, want about %.4f per hour", hours, growth, fullDiskRate)
		}
		previous = current
	}
}

func TestThrottlingStormKeepsCounting(t *testing.T) {
	t.Parallel()
	sfo := testRegion(t, "sfo")
	start := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	throttled := func(at time.Time) float64 {
		var total float64
		for _, operation := range sfo.oci(at, start).Operations {
			total += float64(operation.Throttled)
		}
		return total
	}
	previous := throttled(start.Add(-30 * time.Minute))
	for minutes := -20; minutes <= 6*60; minutes += 10 {
		current := throttled(start.Add(time.Duration(minutes) * time.Minute))
		if current <= previous {
			t.Fatalf("the 429 counter stopped at %d minutes: %v -> %v", minutes, previous, current)
		}
		previous = current
	}
}

func TestOCIDurationCounterIsMonotonicAndPlausible(t *testing.T) {
	t.Parallel()
	gru := testRegion(t, "gru")
	start := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	previous := gru.oci(start, start).Operations
	for seconds := 10; seconds <= 3*3600; seconds += 10 {
		current := gru.oci(start.Add(time.Duration(seconds)*time.Second), start).Operations
		for index, operation := range current {
			calls := float64(operation.Calls) - float64(previous[index].Calls)
			spent := operation.TotalSeconds - previous[index].TotalSeconds
			if spent < 0 {
				t.Fatalf("%s duration counter fell at %ds", operation.Operation, seconds)
			}
			if latency := ociOperations[index].latency; calls >= 5 && (spent/calls < latency*0.6 || spent/calls > latency*1.4) {
				t.Fatalf("%s mean latency %.3fs at %ds, want about %.2fs", operation.Operation, spent/calls, seconds, latency)
			}
		}
		previous = current
	}
}

func TestScalingHoldsInsideTheTargetBand(t *testing.T) {
	t.Parallel()
	for cpu, want := range map[float64]decisionlog.Kind{0.30: decisionlog.KindScaleDown, 0.35: decisionlog.KindScaleDown,
		0.36: "", 0.50: "", 0.65: "", 0.69: "", 0.70: decisionlog.KindScaleUp, 0.80: decisionlog.KindScaleUp} {
		kind, _, comparison, threshold, scaled := scaleDecision(cpu)
		if kind != want || scaled != (want != "") {
			t.Errorf("cpu %.2f = %q, want %q", cpu, kind, want)
		}
		if scaled && !*gate("pool_cpu", cpu, "ratio", comparison, threshold).Passed {
			t.Errorf("cpu %.2f scaled with a failed gate", cpu)
		}
	}
	world := New()
	result, _ := world.store.Query(context.Background(), decisionlog.Query{Limit: decisionlog.MaxQueryLimit,
		Kinds: []decisionlog.Kind{decisionlog.KindScaleUp, decisionlog.KindScaleDown}})
	for _, decision := range result.Decisions {
		if !*decision.Signals[0].Passed {
			t.Fatalf("a recorded scaling decision failed its own gate: %+v", decision.Signals[0])
		}
	}
}

func TestReadinessFollowsEveryCheck(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"gru", "fra"} {
		region := testRegion(t, name)
		snapshot := region.cluster(time.Now(), time.Now())
		for _, member := range snapshot.Members {
			if member.Ready != allOK(member.Checks) {
				t.Fatalf("%s ready = %v with checks %+v", member.Member, member.Ready, member.Checks)
			}
			for _, check := range member.Checks {
				if check.Detail == "" {
					t.Fatalf("%s check %s has no detail for the readiness card", member.Member, check.Name)
				}
			}
		}
		if name == "fra" && snapshot.Members[1].Ready {
			t.Fatal("an FRA follower is ready with its cluster check failing")
		}
	}
}

func TestLeadershipTimelineHasRecentChanges(t *testing.T) {
	t.Parallel()
	world := New()
	since := time.Now().Add(-24 * time.Hour)
	for _, region := range regionNames {
		result, _ := world.store.Query(context.Background(), decisionlog.Query{Regions: []string{region}, Since: since,
			Kinds: []decisionlog.Kind{decisionlog.KindLeaderChanged, decisionlog.KindQuorumDegraded, decisionlog.KindQuorumRestored}})
		kinds := map[string]int{}
		for _, decision := range result.Decisions {
			kinds[string(decision.Kind)+"/"+decision.Subject.Kind]++
		}
		if kinds["leader_changed/member"] < 2 || kinds["leader_changed/nats-meta"] < 2 || kinds["quorum_degraded/cluster"] < 1 {
			t.Fatalf("%s leadership timeline = %v", region, kinds)
		}
	}
}
