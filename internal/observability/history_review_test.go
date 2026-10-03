package observability

import (
	"testing"
	"time"
)

// These pin the fixes for the ts-reviewer findings on PR #121.

func TestRollupRatesUseSampleTimes(t *testing.T) {
	t.Parallel()
	history := NewHistory(HistoryConfig{Interval: 10 * time.Second})
	now := time.Now().Truncate(time.Minute)
	// A counter rising 1/s, sampled every 10s across three minutes.
	for second := 0; second <= 180; second += 10 {
		history.Append(now.Add(time.Duration(second-180)*time.Second),
			[]Sample{{Metric: "c", Value: float64(second), Counter: true}})
	}
	result := history.Range(HistoryQuery{Metric: "c", Start: now.Add(-3 * time.Minute), End: now, Tier: Tier1m, Rate: true})
	if len(result.Series) != 1 || len(result.Series[0].Points) == 0 {
		t.Fatalf("result = %+v", result)
	}
	for _, point := range result.Series[0].Points {
		if point.Value < 0.99 || point.Value > 1.01 {
			t.Fatalf("1m rate = %v at %s, want 1/s", point.Value, point.Time)
		}
	}
}

func TestEmptySeriesDoNotTakeResultSlots(t *testing.T) {
	t.Parallel()
	history := NewHistory(HistoryConfig{})
	now := time.Now()
	history.Append(now.Add(-2*time.Hour), []Sample{{Metric: "m", Labels: L("consumer", "a"), Value: 1}})
	history.Append(now.Add(-time.Minute), []Sample{{Metric: "m", Labels: L("consumer", "b"), Value: 2}})
	result := history.Range(HistoryQuery{Metric: "m", Start: now.Add(-15 * time.Minute), End: now, MaxSeries: 1})
	if len(result.Series) != 1 || result.Series[0].Labels["consumer"] != "b" || result.Truncated {
		t.Fatalf("result = %+v", result)
	}
}

func TestRestoredHistoryIsQueryableAndResumesItsOpenBucket(t *testing.T) {
	t.Parallel()
	now := time.Now().Truncate(time.Minute)
	before := NewHistory(HistoryConfig{})
	for minute := 40; minute >= 0; minute-- {
		before.Append(now.Add(-time.Duration(minute)*time.Minute+5*time.Second), []Sample{{Metric: "g", Value: 1}})
	}
	data, err := before.Export(0)
	if err != nil {
		t.Fatal(err)
	}
	after := NewHistory(HistoryConfig{})
	if err := after.Import(data); err != nil {
		t.Fatal(err)
	}
	// Sampling resumes in the same minute as the last exported bucket.
	after.Append(now.Add(30*time.Second), []Sample{{Metric: "g", Value: 3}})
	// An automatic 30m query must reach the restored rollups, not only the
	// fresh raw tier.
	result := after.Range(HistoryQuery{Metric: "g", Start: now.Add(-30 * time.Minute), End: now.Add(time.Minute)})
	if len(result.Series) != 1 || len(result.Series[0].Points) < 25 {
		t.Fatalf("restored range = %+v", result)
	}
	starts := map[int64]bool{}
	for _, point := range result.Series[0].Points {
		if starts[point.Time.UnixMilli()] {
			t.Fatalf("duplicate bucket at %s after restore", point.Time)
		}
		starts[point.Time.UnixMilli()] = true
	}
	last := result.Series[0].Points[len(result.Series[0].Points)-1]
	if last.Value != 2 { // (1 + 3) / 2: the resumed sample joined the restored bucket
		t.Fatalf("last bucket = %+v", last)
	}
}

func TestSamplerCountersSurviveAMissingMember(t *testing.T) {
	t.Parallel()
	member := func(name string, errors uint64) MemberSnapshot {
		return MemberSnapshot{Member: name, Role: "controller",
			OCI: &OCIView{Operations: []OCIOperationView{{Service: "compute", Operation: "Get", Errors: errors}}}}
	}
	sampler := &SnapshotSampler{}
	value := func(samples []Sample, metric string, pairs ...string) (float64, bool) {
		key := Series(metric, pairs...)
		for _, sample := range samples {
			if seriesKey(sample.Metric, sortedLabels(sample.Labels)) == key {
				return sample.Value, true
			}
		}
		return 0, false
	}
	first := sampler.Samples(ClusterSnapshot{Members: []MemberSnapshot{member("c1", 100), member("c2", 100)}})
	if got, _ := value(first, HistOCIErrors, "operation", "compute.Get"); got != 200 {
		t.Fatalf("first total = %v", got)
	}
	// c2 misses a collection: the total must not fall (a fake reset).
	missing := sampler.Samples(ClusterSnapshot{Members: []MemberSnapshot{member("c1", 101)}, Missing: []string{"c2"}})
	if got, _ := value(missing, HistOCIErrors, "operation", "compute.Get"); got != 201 {
		t.Fatalf("total with c2 missing = %v, want 201", got)
	}
	if up, ok := value(missing, HistMemberUp, "member", "c2", "role", "controller"); !ok || up != 0 {
		t.Fatalf("missing c2 member_up = %v (present %v), want 0", up, ok)
	}
	// c2 returns having made 2 more errors meanwhile; c1 restarted.
	back := sampler.Samples(ClusterSnapshot{Members: []MemberSnapshot{member("c1", 1), member("c2", 102)}})
	if got, _ := value(back, HistOCIErrors, "operation", "compute.Get"); got != 204 {
		t.Fatalf("total after return and restart = %v, want 204", got)
	}
}

func TestSamplerPrefersTheStreamLeadersReport(t *testing.T) {
	t.Parallel()
	follower := MemberSnapshot{Member: "a", NATS: &NATSView{ServerName: "a",
		Streams: []StreamView{{Name: "S", Leader: "b", Messages: 1, MaxReplicaLag: 50}}}}
	leader := MemberSnapshot{Member: "b", NATS: &NATSView{ServerName: "b",
		Streams: []StreamView{{Name: "S", Leader: "b", Messages: 9}}}}
	samples := (&SnapshotSampler{}).Samples(ClusterSnapshot{Members: []MemberSnapshot{follower, leader}})
	for _, sample := range samples {
		if sample.Metric == HistStreamMessages && sample.Value != 9 {
			t.Fatalf("stream messages = %v, want the leader's 9", sample.Value)
		}
	}
}

func TestSamplerRecordsAClearedStageAsZero(t *testing.T) {
	t.Parallel()
	sampler := &SnapshotSampler{}
	placement := func(stages map[string]int) ClusterSnapshot {
		return ClusterSnapshot{Members: []MemberSnapshot{{Member: "c1", Placement: &PlacementView{StageCounts: stages}}}}
	}
	sampler.Samples(placement(map[string]int{"serving": 2, "joining": 1}))
	cleared := sampler.Samples(placement(map[string]int{"serving": 3}))
	for _, sample := range cleared {
		if sample.Metric == HistStageMembers && sample.Labels[0].Value == "joining" {
			if sample.Value != 0 {
				t.Fatalf("joining = %v", sample.Value)
			}
			return
		}
	}
	t.Fatal("the cleared stage got no sample")
}
