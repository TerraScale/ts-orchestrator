package observability

import (
	"math"
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
	result := historyHTTPRange(t, history, HistoryQuery{Metric: "c", Start: now.Add(-3 * time.Minute), End: now, Tier: Tier1m, Rate: true})
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
	result := historyHTTPRange(t, history, HistoryQuery{Metric: "m", Start: now.Add(-15 * time.Minute), End: now, MaxSeries: 1})
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
	result := historyHTTPRange(t, after, HistoryQuery{Metric: "g", Start: now.Add(-30 * time.Minute), End: now.Add(time.Minute)})
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
		got, ok := historySampleValues(t, samples)[Series(metric, pairs...)]
		return got, ok
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
	// c2 returns having made 2 more errors meanwhile; c1 restarted. The
	// returning member is rebaselined: its growth over several collections
	// would otherwise land in one sample and read as a burst.
	back := sampler.Samples(ClusterSnapshot{Members: []MemberSnapshot{member("c1", 1), member("c2", 102)}})
	if got, _ := value(back, HistOCIErrors, "operation", "compute.Get"); got != 202 {
		t.Fatalf("total after return and restart = %v, want 202", got)
	}
	// From then on c2 counts normally, and a new operation on a member
	// that was observed throughout contributes its whole first count.
	withNew := member("c2", 103)
	withNew.OCI.Operations = append(withNew.OCI.Operations, OCIOperationView{Service: "compute", Operation: "List", Errors: 4})
	next := sampler.Samples(ClusterSnapshot{Members: []MemberSnapshot{member("c1", 1), withNew}})
	if got, _ := value(next, HistOCIErrors, "operation", "compute.Get"); got != 203 {
		t.Fatalf("total after the return = %v, want 203", got)
	}
	if got, _ := value(next, HistOCIErrors, "operation", "compute.List"); got != 4 {
		t.Fatalf("a new operation's first errors = %v, want 4", got)
	}
}

func TestSamplerPrefersTheStreamLeadersReport(t *testing.T) {
	t.Parallel()
	follower := MemberSnapshot{Member: "a", NATS: &NATSView{ServerName: "a",
		Streams: []StreamView{{Name: "S", Leader: "b", Messages: 1, MaxReplicaLag: 50}}}}
	leader := MemberSnapshot{Member: "b", NATS: &NATSView{ServerName: "b",
		Streams: []StreamView{{Name: "S", Leader: "b", Messages: 9}}}}
	samples := (&SnapshotSampler{}).Samples(ClusterSnapshot{Members: []MemberSnapshot{follower, leader}})
	if got := historySampleValues(t, samples)[Series(HistStreamMessages, "stream", "S")]; got != 9 {
		t.Fatalf("stream messages = %v, want leader's 9", got)
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
	got, ok := historySampleValues(t, cleared)[Series(HistStageMembers, "stage", "joining")]
	if !ok || got != 0 {
		t.Fatalf("cleared joining stage = %v (present %v)", got, ok)
	}
}

// A short query whose start lies before a fresh tier's first bucket reads
// the restored coarser tier, which holds that start.
func TestShortHistoricalQueryAfterRestoreReadsTheCoveringTier(t *testing.T) {
	t.Parallel()
	now := time.Now().Truncate(5 * time.Minute)
	before := NewHistory(HistoryConfig{})
	for minute := 40; minute >= 0; minute-- {
		before.Append(now.Add(-time.Duration(minute)*time.Minute), []Sample{{Metric: "g", Value: 1}})
	}
	data, err := before.Export(0)
	if err != nil {
		t.Fatal(err)
	}
	after := NewHistory(HistoryConfig{})
	if err := after.Import(data); err != nil {
		t.Fatal(err)
	}
	// Sampling resumes a minute later, so the fresh tiers begin after the
	// query's start.
	after.Append(now.Add(90*time.Second), []Sample{{Metric: "g", Value: 1}})
	result := historyHTTPRange(t, after, HistoryQuery{Metric: "g", Start: now.Add(30 * time.Second), End: now.Add(80 * time.Second)})
	if len(result.Series) != 1 || len(result.Series[0].Points) == 0 {
		t.Fatalf("short query after restore = %+v", result)
	}
}

// A tier whose oldest bucket begins after the query's start does not cover
// it, even when that bucket begins within one step of it.
func TestHistoryHTTPDoesNotInventLiveCoverage(t *testing.T) {
	t.Parallel()
	end := time.Now().Truncate(time.Minute).Add(-time.Minute)
	history := NewHistory(HistoryConfig{})
	first := end.Add(-30*time.Minute + 15*time.Second)
	for second := 0; second <= 30*60; second += 10 {
		history.Append(first.Add(time.Duration(second)*time.Second), []Sample{{Metric: "c", Value: float64(second), Counter: true}})
	}
	for _, start := range []time.Time{first.Add(-10 * time.Minute), first.Add(-10 * time.Second)} {
		result := historyHTTPRange(t, history, HistoryQuery{Metric: "c", Start: start, End: end})
		if len(result.Series) != 1 || result.Series[0].Tier != TierRaw {
			t.Fatalf("live coverage = %+v", result)
		}
	}
}

func TestHistoryHTTPKeepsFreshResolutionAcrossHourBoundary(t *testing.T) {
	t.Parallel()
	end := time.Now().UTC().Truncate(time.Hour).Add(-5 * time.Minute)
	history := NewHistory(HistoryConfig{})
	for step := range 721 {
		history.Append(end.Add(time.Duration(step-720)*10*time.Second), []Sample{{Metric: "g", Value: 1}})
	}
	// Request the latest fifteen minutes through automatic tier selection.
	result := historyHTTPRange(t, history, HistoryQuery{Metric: "g", Start: end.Add(-15 * time.Minute), End: end})
	want := TierFor(end.Add(-15*time.Minute), time.Now())
	if len(result.Series) != 1 || result.Series[0].Tier != want {
		t.Fatalf("fresh range = %+v, want %s", result, want)
	}
}

func TestHistoryIncompleteLiveCoverageKeepsMinuteRates(t *testing.T) {
	t.Parallel()
	// Fix the position within the hour while staying inside minute-tier retention.
	base := time.Now().Truncate(time.Hour).Add(-2 * time.Hour)
	for _, test := range []struct {
		name   string
		offset time.Duration
	}{{"same_hour", 21*time.Minute + 15*time.Second}, {"hour_boundary", 51*time.Minute + 15*time.Second}} {
		t.Run(test.name, func(t *testing.T) {
			history := NewHistory(HistoryConfig{})
			first := base.Add(test.offset)
			end := first.Add(30 * time.Minute)
			for minute := 0; minute <= 30; minute++ {
				history.Append(first.Add(time.Duration(minute)*time.Minute),
					[]Sample{{Metric: "c", Value: float64(minute) * 60, Counter: true}})
			}
			result := historyHTTPRange(t, history, HistoryQuery{Metric: "c", Start: end.Add(-time.Hour), End: end, Rate: true})
			if len(result.Series) != 1 || result.Series[0].Tier != Tier1m || len(result.Series[0].Points) != 30 {
				t.Fatalf("incomplete live range = %+v, want 30 minute rates", result)
			}
			for _, point := range result.Series[0].Points {
				if math.Abs(point.Value-1) > 1e-9 {
					t.Fatalf("rate = %v at %s, want 1/s", point.Value, point.Time)
				}
			}
		})
	}
}

// A counter that resets and recovers inside one rollup bucket keeps all its
// growth: increases are accumulated per raw sample before downsampling.
func TestCounterResetInsideABucketKeepsItsGrowth(t *testing.T) {
	t.Parallel()
	history := NewHistory(HistoryConfig{})
	base := time.Now().Truncate(time.Minute).Add(-10 * time.Minute)
	samples := []struct {
		offset time.Duration
		value  float64
	}{{0, 100}, {time.Minute + 10*time.Second, 150}, {time.Minute + 20*time.Second, 0}, {time.Minute + 30*time.Second, 200}}
	for _, sample := range samples {
		history.Append(base.Add(sample.offset), []Sample{{Metric: "c", Value: sample.value, Counter: true}})
	}
	result := historyHTTPRange(t, history, HistoryQuery{Metric: "c", Start: base.Add(-time.Minute), End: base.Add(2 * time.Minute),
		Tier: Tier1m, Rate: true})
	if len(result.Series) != 1 || len(result.Series[0].Points) != 1 {
		t.Fatalf("rate = %+v", result)
	}
	// 100 -> 150 (+50), reset to 0 (+0), -> 200 (+200): 250 over 90 s.
	if got, want := result.Series[0].Points[0].Value, 250.0/90; math.Abs(got-want) > 1e-9 {
		t.Fatalf("rate = %v, want %v", got, want)
	}
}
