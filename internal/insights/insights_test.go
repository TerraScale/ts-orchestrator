package insights

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/decisionlog"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) Advance(step time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(step)
	c.mu.Unlock()
}

type fakeCluster struct {
	mu       sync.Mutex
	snapshot observability.ClusterSnapshot
	err      error
}

func (cluster *fakeCluster) Cluster(context.Context, bool) (observability.ClusterSnapshot, error) {
	cluster.mu.Lock()
	defer cluster.mu.Unlock()
	return cluster.snapshot, cluster.err
}

func (cluster *fakeCluster) set(snapshot observability.ClusterSnapshot) {
	cluster.mu.Lock()
	cluster.snapshot = snapshot
	cluster.mu.Unlock()
}

func controller(name string, leader bool) observability.MemberSnapshot {
	return observability.MemberSnapshot{Member: name, Role: "controller", Ready: true, BuildVersion: "v1",
		Authority: &observability.AuthorityView{Leader: leader, Ready: true, OwnerID: "0000000000KZ5R9PYPCAJ654M2", Epoch: 3}}
}

func healthy() observability.ClusterSnapshot {
	return observability.ClusterSnapshot{Cell: "gru", Expected: []string{"c1", "c2", "c3"},
		Members: []observability.MemberSnapshot{controller("c1", true), controller("c2", false), controller("c3", false)}}
}

func find(insights []Insight, rule string) *Insight {
	for index := range insights {
		if insights[index].Rule == rule {
			return &insights[index]
		}
	}
	return nil
}

func TestEngineLifecycleOpenEscalateResolve(t *testing.T) {
	c := &clock{now: time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)}
	cluster := &fakeCluster{snapshot: healthy()}
	engine := NewEngine(Config{Region: "GRU", Cluster: cluster, Now: c.Now})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	live := engine.Subscribe(ctx, 8)

	if evaluation := engine.Evaluate(ctx); len(evaluation.Insights) != 0 {
		t.Fatalf("healthy cell raised %+v", evaluation.Insights)
	}
	degraded := healthy()
	degraded.Members, degraded.Missing = degraded.Members[:2], []string{"c3"}
	cluster.set(degraded)
	c.Advance(time.Minute)
	evaluation := engine.Evaluate(ctx)
	quorum := find(evaluation.Insights, "quorum_at_risk")
	if quorum == nil || quorum.Severity != SeverityWarning || quorum.Region != "gru" || quorum.Entity.Region != "gru" ||
		len(quorum.Evidence) == 0 || quorum.Evidence[0].Threshold == nil || *quorum.Evidence[0].Threshold != 2 {
		t.Fatalf("quorum insight = %+v", quorum)
	}
	opened := <-live
	if opened.Type != ChangeOpened || opened.Insight.Key != quorum.Key {
		t.Fatalf("change = %+v", opened)
	}
	firstSeen := quorum.FirstSeen

	critical := healthy()
	critical.Members, critical.Missing = critical.Members[:1], []string{"c2", "c3"}
	cluster.set(critical)
	c.Advance(time.Minute)
	evaluation = engine.Evaluate(ctx)
	quorum = find(evaluation.Insights, "quorum_at_risk")
	if quorum.Severity != SeverityCritical || !quorum.FirstSeen.Equal(firstSeen) || evaluation.Counts.Critical != 1 {
		t.Fatalf("escalated = %+v", quorum)
	}
	if change := <-live; change.Type != ChangeEscalated {
		t.Fatalf("change = %+v", change)
	}

	cluster.set(healthy())
	c.Advance(time.Minute)
	if evaluation := engine.Evaluate(ctx); len(evaluation.Insights) != 0 {
		t.Fatalf("recovered cell still raises %+v", evaluation.Insights)
	}
	if change := <-live; change.Type != ChangeResolved {
		t.Fatalf("change = %+v", change)
	}
	changes := engine.Changes(firstSeen)
	if len(changes) != 3 {
		t.Fatalf("changes = %d", len(changes))
	}
	if later := engine.Changes(c.Now().Add(time.Second)); len(later) != 0 {
		t.Fatalf("later changes = %d", len(later))
	}
}

func TestEngineDurationGatedRules(t *testing.T) {
	c := &clock{now: time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)}
	snapshot := healthy()
	snapshot.Members[1].BuildVersion = "v2"
	snapshot.Members[2].Ready = false
	snapshot.Members[2].Checks = []observability.CheckResult{{Name: "nats", Detail: "regional broker is not connected"}}
	for index := range snapshot.Members {
		snapshot.Members[index].Authority.Leader = false
		snapshot.Members[index].Authority.OwnerID = ""
	}
	cluster := &fakeCluster{snapshot: snapshot}
	engine := NewEngine(Config{Region: "gru", Cluster: cluster, Now: c.Now})
	if evaluation := engine.Evaluate(t.Context()); len(evaluation.Insights) != 0 {
		t.Fatalf("conditions must persist before firing: %+v", evaluation.Insights)
	}
	c.Advance(2 * time.Minute)
	evaluation := engine.Evaluate(t.Context())
	if find(evaluation.Insights, "no_leader") == nil || find(evaluation.Insights, "member_not_ready") == nil {
		t.Fatalf("insights = %+v", evaluation.Insights)
	}
	if find(evaluation.Insights, "mixed_versions") != nil {
		t.Fatal("mixed versions fired before its threshold")
	}
	if notReady := find(evaluation.Insights, "member_not_ready"); !strings.Contains(notReady.Why, "nats") {
		t.Fatalf("why = %q", notReady.Why)
	}
	if evaluation.Insights[0].Rule != "no_leader" {
		t.Fatalf("critical must rank first: %s", evaluation.Insights[0].Rule)
	}
	c.Advance(31 * time.Minute)
	if find(engine.Evaluate(t.Context()).Insights, "mixed_versions") == nil {
		t.Fatal("mixed versions did not fire")
	}
	// A condition that clears resets its clock.
	cluster.set(healthy())
	engine.Evaluate(t.Context())
	cluster.set(snapshot)
	c.Advance(10 * time.Second)
	if find(engine.Evaluate(t.Context()).Insights, "mixed_versions") != nil {
		t.Fatal("mixed versions clock did not reset")
	}
}

func TestEngineFallsBackToLocalSnapshot(t *testing.T) {
	cluster := &fakeCluster{err: errors.New("down")}
	local := observability.SnapshotSource(localSource{snapshot: observability.MemberSnapshot{Member: "c1", Ready: true,
		System: &observability.SystemView{MemTotalBytes: 100, MemAvailBytes: 5}}})
	engine := NewEngine(Config{Region: "gru", Cluster: cluster, Local: local})
	evaluation := engine.Evaluate(t.Context())
	if find(evaluation.Insights, "memory_pressure") == nil || len(evaluation.Unavailable) != 1 {
		t.Fatalf("evaluation = %+v", evaluation)
	}
}

type localSource struct{ snapshot observability.MemberSnapshot }

func (source localSource) Snapshot(context.Context, bool) (observability.MemberSnapshot, error) {
	return source.snapshot, nil
}

func evaluate(t *testing.T, rule func(*Inputs) []Insight, inputs *Inputs) []Insight {
	t.Helper()
	if inputs.Now.IsZero() {
		inputs.Now = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	}
	inputs.Thresholds = inputs.Thresholds.withDefaults()
	inputs.conditions, inputs.touched = map[string]time.Time{}, map[string]struct{}{}
	return rule(inputs)
}

func TestRulesStaySilentWithoutProviders(t *testing.T) {
	for _, rule := range DefaultRules() {
		if got := evaluate(t, rule.Evaluate, &Inputs{Region: "gru"}); len(got) != 0 {
			t.Errorf("%s fired without inputs: %+v", rule.Name, got)
		}
	}
}

func TestDiskRules(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	const size = 100 << 30
	member := func(avail uint64) *observability.ClusterSnapshot {
		return &observability.ClusterSnapshot{Members: []observability.MemberSnapshot{{Member: "c1",
			System: &observability.SystemView{Filesystems: []observability.FilesystemView{{Role: "nats", Path: "/var/lib/nats",
				SizeBytes: size, AvailBytes: avail}}}}}}
	}
	full := evaluate(t, diskTimeToFull, &Inputs{Now: now, Cluster: member(size / 50)})
	if len(full) != 1 || full[0].Severity != SeverityCritical || !strings.Contains(full[0].Title, "98%") {
		t.Fatalf("full = %+v", full)
	}
	// 50% used and growing 1 GiB per hour: full in 50 hours -> warning.
	history := observability.NewHistory(observability.HistoryConfig{})
	for minute := range 120 {
		at := now.Add(time.Duration(minute-120) * time.Minute)
		used := float64(size/2) - float64(120-minute)/60*float64(1<<30)
		history.Append(at, []observability.Sample{{Metric: observability.HistFSUsed,
			Labels: observability.L("member", "c1", "role", "nats"), Value: used}})
	}
	growing := evaluate(t, diskTimeToFull, &Inputs{Now: now, Cluster: member(size / 2), History: history})
	if len(growing) != 1 || growing[0].Severity != SeverityWarning || !strings.Contains(growing[0].Title, "full in about 2d") {
		t.Fatalf("growing = %+v", growing)
	}
	hours := growing[0].Evidence[0].Value
	if hours < 45 || hours > 55 {
		t.Fatalf("time to full = %.1fh", hours)
	}
	if quiet := evaluate(t, diskTimeToFull, &Inputs{Now: now, Cluster: member(size / 2)}); len(quiet) != 0 {
		t.Fatalf("without history a half-full disk is fine: %+v", quiet)
	}
}

func TestOCIErrorRule(t *testing.T) {
	now := time.Now()
	history := observability.NewHistory(observability.HistoryConfig{})
	for second := 0; second <= 300; second += 10 {
		history.Append(now.Add(time.Duration(second-300)*time.Second), []observability.Sample{
			{Metric: observability.HistOCIThrottled, Labels: observability.L("operation", "compute.LaunchInstance"),
				Value: float64(second) / 10, Counter: true},
			{Metric: observability.HistOCIErrors, Labels: observability.L("operation", "compute.LaunchInstance"),
				Value: 0, Counter: true},
		})
	}
	got := evaluate(t, ociErrors, &Inputs{Now: now, History: history})
	if len(got) != 1 || got[0].Key != "oci_errors:throttled" || got[0].Evidence[0].Value < 5.9 {
		t.Fatalf("oci = %+v", got)
	}
}

func TestPlacementRules(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	view := &observability.PlacementView{Databases: []observability.DatabaseView{{DatabaseID: "0000000000T8H7NEY8XQ530245", PartitionID: "00000000003K6TBW31R91GBDRD",
		Members: []observability.MemberView{
			{SeatID: "0000000000DNKA8DBDEPN1J9XM", Stage: "awaiting-attach", UpdatedAt: now.Add(-20 * time.Minute)},
			{SeatID: "0000000000K6ST06WNWDFCTSJY", Stage: "serving", UpdatePhase: "held"},
		},
		Rollout: &observability.RolloutView{OperationID: "0000000000M44BFMMJRNPNN6BB", Seats: 2, Completed: 1}}}}
	cluster := &observability.ClusterSnapshot{Members: []observability.MemberSnapshot{{Member: "c1", Placement: view}}}
	inputs := &Inputs{Now: now, Cluster: cluster,
		Holds: []Hold{{Reason: "member m7 OCI host is not currently observed; retained volume is kept", LastSeen: now}}}
	if got := evaluate(t, volumeStuck, inputs); len(got) != 1 || got[0].Entity.ID != "0000000000T8H7NEY8XQ530245/00000000003K6TBW31R91GBDRD/0000000000DNKA8DBDEPN1J9XM" {
		t.Fatalf("volume = %+v", got)
	}
	held := evaluate(t, memberHeld, inputs)
	if len(held) != 2 || held[0].Entity.ID != "0000000000T8H7NEY8XQ530245/00000000003K6TBW31R91GBDRD/0000000000K6ST06WNWDFCTSJY" || held[1].Entity.ID != "m7" {
		t.Fatalf("held = %+v", held)
	}
	// The rollout must stay at the same progress past the threshold.
	conditions := map[string]time.Time{"rollout:0000000000M44BFMMJRNPNN6BB:1": now.Add(-31 * time.Minute)}
	inputs = &Inputs{Now: now, Cluster: cluster, Thresholds: Thresholds{}.withDefaults(), conditions: conditions,
		touched: map[string]struct{}{}}
	if got := rolloutStalled(inputs); len(got) != 1 || got[0].Entity.ID != "0000000000M44BFMMJRNPNN6BB" {
		t.Fatalf("stalled = %+v", got)
	}
}

func TestOptionalProviderRules(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	inputs := &Inputs{Now: now,
		Rollouts:     []Rollout{{ID: "r1", Release: "sha256:abc", Phase: "soak", PhaseDeadline: now.Add(-2 * time.Hour)}},
		Volumes:      []Volume{{ID: "ocid1.volume.x", State: "ATTACHING", StateSince: now.Add(-time.Hour)}},
		Certificates: []Certificate{{Name: "nats-tls", Kind: "tls", NotAfter: now.Add(48 * time.Hour)}},
		Peers:        []NetBirdPeer{{Name: "host-1", Relayed: true, Connected: true}},
		Autoscalers:  []Autoscaler{{Name: "tb", Current: 5, Max: 5, AtMaxSince: now.Add(-time.Hour)}},
		Budgets:      []Budget{{Name: "ocpu", Used: 95, Ceiling: 100, Unit: "OCPU"}},
		Decisions: []decisionlog.Decision{
			{Kind: decisionlog.KindHeld, Time: now.Add(-time.Minute), Subject: decisionlog.Subject{Kind: "member", ID: "m1"}},
			{Kind: decisionlog.KindHeld, Time: now.Add(-2 * time.Minute), Subject: decisionlog.Subject{Kind: "member", ID: "m1"}},
			{Kind: decisionlog.KindHeld, Time: now.Add(-3 * time.Minute), Subject: decisionlog.Subject{Kind: "member", ID: "m1"}},
		},
	}
	cases := map[string]struct {
		rule     func(*Inputs) []Insight
		severity Severity
	}{
		"rollout":     {rolloutDeadline, SeverityCritical},
		"volume":      {volumeStuck, SeverityWarning},
		"certificate": {certificateExpiring, SeverityCritical},
		"peer":        {netbirdPeers, SeverityInfo},
		"autoscaler":  {autoscalerAtMax, SeverityWarning},
		"budget":      {budgetCeiling, SeverityWarning},
		"holds":       {memberHeld, SeverityInfo},
	}
	for name, test := range cases {
		got := evaluate(t, test.rule, inputs)
		if len(got) != 1 || got[0].Severity != test.severity || got[0].Why == "" || got[0].Title == "" {
			t.Errorf("%s = %+v", name, got)
		}
	}
	inputs.Reachability = []RegionReach{{Region: "sfo", State: decisionlog.RegionUnreachable},
		{Region: "fra", State: decisionlog.RegionNotLinked}}
	inputs.conditions = map[string]time.Time{"region:sfo": now.Add(-2 * time.Minute)}
	inputs.touched = map[string]struct{}{}
	if got := regionUnreachable(inputs); len(got) != 1 || got[0].Region != "sfo" {
		t.Fatalf("regions = %+v", got)
	}
}

func TestSummaryIsDeterministic(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	decisions := []decisionlog.Decision{
		{ID: "1", Kind: decisionlog.KindHeld, Time: now.Add(-10 * time.Minute)},
		{ID: "2", Kind: decisionlog.KindHeld, Time: now.Add(-20 * time.Minute)},
		{ID: "3", Kind: decisionlog.KindLeaderChanged, Time: now.Add(-30 * time.Minute), Epoch: 9,
			Subject: decisionlog.Subject{Kind: "member", ID: "ctrl-2"}},
		{ID: "4", Kind: decisionlog.KindRollback, Time: now.Add(-40 * time.Minute), Reason: "Canary failed its health gate",
			Subject: decisionlog.Subject{Kind: "release", ID: "sha256:0123456789abcdef"}, Status: decisionlog.StatusFailed},
		{ID: "5", Kind: decisionlog.KindScaleUp, Time: now.Add(-2 * time.Hour)},
	}
	open := []Insight{{Key: "a", Severity: SeverityWarning, Title: "Mixed orchestrator versions"},
		{Key: "b", Severity: SeverityCritical, Title: "Controller quorum at risk"}}
	changes := []Change{{Type: ChangeOpened, Time: now.Add(-5 * time.Minute)},
		{Type: ChangeResolved, Time: now.Add(-3 * time.Minute)}, {Type: ChangeOpened, Time: now.Add(-3 * time.Hour)}}
	input := SummaryInput{Now: now, Window: time.Hour, Scope: "GRU", Decisions: decisions, Changes: changes, Open: open}
	first := Summarize(input)
	want := "In the last hour the orchestrator made 4 decisions in GRU: 2 holds, 1 leader change and 1 rollback. " +
		"Authority leadership moved to ctrl-2 (epoch 9). A rollback of 0123456789ab was decided because canary " +
		"failed its health gate. 1 decision failed. 1 problem opened and 1 problem resolved. Now 1 critical " +
		"problem and 1 warning need attention, most urgently: Controller quorum at risk."
	if first.Text != want {
		t.Fatalf("summary:\n got %q\nwant %q", first.Text, want)
	}
	for range 5 {
		if again := Summarize(input); again.Text != first.Text {
			t.Fatal("summary is not deterministic")
		}
	}
	day := Summarize(SummaryInput{Now: now, Window: 24 * time.Hour, Scope: "GRU", Decisions: decisions})
	if !strings.HasPrefix(day.Text, "In the last 24 hours the orchestrator made 5 decisions") ||
		!strings.HasSuffix(day.Text, "Nothing needs attention right now.") {
		t.Fatalf("day = %q", day.Text)
	}
	truncated := Summarize(SummaryInput{Now: now, Window: 24 * time.Hour, Scope: "GRU", Decisions: decisions,
		DecisionsTruncated: true})
	if !strings.HasPrefix(truncated.Text, "In the last 24 hours the orchestrator made at least 5 decisions") {
		t.Fatalf("truncated = %q", truncated.Text)
	}
	empty := Summarize(SummaryInput{Now: now, Window: time.Hour})
	if empty.Text != "In the last hour the orchestrator made no recorded decisions in the region. Nothing needs attention right now." {
		t.Fatalf("empty = %q", empty.Text)
	}
}

func TestSummarizerReadsProviders(t *testing.T) {
	journal := decisionlog.NewJournal(decisionlog.JournalConfig{Region: "gru"})
	journal.Record(t.Context(), decisionlog.Decision{Kind: decisionlog.KindScaleUp})
	engine := NewEngine(Config{Region: "gru", Cluster: &fakeCluster{snapshot: healthy()}, Decisions: journal})
	engine.Evaluate(t.Context())
	summary, err := Summarizer{Decisions: journal, Insights: engine, Scope: "GRU"}.Summary(t.Context(), time.Hour)
	if err != nil || summary.Decisions != 1 || !strings.Contains(summary.Text, "1 scale-up") {
		t.Fatalf("summary = %+v err=%v", summary, err)
	}
}

func TestEngineConcurrentUse(t *testing.T) {
	cluster := &fakeCluster{snapshot: healthy()}
	engine := NewEngine(Config{Region: "gru", Cluster: cluster})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var group sync.WaitGroup
	for worker := range 4 {
		group.Go(func() {
			for index := range 50 {
				snapshot := healthy()
				if (index+worker)%2 == 0 {
					snapshot.Members, snapshot.Missing = snapshot.Members[:2], []string{"c3"}
				}
				cluster.set(snapshot)
				engine.Evaluate(ctx)
			}
		})
		group.Go(func() {
			for range 50 {
				_ = engine.Current()
				_ = engine.Changes(time.Time{})
			}
		})
		group.Go(func() {
			subCtx, subCancel := context.WithTimeout(ctx, 20*time.Millisecond)
			defer subCancel()
			for range engine.Subscribe(subCtx, 4) {
			}
		})
	}
	group.Wait()
}

func TestHandler(t *testing.T) {
	engine := NewEngine(Config{Region: "gru", Cluster: &fakeCluster{snapshot: healthy()}})
	engine.Evaluate(t.Context())
	handler := Handler(engine, Summarizer{Insights: engine, Scope: "GRU"})
	for path, want := range map[string]int{
		"/v1/insights":             http.StatusOK,
		"/v1/summary":              http.StatusOK,
		"/v1/summary?window=24h":   http.StatusOK,
		"/v1/summary?window=1s":    http.StatusBadRequest,
		"/v1/summary?window=never": http.StatusBadRequest,
	} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != want {
			t.Fatalf("%s = %d %s", path, recorder.Code, recorder.Body)
		}
	}
}

func TestClockSkewWarnsPagesAndPagesOnLostSync(t *testing.T) {
	for _, test := range []struct {
		clock observability.ClockView
		want  Severity
	}{
		{observability.ClockView{Synchronized: true, OffsetSeconds: 0.0002, MaxErrorSeconds: 0.03}, ""},
		{observability.ClockView{Synchronized: true, OffsetSeconds: -0.15, MaxErrorSeconds: 0.03}, SeverityWarning},
		{observability.ClockView{Synchronized: true, MaxErrorSeconds: 0.6}, SeverityCritical},
		{observability.ClockView{MaxErrorSeconds: 0.001}, SeverityCritical},
	} {
		clock := test.clock
		got := evaluate(t, clockSkew, &Inputs{Cluster: &observability.ClusterSnapshot{Members: []observability.MemberSnapshot{
			{Member: "ts-gru-1", System: &observability.SystemView{Clock: &clock}}}}})
		if test.want == "" && len(got) != 0 || test.want != "" && (len(got) != 1 || got[0].Severity != test.want) {
			t.Errorf("clock %+v: insights = %+v, want %q", clock, got, test.want)
		}
	}
}
