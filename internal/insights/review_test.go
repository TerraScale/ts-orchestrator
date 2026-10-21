package insights

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/decisionlog"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

// These pin the fixes for the ts-reviewer findings on PR #121.

func TestDiskUsageWarningDoesNotHideAFasterFill(t *testing.T) {
	now := time.Now().UTC()
	const size = 100 << 30
	// 86% used (past the 85% warning) and filling 2 GiB an hour: full in
	// about 7 hours, which is critical.
	used := float64(size) * 0.86
	history := observability.NewHistory(observability.HistoryConfig{})
	for minute := range 120 {
		at := now.Add(time.Duration(minute-120) * time.Minute)
		history.Append(at, []observability.Sample{{Metric: observability.HistFSUsed,
			Labels: observability.L("member", "c1", "role", "nats"), Value: used - float64(120-minute)/60*float64(2<<30)}})
	}
	cluster := &observability.ClusterSnapshot{Members: []observability.MemberSnapshot{{Member: "c1",
		System: &observability.SystemView{Filesystems: []observability.FilesystemView{{Role: "nats", Path: "/var/lib/nats",
			SizeBytes: size, AvailBytes: uint64(size - used)}}}}}}
	got := evaluate(t, diskTimeToFull, &Inputs{Now: now, Cluster: cluster, History: history})
	if len(got) != 1 || got[0].Severity != SeverityCritical || got[0].Key != "disk:c1:nats" ||
		!strings.Contains(got[0].Title, "full in about") {
		t.Fatalf("disk = %+v", got)
	}
	// Without growth the same disk is a usage warning under the same key.
	still := evaluate(t, diskTimeToFull, &Inputs{Now: now, Cluster: cluster})
	if len(still) != 1 || still[0].Severity != SeverityWarning || still[0].Key != "disk:c1:nats" {
		t.Fatalf("still = %+v", still)
	}
}

func TestHoldsInDifferentPartitionsStaySeparate(t *testing.T) {
	view := &observability.PlacementView{Databases: []observability.DatabaseView{
		{DatabaseID: "0000000000T8H7NEY8XQ530245", PartitionID: "00000000003K6TBW31R91GBDRD", Members: []observability.MemberView{{SeatID: "000000000082AXF7GZQT1D126Y", UpdatePhase: "held"}}},
		{DatabaseID: "0000000000T8H7NEY8XQ530245", PartitionID: "00000000003ZJEV7X3HYJENEYG", Members: []observability.MemberView{{SeatID: "000000000082AXF7GZQT1D126Y", UpdatePhase: "held"}}}}}
	engine := NewEngine(Config{Region: "gru", Cluster: &fakeCluster{snapshot: observability.ClusterSnapshot{
		Members: []observability.MemberSnapshot{{Member: "c1", Placement: view}}}}})
	held := 0
	for _, insight := range engine.Evaluate(t.Context()).Insights {
		if insight.Rule == "member_held" {
			held++
		}
	}
	if held != 2 {
		t.Fatalf("held insights = %d, want one per partition", held)
	}
}

// A pass that cannot read an input keeps that input's insights open: a
// missing observation is not a recovery.
func TestUnavailableInputDoesNotResolveInsights(t *testing.T) {
	snapshot := healthy()
	snapshot.Members[2].System = &observability.SystemView{MemTotalBytes: 100, MemAvailBytes: 2}
	cluster := &fakeCluster{snapshot: snapshot}
	local := localSource{snapshot: controller("c1", true)}
	var changes []Change
	engine := NewEngine(Config{Region: "gru", Cluster: cluster, Local: local})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	stream := engine.Subscribe(ctx, 16)
	if find(engine.Evaluate(t.Context()).Insights, "memory_pressure") == nil {
		t.Fatal("no memory insight for c3")
	}
	cluster.mu.Lock()
	cluster.err = errors.New("no responders")
	cluster.mu.Unlock()
	evaluation := engine.Evaluate(t.Context())
	if find(evaluation.Insights, "memory_pressure") == nil {
		t.Fatalf("a failed cluster read resolved c3's memory insight: %+v", evaluation)
	}
	for drained := false; !drained; {
		select {
		case change := <-stream:
			changes = append(changes, change)
		default:
			drained = true
		}
	}
	for _, change := range changes {
		if change.Type == ChangeResolved {
			t.Fatalf("a failed read emitted a resolution: %+v", change)
		}
	}
	// A successful read that no longer shows the problem resolves it.
	cluster.mu.Lock()
	cluster.err, cluster.snapshot = nil, healthy()
	cluster.mu.Unlock()
	if find(engine.Evaluate(t.Context()).Insights, "memory_pressure") != nil {
		t.Fatal("a recovered member stays open")
	}
}

type truncatingDecisions struct{ query decisionlog.Query }

func (source *truncatingDecisions) Query(_ context.Context, query decisionlog.Query) (decisionlog.Result, error) {
	source.query = query
	return decisionlog.Result{Truncated: true}, nil
}

func (*truncatingDecisions) Chain(context.Context, string) (decisionlog.Chain, error) {
	return decisionlog.Chain{}, decisionlog.ErrNotFound
}

func TestRepeatedHoldRuleReadsOnlyHoldsAndRejectsIncompleteInput(t *testing.T) {
	source := &truncatingDecisions{}
	engine := NewEngine(Config{Region: "gru", Decisions: source})
	evaluation := engine.Evaluate(t.Context())
	if len(source.query.Kinds) != 1 || source.query.Kinds[0] != decisionlog.KindHeld {
		t.Fatalf("query = %+v", source.query)
	}
	if !strings.Contains(strings.Join(evaluation.Unavailable, ","), "decisions") {
		t.Fatalf("a truncated hold query is complete input: %+v", evaluation.Unavailable)
	}
}

func TestSummaryQualifiesPartialHistoryAndScope(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	empty := Summarize(SummaryInput{Now: now, Window: time.Hour, Scope: "all regions", DecisionsPartial: true,
		Unanswered: []string{"sjc"}, AttentionScope: "GRU"})
	if strings.Contains(empty.Text, "made no recorded decisions") || !strings.Contains(empty.Text, "SJC did not answer") ||
		!strings.Contains(empty.Text, "Nothing needs attention in GRU") || !empty.Partial {
		t.Fatalf("partial empty summary = %q", empty.Text)
	}
	some := Summarize(SummaryInput{Now: now, Window: time.Hour, Scope: "all regions", DecisionsPartial: true,
		Decisions: []decisionlog.Decision{{Time: now.Add(-time.Minute), Kind: decisionlog.KindScaleUp}},
		Changes:   []Change{{Type: ChangeOpened, Time: now.Add(-time.Minute)}}, ChangesTruncated: true})
	if !strings.Contains(some.Text, "at least 1 decision") || !strings.Contains(some.Text, "At least 1 problem opened") {
		t.Fatalf("partial summary = %q", some.Text)
	}
}

func TestEngineReportsDroppedChanges(t *testing.T) {
	engine := NewEngine(Config{Region: "gru"})
	if !engine.ChangesComplete(time.Time{}) {
		t.Fatal("a fresh engine reports dropped changes")
	}
	engine.mu.Lock()
	engine.droppedThrough = time.Date(2026, 10, 2, 11, 0, 0, 0, time.UTC)
	engine.mu.Unlock()
	if engine.ChangesComplete(time.Date(2026, 10, 2, 10, 0, 0, 0, time.UTC)) ||
		!engine.ChangesComplete(time.Date(2026, 10, 2, 11, 30, 0, 0, time.UTC)) {
		t.Fatal("ChangesComplete does not follow the dropped boundary")
	}
}

// These pin the fixes for the ts-reviewer findings on PRs #127 and #130.

// A rule that observed health resets its timer even while another rule is
// blind, so a later failure waits a fresh interval.
func TestObservableRuleResetsTimerWhileAnotherRuleIsBlind(t *testing.T) {
	ticks := 0
	rules := []Rule{
		{Name: "watched", Evaluate: func(inputs *Inputs) []Insight {
			ticks++
			if ticks == 1 {
				inputs.Since("watched:x")
			}
			return nil
		}},
		{Name: "volume_stuck", Evaluate: func(*Inputs) []Insight { return nil }},
	}
	engine := NewEngine(Config{Region: "gru", Volumes: failingVolumes{}, Rules: rules})
	engine.Evaluate(t.Context())
	engine.Evaluate(t.Context())
	engine.mu.Lock()
	_, kept := engine.conditions["watched:x"]
	engine.mu.Unlock()
	if kept {
		t.Fatal("a healthy observation kept its timer because an unrelated rule was blind")
	}
}

type failingVolumes struct{}

func (failingVolumes) Volumes(context.Context) ([]Volume, error) { return nil, errors.New("down") }

// A held seat read from placement resolves once placement shows the hold
// cleared, even while the journal input of the same rule is unavailable.
func TestSeatHoldResolvesWhileTheJournalIsUnavailable(t *testing.T) {
	held := &observability.PlacementView{Databases: []observability.DatabaseView{{DatabaseID: "0000000000T8H7NEY8XQ530245", PartitionID: "00000000003K6TBW31R91GBDRD",
		Members: []observability.MemberView{{SeatID: "000000000082AXF7GZQT1D126Y", UpdatePhase: "held"}}}}}
	cluster := &fakeCluster{snapshot: observability.ClusterSnapshot{
		Members: []observability.MemberSnapshot{{Member: "c1", Placement: held}}}}
	engine := NewEngine(Config{Region: "gru", Cluster: cluster, Decisions: &truncatingDecisions{}})
	if find(engine.Evaluate(t.Context()).Insights, "member_held") == nil {
		t.Fatal("no hold insight")
	}
	cluster.mu.Lock()
	cluster.snapshot = observability.ClusterSnapshot{Members: []observability.MemberSnapshot{{Member: "c1",
		Placement: &observability.PlacementView{}}}}
	cluster.mu.Unlock()
	if find(engine.Evaluate(t.Context()).Insights, "member_held") != nil {
		t.Fatal("an observed recovery stayed open because the journal input was unavailable")
	}
}

// A stuck attachment reported by its seat is not reported again by the
// volume provider describing the same placement state.
func TestStuckAttachmentIsReportedOnce(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	since := now.Add(-time.Hour)
	view := &observability.PlacementView{Databases: []observability.DatabaseView{{DatabaseID: "0000000000T8H7NEY8XQ530245", PartitionID: "00000000003K6TBW31R91GBDRD",
		Members: []observability.MemberView{{SeatID: "000000000082AXF7GZQT1D126Y", Stage: "awaiting-attach", HostNode: "host-a",
			UpdatedAt: since}}}}}
	cluster := &observability.ClusterSnapshot{Members: []observability.MemberSnapshot{{Member: "c1", Placement: view}}}
	got := evaluate(t, volumeStuck, &Inputs{Now: now, Cluster: cluster, Thresholds: Thresholds{}.withDefaults(),
		Volumes: []Volume{{ID: "vol-1", Host: "host-a", State: "attaching", StateSince: since}}})
	if len(got) != 1 {
		t.Fatalf("stuck attachment insights = %+v, want one", got)
	}
}

// The repeated-hold link searches the subject ID the decision search matches.
func TestRepeatedHoldLinkSearchesTheSubjectID(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	var decisions []decisionlog.Decision
	for range 5 {
		decisions = append(decisions, decisionlog.Decision{Kind: decisionlog.KindHeld, Time: now.Add(-time.Minute),
			Subject: decisionlog.Subject{Kind: "operation", ID: "op 123"}})
	}
	got := evaluate(t, memberHeld, &Inputs{Now: now, Decisions: decisions, Thresholds: Thresholds{}.withDefaults()})
	if len(got) != 1 || got[0].Entity.Href != "/decisions?q=op+123" {
		t.Fatalf("repeated hold = %+v", got)
	}
}

// A truncated decision count is a lower bound and marks the summary partial.
func TestTruncatedDecisionsMarkTheSummaryPartial(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	summary := Summarize(SummaryInput{Now: now, Window: time.Hour, Scope: "GRU", DecisionsTruncated: true,
		Decisions: []decisionlog.Decision{{Time: now.Add(-time.Minute), Kind: decisionlog.KindScaleUp}}})
	if !summary.Partial {
		t.Fatalf("truncated summary = %+v", summary)
	}
}
