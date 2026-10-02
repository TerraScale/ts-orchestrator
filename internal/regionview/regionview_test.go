package regionview

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/insights"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionlink"
)

type staticCluster struct{ snapshot observability.ClusterSnapshot }

func (cluster staticCluster) Cluster(context.Context, bool) (observability.ClusterSnapshot, error) {
	return cluster.snapshot, nil
}

type staticInsights struct{ open []insights.Insight }

func (source staticInsights) Current() insights.Evaluation {
	return insights.Evaluation{Insights: source.open, Counts: insights.Count(source.open)}
}
func (staticInsights) Changes(time.Time) []insights.Change { return nil }
func (staticInsights) Subscribe(ctx context.Context, _ int) <-chan insights.Change {
	out := make(chan insights.Change)
	context.AfterFunc(ctx, func() { close(out) })
	return out
}

func member(name, version string, leader bool) observability.MemberSnapshot {
	return observability.MemberSnapshot{Member: name, Role: "controller", Ready: true, BuildVersion: version,
		Authority: &observability.AuthorityView{Leader: leader, Ready: true, OwnerID: "c1", Epoch: 4},
		NATS:      &observability.NATSView{MetaLeader: "c2", StoreUsedBytes: 10, StoreLimitBytes: 100},
		System: &observability.SystemView{CPUCount: 2, MemTotalBytes: 100, MemAvailBytes: 40,
			Filesystems: []observability.FilesystemView{{Role: "nats", SizeBytes: 1000, AvailBytes: 600}}},
		Placement: &observability.PlacementView{Databases: []observability.DatabaseView{{DatabaseID: "db",
			DesiredSeats: 2, Serving: 2, Rollout: &observability.RolloutView{OperationID: "op", Seats: 2, Completed: 1}}}},
	}
}

func cluster(members ...observability.MemberSnapshot) observability.ClusterSnapshot {
	return observability.ClusterSnapshot{Cell: "gru", Expected: []string{"c1", "c2", "c3"}, Members: members}
}

func TestLocalSummary(t *testing.T) {
	journal := decisionlog.NewJournal(decisionlog.JournalConfig{Region: "gru"})
	for range 7 {
		journal.Record(t.Context(), decisionlog.Decision{Kind: decisionlog.KindHeld})
	}
	open := []insights.Insight{{Rule: "disk_time_to_full", Severity: insights.SeverityWarning},
		{Rule: "quorum_at_risk", Severity: insights.SeverityWarning}}
	provider := &Provider{Cell: "GRU", Cluster: staticCluster{cluster(member("c1", "v1", true), member("c2", "v1", false),
		member("c3", "v1", false))}, Decisions: journal, Insights: staticInsights{open}}
	summary := provider.Local(t.Context())
	if summary.Region != "gru" || !summary.Local || summary.Reach != decisionlog.RegionOK {
		t.Fatalf("identity = %+v", summary)
	}
	if !summary.Quorum.Healthy || summary.Quorum.Required != 2 || summary.Quorum.Ready != 3 {
		t.Fatalf("quorum = %+v", summary.Quorum)
	}
	if summary.Leaders.Authority != "c1" || summary.Leaders.Epoch != 4 || summary.Leaders.MetaLeader != "c2" {
		t.Fatalf("leaders = %+v", summary.Leaders)
	}
	if summary.Capacity.CPUs != 6 || summary.Capacity.MemoryUsedBytes != 180 || summary.Capacity.DiskUsedBytes != 1200 {
		t.Fatalf("capacity = %+v", summary.Capacity)
	}
	if summary.TerraBase.Databases != 1 || len(summary.Rollouts) != 1 || summary.MixedVersions() {
		t.Fatalf("terrabase = %+v rollouts=%d", summary.TerraBase, len(summary.Rollouts))
	}
	if len(summary.Decisions) != DefaultLatestDecisions || summary.Counts.Warning != 2 {
		t.Fatalf("decisions=%d counts=%+v", len(summary.Decisions), summary.Counts)
	}
	// The quorum insight is scored from the snapshot, not twice.
	if summary.Health.Score != 92 || summary.Health.Status != StatusHealthy {
		t.Fatalf("health = %+v", summary.Health)
	}
}

func TestScore(t *testing.T) {
	lost := Summary{Quorum: Quorum{Expected: 3, Answering: 1, Ready: 1, Required: 2}}
	if health := score(lost, true, nil); health.Status != StatusCritical || health.Score != 0 {
		t.Fatalf("lost quorum = %+v", health)
	}
	degraded := Summary{Quorum: Quorum{Expected: 3, Answering: 2, Ready: 2, Required: 2, Healthy: true},
		Leaders: Leaders{Authority: "c1"}, Versions: []Version{{Version: "a"}, {Version: "b"}}}
	health := score(degraded, true, []insights.Insight{{Severity: insights.SeverityCritical}})
	if health.Score != 55 || health.Status != StatusDegraded || len(health.Reasons) != 3 {
		t.Fatalf("degraded = %+v", health)
	}
	if health := score(Summary{}, false, nil); health.Status != StatusUnknown {
		t.Fatalf("unobserved = %+v", health)
	}
}

func TestRegionsAcrossLinks(t *testing.T) {
	srv, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS did not start")
	}
	t.Cleanup(func() { srv.Shutdown(); srv.WaitForShutdown() })
	conn, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	remoteJournal := decisionlog.NewJournal(decisionlog.JournalConfig{Region: "sfo"})
	remoteJournal.Record(ctx, decisionlog.Decision{Kind: decisionlog.KindScaleUp})
	remoteJournal.Ingest(decisionlog.Decision{ID: "forged", Region: "gru", Kind: decisionlog.KindRollback,
		Time: time.Now()})
	remote := &Provider{Cell: "sfo", Cluster: staticCluster{cluster(member("s1", "v2", true))},
		Decisions: remoteJournal}
	if _, err := Serve(ctx, conn, "sfo", remote); err != nil {
		t.Fatal(err)
	}
	links, err := regionlink.New("gru", conn, []string{"GRU", "SFO", "FRA", "MIA"}, 500*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	_ = links.Link("sfo", conn)
	_ = links.Link("mia", conn)
	local := &Provider{Cell: "gru", Cluster: staticCluster{cluster(member("c1", "v1", true))}, Links: links}
	summaries := local.Regions(ctx)
	if len(summaries) != 4 || summaries[0].Region != "gru" || !summaries[0].Local {
		t.Fatalf("summaries = %+v", summaries)
	}
	byRegion := map[string]Summary{}
	for _, summary := range summaries {
		byRegion[summary.Region] = summary
	}
	if sfo := byRegion["sfo"]; sfo.Reach != decisionlog.RegionOK || sfo.Local || len(sfo.Versions) != 1 ||
		sfo.Versions[0].Version != "v2" || len(sfo.Decisions) != 1 {
		t.Fatalf("sfo = %+v", sfo)
	}
	if fra := byRegion["fra"]; fra.Reach != decisionlog.RegionNotLinked || fra.Health.Status != StatusUnknown {
		t.Fatalf("fra = %+v", fra)
	}
	if mia := byRegion["mia"]; mia.Reach != decisionlog.RegionUnreachable {
		t.Fatalf("mia = %+v", mia)
	}
	reach := local.Reachability(ctx)
	if len(reach) != 3 {
		t.Fatalf("reach = %+v", reach)
	}
	if _, err := local.Region(ctx, "SFO"); err != nil {
		t.Fatal(err)
	}
	if _, err := local.Region(ctx, "nowhere"); err == nil {
		t.Fatal("unknown region must fail")
	}
	// Concurrent dashboard streams share the cached gather.
	var group sync.WaitGroup
	for range 8 {
		group.Go(func() { _ = local.Regions(ctx) })
	}
	group.Wait()
}
