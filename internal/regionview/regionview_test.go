package regionview

import (
	"context"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"

	"github.com/TerraScale/ts-orchestrator/internal/decisionlog"
	"github.com/TerraScale/ts-orchestrator/internal/insights"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/ocicost"
	"github.com/TerraScale/ts-orchestrator/internal/regionlink"
)

func TestLocalSummaryCarriesCost(t *testing.T) {
	view := &ocicost.View{Cell: "gru", OCIRegion: "sa-saopaulo-1", Forecast: ocicost.Forecast{MonthEndCents: 3100}}
	provider := &Provider{Cell: "gru", Cost: func(context.Context) *ocicost.View { return view }}
	summary := provider.Local(t.Context())
	if summary.Cost != view {
		t.Fatalf("cost = %+v, want the provider's view", summary.Cost)
	}
	wire, err := json.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}
	var got Summary
	if err := json.Unmarshal(wire, &got); err != nil {
		t.Fatal(err)
	}
	if got.Cost == nil || got.Cost.Forecast.MonthEndCents != 3100 {
		t.Fatalf("cost after a JSON round trip = %+v", got.Cost)
	}
	// A region without a cost view omits the field.
	provider.Cost = nil
	if wire, err = json.Marshal(provider.Local(t.Context())); err != nil || strings.Contains(string(wire), `"cost":`) {
		t.Fatalf("summary without a cost view = %s, %v", wire, err)
	}
}

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
		Authority: &observability.AuthorityView{Leader: leader, Ready: true, OwnerID: "0000000000T3V33JGXVEMDPEYF", Epoch: 4},
		NATS:      &observability.NATSView{MetaLeader: "c2", StoreUsedBytes: 10, StoreLimitBytes: 100},
		System: &observability.SystemView{CPUCount: 2, MemTotalBytes: 100, MemAvailBytes: 40,
			Filesystems: []observability.FilesystemView{{Role: "nats", SizeBytes: 1000, AvailBytes: 600}}},
		Placement: &observability.PlacementView{Databases: []observability.DatabaseView{{DatabaseID: "0000000000FFE2BMB99VWR8Y1A",
			DesiredSeats: 2, Serving: 2, Rollout: &observability.RolloutView{OperationID: "00000000000DXENTQMQFS6VPNY", Seats: 2, Completed: 1}}}},
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

func TestLocalSummaryTopology(t *testing.T) {
	leader := member("c2", "v1", true)
	leader.Placement.Databases[0].Members = []observability.MemberView{
		{SeatID: "0000000000D0AGSZ25QNHAF8B6", HostNode: "h1", Stage: "serving"}, {SeatID: "000000000098SVGR6D35X6XPT3", HostNode: "h1", Stage: "draining"},
		{SeatID: "0000000000VEJ0PH18NVM0KEPW", HostNode: "h0", Stage: "serving"}, {SeatID: "0000000000RPN0Y82EPE5T3G2C"}}
	host := observability.MemberSnapshot{Member: "h0", Role: "host", Ready: false}
	provider := &Provider{Cell: "gru", Cluster: staticCluster{cluster(leader, member("c1", "v1", false), host)}}
	summary := provider.Local(t.Context())
	want := []Member{{Name: "c1", Role: "controller", Ready: true, Version: "v1"},
		{Name: "c2", Role: "controller", Ready: true, Version: "v1"}, {Name: "h0", Role: "host"}}
	if !slices.Equal(summary.Members, want) {
		t.Fatalf("members = %+v", summary.Members)
	}
	hosts := []Host{{Name: "h0", Seats: 1, Readiness: "unknown", ReadinessReason: "current native root task and member readiness source is unavailable"},
		{Name: "h1", Seats: 2, Readiness: "unknown", ReadinessReason: "current native root task and member readiness source is unavailable"}}
	if !slices.Equal(summary.Hosts, hosts) {
		t.Fatalf("hosts = %+v", summary.Hosts)
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

	remoteJournal := decisionlog.NewJournal(decisionlog.JournalConfig{Region: "sjc"})
	remoteJournal.Record(ctx, decisionlog.Decision{Kind: decisionlog.KindScaleUp})
	remoteJournal.Ingest(decisionlog.Decision{ID: "forged", Region: "gru", Kind: decisionlog.KindRollback,
		Time: time.Now()})
	remote := &Provider{Cell: "sjc", Cluster: staticCluster{cluster(member("s1", "v2", true))},
		Decisions: remoteJournal}
	if _, err := Serve(ctx, conn, "sjc", remote); err != nil {
		t.Fatal(err)
	}
	links, err := regionlink.New("gru", conn, []string{"GRU", "SJC", "FRA", "MIA"}, 500*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	_ = links.Link("sjc", conn)
	_ = links.Link("mia", conn)
	local := &Provider{Cell: "gru", Cluster: staticCluster{cluster(member("c1", "v1", true))}, Links: links}
	sjc := local.Probe(ctx, "sjc")
	if sjc.Reach != decisionlog.RegionOK || sjc.Local || len(sjc.Versions) != 1 ||
		sjc.Versions[0].Version != "v2" || len(sjc.Decisions) != 1 {
		t.Fatalf("sjc = %+v", sjc)
	}
	if fra := local.Probe(ctx, "fra"); fra.Reach != decisionlog.RegionNotLinked || fra.Health.Status != StatusUnknown {
		t.Fatalf("fra = %+v", fra)
	}
	if mia := local.Probe(ctx, "mia"); mia.Reach != decisionlog.RegionUnreachable {
		t.Fatalf("mia = %+v", mia)
	}
	// The dashboard reads other regions from the global view; probes alone
	// feed reachability.
	if reach := local.Reachability(ctx); reach != nil {
		t.Fatalf("reach = %+v", reach)
	}

	observedAt := time.Now().UTC()
	reverse, err := regionlink.New("sjc", conn, []string{"gru", "lab", "sjc"}, 500*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	for _, region := range []string{"gru", "lab"} {
		if err := reverse.Link(region, conn); err != nil {
			t.Fatal(err)
		}
	}
	requester := &Provider{Cell: "sjc", Links: reverse, Now: func() time.Time { return observedAt }}
	journal := decisionlog.NewJournal(decisionlog.JournalConfig{Region: "gru"})
	for range 7 {
		journal.Record(ctx, decisionlog.Decision{Kind: decisionlog.KindHeld})
	}
	oldLeader := member("c1", "v1", true)
	oldLeader.Authority = &observability.AuthorityView{Leader: true, Ready: true, OwnerID: "c1", Epoch: 4}
	follower := member("c2", "v1", false)
	follower.Authority = &observability.AuthorityView{Ready: true, OwnerID: "c3", Epoch: 5}
	lost := member("c1", "v1", false)
	lost.Authority = &observability.AuthorityView{Ready: false, OwnerID: "c1-candidate"}
	databaseLeader := member("c1", "v1", true)
	databaseLeader.Placement = &observability.PlacementView{Databases: []observability.DatabaseView{
		{DatabaseID: "orders", PartitionID: "p0", DesiredSeats: 2}, {DatabaseID: "orders", PartitionID: "p1", DesiredSeats: 2},
		{DatabaseID: "billing", PartitionID: "p0", DesiredSeats: 2}}}
	var legacyMembers []observability.MemberSnapshot
	legacyNames := make(map[string][]string)
	for version := range maxTopologyMembers {
		label := fmt.Sprint(version)
		for index := range maxTopologyMembers {
			name := fmt.Sprintf("v%d-m%d", version, index)
			legacyMembers = append(legacyMembers, observability.MemberSnapshot{Member: name, BuildVersion: label})
			legacyNames[label] = append(legacyNames[label], name)
		}
		slices.Sort(legacyNames[label])
	}
	for _, test := range []struct {
		name, region string
		provider     *Provider
	}{
		{"summary", "gru", &Provider{Cell: "GRU", Cluster: staticCluster{cluster(member("c1", "v1", true), member("c2", "v1", false),
			member("c3", "v1", false))}, Decisions: journal, Insights: staticInsights{[]insights.Insight{
			{Rule: "disk_time_to_full", Severity: insights.SeverityWarning}, {Rule: "quorum_at_risk", Severity: insights.SeverityWarning}}}}},
		{"insight region", "gru", &Provider{Cell: "gru", Cluster: staticCluster{cluster(member("c1", "v1", true), member("c2", "v1", false),
			member("c3", "v1", false))}, Insights: staticInsights{[]insights.Insight{
			{Rule: "region_unreachable", Region: "sjc", Severity: insights.SeverityCritical},
			{Rule: "disk_time_to_full", Region: "gru", Severity: insights.SeverityWarning}}}}},
		{"leader first", "gru", &Provider{Cell: "gru", Cluster: staticCluster{cluster(oldLeader, follower)}}},
		{"follower first", "gru", &Provider{Cell: "gru", Cluster: staticCluster{cluster(follower, oldLeader)}}},
		{"lost lease", "gru", &Provider{Cell: "gru", Cluster: staticCluster{cluster(lost)}}},
		{"failed cluster", "gru", &Provider{Cell: "gru", Cluster: failingCluster{}, Snapshot: staticSnapshot{member("c1", "v1", true)}}},
		{"single member", "lab", &Provider{Cell: "lab", Snapshot: staticSnapshot{member("c1", "v1", true)}}},
		{"distinct databases", "gru", &Provider{Cell: "gru", Cluster: staticCluster{cluster(databaseLeader)}}},
		{"request version", "gru", &Provider{Cell: "gru"}},
		{"lost quorum", "gru", &Provider{Cell: "gru", Cluster: staticCluster{cluster(observability.MemberSnapshot{Member: "c1", Ready: true})}}},
		{"degraded score", "gru", &Provider{Cell: "gru", Cluster: staticCluster{cluster(
			observability.MemberSnapshot{Member: "c1", Ready: true, BuildVersion: "a", Authority: &observability.AuthorityView{Leader: true, Ready: true, Epoch: 4}},
			observability.MemberSnapshot{Member: "c2", Ready: true, BuildVersion: "b"})},
			Insights: staticInsights{[]insights.Insight{{Severity: insights.SeverityCritical}}}}},
		{"unobserved score", "gru", &Provider{Cell: "gru"}},
		{"legacy budget", "gru", &Provider{Cell: "gru", Cluster: staticCluster{cluster(legacyMembers...)}}},
	} {
		test.provider.Now = func() time.Time { return observedAt }
		subscription, err := Serve(ctx, conn, test.region, test.provider)
		if err != nil {
			t.Fatalf("%s responder: %v", test.name, err)
		}
		if err := conn.Flush(); err != nil {
			t.Fatal(err)
		}
		payload, err := reverse.Request(ctx, test.region, SummaryLeaf, summaryRequestPayload)
		if err != nil || len(payload) == 0 {
			t.Fatalf("%s native summary request: payload=%s err=%v", test.name, payload, err)
		}
		var raw Summary
		if err := jsonv2.Unmarshal(payload, &raw); err != nil {
			t.Fatalf("%s native summary decode: %v", test.name, err)
		}
		if raw.Version != summaryVersion || raw.Region != test.region || !raw.Local || raw.Reach != decisionlog.RegionOK || !raw.ObservedAt.Equal(observedAt) {
			t.Fatalf("%s raw native identity = %+v", test.name, raw)
		}
		switch test.name {
		case "summary":
			if !raw.Quorum.Healthy || raw.Quorum.Required != 2 || raw.Quorum.Ready != 3 {
				t.Fatalf("native quorum = %+v", raw.Quorum)
			}
			if raw.Leaders.Authority != "c1" || raw.Leaders.Epoch != 4 || raw.Leaders.MetaLeader != "c2" {
				t.Fatalf("native leaders = %+v", raw.Leaders)
			}
			if raw.Capacity.CPUs != 6 || raw.Capacity.MemoryUsedBytes != 180 || raw.Capacity.DiskUsedBytes != 1200 {
				t.Fatalf("native capacity = %+v", raw.Capacity)
			}
			if raw.TerraBase.Databases != 1 || len(raw.Rollouts) != 1 || raw.MixedVersions() {
				t.Fatalf("native terrabase = %+v rollouts=%d", raw.TerraBase, len(raw.Rollouts))
			}
			if len(raw.Decisions) != DefaultLatestDecisions || raw.Counts.Warning != 2 {
				t.Fatalf("native decisions=%d counts=%+v", len(raw.Decisions), raw.Counts)
			}
			if raw.Health.Score != 92 || raw.Health.Status != StatusHealthy {
				t.Fatalf("native health = %+v", raw.Health)
			}
		case "insight region":
			if raw.Counts.Critical != 0 || raw.Counts.Warning != 1 || len(raw.Insights) != 1 || raw.Health.Score != 92 {
				t.Fatalf("native insight region counts=%+v insights=%+v health=%+v", raw.Counts, raw.Insights, raw.Health)
			}
		case "leader first", "follower first":
			if raw.Leaders.Authority != "c3" || raw.Leaders.Epoch != 5 {
				t.Fatalf("%s native leaders = %+v", test.name, raw.Leaders)
			}
		case "lost lease":
			if raw.Leaders.Authority != "" || raw.Health.Status == StatusHealthy {
				t.Fatalf("native failed lease invented a leader: %+v %+v", raw.Leaders, raw.Health)
			}
		case "failed cluster":
			if !raw.Quorum.Unobserved || raw.Quorum.Healthy || raw.Quorum.Expected != 0 || raw.Health.Status == StatusHealthy {
				t.Fatalf("native failed cluster fallback quorum=%+v health=%+v", raw.Quorum, raw.Health)
			}
		case "single member":
			if raw.Quorum.Unobserved || !raw.Quorum.Healthy {
				t.Fatalf("native single-member lab quorum = %+v", raw.Quorum)
			}
		case "distinct databases":
			if raw.TerraBase.Databases != 2 || raw.TerraBase.DesiredSeats != 6 {
				t.Fatalf("native distinct databases = %+v", raw.TerraBase)
			}
		case "lost quorum":
			if raw.Quorum.Expected != 3 || raw.Quorum.Answering != 1 || raw.Quorum.Ready != 1 || raw.Quorum.Required != 2 ||
				raw.Quorum.Healthy || raw.Quorum.Unobserved || raw.Leaders.Authority != "" || len(raw.Versions) != 0 || len(raw.Insights) != 0 {
				t.Fatalf("native lost-quorum score inputs = %+v", raw)
			}
			if raw.Health.Status != StatusCritical || raw.Health.Score != 0 {
				t.Fatalf("native lost quorum = %+v", raw.Health)
			}
		case "degraded score":
			if raw.Quorum.Expected != 3 || raw.Quorum.Answering != 2 || raw.Quorum.Ready != 2 || raw.Quorum.Required != 2 ||
				!raw.Quorum.Healthy || raw.Quorum.Unobserved || raw.Leaders.Authority != "c1" || len(raw.Versions) != 2 ||
				raw.Versions[0].Version != "a" || raw.Versions[1].Version != "b" || len(raw.Insights) != 1 || raw.Insights[0].Severity != insights.SeverityCritical {
				t.Fatalf("native degraded score inputs = %+v", raw)
			}
			if raw.Health.Score != 55 || raw.Health.Status != StatusDegraded || len(raw.Health.Reasons) != 3 {
				t.Fatalf("native degraded score = %+v", raw.Health)
			}
		case "unobserved score":
			if raw.Quorum.Answering != 0 || raw.Leaders.Authority != "" || len(raw.Versions) != 0 || len(raw.Insights) != 0 {
				t.Fatalf("native unobserved score inputs = %+v", raw)
			}
			if raw.Health.Status != StatusUnknown {
				t.Fatalf("native unobserved score = %+v", raw.Health)
			}
		case "legacy budget":
			if len(raw.Versions) != maxTopologyMembers {
				t.Fatalf("native raw legacy versions = %d, want %d", len(raw.Versions), maxTopologyMembers)
			}
			seen := make(map[string]bool)
			total := 0
			for _, version := range raw.Versions {
				names, exists := legacyNames[version.Version]
				if !exists || seen[version.Version] || len(version.Members) != maxTopologyMembers || !slices.Equal(version.Members, names) {
					t.Fatalf("native raw legacy version = %+v, want exact names %v", version, names)
				}
				seen[version.Version] = true
				total += len(version.Members)
			}
			if total != maxTopologyMembers*maxTopologyMembers {
				t.Fatalf("native raw legacy member count = %d, want %d", total, maxTopologyMembers*maxTopologyMembers)
			}
		}
		probed := requester.Probe(ctx, test.region)
		if probed.Version != summaryVersion || probed.Region != test.region || probed.Local || probed.Reach != decisionlog.RegionOK || !probed.ObservedAt.Equal(observedAt) {
			t.Fatalf("%s native Probe identity = %+v", test.name, probed)
		}
		wantProbe := raw
		wantProbe.Local = false
		readback := probed
		if test.name == "legacy budget" {
			if len(probed.Versions) != len(raw.Versions) {
				t.Fatalf("native Probe legacy versions = %d, want %d", len(probed.Versions), len(raw.Versions))
			}
			total := 0
			for index, version := range probed.Versions {
				var names []string
				if index == 0 {
					names = raw.Versions[index].Members
				}
				if version.Version != raw.Versions[index].Version || !slices.Equal(version.Members, names) {
					t.Fatalf("native Probe legacy budget at version %d = %+v, want names %v", index, version, names)
				}
				total += len(version.Members)
			}
			if total > maxTopologyMembers {
				t.Fatalf("native Probe legacy members = %d, want at most %d", total, maxTopologyMembers)
			}
			if total != maxTopologyMembers {
				t.Fatalf("native Probe discarded legacy members: got %d, want %d", total, maxTopologyMembers)
			}
			readback.Versions = raw.Versions
		}
		if !reflect.DeepEqual(readback, wantProbe) {
			t.Fatalf("%s native Probe changed raw summary: got %+v, want %+v", test.name, probed, wantProbe)
		}
		if err := subscription.Unsubscribe(); err != nil {
			t.Fatal(err)
		}
		if err := conn.Flush(); err != nil {
			t.Fatal(err)
		}
	}
}
