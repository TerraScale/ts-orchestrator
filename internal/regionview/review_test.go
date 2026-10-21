package regionview

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/insights"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

// These pin the fixes for the ts-reviewer findings on PR #121.

type failingCluster struct{}

func (failingCluster) Cluster(context.Context, bool) (observability.ClusterSnapshot, error) {
	return observability.ClusterSnapshot{}, errors.New("no responders")
}

type staticSnapshot struct{ snapshot observability.MemberSnapshot }

func (source staticSnapshot) Snapshot(context.Context, bool) (observability.MemberSnapshot, error) {
	return source.snapshot, nil
}

func TestRemoteRegionInsightsDoNotScoreThisRegion(t *testing.T) {
	t.Parallel()
	open := []insights.Insight{{Rule: "region_unreachable", Region: "sfo", Severity: insights.SeverityCritical},
		{Rule: "disk_time_to_full", Region: "gru", Severity: insights.SeverityWarning}}
	provider := &Provider{Cell: "gru", Cluster: staticCluster{cluster(member("c1", "v1", true), member("c2", "v1", false),
		member("c3", "v1", false))}, Insights: staticInsights{open}}
	summary := provider.Local(t.Context())
	if summary.Counts.Critical != 0 || summary.Counts.Warning != 1 || len(summary.Insights) != 1 || summary.Health.Score != 92 {
		t.Fatalf("an unreachable SFO scored GRU: counts=%+v health=%+v", summary.Counts, summary.Health)
	}
}

func TestAuthorityIsTheNewestValidLease(t *testing.T) {
	t.Parallel()
	oldLeader := member("c1", "v1", true)
	oldLeader.Authority = &observability.AuthorityView{Leader: true, Ready: true, OwnerID: "c1", Epoch: 4}
	follower := member("c2", "v1", false)
	follower.Authority = &observability.AuthorityView{Ready: true, OwnerID: "c3", Epoch: 5}
	for _, members := range [][]observability.MemberSnapshot{{oldLeader, follower}, {follower, oldLeader}} {
		provider := &Provider{Cell: "gru", Cluster: staticCluster{cluster(members...)}}
		if leaders := provider.Local(t.Context()).Leaders; leaders.Authority != "c3" || leaders.Epoch != 5 {
			t.Fatalf("leaders = %+v, want the epoch 5 owner whatever the member order", leaders)
		}
	}
	// A control-log failure snapshot keeps the member's own candidate as
	// OwnerID with Ready false: that is no leader.
	lost := member("c1", "v1", false)
	lost.Authority = &observability.AuthorityView{Ready: false, OwnerID: "c1-candidate"}
	provider := &Provider{Cell: "gru", Cluster: staticCluster{cluster(lost)}}
	summary := provider.Local(t.Context())
	if summary.Leaders.Authority != "" || summary.Health.Status == StatusHealthy {
		t.Fatalf("a failure snapshot invented a leader: %+v %+v", summary.Leaders, summary.Health)
	}
}

func TestFailedClusterViewLeavesQuorumUnknown(t *testing.T) {
	t.Parallel()
	provider := &Provider{Cell: "gru", Cluster: failingCluster{}, Snapshot: staticSnapshot{member("c1", "v1", true)}}
	summary := provider.Local(t.Context())
	if !summary.Quorum.Unobserved || summary.Quorum.Healthy || summary.Quorum.Expected != 0 ||
		summary.Health.Status == StatusHealthy {
		t.Fatalf("a failed cluster view reads as a healthy one-member cell: quorum=%+v health=%+v", summary.Quorum, summary.Health)
	}
	alone := &Provider{Cell: "lab", Snapshot: staticSnapshot{member("c1", "v1", true)}}
	if summary := alone.Local(t.Context()); summary.Quorum.Unobserved || !summary.Quorum.Healthy {
		t.Fatalf("a single-member cell without a cluster source = %+v", summary.Quorum)
	}
}

func TestDatabasesCountDistinctIDsNotPartitions(t *testing.T) {
	t.Parallel()
	leader := member("c1", "v1", true)
	leader.Placement = &observability.PlacementView{Databases: []observability.DatabaseView{
		{DatabaseID: "orders", PartitionID: "p0", DesiredSeats: 2}, {DatabaseID: "orders", PartitionID: "p1", DesiredSeats: 2},
		{DatabaseID: "billing", PartitionID: "p0", DesiredSeats: 2}}}
	provider := &Provider{Cell: "gru", Cluster: staticCluster{cluster(leader)}}
	if terrabase := provider.Local(t.Context()).TerraBase; terrabase.Databases != 2 || terrabase.DesiredSeats != 6 {
		t.Fatalf("terrabase = %+v", terrabase)
	}
}

// These pin the fixes for the ts-reviewer findings on PRs #127 and #129.

// A torn-down (terminal) partition keeps its roster but is not live work.
func TestTerminalPartitionsAreNotActiveWork(t *testing.T) {
	t.Parallel()
	leader := member("c1", "v1", true)
	leader.Placement = &observability.PlacementView{Databases: []observability.DatabaseView{
		{DatabaseID: "orders", PartitionID: "p0", DesiredSeats: 2, Serving: 2,
			Members: []observability.MemberView{{SeatID: "a", HostNode: "h1", Stage: "serving"}}},
		{DatabaseID: "gone", PartitionID: "p0", DesiredSeats: 2, Serving: 2, Terminal: true,
			Members: []observability.MemberView{{SeatID: "a", HostNode: "h2", Stage: "serving"}},
			Rollout: &observability.RolloutView{OperationID: "op", Seats: 2, Completed: 1}}}}
	summary := (&Provider{Cell: "gru", Cluster: staticCluster{cluster(leader)}}).Local(t.Context())
	if summary.TerraBase.Databases != 1 || summary.TerraBase.ServingSeats != 0 || summary.TerraBase.Readiness != "unknown" || summary.TerraBase.ReadinessReason == "" || len(summary.Hosts) != 1 ||
		len(summary.Rollouts) != 0 {
		t.Fatalf("terminal partition counted as live: terrabase=%+v hosts=%+v rollouts=%+v", summary.TerraBase,
			summary.Hosts, summary.Rollouts)
	}
}

// Legacy version members are bounded across the whole summary.
func TestLegacyVersionMembersAreBoundedAcrossTheSummary(t *testing.T) {
	t.Parallel()
	summary := Summary{}
	for version := range maxTopologyMembers {
		var members []string
		for index := range maxTopologyMembers {
			members = append(members, fmt.Sprintf("v%d-m%d", version, index))
		}
		summary.Versions = append(summary.Versions, Version{Version: fmt.Sprint(version), Members: members})
	}
	summary.boundTopology()
	total := 0
	for _, version := range summary.Versions {
		total += len(version.Members)
	}
	if total > maxTopologyMembers {
		t.Fatalf("legacy members after bounding = %d, want at most %d", total, maxTopologyMembers)
	}
}

// The summary request is derived from the version the responder checks.
func TestSummaryRequestCarriesTheCurrentVersion(t *testing.T) {
	t.Parallel()
	if !validSummaryRequest(summaryRequestPayload) {
		t.Fatalf("the requester's payload %s is refused by the responder", summaryRequestPayload)
	}
}
