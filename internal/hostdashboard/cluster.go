package hostdashboard

import (
	"context"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/regionhealth"
)

// Role is how the dashboard lists a single-host region's host: it runs the
// region's controller.
const Role = "controller"

// meshCluster is the dashboard's whole-mesh view: this host's own snapshot
// and every other region's host from its health report over the mesh. A
// region that does not answer is listed as missing.
type meshCluster struct {
	region string
	local  observability.SnapshotSource
	// regions are the regions expected to answer; ask collects their reports.
	regions func() []string
	ask     func(context.Context) (map[string]regionhealth.Report, error)
}

func (cluster *meshCluster) Cluster(ctx context.Context, includeMetrics bool) (observability.ClusterSnapshot, error) {
	reports, _ := cluster.ask(ctx)
	snapshot := observability.ClusterSnapshot{Cell: cluster.region, ObservedAt: time.Now().UTC()}
	regions := cluster.regions()
	for region := range reports {
		if !slices.Contains(regions, region) {
			regions = append(regions, region)
		}
	}
	slices.Sort(regions)
	for _, region := range regions {
		report, answered := reports[region]
		if region == cluster.region {
			local, err := cluster.local.Snapshot(ctx, includeMetrics)
			if err == nil {
				snapshot.Members = append(snapshot.Members, local)
				continue
			}
		}
		if !answered {
			snapshot.Missing = append(snapshot.Missing, region)
			continue
		}
		snapshot.Members = append(snapshot.Members, remoteMember(report))
	}
	return snapshot, nil
}

// remoteMember is another region's host as its health report describes it.
func remoteMember(report regionhealth.Report) observability.MemberSnapshot {
	ok := report.State == regionhealth.StateOK
	return observability.MemberSnapshot{Version: observability.SnapshotVersion, Cell: report.Region, Member: report.Server,
		Role: Role, ObservedAt: report.At, Ready: ok,
		Checks: []observability.CheckResult{{Name: "region health", OK: ok, Detail: describe(report)}}}
}

// describe is a report's state with its reasons.
func describe(report regionhealth.Report) string {
	if len(report.Reasons) == 0 {
		return report.State
	}
	return report.State + ": " + strings.Join(report.Reasons, "; ")
}

// meshReports asks every region's health over this host's mesh node,
// reconnecting after the mesh restarts.
type meshReports struct {
	state string
	mu    sync.Mutex
	conn  *nats.Conn
}

func (reports *meshReports) ask(ctx context.Context) (map[string]regionhealth.Report, error) {
	reports.mu.Lock()
	if reports.conn == nil || reports.conn.IsClosed() {
		conn, err := mesh.Connect(reports.state)
		if err != nil {
			reports.mu.Unlock()
			return nil, err
		}
		reports.conn = conn
	}
	conn := reports.conn
	reports.mu.Unlock()
	return regionhealth.Ask(ctx, conn)
}

func (reports *meshReports) close() {
	reports.mu.Lock()
	defer reports.mu.Unlock()
	if reports.conn != nil {
		reports.conn.Close()
	}
}

var _ observability.ClusterSource = (*meshCluster)(nil)
