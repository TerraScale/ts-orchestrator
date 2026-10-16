package app

import (
	"context"
	"fmt"
	"io"
	"math"
	"slices"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/decisionlog"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/regionlink"
	"github.com/TerraScale/ts-orchestrator/internal/regionview"
)

const regionLinkProbeInterval = time.Minute

// Repairs are coalesced across destinations because they can share one leaf hop.
const regionLinkRepairInterval = 5 * time.Minute

type regionLinkSupervisor struct {
	cell, member string
	source       *regionview.Provider
	reconnect    func(context.Context) (int, error)
	recorder     decisionlog.Recorder
	now          func() time.Time

	mu         sync.Mutex
	probes     []regionview.LinkProbe
	failures   map[string]string
	nextRepair time.Time
	ahead      map[string]wanCounter
}

type wanCounter struct {
	at     time.Time
	value  float64
	failed bool
}

func (supervisor *regionLinkSupervisor) time() time.Time {
	if supervisor.now != nil {
		return supervisor.now().UTC()
	}
	return time.Now().UTC()
}

func (supervisor *regionLinkSupervisor) snapshot() []regionview.LinkProbe {
	supervisor.mu.Lock()
	defer supervisor.mu.Unlock()
	probes := slices.Clone(supervisor.probes)
	for index := range probes {
		if probes[index].Reach != decisionlog.RegionNotLinked && supervisor.time().Sub(probes[index].ObservedAt) > 2*regionLinkProbeInterval {
			probes[index].Reach, probes[index].WAN = "stale", regionlink.WANUnknown
			probes[index].Lag = nil
			probes[index].Detail = "scheduled probe is overdue"
		}
	}
	return probes
}

func (supervisor *regionLinkSupervisor) writeMetrics(writer io.Writer) {
	for _, probe := range supervisor.snapshot() {
		labels := fmt.Sprintf("peer=%q,member=%q", probe.Region, probe.Member)
		fmt.Fprintf(writer, "ts_orch_region_link_probe_timestamp_seconds{%s} %g\n", labels, float64(probe.ObservedAt.UnixMilli())/1000)
		fmt.Fprintf(writer, "ts_orch_region_link_probe_success{%s} %g\n", labels, observability.Bool(probe.Reach == decisionlog.RegionOK))
		fmt.Fprintf(writer, "ts_orch_region_link_probe_duration_seconds{%s} %g\n", labels, probe.RoundTripMS/1000)
		fmt.Fprintf(writer, "ts_orch_region_wan_observed{%s} %g\n", labels, observability.Bool(probe.Lag != nil))
		fmt.Fprintf(writer, "ts_orch_region_wan_healthy{%s} %g\n", labels, observability.Bool(probe.WAN == regionlink.WANOK))
		if probe.Lag != nil {
			fmt.Fprintf(writer, "ts_orch_region_wan_lag_groups{%s} %g\n", labels, *probe.Lag)
		}
	}
}

func (supervisor *regionLinkSupervisor) Run(ctx context.Context) error {
	ticker := time.NewTicker(regionLinkProbeInterval)
	defer ticker.Stop()
	for {
		ctx := observability.StartTrace(ctx)
		supervisor.round(ctx)
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (supervisor *regionLinkSupervisor) round(ctx context.Context) {
	local := supervisor.source.Local(ctx)
	peers := slices.DeleteFunc(supervisor.source.Links.Regions(), func(region string) bool { return region == supervisor.cell })
	probes := make([]regionview.LinkProbe, len(peers))
	remotes := make([]regionview.Summary, len(peers))
	var requests sync.WaitGroup
	for index, peer := range peers {
		requests.Go(func() {
			started := supervisor.time()
			remote := supervisor.source.Probe(ctx, peer)
			remotes[index] = remote
			probe := regionview.LinkProbe{Region: peer, Member: supervisor.member,
				StartedAt: started, ObservedAt: supervisor.time(), Reach: remote.Reach, WAN: regionlink.WANUnknown,
				RoundTripMS: float64(supervisor.time().Sub(started)) / float64(time.Millisecond)}
			switch remote.Reach {
			case decisionlog.RegionOK:
				probe.WAN, probe.Lag, probe.Detail = checkRegionWAN(local, remote, probe.ObservedAt)
			case decisionlog.RegionNotLinked:
				probe.Detail = "no authenticated interregion link is available"
			default:
				probe.Detail = "authenticated region telemetry request failed"
			}
			probes[index] = probe
		})
	}
	requests.Wait()
	if ctx.Err() != nil {
		return
	}
	previous := supervisor.snapshot()
	if supervisor.failures == nil {
		supervisor.failures = map[string]string{}
	}
	repair := false
	for index := range probes {
		probe := &probes[index]
		if probe.Lag != nil && supervisor.newAheadFailures(remotes[index], local.TerraBase.NativeRegion, probe.ObservedAt) && probe.WAN != regionlink.WANUnknown {
			probe.WAN, probe.Detail = regionlink.WANFailed, "WAN replication reported new ahead failures"
		}
		for _, old := range previous {
			if old.Region == probe.Region {
				probe.LastSuccessAt = old.LastSuccessAt
				probe.Recovery = old.Recovery
			}
		}
		if probe.Reach == decisionlog.RegionOK && probe.WAN == regionlink.WANOK {
			probe.LastSuccessAt = probe.ObservedAt
			probe.Recovery = ""
			if failure := supervisor.failures[probe.Region]; failure != "" {
				supervisor.record(ctx, "region_link_recovered", decisionlog.StatusSucceeded, probe.Region, failure,
					"Authenticated telemetry and TerraBase WAN are healthy", "fresh read verified recovery")
				delete(supervisor.failures, probe.Region)
			}
			continue
		}
		if supervisor.needsRepair(*probe) && supervisor.failures[probe.Region] == "" {
			supervisor.failures[probe.Region] = supervisor.record(ctx, "region_link_failed", decisionlog.StatusFailed,
				probe.Region, "", "Cross-region telemetry or TerraBase WAN is unhealthy", probe.Detail)
		}
		// Missing observations and unadmitted links do not authorize tearing
		// down a healthy transport. Explicit request/staleness failures do.
		repair = repair || supervisor.needsRepair(*probe)
	}
	supervisor.mu.Lock()
	supervisor.probes = probes
	supervisor.mu.Unlock()
	if !repair {
		return
	}
	if supervisor.time().Before(supervisor.nextRepair) {
		return
	}
	supervisor.nextRepair = supervisor.time().Add(regionLinkRepairInterval)
	for _, probe := range probes {
		if !supervisor.needsRepair(probe) {
			continue
		}
		parent := supervisor.record(ctx, "region_link_reconnect", decisionlog.StatusInProgress, probe.Region,
			supervisor.failures[probe.Region], "Reconnecting the broker's authenticated interregion leaves", probe.Detail)
		count, err := supervisor.reconnect(ctx)
		status, outcome := decisionlog.StatusInProgress, fmt.Sprintf("disconnected %d leaves; awaiting a fresh authenticated probe", count)
		if err != nil {
			status, outcome = decisionlog.StatusFailed, "broker reconnect failed; link remains unhealthy"
		}
		supervisor.record(ctx, "region_link_reconnect", status, probe.Region, parent, outcome, "reconnect does not establish recovery")
		supervisor.mu.Lock()
		for index := range supervisor.probes {
			if supervisor.needsRepair(supervisor.probes[index]) {
				supervisor.probes[index].Recovery = outcome
			}
		}
		supervisor.mu.Unlock()
		return
	}
}

func (supervisor *regionLinkSupervisor) needsRepair(probe regionview.LinkProbe) bool {
	return supervisor.source.Links.Linked(probe.Region) && probe.Reach != decisionlog.RegionNotLinked &&
		(probe.Reach != decisionlog.RegionOK || probe.WAN == regionlink.WANFailed)
}

func (supervisor *regionLinkSupervisor) newAheadFailures(remote regionview.Summary, sourceRegion string, now time.Time) bool {
	if supervisor.ahead == nil {
		supervisor.ahead = map[string]wanCounter{}
	}
	failed := false
	for _, row := range remote.TerraBase.WAN {
		if row.SourceRegion != sourceRegion || row.ObservedAt.After(now.Add(time.Minute)) || now.Sub(row.ObservedAt) > 2*time.Minute {
			continue
		}
		key := remote.Region + "/" + row.Node + "/" + row.SourceRegion
		if row.AheadFailures == nil || !nonnegativeFinite(*row.AheadFailures) {
			delete(supervisor.ahead, key)
			continue
		}
		old, known := supervisor.ahead[key]
		if known && !row.ObservedAt.After(old.at) {
			failed = failed || old.failed
			continue
		}
		value := *row.AheadFailures
		newFailures := false
		if known {
			// A smaller counter is a process reset; its new failures still count.
			newFailures = value > old.value || (value < old.value && value > 0)
		}
		failed = failed || newFailures
		supervisor.ahead[key] = wanCounter{at: row.ObservedAt, value: value, failed: newFailures}
	}
	return failed
}

func (supervisor *regionLinkSupervisor) record(ctx context.Context, kind decisionlog.Kind, status decisionlog.Status,
	peer, parent, summary, reason string,
) string {
	return supervisor.recorder.Record(ctx, decisionlog.Decision{Region: supervisor.cell, Kind: kind, Status: status,
		Actor:   decisionlog.Actor{Slice: "regionlink", Member: supervisor.member},
		Subject: decisionlog.Subject{Kind: "region", ID: peer}, ParentID: parent, Summary: summary, Reason: reason})
}

// The remote receivers measure replication from this region to that region.
func checkRegionWAN(local, remote regionview.Summary, now time.Time) (string, *float64, string) {
	if local.NodesIncomplete || remote.NodesIncomplete {
		return regionlink.WANUnknown, nil, "TerraBase node roster is incomplete"
	}
	receivers := terraBaseReceivers(remote)
	expectedSources := len(terraBaseReceivers(local))
	if len(receivers) == 0 || expectedSources == 0 || local.TerraBase.NativeRegion == "" {
		return regionlink.WANUnknown, nil, "TerraBase replication membership is unobserved"
	}
	seen := map[string]bool{}
	lag := 0.0
	state, detail := regionlink.WANOK, "all observed receivers are caught up"
	for _, row := range remote.TerraBase.WAN {
		if row.SourceRegion != local.TerraBase.NativeRegion {
			continue
		}
		if seen[row.Node] || !slices.Contains(receivers, row.Node) || row.ObservedAt.IsZero() ||
			now.Sub(row.ObservedAt) > 2*time.Minute || row.ObservedAt.After(now.Add(time.Minute)) ||
			row.Members != expectedSources || !nonnegativeFinite(row.Lag) || !nonnegativeFinite(row.StalenessSeconds) ||
			!nonnegativeFinite(row.Conflicts) || !nonnegativeFinite(row.Unregistered) {
			return regionlink.WANUnknown, nil, "WAN telemetry is stale, invalid or has incomplete membership"
		}
		seen[row.Node] = true
		lag = max(lag, row.Lag)
		if row.Conflicts > 0 || row.StalenessSeconds > 60 {
			state, detail = regionlink.WANFailed, "WAN replication has conflicts or has not caught up for over one minute"
		} else if row.Unregistered > 0 && state != regionlink.WANFailed {
			state, detail = regionlink.WANUnknown, "WAN reports unregistered databases"
		} else if row.Lag > 0 && state == regionlink.WANOK {
			state, detail = regionlink.WANCatchingUp, "WAN has unapplied change groups"
		}
	}
	if len(seen) != len(receivers) {
		return regionlink.WANUnknown, nil, "not every TerraBase receiver has fresh WAN telemetry"
	}
	return state, new(lag), detail
}

func nonnegativeFinite(value float64) bool {
	return value >= 0 && !math.IsNaN(value) && !math.IsInf(value, 0)
}

func terraBaseReceivers(summary regionview.Summary) []string {
	var nodes []string
	for _, node := range summary.Nodes {
		for _, service := range node.Services {
			if service.Role == "terrabase" {
				nodes = append(nodes, node.Name)
				break
			}
		}
	}
	return nodes
}
