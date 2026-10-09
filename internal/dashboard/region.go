package dashboard

import (
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
)

// regionKPIs are this region's tiles: readiness, members, leaders, TerraBase
// and resource use, with sparklines from the metric history.
func (current view) regionKPIs() []kpi {
	readiness := "ready"
	if !current.Ready {
		readiness = "not ready"
	}
	tiles := []kpi{{Label: "Readiness", Value: readiness, Sub: "this member: " + current.memberName(),
		Status: boolStatus(current.Ready), Href: current.State.link("/region")}}
	missing := current.missing()
	sub := "all expected members answer"
	if len(missing) > 0 {
		sub = itoa(len(missing)) + " missing: " + joinWords(missing)
	}
	tiles = append(tiles, kpi{Label: "Members answering", Value: itoa(len(current.members())), Sub: sub,
		Status: boolStatus(len(missing) == 0),
		Spark:  sparkValues(current.historyRange(observability.HistMembersAnswering, nil, "", false)),
		Href:   current.State.link("/members")})
	if lease := current.authority(); lease != nil {
		tiles = append(tiles, kpi{Label: "Authority lease", Value: orDash(lease.OwnerID),
			Sub: "epoch " + itoa(lease.Epoch) + " · revision " + itoa(lease.Revision), Status: boolStatus(lease.Ready),
			Spark: sparkValues(current.historyRange(observability.HistAuthorityEpoch, nil, "", false)),
			Href:  current.State.link("/decisions", "kind", "leader_changed")})
	}
	if leader := current.metaLeader(); leader != "" {
		tiles = append(tiles, kpi{Label: "JetStream meta leader", Value: leader, Sub: "raft metadata leader",
			Status: "ok", Href: current.State.link("/nats")})
	}
	if placement := current.placement(); placement != nil {
		partitions := 0
		for _, database := range placement.Databases {
			if !database.Terminal {
				partitions++
			}
		}
		tiles = append(tiles, kpi{Label: "Managed TerraBase partitions", Value: itoa(partitions),
			Sub: counts(placement.StageCounts), Status: "info",
			// Active partitions have their own history, separate from seats.
			Spark: sparkValues(current.historyRange(observability.HistDatabases, nil, "", false)),
			Href:  current.State.link("/terrabase")})
	}
	cpu := current.historyRange(observability.HistCPUUtilization, nil, "member", false)
	if average := averageSeries("cpu", cpu); average != nil {
		value, _ := lastValue(average)
		tiles = append(tiles, kpi{Label: "CPU (mean)", Value: percent(value), Sub: itoa(len(cpu)) + " members",
			Status: ratioStatus(value), Spark: sparkValues(average), Href: current.State.link("/members")})
	}
	memory := current.historyRange(observability.HistMemoryRatio, nil, "member", false)
	if average := averageSeries("memory", memory); average != nil {
		value, _ := lastValue(average)
		tiles = append(tiles, kpi{Label: "Memory (mean)", Value: percent(value), Sub: "used of total",
			Status: ratioStatus(value), Spark: sparkValues(average), Href: current.State.link("/members")})
	}
	if reporter := current.natsReporter(); reporter != nil {
		used := storeUsed(reporter.NATS)
		tiles = append(tiles, kpi{Label: "JetStream store", Value: percent(used),
			Sub: formatBytes(reporter.NATS.StoreUsedBytes) + " used", Status: ratioStatus(used),
			Href: current.State.link("/nats")})
	}
	return tiles
}

// readinessRow is one member's readiness in the region readiness card.
type readinessRow struct {
	Member  string
	Role    string
	Ready   bool
	Missing bool
	Checks  []observability.CheckResult
}

// readiness lists every answering member's readiness checks, as each member
// evaluated them, then the expected members that did not answer. Without a
// cell-wide view it is this member's own checks.
func (current view) readiness() []readinessRow {
	var rows []readinessRow
	for _, member := range current.members() {
		checks, ready := member.Checks, member.Ready
		if current.Local != nil && member.Member == current.Local.Member && len(current.Checks) > 0 {
			// This member's checks were just evaluated for this render.
			checks, ready = current.Checks, current.Ready
		}
		rows = append(rows, readinessRow{Member: member.Member, Role: member.Role, Ready: ready, Checks: checks})
	}
	if len(rows) == 0 && len(current.Checks) > 0 {
		rows = append(rows, readinessRow{Member: current.memberName(), Ready: current.Ready, Checks: current.Checks})
	}
	for _, name := range current.missing() {
		rows = append(rows, readinessRow{Member: name, Missing: true})
	}
	return rows
}

// averageSeries averages series point by point on shared timestamps.
func averageSeries(name string, series []chartSeries) []chartSeries {
	total := sumSeries(name, series)
	if total == nil {
		return nil
	}
	counts := map[float64]float64{}
	for _, one := range series {
		for _, point := range one.Points {
			counts[point[0]]++
		}
	}
	for index, point := range total[0].Points {
		total[0].Points[index][1] = round(point[1] / counts[point[0]])
	}
	return total
}

func (current view) membersChart() chartSpec {
	answering := current.historyRange(observability.HistMembersAnswering, nil, "", false)
	expected := current.historyRange(observability.HistMembersExpected, nil, "", false)
	var series []chartSeries
	if len(expected) > 0 {
		expected[0].Name, expected[0].Dashed, expected[0].Status = "expected", true, "idle"
		series = append(series, expected[0])
	}
	if len(answering) > 0 {
		answering[0].Name, answering[0].Status = "answering", "ok"
		series = append(series, answering[0])
	}
	spec := current.lineChart("line", "count", series, "No membership history yet.")
	spec.Min = float(0)
	return spec
}
