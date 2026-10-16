package dashboard

import (
	"fmt"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

// autoscaledService is one reconciled service's charts: replicas against
// the autoscaler's goal, and every signal's per-replica reading against its
// target.
type autoscaledService struct {
	Name     string
	Replicas chartSpec
	Signals  chartSpec
}

// maxAutoscaledServices bounds how many services the page charts.
const maxAutoscaledServices = 12

// autoscaledServicesView is the charted services plus the names of those
// beyond maxAutoscaledServices, which the page lists instead of charting.
type autoscaledServicesView struct {
	Services []autoscaledService
	Hidden   []string
}

// autoscaledServices builds the per-service charts from the leader's
// history, alphabetically. Services appear once the reconciler has reported
// them; a follower or a cell without autoscaling has none.
func (current view) autoscaledServices() autoscaledServicesView {
	replicas := current.historyRange(observability.HistAutoscaleReplicas, nil, "service", false)
	var out autoscaledServicesView
	for _, series := range replicas {
		if len(out.Services) == maxAutoscaledServices {
			out.Hidden = append(out.Hidden, series.Name)
			continue
		}
		name := series.Name
		labels := map[string]string{"service": name}
		lines := []chartSeries{{Name: "replicas", Points: series.Points, Status: "ok"}}
		if goal := current.historyRange(observability.HistAutoscaleGoal, labels, "service", false); len(goal) > 0 {
			goal[0].Name, goal[0].Dashed, goal[0].Status = "goal", true, "info"
			lines = append(lines, goal[0])
		}
		replicaChart := current.lineChart("line", "count", lines, "No replica history yet.")
		replicaChart.Min = float(0)
		// One axis is enough: the signed config accepts only the
		// utilization signals (cpu_util, mem_util, disk_util, all fractions)
		// for reconciled services (app.validateAutoscaleConfig). Split this
		// chart by unit before admitting count or byte signals.
		signals := current.historyRange(observability.HistAutoscaleSignal, labels, "signal", false)
		for _, target := range current.historyRange(observability.HistAutoscaleSignalTarget, labels, "signal", false) {
			target.Name, target.Dashed, target.Status = target.Name+" target", true, "idle"
			signals = append(signals, target)
		}
		signalChart := current.lineChart("line", "", signals,
			"No signal readings yet: the service has no scaling policy, host telemetry is off, or the replica set has not converged.")
		signalChart.Min = float(0)
		out.Services = append(out.Services, autoscaledService{Name: name, Replicas: replicaChart, Signals: signalChart})
	}
	return out
}

// hiddenNotice lists the services beyond the charted ones.
func (v autoscaledServicesView) hiddenNotice() string {
	if len(v.Hidden) == 0 {
		return ""
	}
	return fmt.Sprintf("Charting the first %d services alphabetically. Not charted: %s; their decisions are in the journal.",
		maxAutoscaledServices, strings.Join(v.Hidden, ", "))
}

// terraBaseLoadChart charts one TerraBase load metric by member.
func (current view) terraBaseLoadChart(metric, unit string) chartSpec {
	spec := current.lineChart("line", unit, current.historyRange(metric, nil, "member,role", false),
		"No TerraBase load yet: members report it only with host telemetry enabled and a TerraBase release that exports the load block.")
	spec.Min = float(0)
	return spec
}
