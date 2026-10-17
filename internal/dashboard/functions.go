package dashboard

import (
	"fmt"

	"github.com/TerraScale/ts-orchestrator/internal/globalview"
)

func functionTable(region globalview.Region) table {
	listing := table{Caption: "Functions", Headers: []string{"Tenant", "Function", "Revision", "Requested digest", "Task", "Node", "Source", "Worker", "Active", "Succeeded", "Failed", "Rejected", "Observed"}, Empty: "No admitted functions in the current complete observation."}
	if region.Rollup == nil {
		listing.Empty = "Functions unknown: no regional observation."
		return listing
	}
	if region.Rollup.Truncated {
		listing.Caption += " (truncated: function and task lists may be incomplete)"
		listing.Empty = "No function rows retained in the truncated observation."
	}
	if state := region.FunctionState(nil, true); state != "current" {
		listing.Caption += " (" + state + " observation)"
		listing.Empty = "Functions unknown: " + state + " observation."
	}
	for _, function := range region.Rollup.Functions {
		state := region.FunctionState(&function, true)
		active, succeeded, failed, rejected := "unknown", "unknown", "unknown", "unknown"
		if state == "current" && function.State == "observed" && function.Snapshot != nil {
			active = fmt.Sprint(function.Snapshot.Active)
			succeeded = fmt.Sprint(function.Snapshot.Succeeded)
			failed = fmt.Sprint(function.Snapshot.Failed)
			rejected = fmt.Sprint(function.Snapshot.Rejected)
		}
		listing.Rows = append(listing.Rows, []cell{
			textCell(function.TenantID), textCell(function.FunctionID), textCell(function.Revision), textCell(function.Digest),
			textCell(orDash(function.TaskID)), textCell(orDash(function.NodeID)), textCell(state), textCell(function.State),
			textCell(active), textCell(succeeded), textCell(failed), textCell(rejected), textCell(metricObserved(function.ObservedAt)),
		})
	}
	return listing
}
