package dashboard

import (
	"fmt"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/globalview"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
)

func managedServiceTable(current view, region globalview.Region) table {
	listing := table{Caption: "Managed services", Headers: []string{"Service", "Role", "Requested", "Running", "Ready", "Requested digest", "Update", "Observed"}, Empty: "No managed services in the current complete observation."}
	if region.Rollup == nil {
		listing.Empty = "Managed services unknown: no regional observation."
		return listing
	}
	if region.Rollup.Truncated {
		listing.Caption += " (truncated: service and task lists may be incomplete)"
	}
	if state := region.ManagedServiceState(true, region.Rollup.ServicesObservedAt); state != "current" {
		listing.Empty = "Managed services unknown: " + state + " observation."
	}
	for _, service := range region.Rollup.Services {
		listing.Rows = append(listing.Rows, []cell{
			{Text: service.ServiceID, Href: current.State.managedServiceLink(region.Cell, service.ServiceID)},
			textCell(service.Role), textCell(fmt.Sprint(service.RequestedReplicas)), textCell(fmt.Sprint(service.RunningReplicas)),
			textCell(managedServiceReady(service)), textCell(service.RequestedDigest), textCell(orDash(service.UpdateState)), textCell(metricObserved(service.ObservedAt)),
		})
	}
	return listing
}

func managedServiceReady(service swarmruntime.ServiceObservation) string {
	if service.Readiness != "observed" {
		return "unknown"
	}
	return fmt.Sprint(service.ReadyReplicas)
}

func managedServiceNamed(region globalview.Region, id string) (swarmruntime.ServiceObservation, bool) {
	if region.Rollup == nil || region.Rollup.ServicesObservedAt.IsZero() {
		return swarmruntime.ServiceObservation{}, false
	}
	return find(region.Rollup.Services, func(service swarmruntime.ServiceObservation) bool { return service.ServiceID == id })
}

func managedServiceTasks(service swarmruntime.ServiceObservation) table {
	listing := table{Caption: "Observed managed tasks", Headers: []string{"Task", "Node", "Digest", "Lifecycle", "Ready", "Error", "Updated"}, Empty: "No task has been observed; the service may be unplaced."}
	for _, task := range service.Tasks {
		ready := "unknown"
		if service.Readiness == "observed" {
			ready = fmt.Sprint(task.Ready)
		}
		listing.Rows = append(listing.Rows, []cell{textCell(task.TaskID), textCell(orDash(task.NodeID)), textCell(orDash(task.Digest)), textCell(task.State), textCell(ready), textCell(orDash(task.Error)), textCell(metricObserved(task.UpdatedAt))})
	}
	return listing
}

func managedServiceState(region globalview.Region, service swarmruntime.ServiceObservation, found bool) string {
	observed := service.ObservedAt
	if !found && region.Rollup != nil {
		observed = region.Rollup.ServicesObservedAt
	}
	state := region.ManagedServiceState(found, observed)
	if region.Rollup != nil && region.Rollup.Truncated {
		state += "; service and task lists are truncated"
	}
	return state
}

func (state uiState) managedServiceLink(region, service string) string {
	return state.drillLink(detailPath("/regions/{r}/services/{s}", map[string]string{"r": region, "s": service}))
}

func managedServicesObserved(region globalview.Region) string {
	if region.Rollup == nil || region.Rollup.ServicesObservedAt.IsZero() {
		return "unknown"
	}
	return region.Rollup.ServicesObservedAt.UTC().Format(time.RFC3339Nano)
}
