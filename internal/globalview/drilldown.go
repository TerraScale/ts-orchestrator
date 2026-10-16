package globalview

import (
	"net/http"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
)

// ResourceView retains the observation metadata alongside a node, service or
// volume. Data is nil when the resource cannot be established from this view.
type ResourceView struct {
	Version    int       `json:"version"`
	Cell       string    `json:"cell"`
	ObservedAt time.Time `json:"observed_at,omitzero"`
	State      string    `json:"state"`
	Truncated  bool      `json:"truncated"`
	Data       any       `json:"data"`
}

// ResourceState distinguishes an absent observation from a confirmed absence.
// A retained, incomplete list cannot establish that an omitted resource is gone.
func (region Region) ResourceState(found bool) string {
	switch {
	case region.Rollup == nil:
		return "missing"
	case region.Stale:
		return "stale"
	case !found && region.Rollup.Truncated:
		return "truncated"
	case !found:
		return "not_found"
	default:
		return "current"
	}
}

func mountDrilldowns(mux *http.ServeMux, view *View) {
	for _, resource := range []string{"nodes", "nodes/{node}", "nodes/{node}/services", "nodes/{node}/services/{service}", "volumes", "volumes/{volume}", "services", "services/{service}"} {
		mux.HandleFunc("GET /v1/regions/{region}/"+resource, func(writer http.ResponseWriter, request *http.Request) {
			region, listed := view.Region(request.PathValue("region"))
			result := ResourceView{Version: 1, Cell: region.Cell, State: "not_found"}
			if !listed {
				writeResource(writer, result, http.StatusNotFound)
				return
			}
			if region.Rollup == nil {
				result.State = "missing"
				writeResource(writer, result, http.StatusServiceUnavailable)
				return
			}
			result.ObservedAt, result.Truncated = region.Rollup.ObservedAt, region.Rollup.Truncated
			data, found := drilldownData(region.Rollup, resource, request)
			result.State, result.Data = region.ResourceState(found), data
			if resource == "services" || resource == "services/{service}" {
				observed := region.Rollup.ServicesObservedAt
				for _, service := range region.Rollup.Services {
					if resource == "services" || service.ServiceID == request.PathValue("service") {
						if service.ObservedAt.IsZero() || service.ObservedAt.Before(observed) {
							observed = service.ObservedAt
						}
					}
				}
				result.State = region.ManagedServiceState(found, observed)
				result.ObservedAt = observed
				if result.State == "unavailable" {
					result.Data, found = nil, false
				}
			}
			if (resource == "volumes" || resource == "volumes/{volume}") && region.Rollup.VolumesUnavailable {
				result.State, result.Data = "unavailable", nil
				found = false
			}
			status := http.StatusOK
			if !found {
				status = http.StatusServiceUnavailable
				if result.State == "not_found" {
					status = http.StatusNotFound
				}
			}
			writeResource(writer, result, status)
		})
	}
}

func drilldownData(rollup *Rollup, resource string, request *http.Request) (any, bool) {
	switch resource {
	case "services":
		return slices.Clone(rollup.Services), true
	case "services/{service}":
		if index := slices.IndexFunc(rollup.Services, func(service swarmruntime.ServiceObservation) bool {
			return service.ServiceID == request.PathValue("service")
		}); index >= 0 {
			return rollup.Services[index], true
		}
	case "nodes":
		return append([]Node{}, rollup.Nodes...), true
	case "volumes":
		return append([]Volume{}, rollup.Volumes...), true
	case "volumes/{volume}":
		if index := slices.IndexFunc(rollup.Volumes, func(volume Volume) bool { return volume.ID == request.PathValue("volume") }); index >= 0 {
			return rollup.Volumes[index], true
		}
	default:
		index := slices.IndexFunc(rollup.Nodes, func(node Node) bool { return node.Name == request.PathValue("node") })
		if index < 0 {
			return nil, false
		}
		node := rollup.Nodes[index]
		switch resource {
		case "nodes/{node}":
			return node, true
		case "nodes/{node}/services":
			return append([]Service{}, node.Services...), true
		case "nodes/{node}/services/{service}":
			if index := slices.IndexFunc(node.Services, func(service Service) bool { return service.Role == request.PathValue("service") }); index >= 0 {
				return node.Services[index], true
			}
		}
	}
	return nil, false
}

func writeResource(writer http.ResponseWriter, result ResourceView, status int) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
	writeJSON(writer, result)
}
