package globalview

import (
	"net/http"
	"slices"
)

func mountFunctionViews(mux *http.ServeMux, view *View) {
	for _, path := range []string{"functions", "functions/{tenant}/{function}"} {
		mux.HandleFunc("GET /v1/regions/{region}/"+path, func(w http.ResponseWriter, r *http.Request) {
			region, listed := view.Region(r.PathValue("region"))
			result := ResourceView{Version: 1, Cell: region.Cell, State: "not_found"}
			found := false
			if listed && region.Rollup != nil {
				result.Truncated, result.ObservedAt = region.Rollup.Truncated, region.Rollup.FunctionsObservedAt
				if path == "functions" {
					found, result.Data = true, slices.Clone(region.Rollup.Functions)
					result.State = region.FunctionState(nil, true)
					for _, function := range region.Rollup.Functions {
						if state := region.FunctionState(&function, true); state != "current" {
							result.State = state
							break
						}
					}
				} else {
					var functions []FunctionObservation
					for _, function := range region.Rollup.Functions {
						if function.TenantID == r.PathValue("tenant") && function.FunctionID == r.PathValue("function") {
							functions = append(functions, function)
						}
					}
					found = len(functions) > 0
					result.State = region.FunctionState(nil, found)
					if found {
						result.Data = functions
						for _, function := range functions {
							if state := region.FunctionState(&function, true); state != "current" {
								result.State = state
							}
							if function.ObservedAt.Before(result.ObservedAt) {
								result.ObservedAt = function.ObservedAt
							}
						}
					}
				}
			} else if listed {
				result.State = "missing"
			}
			status := http.StatusOK
			if !found || result.State == "unavailable" && result.Data == nil {
				status = http.StatusServiceUnavailable
				if result.State == "not_found" {
					status = http.StatusNotFound
				}
			}
			writeResource(w, result, status)
		})
	}
}
