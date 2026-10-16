package cli

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/TerraScale/ts-orchestrator/internal/globalview"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
)

func isObserveResource(view string) bool {
	return slices.Contains([]string{"regions", "region", "nodes", "node", "services", "service", "functions", "function", "volumes", "volume"}, view)
}

func observeResourcePath(view, cell, node, service, volume, tenant, function string) (string, error) {
	for _, selector := range []string{cell, node, service, volume, tenant, function} {
		if len(selector) > 256 || strings.ContainsAny(selector, "/\\") || strings.IndexFunc(selector, unicode.IsControl) >= 0 || selector == "." || selector == ".." {
			return "", errors.New("resource selectors must be at most 256 characters without path separators or control characters")
		}
	}
	if view == "regions" {
		return "/v1/regions", nil
	}
	if view == "node" && node == "" {
		return "", errors.New("this observation requires --node NAME")
	}
	if view == "service" && service == "" {
		return "", errors.New("observe service requires --service ID (or ROLE with --node)")
	}
	if view == "volume" && volume == "" {
		return "", errors.New("observe volume requires --volume ID")
	}
	if view == "function" && (tenant == "" || function == "") {
		return "", errors.New("observe function requires --tenant ID and --function ID")
	}
	path := "/v1/regions/" + cell
	switch view {
	case "functions":
		path += "/functions"
	case "function":
		path += "/functions/" + tenant + "/" + function
	case "nodes":
		path += "/nodes"
	case "node":
		path += "/nodes/" + node
	case "services":
		if node != "" {
			path += "/nodes/" + node
		}
		path += "/services"
	case "service":
		if node != "" {
			path += "/nodes/" + node
		}
		path += "/services/" + service
	case "volumes":
		path += "/volumes"
	case "volume":
		path += "/volumes/" + volume
	}
	return path, nil
}

func observeLocalCell(data []byte) (string, error) {
	var regions []globalview.Region
	if err := json.Unmarshal(data, &regions); err != nil || len(regions) == 0 || regions[0].Cell == "" {
		return "", errors.New("regional API did not identify its local region")
	}
	return regions[0].Cell, nil
}

func observeResourceError(path string, status int, data []byte) bool {
	if !strings.HasPrefix(path, "/v1/regions/") || (status != http.StatusNotFound && status != http.StatusServiceUnavailable) {
		return false
	}
	var result globalview.ResourceView
	if json.Unmarshal(data, &result) != nil || result.Version != 1 {
		return false
	}
	return slices.Contains([]string{"stale", "missing", "truncated", "unavailable", "not_found"}, result.State)
}

func writeObserveResource(out io.Writer, view, format string, data []byte) (any, bool, error) {
	if view == "regions" || view == "region" {
		var regions []globalview.Region
		if view == "region" {
			var region globalview.Region
			if err := json.Unmarshal(data, &region); err != nil || region.Cell == "" {
				return nil, false, errors.New("invalid region observation JSON")
			}
			regions = []globalview.Region{region}
		} else if err := json.Unmarshal(data, &regions); err != nil {
			return nil, false, errors.New("invalid regional observation JSON")
		}
		partial := len(regions) == 0
		if format == "table" {
			fmt.Fprintln(out, "CELL\tSTATE\tOBSERVED\tTRUNCATED\tNODES\tREADY")
		}
		for _, region := range regions {
			state, observed, truncated, nodes, ready := region.ResourceState(true), "unknown", false, 0, 0
			if region.Rollup != nil {
				observed = region.Rollup.ObservedAt.Format(time.RFC3339)
				truncated = region.Rollup.Truncated
				nodes = region.Rollup.Totals.Nodes
				ready = region.Rollup.Totals.Ready
			}
			partial = partial || state != "current" || truncated
			if format == "table" {
				fmt.Fprintf(out, "%s\t%s\t%s\t%t\t%d\t%d\n", region.Cell, state, observed, truncated, nodes, ready)
			}
		}
		if view == "region" {
			return regions[0], partial, nil
		}
		return regions, partial, nil
	}
	var result globalview.ResourceView
	if err := json.Unmarshal(data, &result); err != nil || result.Version != 1 || !slices.Contains([]string{"current", "stale", "missing", "truncated", "unavailable", "not_found"}, result.State) {
		return nil, false, errors.New("invalid resource observation JSON")
	}
	partial := result.State != "current" || result.Truncated
	var raw struct {
		Data jsontext.Value `json:"data"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, false, err
	}
	if format == "table" {
		observed := "unknown"
		if !result.ObservedAt.IsZero() {
			observed = result.ObservedAt.Format(time.RFC3339)
		}
		fmt.Fprintf(out, "CELL\t%s\tSTATE\t%s\tOBSERVED\t%s\tTRUNCATED\t%t\n", result.Cell, result.State, observed, result.Truncated)
		if string(raw.Data) != "null" {
			switch view {
			case "functions", "function":
				var functions []globalview.FunctionObservation
				if err := json.Unmarshal(raw.Data, &functions); err != nil {
					return nil, false, err
				}
				fmt.Fprintln(out, "TENANT\tFUNCTION\tREVISION\tDIGEST\tTASK\tSTATE\tACTIVE\tSUCCEEDED\tFAILED\tREJECTED\tOBSERVED")
				for _, function := range functions {
					active, succeeded, failed, rejected := "unknown", "unknown", "unknown", "unknown"
					if function.State == "observed" && function.Snapshot != nil {
						active, succeeded, failed, rejected = fmt.Sprint(function.Snapshot.Active), fmt.Sprint(function.Snapshot.Succeeded), fmt.Sprint(function.Snapshot.Failed), fmt.Sprint(function.Snapshot.Rejected)
					}
					fmt.Fprintf(out, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", function.TenantID, function.FunctionID, function.Revision, function.Digest, function.TaskID, function.State, active, succeeded, failed, rejected, function.ObservedAt.Format(time.RFC3339))
				}
			case "nodes":
				var nodes []globalview.Node
				if err := json.Unmarshal(raw.Data, &nodes); err != nil {
					return nil, false, err
				}
				fmt.Fprintln(out, "NODE\tHEALTH\tREPORTED\tCPU CORES\tMEMORY bytes\tSERVICES")
				for _, node := range nodes {
					var roles []string
					for _, service := range node.Services {
						roles = append(roles, service.Role)
					}
					fmt.Fprintf(out, "%s\t%s\t%s\t%d\t%d\t%s\n", node.Name, node.Health, node.ReportedAt.Format(time.RFC3339), node.CPUCores, node.MemoryBytes, strings.Join(roles, ","))
				}
			case "services":
				var managed []swarmruntime.ServiceObservation
				if err := json.Unmarshal(raw.Data, &managed); err != nil {
					return nil, false, err
				}
				if len(managed) > 0 && managed[0].ServiceID != "" {
					fmt.Fprintln(out, "SERVICE\tROLE\tREQUESTED\tRUNNING\tREADY\tREQUESTED DIGEST\tUPDATE\tOBSERVED")
					for _, service := range managed {
						ready := "unknown"
						if service.Readiness == "observed" {
							ready = fmt.Sprint(service.ReadyReplicas)
						}
						fmt.Fprintf(out, "%s\t%s\t%d\t%d\t%s\t%s\t%s\t%s\n", service.ServiceID, service.Role, service.RequestedReplicas, service.RunningReplicas, ready, service.RequestedDigest, service.UpdateState, service.ObservedAt.Format(time.RFC3339))
					}
					break
				}
				var services []globalview.Service
				if err := json.Unmarshal(raw.Data, &services); err != nil {
					return nil, false, err
				}
				fmt.Fprintln(out, "ROLE\tEXECUTION STATE\tDIGEST")
				for _, service := range services {
					fmt.Fprintf(out, "%s\t%s\t%s\n", service.Role, service.State, service.Digest)
				}
			case "volumes":
				var volumes []globalview.Volume
				if err := json.Unmarshal(raw.Data, &volumes); err != nil {
					return nil, false, err
				}
				fmt.Fprintln(out, "VOLUME\tNODE\tSTATE\tDETAIL\tSINCE")
				for _, volume := range volumes {
					fmt.Fprintf(out, "%s\t%s\t%s\t%s\t%s\n", volume.ID, volume.Node, volume.State, volume.Detail, volume.Since.Format(time.RFC3339))
				}
			default:
				fmt.Fprintf(out, "DATA\t%s\n", raw.Data)
			}
		}
	}
	return jsontext.Value(data), partial, nil
}
