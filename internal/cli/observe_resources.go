package cli

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/globalview"
)

func isObserveResource(view string) bool {
	return slices.Contains([]string{"regions", "region", "nodes", "node", "services", "service", "volumes", "volume"}, view)
}

func observeResourcePath(view, cell, node, service, volume string) (string, error) {
	for _, selector := range []string{cell, node, service, volume} {
		if len(selector) > 256 || strings.ContainsAny(selector, "/\\\x00\r\n\t") || selector == "." || selector == ".." {
			return "", errors.New("resource selectors must be at most 256 characters without path separators or control characters")
		}
	}
	if view == "regions" {
		return "/v1/regions", nil
	}
	if (view == "node" || view == "services" || view == "service") && node == "" {
		return "", errors.New("this observation requires --node NAME")
	}
	if view == "service" && service == "" {
		return "", errors.New("observe service requires --service ROLE")
	}
	if view == "volume" && volume == "" {
		return "", errors.New("observe volume requires --volume ID")
	}
	path := "/v1/regions/" + cell
	switch view {
	case "nodes":
		path += "/nodes"
	case "node":
		path += "/nodes/" + node
	case "services":
		path += "/nodes/" + node + "/services"
	case "service":
		path += "/nodes/" + node + "/services/" + service
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
	if format == "table" {
		observed := "unknown"
		if !result.ObservedAt.IsZero() {
			observed = result.ObservedAt.Format(time.RFC3339)
		}
		fmt.Fprintf(out, "CELL\t%s\tSTATE\t%s\tOBSERVED\t%s\tTRUNCATED\t%t\n", result.Cell, result.State, observed, result.Truncated)
		data, err := json.Marshal(result.Data)
		if err != nil {
			return nil, false, err
		}
		fmt.Fprintf(out, "DATA\t%s\n", data)
	}
	return result, partial, nil
}
