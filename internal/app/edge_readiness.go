package app

import (
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/moby/swarmkit/v2/api"
)

func edgeReadinessRoutes(services []*api.Service, region string) []mesh.EdgeRoute {
	web, _ := edgeRoutes(services, region)
	routes := []mesh.EdgeRoute{}
	seen := map[int]bool{}
	for _, service := range services {
		labels := service.Spec.Annotations.Labels
		path := labels[swarmruntime.LabelReadyPath]
		if path == "" {
			path = swarmruntime.DefaultReadyPath
		}
		for host := range strings.SplitSeq(labels[swarmruntime.LabelHostnames], ",") {
			port, ok := web[host]
			if !ok || seen[port] {
				continue
			}
			seen[port] = true
			routes = append(routes, mesh.EdgeRoute{Host: host, Port: port, Path: path})
		}
	}
	return routes
}
