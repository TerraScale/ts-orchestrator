package app

import (
	"maps"
	"testing"

	"github.com/gogo/protobuf/types"
	"github.com/moby/swarmkit/v2/api"

	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
)

func TestEdgeRoutesMapsHostnamesToPublishedPort(t *testing.T) {
	created := int64(0)
	service := func(hosts string, port uint32) *api.Service {
		created++
		spec := api.ServiceSpec{Annotations: api.Annotations{Labels: map[string]string{}}}
		if hosts != "" {
			spec.Annotations.Labels[swarmruntime.LabelHostnames] = hosts
		}
		if port != 0 {
			spec.Endpoint = &api.EndpointSpec{Ports: []*api.PortConfig{{PublishedPort: port}}}
		}
		return &api.Service{Spec: spec, Meta: api.Meta{CreatedAt: &types.Timestamp{Seconds: created}}}
	}
	auth := service("auth.example.com", 8090)
	thief := service("auth.example.com", 9999) // newer claim on an owned hostname
	got := edgeRoutes([]*api.Service{
		thief,
		auth,
		service("api.example.com,www.example.com", 8080),
		service("", 9000),                // internal only
		service("noport.example.com", 0), // no published port
	})
	want := map[string]int{"auth.example.com": 8090, "api.example.com": 8080, "www.example.com": 8080}
	if !maps.Equal(got, want) {
		t.Fatalf("routes = %v, want %v", got, want)
	}
}
