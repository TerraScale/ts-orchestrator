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
	pg := service("", 8080)
	pg.Spec.Annotations.Labels[swarmruntime.LabelPostgres] = "pg.example.com"
	pg.Spec.Endpoint.Ports = append(pg.Spec.Endpoint.Ports, &api.PortConfig{PublishedPort: 6432})
	taskPort := service("login.example.com", 0) // a ${PORT} spec publishes none
	taskPort.Spec.Annotations.Labels[swarmruntime.LabelPort] = "8091"
	got, gotPG := edgeRoutes([]*api.Service{
		pg,
		thief,
		auth,
		service("api.example.com,www.example.com", 8080),
		service("", 9000),                // internal only
		service("noport.example.com", 0), // no published port
		taskPort,
	}, "")
	want := map[string]int{"login.example.com": 8091, "auth.example.com": 8090, "api.example.com": 8080, "www.example.com": 8080}
	if !maps.Equal(got, want) || !maps.Equal(gotPG, map[string]int{"pg.example.com": 6432}) {
		t.Fatalf("routes = %v %v, want %v", got, gotPG, want)
	}
}

func TestEdgeRoutesAddsOwnRegionHostnames(t *testing.T) {
	service := func(created int64, hosts string, port uint32) *api.Service {
		return &api.Service{
			Spec: api.ServiceSpec{
				Annotations: api.Annotations{Labels: map[string]string{swarmruntime.LabelHostnames: hosts}},
				Endpoint:    &api.EndpointSpec{Ports: []*api.PortConfig{{PublishedPort: port}}},
			},
			Meta: api.Meta{CreatedAt: &types.Timestamp{Seconds: created}},
		}
	}
	services := []*api.Service{
		service(3, "api.example.com", 9999), // newer claim: neither api nor sjc.api moves
		service(1, "api.example.com,gru.api.example.com", 8080),
		service(2, "sjc.auth.example.com", 7000), // declared: wins over the derived sjc.auth
		service(4, "auth.example.com", 8090),
	}
	got, _ := edgeRoutes(services, "sjc")
	want := map[string]int{
		"api.example.com": 8080, "sjc.api.example.com": 8080, "gru.api.example.com": 8080,
		"sjc.auth.example.com": 7000, "auth.example.com": 8090,
	}
	if !maps.Equal(got, want) {
		t.Fatalf("sjc routes = %v, want %v", got, want)
	}
	got, _ = edgeRoutes(services, "fra")
	want = map[string]int{
		"api.example.com": 8080, "fra.api.example.com": 8080, "gru.api.example.com": 8080,
		"sjc.auth.example.com": 7000, "auth.example.com": 8090, "fra.auth.example.com": 8090,
	}
	if !maps.Equal(got, want) {
		t.Fatalf("fra routes = %v, want %v", got, want)
	}
}
