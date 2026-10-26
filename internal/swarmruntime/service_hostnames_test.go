package swarmruntime

import (
	"testing"

	"github.com/moby/swarmkit/v2/api"
)

func TestHostnameClaimedByOtherRefusesTakeover(t *testing.T) {
	owner := &api.Service{Spec: api.ServiceSpec{Annotations: api.Annotations{Name: "ts-auth",
		Labels: map[string]string{LabelHostnames: "auth.example.com,login.example.com"}}}}
	services := []*api.Service{owner}
	if err := hostnameClaimedByOther(services, "evil", []string{"login.example.com"}); err == nil {
		t.Fatal("another service took over login.example.com")
	}
	if err := hostnameClaimedByOther(services, "ts-auth", []string{"auth.example.com"}); err != nil {
		t.Fatalf("owner re-apply refused: %v", err)
	}
	if err := hostnameClaimedByOther(services, "api", []string{"api.example.com"}); err != nil {
		t.Fatalf("free hostname refused: %v", err)
	}
	if err := hostnameClaimedByOther(services, "worker", nil); err != nil {
		t.Fatalf("service without hostnames refused: %v", err)
	}
}

func TestServiceSpecPostgresPublishesSecondPort(t *testing.T) {
	base := ServiceSpec{Name: "terrabase", Image: "docker.io/library/alpine@sha256:3e9b4b680bfc9fb5269227cffbd6d42be39fbf7c0b908123913864aa4447e764",
		Port: 8080, Replicas: 1, Postgres: &ServicePostgres{Port: 6432, Hostname: "pg.example.com"}}
	spec, err := base.SwarmSpec()
	if err != nil {
		t.Fatal(err)
	}
	if ports := spec.Endpoint.Ports; len(ports) != 2 || ports[0].PublishedPort != 8080 || ports[1].PublishedPort != 6432 || ports[1].TargetPort != 6432 || spec.Annotations.Labels[LabelPostgres] != "pg.example.com" {
		t.Fatalf("endpoint %v labels %v", spec.Endpoint.Ports, spec.Annotations.Labels)
	}
	inspected, err := InspectService(&api.Service{Spec: *spec})
	if err != nil || *inspected.Spec.Postgres != *base.Postgres {
		t.Fatalf("inspect postgres = %+v, %v", inspected.Spec.Postgres, err)
	}
	owner := &api.Service{Spec: *spec}
	if err := hostnameClaimedByOther([]*api.Service{owner}, "evil", []string{"pg.example.com"}); err == nil {
		t.Fatal("another service took over the postgres hostname")
	}
	for _, pg := range []ServicePostgres{{Port: 8080, Hostname: "pg.example.com"}, {Port: 80, Hostname: "pg.example.com"}, {Port: 6432, Hostname: "Not A Host"}} {
		bad := base
		bad.Postgres = &pg
		if _, err := bad.SwarmSpec(); err == nil {
			t.Fatalf("postgres %+v accepted", pg)
		}
	}
}

func TestServiceSpecWirePublishesPrivatePortAndRoundTrips(t *testing.T) {
	base := ServiceSpec{Name: "terrabase", Image: "docker.io/library/alpine@sha256:3e9b4b680bfc9fb5269227cffbd6d42be39fbf7c0b908123913864aa4447e764",
		Port: 8080, Replicas: 1, Env: map[string]string{"TERRABASE_WIRE_PORT": "7465"},
		Postgres: &ServicePostgres{Port: 6432, Hostname: "pg.example.com"}, Wire: &ServicePostgres{Port: 7465, Hostname: "api.example.com"}}
	spec, err := base.SwarmSpec()
	if err != nil {
		t.Fatal(err)
	}
	ports := spec.Endpoint.Ports
	if len(ports) != 3 || ports[2].PublishedPort != 7465 || ports[2].TargetPort != 7465 {
		t.Fatalf("ports = %v", ports)
	}
	inspected, err := InspectService(&api.Service{Spec: *spec})
	if err != nil || inspected.Spec.Wire == nil || *inspected.Spec.Wire != *base.Wire || inspected.Spec.Postgres == nil || *inspected.Spec.Postgres != *base.Postgres {
		t.Fatalf("inspect = %+v, %v", inspected.Spec, err)
	}
	if err := hostnameClaimedByOther([]*api.Service{{Spec: *spec}}, "evil", []string{"api.example.com"}); err == nil {
		t.Fatal("wire hostname takeover accepted")
	}
	for _, wire := range []ServicePostgres{{Port: 8080, Hostname: "api.example.com"}, {Port: 6432, Hostname: "api.example.com"}, {Port: 7464, Hostname: "api.example.com"}, {Port: 80, Hostname: "api.example.com"}, {Port: 7465, Hostname: "bad host"}, {Port: 7466, Hostname: "api.example.com"}} {
		bad := base
		bad.Wire = &wire
		if _, err := bad.SwarmSpec(); err == nil {
			t.Fatalf("accepted invalid wire %+v", wire)
		}
	}
}
