package swarmruntime

import (
	"slices"
	"testing"

	"github.com/moby/swarmkit/v2/api"
)

func TestServiceSpecTaskPortStartsFirst(t *testing.T) {
	base := ServiceSpec{Name: "ts-auth", Image: "docker.io/library/alpine@sha256:3e9b4b680bfc9fb5269227cffbd6d42be39fbf7c0b908123913864aa4447e764",
		Port: 8090, ReadyPath: "/readyz", Replicas: 1, Env: map[string]string{"TS_AUTH_LISTEN": "http://127.0.0.1:" + TaskPortEnv}}
	spec, err := base.SwarmSpec()
	if err != nil {
		t.Fatal(err)
	}
	if len(spec.Endpoint.Ports) != 0 || spec.Annotations.Labels[LabelPort] != "8090" || spec.Update.Order != api.UpdateConfig_START_FIRST {
		t.Fatalf("endpoint %v labels %v order %v", spec.Endpoint.Ports, spec.Annotations.Labels, spec.Update.Order)
	}
	task := &api.Task{ServiceAnnotations: spec.Annotations}
	if port, err := hostPort(task); err != nil || port != 8090 {
		t.Fatalf("hostPort = %d, %v", port, err)
	}
	if inspected, err := InspectService(&api.Service{Spec: *spec}); err != nil || inspected.Spec.Port != 8090 {
		t.Fatalf("inspect port = %d, %v", inspected.Spec.Port, err)
	}
	container, err := containerOf(*spec)
	if err != nil {
		t.Fatal(err)
	}
	if got := withTaskPort(container.Env, 41234); !slices.Equal(got, []string{"TS_AUTH_LISTEN=http://127.0.0.1:41234"}) {
		t.Fatalf("env = %v", got)
	}
	for _, bad := range []func(*ServiceSpec){
		func(s *ServiceSpec) { s.ReadyPath = "" },
		func(s *ServiceSpec) { s.Postgres = &ServicePostgres{Port: 6432, Hostname: "pg.example.com"} },
		func(s *ServiceSpec) { s.Mounts = []ServiceMount{{Source: "/var/lib/ts-data/a", Target: "/a"}} },
	} {
		s := base
		bad(&s)
		if _, err := s.SwarmSpec(); err == nil {
			t.Fatalf("spec %+v accepted", s)
		}
	}
	plain := base
	plain.Env = nil
	if spec, err := plain.SwarmSpec(); err != nil || len(spec.Endpoint.Ports) != 1 || spec.Update.Order != api.UpdateConfig_STOP_FIRST {
		t.Fatalf("plain spec = %v, %v", spec, err)
	}
}
