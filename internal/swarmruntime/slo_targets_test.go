package swarmruntime

import (
	"reflect"
	"testing"

	"github.com/moby/swarmkit/v2/api"
)

func TestSLOTargetsPreserveOverlappingProcessIdentity(t *testing.T) {
	service := func(id, name string) *api.Service {
		return &api.Service{ID: id, Spec: api.ServiceSpec{Annotations: api.Annotations{Name: name}}}
	}
	services := []*api.Service{service("auth", "ts-auth"), service("dash", "ts-dashboard"), service("other", "customer-app"), service("base", "terrabase")}
	container := func(service, task, port string) map[string]string {
		return map[string]string{"terrascale.service": service, "terrascale.task": task, portsLabel: port}
	}
	containers := []map[string]string{
		container("auth", "old", "41001"), container("auth", "new", "41002"),
		container("dash", "dashboard", "8085"), container("other", "untrusted", "1234"),
		container("base", "terrabase", "8080,6432"), container("auth", "released", releasedPorts),
		container("auth", "zero", "0"), container("auth", "overflow", "65536"),
		container("auth", "multiple", "1111,2222"), container("auth", "", "3333"),
	}
	got := sloTargets(services, containers, "gru")
	want := []SLOTarget{
		{Targets: []string{"127.0.0.1:41001"}, Labels: map[string]string{"service": "ts-auth", "region": "gru", "instance": "old"}},
		{Targets: []string{"127.0.0.1:41002"}, Labels: map[string]string{"service": "ts-auth", "region": "gru", "instance": "new"}},
		{Targets: []string{"127.0.0.1:8085"}, Labels: map[string]string{"service": "ts-dashboard", "region": "gru", "instance": "dashboard"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("targets = %#v, want %#v", got, want)
	}
	// A retired process disappears; its successor keeps its own counter identity.
	got = sloTargets(services, containers[1:2], "gru")
	if !reflect.DeepEqual(got, want[1:2]) {
		t.Fatalf("replacement targets = %#v", got)
	}
	services[0].PendingDelete = true
	if got := sloTargets(services, containers[1:2], "gru"); len(got) != 0 {
		t.Fatalf("deleted service remains discoverable: %#v", got)
	}
}
