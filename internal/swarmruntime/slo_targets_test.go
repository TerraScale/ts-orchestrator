package swarmruntime

import (
	"context"
	"reflect"
	"slices"
	"testing"

	"github.com/moby/swarmkit/v2/api"
)

func TestSLOTargetsPreserveOverlappingProcessIdentity(t *testing.T) {
	service := func(id, name string) *api.Service {
		return &api.Service{ID: id, Spec: api.ServiceSpec{Annotations: api.Annotations{Name: name}}}
	}
	services := []*api.Service{service("auth", "ts-auth"), service("dash", "ts-dashboard"), service("other", "customer-app"), service("base", "terrabase")}
	oldPID, oldPort, oldMetrics, _ := startSLOListenerProcess(t)
	newPID, newPort, newMetrics, _ := startSLOListenerProcess(t)
	container := func(service, task, port string) sloContainer {
		pid := uint32(0)
		if task == "old" {
			pid = oldPID
		}
		if task == "new" {
			pid = newPID
		}
		return sloContainer{map[string]string{"terrascale.service": service, "terrascale.task": task, portsLabel: port}, pid}
	}
	containers := []sloContainer{
		container("auth", "old", oldPort), container("auth", "new", newPort),
		container("dash", "dashboard", "8085"), container("other", "untrusted", "1234"),
		container("base", "terrabase", "8080,6432"), container("auth", "released", releasedPorts),
		container("auth", "zero", "0"), container("auth", "overflow", "65536"),
		container("auth", "multiple", "1111,2222"), container("auth", "", "3333"),
	}
	got := sloTargets(context.Background(), services, containers, "gru")
	want := []SLOTarget{
		{Targets: []string{oldMetrics}, Labels: map[string]string{"service": "ts-auth", "region": "gru", "instance": "old"}},
		{Targets: []string{newMetrics}, Labels: map[string]string{"service": "ts-auth", "region": "gru", "instance": "new"}},
		{Targets: []string{"127.0.0.1:8085"}, Labels: map[string]string{"service": "ts-dashboard", "region": "gru", "instance": "dashboard"}},
	}
	slices.SortFunc(want, func(a, b SLOTarget) int { return slices.Compare(a.Targets, b.Targets) })
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("targets = %#v, want %#v", got, want)
	}
	// A retired process disappears; its successor keeps its own counter identity.
	got = sloTargets(context.Background(), services, containers[1:2], "gru")
	if len(got) != 1 || got[0].Targets[0] != newMetrics || got[0].Labels["instance"] != "new" {
		t.Fatalf("replacement targets = %#v", got)
	}
	services[0].PendingDelete = true
	if got := sloTargets(context.Background(), services, containers[1:2], "gru"); len(got) != 0 {
		t.Fatalf("deleted service remains discoverable: %#v", got)
	}
}
