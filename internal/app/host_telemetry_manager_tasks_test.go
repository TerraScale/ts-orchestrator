package app

import (
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/moby/swarmkit/v2/api"
)

func TestManagerUsageTaskInventoryRefusesUnknownState(t *testing.T) {
	registration := host.Registration{Cell: "gru", Node: "host-a", Environment: "production",
		ID: entityid.Derive("host", "gru", "host-a")}
	node := &api.Node{ID: "manager-node-id", Role: api.NodeRoleWorker,
		Spec: api.NodeSpec{Membership: api.NodeMembershipAccepted, Annotations: api.Annotations{
			Name: registration.ID, Labels: map[string]string{swarmruntime.LabelRegion: "sa-saopaulo-1"},
		}}}
	for _, tc := range []struct {
		name    string
		state   api.TaskState
		unknown bool
		count   int
	}{
		{name: "shutdown desired still reserves", state: api.TaskStateRunning, count: 1},
		{name: "completed releases reservation", state: api.TaskStateCompleted},
		{name: "shutdown releases reservation", state: api.TaskStateShutdown},
		{name: "negative state is unknown", state: -1, unknown: true},
		{name: "future state is unknown", state: 1000000, unknown: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			task := &api.Task{ID: "task-id", NodeID: node.ID, Status: api.TaskStatus{State: tc.state}, DesiredState: api.TaskStateShutdown,
				ServiceAnnotations: api.Annotations{Labels: map[string]string{
					swarmruntime.LabelRegion: "sa-saopaulo-1", swarmruntime.LabelEnvironment: registration.Environment,
				}}}
			tasks, err := telemetrySnapshotTasks(nil, []*api.Node{node}, []*api.Task{task}, registration, func(string) bool { return true })
			if (err != nil) != tc.unknown || len(tasks) != tc.count {
				t.Fatalf("allocation inventory for state %d: tasks=%d, error=%v", tc.state, len(tasks), err)
			}
		})
	}
}

func TestManagerUsageTaskInventoryRequiresManagedNode(t *testing.T) {
	for _, tc := range []struct {
		name    string
		roles   []string
		missing bool
	}{
		{name: "generic role", roles: []string{"api"}, missing: true},
		{name: "function role", roles: []string{"function-worker"}, missing: true},
		{name: "native and generic roles", roles: []string{"terrabase", "api"}, missing: true},
		{name: "native data role", roles: []string{"terrabase"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			registration := host.Registration{Cell: "gru", Node: "host-a", Environment: "production", Roles: tc.roles,
				ID: entityid.Derive("host", "gru", "host-a")}
			owns := func(role string) bool { return role == "api" || role == "function-worker" }
			tasks, err := telemetrySnapshotTasks(nil, nil, nil, registration, owns)
			if (err != nil) != tc.missing || len(tasks) != 0 {
				t.Fatalf("missing manager node for registered roles %v: tasks=%d, error=%v", tc.roles, len(tasks), err)
			}
		})
	}
}
