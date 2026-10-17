//go:build linux

package swarmruntime

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/gogo/protobuf/types"
	"github.com/moby/swarmkit/v2/api"
)

func TestStoppedOwnersRequireActualTerminalReports(t *testing.T) {
	stamp, err := types.TimestampProto(time.Now().Add(-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range []api.TaskState{api.TaskStateNew, api.TaskStatePending, api.TaskStateAssigned, api.TaskStateAccepted,
		api.TaskStatePreparing, api.TaskStateReady, api.TaskStateStarting, api.TaskStateRunning, api.TaskStateFailed,
		api.TaskStateRejected, api.TaskStateRemove, api.TaskStateOrphaned, api.TaskStateShutdown, api.TaskStateCompleted} {
		task := &api.Task{DesiredState: api.TaskStateShutdown, Status: api.TaskStatus{State: state, Timestamp: stamp}}
		want := state == api.TaskStateShutdown || state == api.TaskStateCompleted
		if allStopped([]*api.Task{task}) != want {
			t.Fatalf("desired shutdown changed stopped proof for actual state %v", state)
		}
	}
	for _, tasks := range [][]*api.Task{nil, {nil}, {{Status: api.TaskStatus{State: api.TaskStateShutdown}}},
		{{Status: api.TaskStatus{State: api.TaskStateCompleted, Timestamp: &types.Timestamp{Seconds: 1 << 62}}}}} {
		if allStopped(tasks) {
			t.Fatal("missing or invalid terminal report accepted as stopped")
		}
	}
}

func TestProtectedNodesRetainConflictingWorkerOwners(t *testing.T) {
	manager := &api.Node{ID: "manager", Role: api.NodeRoleManager}
	oldWorker := &api.Node{ID: "old-worker", Role: api.NodeRoleWorker}
	otherWorker := &api.Node{ID: "other-worker", Role: api.NodeRoleWorker}
	protected := protectedNodes([]*api.Node{manager, oldWorker, otherWorker}, []*api.Node{oldWorker})
	if len(protected) != 2 || protected[0] != manager || protected[1] != oldWorker {
		t.Fatal("conflicting worker disappeared from native node version checks")
	}
}

func TestControllerRequestGuardPreservesOriginalDenial(t *testing.T) {
	originalDenial := errors.New("original root request ended")
	original := ociclient.WithRequestGuard(t.Context(), func(context.Context) error { return originalDenial })
	admitted := new(controllerActivationAdmission)
	if err := ociclient.CheckRequestGuard(admitted.requestContext(original)); !errors.Is(err, originalDenial) {
		t.Fatalf("original request guard was replaced: %v", err)
	}
	acceptedOriginal := ociclient.WithRequestGuard(t.Context(), func(context.Context) error { return nil })
	if err := ociclient.CheckRequestGuard(admitted.requestContext(acceptedOriginal)); !errors.Is(err, ErrControllerActivationPending) {
		t.Fatalf("original acceptance bypassed unavailable concrete sources: %v", err)
	}
}
