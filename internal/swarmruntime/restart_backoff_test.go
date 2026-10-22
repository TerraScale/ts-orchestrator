package swarmruntime

import (
	"testing"
	"time"

	"github.com/gogo/protobuf/types"
	"github.com/moby/swarmkit/v2/api"
)

func TestRestartBackoffDoublesCapsAndResets(t *testing.T) {
	for n, want := range map[int]time.Duration{1: time.Second, 2: 2 * time.Second, 3: 4 * time.Second, 6: 32 * time.Second, 7: time.Minute, 50: time.Minute} {
		if got := restartBackoff(n); got != want {
			t.Fatalf("backoff(%d) = %s, want %s", n, got, want)
		}
	}
	e := &Executor{}
	task := &api.Task{ServiceID: "svc", Slot: 1, NodeID: "n1"}
	now := time.Unix(1_000, 0)
	if d := e.restartDelayLocked(task, "v1", now); d != 0 {
		t.Fatalf("first start waits %s", d)
	}
	for range 3 {
		e.recordExitLocked(task, "v1", time.Second, now)
	}
	if d := e.restartDelayLocked(task, "v1", now.Add(time.Second)); d != 3*time.Second {
		t.Fatalf("third crash waits %s, want 3s left of 4s", d)
	}
	if d := e.restartDelayLocked(&api.Task{ServiceID: "svc", Slot: 2, NodeID: "n1"}, "v1", now); d != 0 {
		t.Fatalf("other slot waits %s", d)
	}
	if d := e.restartDelayLocked(task, "v2", now); d != 0 {
		t.Fatalf("new spec waits %s", d)
	}
	e.recordExitLocked(task, "v1", restartResetAfter, now)
	if d := e.restartDelayLocked(task, "v1", now); d != time.Second {
		t.Fatalf("crash after a healthy minute waits %s, want 1s", d)
	}
	e.recordExitLocked(task, "v2", time.Second, now)
	if d := e.restartDelayLocked(task, "v2", now); d != time.Second {
		t.Fatalf("first crash of a new spec waits %s, want 1s", d)
	}
}

func TestTaskRowsShowRestartsExitAndCrashLoop(t *testing.T) {
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	task := func(id string, slot uint64, state api.TaskState, ago time.Duration, exit int32) *api.Task {
		ts, _ := types.TimestampProto(now.Add(-ago))
		status := api.TaskStatus{State: state, Timestamp: ts}
		if exit >= 0 {
			status.RuntimeStatus = &api.TaskStatus_Container{Container: &api.ContainerStatus{ExitCode: exit}}
		}
		return &api.Task{ID: id, NodeID: "n1", Slot: slot, Status: status}
	}
	rows := TaskRows([]*api.Task{
		task("a1", 1, api.TaskStateFailed, 30*time.Second, 3), task("a2", 1, api.TaskStateFailed, 20*time.Second, 3),
		task("a3", 1, api.TaskStateFailed, 10*time.Second, 137), task("a4", 1, api.TaskStateStarting, time.Second, -1),
		task("b1", 2, api.TaskStateFailed, time.Hour, 1), task("b2", 2, api.TaskStateFailed, time.Hour+time.Second, 1),
		task("b3", 2, api.TaskStateFailed, time.Hour+2*time.Second, 1), task("b4", 2, api.TaskStateRunning, time.Hour-time.Second, 0),
	}, map[string]string{"n1": "host"}, now)
	byID := map[string]TaskRow{}
	for _, row := range rows {
		byID[row.ID] = row
	}
	if rows[0].ID != "a4" || rows[0].State != "CRASH-LOOP" || rows[0].Restarts != 3 || rows[0].Exit != -1 || rows[0].Node != "host" {
		t.Fatalf("crash-looping slot head %+v", rows[0])
	}
	if a3 := byID["a3"]; a3.State != "FAILED" || a3.Exit != 137 || a3.Restarts != 3 {
		t.Fatalf("older failure %+v", a3)
	}
	// Three failures an hour ago are history, not a loop.
	if b4 := byID["b4"]; b4.State != "RUNNING" || b4.Restarts != 3 || b4.Exit != 0 {
		t.Fatalf("recovered slot %+v", b4)
	}
}
