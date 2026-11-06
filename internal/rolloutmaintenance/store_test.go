package rolloutmaintenance

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func testJob() Job {
	source := Pin{Node: "sjc-1", Service: "terrabase-service", Task: "legacy", Fingerprint: strings.Repeat("a", 64), Image: "registry/terrabase@sha256:" + strings.Repeat("1", 64)}
	target := source
	target.Task = "candidate"
	target.Image = "registry/terrabase@sha256:" + strings.Repeat("2", 64)
	target.Fingerprint = strings.Repeat("b", 64)
	return Job{Member: "sjc-1", ID: "pinned-bootstrap", Source: source, Target: target, Owner: "sjc-1", Epoch: 5, Process: Process{PID: 1, Start: 1}}
}

type processRuntime struct {
	store     *Store
	cmd       *exec.Cmd
	stopped   bool
	started   bool
	failExit  bool
	held      bool
	exitedAt  time.Time
	startedAt time.Time
}

func (r *processRuntime) Staged(context.Context, Job) error             { return nil }
func (r *processRuntime) Resolve(_ context.Context, j Job) (Pin, error) { return j.Target, nil }
func (r *processRuntime) Prepare(ctx context.Context, p Pin) error {
	_, done, e := r.store.Enter(ctx, p, true, "prepare")
	defer done()
	return e
}
func (r *processRuntime) Quiesce(context.Context, Job) (func(context.Context) error, error) {
	r.held = true
	return func(context.Context) error { r.held = false; return nil }, nil
}
func (r *processRuntime) Stop(ctx context.Context, p Pin) error {
	_, done, e := r.store.Enter(ctx, p, true, "stop")
	defer done()
	if e != nil {
		return e
	}
	if !PinnedStop(ctx, p) || !r.held {
		return errors.New("missing drain or private stop grant")
	}
	if r.stopped {
		return nil
	}
	r.stopped = true
	// TERM and Wait exercise actual process exit, not a returned fake API status.
	if e = r.cmd.Process.Signal(syscall.SIGTERM); e != nil {
		return e
	}
	_ = r.cmd.Wait()
	return nil
}
func (r *processRuntime) Exited(context.Context, Pin, Process) error {
	if r.failExit {
		return errors.New("lost runtime response: no exit proof")
	}
	if !r.stopped || r.cmd.ProcessState == nil || !r.cmd.ProcessState.Exited() {
		// Signalled Unix processes have Exited=false but are still physically reaped.
		if r.cmd.ProcessState == nil || !r.cmd.ProcessState.Sys().(syscall.WaitStatus).Signaled() {
			return errors.New("old process lives")
		}
	}
	if err := r.cmd.Process.Signal(syscall.Signal(0)); !errors.Is(err, os.ErrProcessDone) {
		return errors.New("old PID is still usable")
	}
	if r.exitedAt.IsZero() {
		r.exitedAt = time.Now().UTC()
	}
	return nil
}
func (r *processRuntime) Start(ctx context.Context, p Pin) error {
	_, done, e := r.store.Enter(ctx, p, true, "start")
	defer done()
	if e != nil {
		return e
	}
	if r.exitedAt.IsZero() || !r.held {
		return errors.New("admission before exit/drain")
	}
	r.started = true
	r.startedAt = time.Now().UTC()
	return nil
}
func (r *processRuntime) Verify(context.Context, Job) error {
	if !r.started {
		return errors.New("not ready")
	}
	return nil
}
func newProcessRuntime(t *testing.T, s *Store) *processRuntime {
	t.Helper()
	cmd := exec.Command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})
	return &processRuntime{store: s, cmd: cmd}
}

func TestPinnedReplacementRetainsFenceAcrossOperatorAndExecutorRestart(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	dir := t.TempDir()
	s, e := Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	j := testJob()
	if e = s.Arm(ctx, j); e != nil {
		t.Fatal(e)
	}
	r := newProcessRuntime(t, s)
	r.failExit = true
	if e = (Driver{Store: s, Runtime: r}).Replace(ctx, j.ID); e == nil || r.started {
		t.Fatal("replacement admitted without physical exit proof", e)
	}
	retained, e := s.Status(ctx)
	if e != nil || retained.Deadline.IsZero() || retained.Phase != "stopping" {
		t.Fatal(retained, e)
	}
	// A new Store/Driver represents an operator reconnect and daemon reopening
	// its durable state. New intents, including changed labels/services, stay held.
	restarted, e := Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	r.store = restarted
	r.failExit = false
	for _, node := range []string{"gru-1", "gru-2", "sjc-1", "sjc-2", "fra-1", "fra-2"} {
		for _, action := range []string{"prepare", "start", "stop", "terminate", "remove", "reap"} {
			intent := j.Target
			intent.Node = node
			intent.Task = "newly-published-intent"
			_, done, e := restarted.Enter(ctx, intent, true, action)
			done()
			if !errors.Is(e, ErrFenced) {
				t.Fatalf("%s %s escaped: %v", node, action, e)
			}
		}
	}
	if e = (Driver{Store: restarted, Runtime: r}).Replace(ctx, j.ID); e != nil {
		t.Fatal(e)
	}
	if r.held || !r.started || !r.exitedAt.Before(r.startedAt) {
		t.Fatal("exit/start/readiness order violated")
	}
	after, e := restarted.Status(ctx)
	if e != nil || after.Phase != "verified" || after.Deadline != retained.Deadline {
		t.Fatal(after, e)
	}
	if e = restarted.Publication(ctx, "terrabase"); !errors.Is(e, ErrFenced) {
		t.Fatal("verified reopened fleet publication", e)
	}
	t.Logf("physical_old_exit=%s new_admission=%s persisted_deadline=%s", r.exitedAt.Format(time.RFC3339Nano), r.startedAt.Format(time.RFC3339Nano), after.Deadline.Format(time.RFC3339Nano))
}

func TestBootstrapFailsClosedOnCorruptionDeadlineAndUnselectedGrant(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	s, e := Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	j := testJob()
	if e = s.Arm(ctx, j); e != nil {
		t.Fatal(e)
	}
	j.Phase = "stopping"
	j.Deadline = time.Now().Add(-time.Second)
	if e = s.write(j); e != nil {
		t.Fatal(e)
	}
	r := newProcessRuntime(t, s)
	if e = (Driver{Store: s, Runtime: r}).Replace(ctx, j.ID); !errors.Is(e, ErrFenced) || r.stopped || r.started {
		t.Fatal("expired budget mutated runtime", e)
	}
	granted := context.WithValue(ctx, grantKey{}, &grant{store: s.root, job: j, action: "stop"})
	for _, p := range []Pin{j.Target, {Node: j.Source.Node, Service: j.Source.Service, Task: "foreign"}} {
		_, done, e := s.Enter(granted, p, true, "stop")
		done()
		if !errors.Is(e, ErrFenced) {
			t.Fatal("private grant escaped selected source", e)
		}
	}
	if e = os.WriteFile(filepath.Join(s.root, "job.json"), []byte(`{"phase":"held"}`), 0600); e != nil {
		t.Fatal(e)
	}
	_, done, e := s.Enter(ctx, j.Source, true, "stop")
	done()
	if e == nil {
		t.Fatal("corrupt journal failed open")
	}
	if e = s.Publication(ctx, "terrabase"); e == nil {
		t.Fatal("corrupt journal allowed publication")
	}
}
