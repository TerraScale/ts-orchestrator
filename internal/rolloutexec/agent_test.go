package rolloutexec

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"

	"github.com/TerraScale/ts-orchestrator/internal/rollout"
	"github.com/TerraScale/ts-orchestrator/internal/selfupdate"
)

const agentUnit = "terrascale-orchestrator-controller.service"

// stageTestRelease installs content as a release through the exported seed
// path and points current back at keep (when set).
func stageTestRelease(t *testing.T, layout selfupdate.Layout, content, keep string) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "binary")
	if err := os.WriteFile(binary, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(layout.Root, "current")); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	digest, err := selfupdate.Seed(layout, binary)
	if err != nil {
		t.Fatal(err)
	}
	// Seeded releases carry the baked marker, which pruning keeps; drop it
	// so the release behaves like a staged one.
	if err := os.Remove(filepath.Join(layout.ReleaseDir(digest), "baked")); err != nil {
		t.Fatal(err)
	}
	if keep != "" {
		pointCurrent(t, layout, keep)
	}
	return digest
}

func pointCurrent(t *testing.T, layout selfupdate.Layout, digest string) {
	t.Helper()
	temporary := filepath.Join(layout.Root, ".current-test")
	_ = os.Remove(temporary)
	if err := os.Symlink("releases/"+digest, temporary); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(temporary, filepath.Join(layout.Root, "current")); err != nil {
		t.Fatal(err)
	}
}

func digestOf(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

type restarts struct {
	mu    sync.Mutex
	units []string
	fail  bool
}

func (r *restarts) restart(_ context.Context, unit string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail {
		return errors.New("systemctl failed")
	}
	r.units = append(r.units, unit)
	return nil
}

func (r *restarts) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.units)
}

type agentFixture struct {
	agent    *Agent
	key      []byte
	restarts *restarts
	from, to string
	now      time.Time
}

func newAgentFixture(t *testing.T) *agentFixture {
	t.Helper()
	layout := selfupdate.Layout{Root: filepath.Join(t.TempDir(), "root"), Owner: os.Getuid()}
	from := stageTestRelease(t, layout, "release from", "")
	to := stageTestRelease(t, layout, "release to", from)
	key, keys := testKey(t)
	r := &restarts{}
	now := time.Now().UTC().Truncate(time.Second)
	agent := &Agent{Cell: "gru", Unit: "ctl-b", SystemdUnit: agentUnit, Layout: layout, Leaders: keys,
		Restart: r.restart, Now: func() time.Time { return now }}
	return &agentFixture{agent: agent, key: key, restarts: r, from: from, to: to, now: now}
}

func (f *agentFixture) command(t *testing.T, action StepAction, digest string, epoch uint64) []byte {
	t.Helper()
	command := StepCommand{Schema: StepSchema, Cell: "gru", RolloutID: entityid.Derive("release-controllers", "rel1"), Kind: rollout.KindController,
		Unit: "ctl-b", OperationID: rollout.OperationID(entityid.Derive("release-controllers", "rel1"), "ctl-b", rollout.PhaseCanary, 0),
		Action: action, Digest: digest, Epoch: epoch, ProofWindowSeconds: 600, Receipt: []byte("signed receipt")}
	// A rollback replaces the rejected target; a forward step replaces the
	// predecessor (the other release when it targets the predecessor).
	command.Replaces = f.from
	if action == StepRollback || digest == f.from {
		command.Replaces = f.to
	}
	wire, err := SignStepCommand(command, f.key, f.now, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestAgentActivatesOnceAndAnswersRetriesIdempotently(t *testing.T) {
	f := newAgentFixture(t)
	ctx := t.Context()
	if reply := f.agent.Handle(ctx, f.command(t, StepPrepare, f.to, 7)); reply.Outcome != OutcomeActivated {
		t.Fatalf("first step = %+v", reply)
	}
	activation, pending, err := f.agent.Layout.Pending()
	if err != nil || !pending || activation.Target != f.to || activation.Previous != f.from ||
		activation.Deadline.Sub(activation.ActivatedAt) != 600*time.Second {
		t.Fatalf("activation = %+v %v %v", activation, pending, err)
	}
	if reply := f.agent.Handle(ctx, f.command(t, StepPrepare, f.to, 7)); reply.Outcome != OutcomePending {
		t.Fatalf("retried step = %+v", reply)
	}
	if f.restarts.count() != 1 {
		t.Fatalf("restarts = %d, want one", f.restarts.count())
	}
	// A rollback of the still-pending forward activation resolves it as
	// the watchdog would: the target becomes known bad, the predecessor
	// current, and no activation is left for the watchdog to revert.
	if reply := f.agent.Handle(ctx, f.command(t, StepRollback, f.from, 7)); reply.Outcome != OutcomeActivated {
		t.Fatalf("rollback during a pending activation = %+v", reply)
	}
	f.assertRestored(t)
	if f.restarts.count() != 2 {
		t.Fatalf("restarts = %d, want two", f.restarts.count())
	}
}

// assertRestored checks that the unit runs the predecessor with no pending
// activation, the rejected release known bad and the restart still owed
// until the unit's own start (selfupdate prepare) clears it.
func (f *agentFixture) assertRestored(t *testing.T) {
	t.Helper()
	layout := f.agent.Layout
	if _, pending, err := layout.Pending(); err != nil || pending {
		t.Fatalf("a restore left a pending activation: %v %v", pending, err)
	}
	if current, err := layout.Current(); err != nil || current != f.from {
		t.Fatalf("current = %s %v, want the predecessor", current, err)
	}
	if bad, err := layout.KnownBad(); err != nil || !bad[f.to] {
		t.Fatalf("rejected release is not known bad: %v %v", bad, err)
	}
	if owed, err := layout.RestartPending(agentUnit); err != nil || !owed {
		t.Fatalf("restore left no restart obligation: %v %v", owed, err)
	}
}

func TestAgentRefusesUnverifiedAndStaleSteps(t *testing.T) {
	f := newAgentFixture(t)
	ctx := t.Context()
	if reply := f.agent.Handle(ctx, f.command(t, StepPrepare, f.from, 9)); reply.Outcome != OutcomeCurrent {
		t.Fatalf("step to the current release = %+v", reply)
	}
	if reply := f.agent.Handle(ctx, f.command(t, StepPrepare, f.to, 8)); reply.Outcome != OutcomeRefused {
		t.Fatalf("step from an older epoch = %+v", reply)
	}
	other, _ := testKey(t)
	wire, err := SignStepCommand(StepCommand{Schema: StepSchema, Cell: "gru", RolloutID: "00000000002JW3D8YH3EBSQV5Q", Kind: rollout.KindController,
		Unit: "ctl-b", OperationID: "0000000000N6KCZG3MWDGZ0WBE", Action: StepPrepare, Digest: f.to, Replaces: f.from, Epoch: 9, ProofWindowSeconds: 60}, other, f.now, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if reply := f.agent.Handle(ctx, wire); reply.Outcome != OutcomeRefused {
		t.Fatalf("step signed by an unknown key = %+v", reply)
	}
	f.agent.Unit = "ctl-c"
	if reply := f.agent.Handle(ctx, f.command(t, StepPrepare, f.to, 9)); reply.Outcome != OutcomeRefused {
		t.Fatalf("step for another unit = %+v", reply)
	}
	f.agent.Unit = "ctl-b"
	// The accepted epoch is durable: a recreated agent still refuses a
	// still-valid step from the older leader.
	recreated := &Agent{Cell: "gru", Unit: "ctl-b", SystemdUnit: agentUnit, Layout: f.agent.Layout,
		Leaders: f.agent.Leaders, Restart: f.restarts.restart, Now: f.agent.Now}
	if reply := recreated.Handle(ctx, f.command(t, StepPrepare, f.to, 8)); reply.Outcome != OutcomeRefused {
		t.Fatalf("older epoch replayed to a recreated agent = %+v", reply)
	}
	f.agent.Now = func() time.Time { return f.now.Add(StepLifetime + time.Minute) }
	if reply := f.agent.Handle(ctx, f.command(t, StepPrepare, f.to, 9)); reply.Outcome != OutcomeRefused {
		t.Fatalf("expired step = %+v", reply)
	}
	if f.restarts.count() != 0 {
		t.Fatal("a refused step restarted the unit")
	}
}
