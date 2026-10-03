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

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/rollout"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/selfupdate"
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

// fetchFake restages a release as the artifact fetch would, once.
type fetchFake struct {
	t       *testing.T
	content string
	keep    string
	calls   int
}

func (f *fetchFake) Fetch(_ context.Context, layout selfupdate.Layout, receipt, _ []byte) (string, error) {
	f.calls++
	if string(receipt) != "signed receipt" {
		return "", errors.New("receipt does not verify")
	}
	return stageTestRelease(f.t, layout, f.content, f.keep), nil
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
	command := StepCommand{Schema: StepSchema, Cell: "gru", RolloutID: "rel1-controllers", Kind: rollout.KindController,
		Unit: "ctl-b", OperationID: rollout.OperationID("rel1-controllers", "ctl-b", rollout.PhaseCanary, 0),
		Action: action, Digest: digest, Epoch: epoch, ProofWindowSeconds: 600, Receipt: []byte("signed receipt")}
	if action == StepRollback {
		command.Replaces = f.to
	}
	wire, err := SignStepCommand(command, f.key, f.now)
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
// activation, the rejected release known bad and no restart owed.
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
	if owed, err := layout.RestartPending(agentUnit); err != nil || owed {
		t.Fatalf("restart still owed after a successful restart: %v %v", owed, err)
	}
}

// A matching pending activation whose link flip was interrupted is repaired
// by the retry instead of being reported as done.
func TestAgentRetryRepairsAnInterruptedActivation(t *testing.T) {
	f := newAgentFixture(t)
	ctx := t.Context()
	if reply := f.agent.Handle(ctx, f.command(t, StepPrepare, f.to, 7)); reply.Outcome != OutcomeActivated {
		t.Fatalf("first step = %+v", reply)
	}
	pointCurrent(t, f.agent.Layout, f.from)
	if reply := f.agent.Handle(ctx, f.command(t, StepPrepare, f.to, 7)); reply.Outcome != OutcomePending {
		t.Fatalf("retry = %+v", reply)
	}
	if current, err := f.agent.Layout.Current(); err != nil || current != f.to {
		t.Fatalf("retry did not repair the current link: %s %v", current, err)
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
	wire, err := SignStepCommand(StepCommand{Schema: StepSchema, Cell: "gru", RolloutID: "r", Kind: rollout.KindController,
		Unit: "ctl-b", OperationID: "ro-1", Action: StepPrepare, Digest: f.to, Epoch: 9, ProofWindowSeconds: 60}, other, f.now)
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
	f.agent.Now = func() time.Time { return f.now.Add(StepLifetime + time.Minute) }
	if reply := f.agent.Handle(ctx, f.command(t, StepPrepare, f.to, 9)); reply.Outcome != OutcomeRefused {
		t.Fatalf("expired step = %+v", reply)
	}
	if f.restarts.count() != 0 {
		t.Fatal("a refused step restarted the unit")
	}
}

func TestAgentRestagesAPrunedRollbackTarget(t *testing.T) {
	f := newAgentFixture(t)
	ctx := t.Context()
	// The target settled as current and the old release was pruned.
	pointCurrent(t, f.agent.Layout, f.to)
	if err := os.RemoveAll(f.agent.Layout.ReleaseDir(f.from)); err != nil {
		t.Fatal(err)
	}
	if reply := f.agent.Handle(ctx, f.command(t, StepRollback, f.from, 7)); reply.Outcome != OutcomeRefused {
		t.Fatalf("rollback without a fetcher = %+v", reply)
	}
	fetch := &fetchFake{t: t, content: "release from", keep: f.to}
	f.agent.Fetch = fetch
	if reply := f.agent.Handle(ctx, f.command(t, StepRollback, f.from, 7)); reply.Outcome != OutcomeActivated {
		t.Fatalf("rollback with a fetcher = %+v", reply)
	}
	if fetch.calls != 1 {
		t.Fatalf("fetches = %d", fetch.calls)
	}
	f.assertRestored(t)
	if reply := f.agent.Handle(ctx, f.command(t, StepRollback, f.from, 7)); reply.Outcome != OutcomeCurrent {
		t.Fatalf("repeated rollback = %+v", reply)
	}
	if digestOf("release from") != f.from {
		t.Fatal("test digests are inconsistent")
	}
}

// A restore is never proof-gated, and it refuses a node that runs neither
// release of the rollout or whose predecessor is known bad locally.
func TestAgentRestoreRefusesUnrelatedOrKnownBadReleases(t *testing.T) {
	f := newAgentFixture(t)
	ctx := t.Context()
	third := stageTestRelease(t, f.agent.Layout, "a third release", "")
	if reply := f.agent.Handle(ctx, f.command(t, StepRollback, f.from, 7)); reply.Outcome != OutcomeRefused {
		t.Fatalf("restore on a node running %s = %+v", short(third), reply)
	}
	pointCurrent(t, f.agent.Layout, f.to)
	if reply := f.agent.Handle(ctx, f.command(t, StepRollback, f.from, 7)); reply.Outcome != OutcomeActivated {
		t.Fatalf("restore = %+v", reply)
	}
	f.assertRestored(t)
	// The restored predecessor is now current; a later forward step to the
	// rejected release is refused on this node.
	if reply := f.agent.Handle(ctx, f.command(t, StepPrepare, f.to, 7)); reply.Outcome != OutcomeRefused {
		t.Fatalf("forward step to the rejected release = %+v", reply)
	}
}

func TestAgentRetriesARestartThatFailed(t *testing.T) {
	f := newAgentFixture(t)
	ctx := t.Context()
	f.restarts.fail = true
	if reply := f.agent.Handle(ctx, f.command(t, StepPrepare, f.to, 7)); reply.Outcome != OutcomeRetry {
		t.Fatalf("step with a failed restart = %+v", reply)
	}
	// The failed restart is owed durably, so the watchdog retries it even
	// if this agent is gone.
	if owed, err := f.agent.Layout.RestartPending(agentUnit); err != nil || !owed {
		t.Fatalf("failed restart is not owed durably: %v %v", owed, err)
	}
	f.restarts.fail = false
	if reply := f.agent.Handle(ctx, f.command(t, StepPrepare, f.to, 7)); reply.Outcome != OutcomePending || f.restarts.count() != 1 {
		t.Fatalf("retry = %+v restarts %d", reply, f.restarts.count())
	}
	if owed, err := f.agent.Layout.RestartPending(agentUnit); err != nil || owed {
		t.Fatalf("served restart is still owed: %v %v", owed, err)
	}
	if reply := f.agent.Handle(ctx, f.command(t, StepPrepare, f.to, 7)); reply.Outcome != OutcomePending || f.restarts.count() != 1 {
		t.Fatalf("second retry restarted again: %+v restarts %d", reply, f.restarts.count())
	}
}

func TestNATSDriverReachesTheAgent(t *testing.T) {
	f := newAgentFixture(t)
	conn, _ := testNATS(t)
	sub, err := f.agent.Serve(t.Context(), conn)
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Unsubscribe()
	driver := NATSDriver{Conn: conn, Cell: "gru", Key: f.key, Timeout: 5 * time.Second, Now: func() time.Time { return f.now }}
	step := Step{RolloutID: "rel1-controllers", Kind: rollout.KindController, Unit: "ctl-b",
		OperationID: rollout.OperationID("rel1-controllers", "ctl-b", rollout.PhaseCanary, 0), Action: StepPrepare,
		Digest: f.to, Epoch: 7, ProofWindow: 10 * time.Minute}
	reply, err := driver.Step(t.Context(), step)
	if err != nil || reply.Outcome != OutcomeActivated {
		t.Fatalf("step over NATS = %+v %v", reply, err)
	}
	if _, err := driver.Step(t.Context(), Step{RolloutID: "r", Kind: rollout.KindController, Unit: "ctl-z",
		OperationID: "ro-2", Action: StepPrepare, Digest: f.to, Epoch: 7, ProofWindow: time.Minute}); err == nil {
		t.Fatal("a step to a unit without an agent succeeded")
	}
}
