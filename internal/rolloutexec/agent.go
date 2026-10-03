package rolloutexec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/selfupdate"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

// Fetcher stages a release that is not (or no longer) in the release root,
// from its signed receipt. It verifies the receipt before it keeps a byte
// and returns the staged digest.
type Fetcher interface {
	Fetch(ctx context.Context, layout selfupdate.Layout, receipt, delegation []byte) (string, error)
}

// ArtifactStoreFetcher stages from the signed delivery artifact store over
// NATS, checking every chunk and the object digest. Controllers use it; a
// host stages through its controller session's chunked artifact path.
type ArtifactStoreFetcher struct {
	JS       jetstream.JetStream
	Store    selfupdate.ArtifactStore
	Verifier selfupdate.Verifier
	Now      func() time.Time
}

// Fetch implements Fetcher.
func (f ArtifactStoreFetcher) Fetch(ctx context.Context, layout selfupdate.Layout, receipt, delegation []byte) (string, error) {
	now := time.Now
	if f.Now != nil {
		now = f.Now
	}
	return selfupdate.StageFromArtifactStore(ctx, layout, f.JS, f.Store, receipt, delegation, f.Verifier, now())
}

// Agent applies leader-signed steps to one unit's release root. It runs as
// the root-owned owner of that root, next to the unit it updates.
type Agent struct {
	Cell string
	// Unit is the rollout unit ID; SystemdUnit is the service it restarts.
	Unit        string
	SystemdUnit string
	Layout      selfupdate.Layout
	// Leaders are the controller keys allowed to sign steps.
	Leaders trust.Keyring
	// Fetch restages a pruned release; nil refuses steps to a missing one.
	Fetch   Fetcher
	Restart func(ctx context.Context, unit string) error
	Now     func() time.Time

	// mu serializes this agent's steps; Layout.Lock serializes them with
	// the watchdog and unit starts.
	mu sync.Mutex
	// served names the operation whose owed restart this agent already
	// performed. The obligation itself is cleared only by the unit's start
	// (selfupdate prepare), so a retry before that start does not restart
	// the unit a second time, while a new agent, which cannot know whether
	// its predecessor restarted, serves it once.
	served string
}

func (a *Agent) now() time.Time {
	if a.Now != nil {
		return a.Now().UTC()
	}
	return time.Now().UTC()
}

// Handle verifies and applies one step and returns the reply.
func (a *Agent) Handle(ctx context.Context, wire []byte) StepReply {
	command, expires, err := VerifyStepCommand(wire, a.Cell, a.Unit, a.Leaders, a.now())
	if err != nil {
		return StepReply{Unit: a.Unit, Outcome: OutcomeRefused, Reason: "step command did not verify"}
	}
	reply := StepReply{OperationID: command.OperationID, Unit: a.Unit}
	a.mu.Lock()
	defer a.mu.Unlock()
	window := max(selfupdate.MinProofWindow, min(selfupdate.MaxProofWindow,
		time.Duration(command.ProofWindowSeconds)*time.Second))
	// Nothing, staging included, outlives the signed command.
	stepCtx, cancel := context.WithDeadline(ctx, expires)
	defer cancel()
	reply.Outcome, reply.Reason = a.apply(stepCtx, command, expires, window)
	return reply
}

// apply fences the step by its authority epoch, which the release root
// records durably: an older leader's step is refused even after this agent
// restarted. The restart obligation is recorded before the release changes
// and cleared only by the unit's next start, so any interruption leaves the
// watchdog (and a retry by a new agent) a restart to finish.
func (a *Agent) apply(ctx context.Context, command StepCommand, expires time.Time, window time.Duration) (StepOutcome, string) {
	if outcome, reason := a.locked(func() (StepOutcome, string) { return a.admit(command) }); outcome != "" {
		return outcome, reason
	}
	if outcome, reason := a.ensureStaged(ctx, command); outcome != "" {
		return outcome, reason
	}
	outcome, reason := a.locked(func() (StepOutcome, string) {
		// Re-checked under the lock, immediately before the selection
		// changes: waiting for the lock or a staging download must not
		// let an expired command act.
		if !a.now().Before(expires) {
			return OutcomeRetry, "step command expired before it could be applied"
		}
		if outcome, reason := a.admit(command); outcome != "" {
			return outcome, reason
		}
		if command.Action == StepRollback {
			return a.restore(command)
		}
		return a.activate(command, window)
	})
	if !outcome.Accepted() {
		return outcome, reason
	}
	owed, err := a.owed()
	if err != nil {
		return OutcomeRetry, "restart obligation is unreadable"
	}
	if !owed || a.served == command.OperationID && outcome != OutcomeActivated {
		return outcome, reason
	}
	if err := a.restart(ctx); err != nil {
		slog.Warn("rollout agent could not restart its unit", "component", "rollout", "unit", a.Unit, "error", err)
		return OutcomeRetry, "unit restart failed"
	}
	a.served = command.OperationID
	return outcome, reason
}

// admit records the step's epoch, refusing an older one. The caller holds
// Layout.Lock.
func (a *Agent) admit(command StepCommand) (StepOutcome, string) {
	if err := a.Layout.AdmitEpoch(command.Epoch); errors.Is(err, selfupdate.ErrStaleEpoch) {
		return OutcomeRefused, "step is from an older authority epoch"
	} else if err != nil {
		return OutcomeRetry, "authority epoch record is unreadable"
	}
	return "", ""
}

func (a *Agent) owed() (bool, error) {
	unlock, err := a.Layout.Lock()
	if err != nil {
		return false, err
	}
	defer unlock()
	return a.Layout.RestartPending(a.SystemdUnit)
}

// locked runs step under Layout.Lock.
func (a *Agent) locked(step func() (StepOutcome, string)) (StepOutcome, string) {
	unlock, err := a.Layout.Lock()
	if err != nil {
		return OutcomeRetry, "release root is locked"
	}
	defer unlock()
	return step()
}

// ensureStaged restages a release that is not in the release root (a
// rollback target pruned after its activation settled) from the step's
// signed receipt. It runs unlocked, like selfupdate's own fetch.
func (a *Agent) ensureStaged(ctx context.Context, command StepCommand) (StepOutcome, string) {
	err := a.Layout.VerifyRelease(command.Digest)
	switch {
	case err == nil:
		return "", ""
	case !errors.Is(err, fs.ErrNotExist):
		return OutcomeRefused, "staged release does not verify"
	case a.Fetch == nil || len(command.Receipt) == 0:
		return OutcomeRefused, "release is not staged and cannot be restaged"
	}
	staged, err := a.Fetch.Fetch(ctx, a.Layout, command.Receipt, command.Delegation)
	if err != nil {
		slog.Warn("rollout agent could not stage a release", "component", "rollout", "unit", a.Unit,
			"digest", command.Digest, "error", err)
		return OutcomeRetry, "release staging failed"
	}
	if staged != command.Digest {
		return OutcomeRefused, "the step's receipt names another release"
	}
	return "", ""
}

// activate moves the unit forward through a proof-gated A/B activation.
// A retry of a matching pending activation goes through Activate again, so
// its gates rerun and an interrupted link flip is repaired. The caller
// holds Layout.Lock.
func (a *Agent) activate(command StepCommand, window time.Duration) (StepOutcome, string) {
	digest := command.Digest
	pending, exists, err := a.Layout.Pending()
	if err != nil {
		return OutcomeRetry, "activation state is unreadable"
	}
	if exists && (pending.Target != digest || pending.Unit != a.SystemdUnit) {
		// The watchdog resolves the other activation by its deadline.
		return OutcomeRetry, "another activation is pending"
	}
	if !exists {
		if current, err := a.Layout.Current(); err != nil {
			return OutcomeRetry, "current release is unreadable"
		} else if current == digest {
			return OutcomeCurrent, ""
		}
		// Owed before the link moves, so an interruption after it never
		// leaves the old process running until the watchdog rejects a
		// release that never started.
		if err := a.Layout.MarkRestartPending(a.SystemdUnit); err != nil {
			return OutcomeRetry, "restart obligation could not be recorded"
		}
	}
	if _, err := selfupdate.Activate(a.Layout, digest, a.SystemdUnit, a.now(), window); err != nil {
		if !exists {
			// Nothing to restart unless the activation record was written.
			if _, recorded, _ := a.Layout.Pending(); !recorded {
				_ = a.Layout.ClearRestartPending(a.SystemdUnit)
			}
		}
		if errors.Is(err, selfupdate.ErrKnownBad) {
			return OutcomeRefused, "release is known bad on this node"
		}
		slog.Warn("rollout agent could not activate a release", "component", "rollout", "unit", a.Unit,
			"digest", digest, "error", err)
		return OutcomeRetry, "activation failed"
	}
	if exists {
		return OutcomePending, ""
	}
	return OutcomeActivated, ""
}

// restore returns the unit to the rollout's predecessor without a pending
// activation (selfupdate.Restore), so the watchdog can never flip it back
// to the rejected release. The caller holds Layout.Lock.
func (a *Agent) restore(command StepCommand) (StepOutcome, string) {
	if pending, exists, err := a.Layout.Pending(); err != nil {
		return OutcomeRetry, "activation state is unreadable"
	} else if exists && (pending.Unit != a.SystemdUnit || pending.Target != command.Replaces || pending.Previous != command.Digest) {
		return OutcomeRetry, "another activation is pending"
	}
	changed, err := selfupdate.Restore(a.Layout, command.Digest, command.Replaces, a.SystemdUnit)
	switch {
	case errors.Is(err, selfupdate.ErrKnownBad):
		return OutcomeRefused, "release is known bad on this node"
	case errors.Is(err, selfupdate.ErrInvalid):
		return OutcomeRefused, "the unit runs neither release of the rollout"
	case err != nil:
		slog.Warn("rollout agent could not restore a release", "component", "rollout", "unit", a.Unit,
			"digest", command.Digest, "error", err)
		return OutcomeRetry, "restore failed"
	case !changed:
		return OutcomeCurrent, ""
	}
	return OutcomeActivated, ""
}

func (a *Agent) restart(ctx context.Context) error {
	if a.Restart == nil {
		return errors.New("no restarter")
	}
	return a.Restart(ctx, a.SystemdUnit)
}

// Serve answers steps for this unit until the subscription is closed.
func (a *Agent) Serve(ctx context.Context, conn *nats.Conn) (*nats.Subscription, error) {
	if conn == nil || !unitRE.MatchString(a.Cell) || !unitRE.MatchString(a.Unit) || len(a.Leaders) == 0 {
		return nil, fmt.Errorf("%w: rollout agent configuration", ErrInvalid)
	}
	return conn.Subscribe(protocol.RolloutStepSubject(a.Cell, a.Unit), func(msg *nats.Msg) {
		if msg.Reply == "" || len(msg.Data) > trust.MaxEnvelopeBytes {
			return
		}
		reply := a.Handle(ctx, msg.Data)
		if data, err := json.Marshal(reply); err == nil {
			_ = msg.Respond(data)
		}
	})
}
