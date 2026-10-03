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

	// mu serializes steps and guards the fencing and restart state.
	mu sync.Mutex
	// epoch is the newest authority epoch a verified step carried. An
	// older leader's step is refused, so a deposed leader cannot move the
	// unit after its successor did.
	epoch uint64
	// owed names a release activated by an earlier step whose restart
	// failed; a retry of that step restarts the unit again.
	owed string
}

func (a *Agent) now() time.Time {
	if a.Now != nil {
		return a.Now().UTC()
	}
	return time.Now().UTC()
}

// Handle verifies and applies one step and returns the reply.
func (a *Agent) Handle(ctx context.Context, wire []byte) StepReply {
	command, err := VerifyStepCommand(wire, a.Cell, a.Unit, a.Leaders, a.now())
	if err != nil {
		return StepReply{Unit: a.Unit, Outcome: OutcomeRefused, Reason: "step command did not verify"}
	}
	reply := StepReply{OperationID: command.OperationID, Unit: a.Unit}
	a.mu.Lock()
	defer a.mu.Unlock()
	if command.Epoch < a.epoch {
		reply.Outcome, reply.Reason = OutcomeRefused, "step is from an older authority epoch"
		return reply
	}
	a.epoch = command.Epoch
	window := max(selfupdate.MinProofWindow, min(selfupdate.MaxProofWindow,
		time.Duration(command.ProofWindowSeconds)*time.Second))
	reply.Outcome, reply.Reason = a.apply(ctx, command, window)
	return reply
}

func (a *Agent) apply(ctx context.Context, command StepCommand, window time.Duration) (StepOutcome, string) {
	digest := command.Digest
	if pending, exists, err := a.Layout.Pending(); err != nil {
		return OutcomeRetry, "activation state is unreadable"
	} else if exists && pending.Target == digest && pending.Unit == a.SystemdUnit {
		if a.owed == digest {
			if err := a.restart(ctx); err != nil {
				return OutcomeRetry, "unit restart failed"
			}
		}
		return OutcomePending, ""
	} else if exists {
		// The watchdog resolves the other activation by its deadline.
		return OutcomeRetry, "another activation is pending"
	}
	if current, err := a.Layout.Current(); err != nil {
		return OutcomeRetry, "current release is unreadable"
	} else if current == digest {
		return OutcomeCurrent, ""
	}
	if err := a.Layout.VerifyRelease(digest); errors.Is(err, fs.ErrNotExist) {
		// A rollback target pruned after its activation settled is staged
		// again from its signed receipt.
		if a.Fetch == nil || len(command.Receipt) == 0 {
			return OutcomeRefused, "release is not staged and cannot be restaged"
		}
		staged, err := a.Fetch.Fetch(ctx, a.Layout, command.Receipt, command.Delegation)
		if err != nil {
			slog.Warn("rollout agent could not stage a release", "component", "rollout", "unit", a.Unit,
				"digest", digest, "error", err)
			return OutcomeRetry, "release staging failed"
		}
		if staged != digest {
			return OutcomeRefused, "the step's receipt names another release"
		}
	} else if err != nil {
		return OutcomeRefused, "staged release does not verify"
	}
	unlock, err := a.Layout.Lock()
	if err != nil {
		return OutcomeRetry, "release root is locked"
	}
	_, err = selfupdate.Activate(a.Layout, digest, a.SystemdUnit, a.now(), window)
	unlock()
	if errors.Is(err, selfupdate.ErrKnownBad) {
		return OutcomeRefused, "release is known bad on this node"
	}
	if err != nil {
		slog.Warn("rollout agent could not activate a release", "component", "rollout", "unit", a.Unit,
			"digest", digest, "error", err)
		return OutcomeRetry, "activation failed"
	}
	a.owed = digest
	if err := a.restart(ctx); err != nil {
		return OutcomeRetry, "unit restart failed"
	}
	return OutcomeActivated, ""
}

func (a *Agent) restart(ctx context.Context) error {
	if a.Restart == nil {
		return errors.New("no restarter")
	}
	if err := a.Restart(ctx, a.SystemdUnit); err != nil {
		return err
	}
	a.owed = ""
	return nil
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
