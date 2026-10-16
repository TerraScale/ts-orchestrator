package rolloutexec

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/rollout"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

const (
	StepDomain = "terrascale.orchestrator.rollout-step"
	StepSchema = "terrascale.orchestrator.rollout-step.v1"
	// StepLifetime bounds one signed step; a retry is signed again.
	StepLifetime  = 2 * time.Minute
	stepClockSkew = 30 * time.Second
	// maxReleaseWire bounds the receipt and delegation carried in a step.
	maxReleaseWire  = 64 << 10
	maxReplyBytes   = 4 << 10
	maxReplyReason  = 256
	stepEnvironment = "rollout"
)

// StepAction is the effect one step asks for.
type StepAction string

const (
	// StepPrepare moves the unit forward to the rollout's target digest.
	StepPrepare StepAction = "prepare"
	// StepRollback restores the rollout's FromDigest over the rejected
	// target (selfupdate.Restore): no pending activation is created, so a
	// failed restore never lets the watchdog return to the rejected
	// release. The agent restages FromDigest first when it was pruned.
	StepRollback StepAction = "rollback"
)

// Step is one unit step the executor asks a Driver to perform.
type Step struct {
	RolloutID   string
	Kind        rollout.Kind
	Unit        string
	OperationID string
	Action      StepAction
	Digest      string
	// Replaces is the release the step moves the unit away from: the
	// rollout's predecessor for a forward step, the rejected target for a
	// rollback. An agent refuses a step whose Replaces the unit does not
	// run, so a replayed forward step never undoes a later update.
	Replaces string
	Epoch    uint64
	// ProofWindow is how long the unit's watchdog waits for the new
	// process's version proof before it rolls the activation back.
	ProofWindow time.Duration
	// Deadline is the phase deadline of the step; the signed command
	// expires no later, so an agent never applies it after the leader
	// gave up on it.
	Deadline time.Time
	// Fence, when set, re-checks the leader's authority lease; a driver
	// calls it after its own preparation (receipt lookup, signing) and
	// immediately before the step leaves, and sends nothing if it fails.
	Fence func(context.Context) error
}

// StepCommand is the leader-signed wire form of a Step. Receipt and
// Delegation are the release receipt (and optional scoped delegation) of
// Digest, so an agent can restage a pruned release; the agent verifies
// them against its own release roots before it keeps any byte.
type StepCommand struct {
	Schema             string       `json:"schema"`
	Cell               string       `json:"cell"`
	RolloutID          string       `json:"rollout_id"`
	Kind               rollout.Kind `json:"kind"`
	Unit               string       `json:"unit"`
	OperationID        string       `json:"operation_id"`
	Action             StepAction   `json:"action"`
	Digest             string       `json:"digest"`
	Replaces           string       `json:"replaces,omitempty"`
	Epoch              uint64       `json:"epoch"`
	ProofWindowSeconds int64        `json:"proof_window_seconds"`
	Receipt            []byte       `json:"receipt,omitempty"`
	Delegation         []byte       `json:"delegation,omitempty"`
}

func (command StepCommand) validate() error {
	if command.Schema != StepSchema || !unitRE.MatchString(command.Cell) || !entityid.Valid(command.RolloutID) ||
		command.Kind != rollout.KindController && command.Kind != rollout.KindHost || !unitRE.MatchString(command.Unit) ||
		!entityid.Valid(command.OperationID) || command.Action != StepPrepare && command.Action != StepRollback ||
		!digestRE.MatchString(command.Digest) || command.Epoch == 0 || command.ProofWindowSeconds <= 0 ||
		len(command.Receipt) > maxReleaseWire || len(command.Delegation) > maxReleaseWire ||
		len(command.Delegation) > 0 && len(command.Receipt) == 0 ||
		!digestRE.MatchString(command.Replaces) || command.Replaces == command.Digest {
		return fmt.Errorf("%w: step command", ErrInvalid)
	}
	return nil
}

// stepScope binds the signature to one operation, action and unit.
func stepScope(command StepCommand) trust.Scope {
	return trust.Scope{Domain: StepDomain, DeploymentID: command.OperationID, Cell: command.Cell,
		Environment: stepEnvironment, Role: string(command.Action), Slot: command.Unit}
}

// SignStepCommand signs command with the leader's controller key. The
// signature expires at deadline, or StepLifetime after now when that is
// sooner or deadline is zero: an agent never acts on a step after the phase
// deadline the leader enforces for it.
func SignStepCommand(command StepCommand, key ed25519.PrivateKey, now, deadline time.Time) ([]byte, error) {
	if err := command.validate(); err != nil {
		return nil, err
	}
	expires := now.Add(StepLifetime)
	if !deadline.IsZero() && deadline.Before(expires) {
		expires = deadline
	}
	if !expires.After(now) {
		return nil, fmt.Errorf("%w: step deadline has passed", ErrInvalid)
	}
	payload, err := trust.EncodePayload(command)
	if err != nil {
		return nil, err
	}
	envelope, err := trust.Sign(payload, stepScope(command), now, expires, key)
	if err != nil {
		return nil, err
	}
	return trust.EncodeEnvelope(envelope)
}

// VerifyStepCommand accepts a current command for exactly this cell and
// unit, signed by one of the controller keys. It also returns when the
// signature expires: the agent must not act on the command after that.
func VerifyStepCommand(wire []byte, cell, unit string, keys trust.Keyring, now time.Time) (StepCommand, time.Time, error) {
	envelope, err := trust.DecodeEnvelope(wire)
	if err != nil {
		return StepCommand{}, time.Time{}, err
	}
	scope := envelope.Scope
	if scope.Domain != StepDomain || scope.Cell != cell || scope.Slot != unit || scope.Environment != stepEnvironment ||
		scope.Role != string(StepPrepare) && scope.Role != string(StepRollback) {
		return StepCommand{}, time.Time{}, trust.ErrScopeMismatch
	}
	payload, err := trust.VerifyCurrent(envelope, scope, keys, now, trust.Policy{MaxLifetime: StepLifetime, ClockSkew: stepClockSkew})
	if err != nil {
		return StepCommand{}, time.Time{}, err
	}
	var command StepCommand
	if err := protocol.DecodeStrict(payload, &command, trust.MaxPayloadBytes); err != nil {
		return StepCommand{}, time.Time{}, err
	}
	if err := command.validate(); err != nil {
		return StepCommand{}, time.Time{}, err
	}
	if stepScope(command) != scope {
		return StepCommand{}, time.Time{}, trust.ErrScopeMismatch
	}
	return command, envelope.ExpiresAt, nil
}

// StepOutcome is an agent's answer to one step.
type StepOutcome string

const (
	// OutcomeActivated: the agent activated the release and restarted the unit.
	OutcomeActivated StepOutcome = "activated"
	// OutcomePending: an activation of this release is already pending.
	OutcomePending StepOutcome = "pending"
	// OutcomeCurrent: the release is already current; nothing changed.
	OutcomeCurrent StepOutcome = "current"
	// OutcomeRetry: the agent cannot act yet (for example another
	// activation is pending); the executor retries with the same operation.
	OutcomeRetry StepOutcome = "retry"
	// OutcomeRefused: the step can never succeed (a known-bad release,
	// changed bytes, a release that cannot be restaged).
	OutcomeRefused StepOutcome = "refused"
)

// Accepted reports whether the unit runs, or is moving to, the release.
func (outcome StepOutcome) Accepted() bool {
	return outcome == OutcomeActivated || outcome == OutcomePending || outcome == OutcomeCurrent
}

// StepReply is the agent's unsigned reply. It only tells the executor
// whether to wait or retry: completion is proven by a signed health proof.
type StepReply struct {
	OperationID string `json:"operation_id"`
	Unit        string `json:"unit"`
	// Epoch is the answered step's authority epoch: an operation ID spans
	// leaders, so a reply to a deposed leader's late step never answers its
	// successor.
	Epoch   uint64      `json:"epoch,omitzero"`
	Outcome StepOutcome `json:"outcome"`
	Reason  string      `json:"reason,omitempty"`
}

// Driver performs one unit step. It must be idempotent per OperationID: the
// executor resends a step after a leader change or a lost reply.
type Driver interface {
	Step(ctx context.Context, step Step) (StepReply, error)
}

// ReleaseSource returns the release receipt and delegation of a digest, so
// a step can carry what an agent needs to restage it. A digest without a
// receipt returns empty slices; the agent then refuses to restage it.
type ReleaseSource interface {
	Receipt(ctx context.Context, digest string) (receipt, delegation []byte, err error)
}

// Steps travel through the replicated rollout bucket, not a direct
// request: the leader writes each signed step under its unit's step key and
// reads the agent's answer from the unit's reply key. The unit's own
// controller relays both to and from the node's root step agent (Relay),
// because the controller runs unprivileged and the agent, the root-run
// self-update watchdog, has no NATS connection. Every controller credential
// already writes and reads KV, so no grant changes.

// StepKey and ReplyKey are one unit's keys in rollout.Bucket. Unit
// identities are hashed so caller-controlled names never become key tokens.
func StepKey(unit string) string  { return entityid.Derive("rollout-step", unit) }
func ReplyKey(unit string) string { return entityid.Derive("rollout-step-reply", unit) }

// KVDriver posts signed steps to unit agents through the rollout bucket.
type KVDriver struct {
	KV       jetstream.KeyValue
	Cell     string
	Key      ed25519.PrivateKey
	Releases ReleaseSource
	Timeout  time.Duration
	Now      func() time.Time
}

// Step signs and posts one step and returns the agent's reply to it. Until
// the agent answered this operation it asks the executor to retry; the
// executor posts the step again, freshly signed, on its next tick.
func (d KVDriver) Step(ctx context.Context, step Step) (StepReply, error) {
	if d.KV == nil || len(d.Key) != ed25519.PrivateKeySize {
		return StepReply{}, fmt.Errorf("%w: step driver configuration", ErrInvalid)
	}
	now := time.Now
	if d.Now != nil {
		now = d.Now
	}
	timeout := d.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	// The receipt lookup, signing and the writes share one deadline.
	requestCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	command := StepCommand{Schema: StepSchema, Cell: d.Cell, RolloutID: step.RolloutID, Kind: step.Kind, Unit: step.Unit,
		OperationID: step.OperationID, Action: step.Action, Digest: step.Digest, Replaces: step.Replaces, Epoch: step.Epoch,
		ProofWindowSeconds: int64(step.ProofWindow / time.Second)}
	if d.Releases != nil {
		receipt, delegation, err := d.Releases.Receipt(requestCtx, step.Digest)
		if err != nil {
			return StepReply{}, fmt.Errorf("read release receipt: %w", err)
		}
		command.Receipt, command.Delegation = receipt, delegation
	}
	wire, err := SignStepCommand(command, d.Key, now().UTC(), step.Deadline)
	if err != nil {
		return StepReply{}, err
	}
	// The lease is re-checked after the lookup and signing, immediately
	// before the step leaves: a leader that lost it meanwhile sends nothing.
	if step.Fence != nil {
		if err := step.Fence(requestCtx); err != nil {
			return StepReply{}, err
		}
	}
	if _, err := d.KV.Put(requestCtx, StepKey(step.Unit), wire); err != nil {
		return StepReply{}, fmt.Errorf("post rollout step: %w", err)
	}
	waiting := StepReply{OperationID: step.OperationID, Unit: step.Unit, Outcome: OutcomeRetry,
		Reason: "waiting for the unit's step agent"}
	entry, err := d.KV.Get(requestCtx, ReplyKey(step.Unit))
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return waiting, nil
	}
	if err != nil {
		return StepReply{}, fmt.Errorf("read rollout step reply: %w", err)
	}
	// A reply to an earlier step of the unit is not an answer to this one.
	if reply, err := decodeReply(entry.Value(), step); err == nil {
		return reply, nil
	}
	return waiting, nil
}

func decodeReply(data []byte, step Step) (StepReply, error) {
	if len(data) > maxReplyBytes {
		return StepReply{}, fmt.Errorf("%w: step reply too large", ErrInvalid)
	}
	var reply StepReply
	if err := json.Unmarshal(data, &reply); err != nil {
		return StepReply{}, fmt.Errorf("decode step reply: %w", err)
	}
	switch reply.Outcome {
	case OutcomeActivated, OutcomePending, OutcomeCurrent, OutcomeRetry, OutcomeRefused:
	default:
		return StepReply{}, fmt.Errorf("%w: step reply outcome", ErrInvalid)
	}
	if reply.OperationID != step.OperationID || reply.Unit != step.Unit || reply.Epoch != step.Epoch ||
		len(reply.Reason) > maxReplyReason {
		return StepReply{}, errors.New("step reply does not answer this step")
	}
	return reply, nil
}
