package rolloutexec

import (
	"fmt"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"

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
