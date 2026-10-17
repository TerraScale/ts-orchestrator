package host

import (
	"context"
	"errors"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/storage/executionwire"
)

// ContainerReadinessChallenge is a one-use observation request, never execution authority.
type ContainerReadinessChallenge struct {
	Nonce           string    `json:"nonce"`
	TaskID          string    `json:"task_id"`
	TaskSHA256      string    `json:"task_sha256"`
	AdmissionSHA256 string    `json:"admission_sha256"`
	EffectID        string    `json:"effect_id"`
	Deadline        time.Time `json:"deadline"`
}

type containerReadinessQuery struct {
	TaskID          string                       `json:"task_id"`
	TaskSHA256      string                       `json:"task_sha256"`
	AdmissionSHA256 string                       `json:"admission_sha256"`
	EffectID        string                       `json:"effect_id"`
	Challenge       *ContainerReadinessChallenge `json:"challenge,omitempty"`
	Report          *ManagedRuntimeReport        `json:"report,omitempty"`
}

type containerReadinessReply struct {
	Challenge *ContainerReadinessChallenge `json:"challenge,omitempty"`
}

func sameContainerReadinessChallenge(a, b ContainerReadinessChallenge) bool {
	return a.Nonce == b.Nonce && a.TaskID == b.TaskID && a.TaskSHA256 == b.TaskSHA256 &&
		a.AdmissionSHA256 == b.AdmissionSHA256 && a.EffectID == b.EffectID && a.Deadline.Equal(b.Deadline)
}

type containerReadinessPending struct {
	challenge ContainerReadinessChallenge
	effect    authority.RuntimeEffect
	result    chan ManagedRuntimeReport
	completed bool
	envelope  protocol.Envelope
}

// ObserveContainerReadiness challenges only the original held host session. The
// verifier runs around the exchange using the same immutable effect deadline.
func (c *Controller) ObserveContainerReadiness(ctx context.Context, effect authority.RuntimeEffect, verify func(context.Context, RuntimeEffectCaller) error) (ManagedRuntimeReport, time.Time, error) {
	report, deadline, _, err := c.observeContainerReadiness(ctx, effect, nil, verify)
	return report, deadline, err
}

// ObserveSignedContainerReadiness retains the original worker-signed observation.
// A relay supplies a challenge, never authority to accept the result.
func (c *Controller) ObserveSignedContainerReadiness(ctx context.Context, effect authority.RuntimeEffect, challenge ContainerReadinessChallenge, verify func(context.Context, RuntimeEffectCaller) error) (protocol.Envelope, error) {
	_, _, envelope, err := c.observeContainerReadiness(ctx, effect, &challenge, verify)
	return envelope, err
}

func (c *Controller) observeContainerReadiness(ctx context.Context, effect authority.RuntimeEffect, requested *ContainerReadinessChallenge, verify func(context.Context, RuntimeEffectCaller) error) (ManagedRuntimeReport, time.Time, protocol.Envelope, error) {
	if ctx == nil || verify == nil || c.readOnly || effect.Phase != authority.RuntimeEffectHeld || !time.Now().Before(effect.ExpiresAt) {
		return ManagedRuntimeReport{}, time.Time{}, protocol.Envelope{}, errors.New("live held runtime readiness unavailable")
	}
	nonce, err := randomNonce()
	if err != nil {
		return ManagedRuntimeReport{}, time.Time{}, protocol.Envelope{}, err
	}
	deadline := minReadinessDeadline(effect.ExpiresAt, time.Now().Add(3*time.Second))
	if originalDeadline, ok := ctx.Deadline(); ok {
		deadline = minReadinessDeadline(deadline, originalDeadline)
	}
	if requested != nil {
		if !lowerHex(requested.Nonce, 32) || requested.TaskID != effect.TaskID || requested.TaskSHA256 != effect.TaskSHA256 ||
			requested.AdmissionSHA256 != effect.AdmissionSHA256 || requested.EffectID != effect.EffectID ||
			requested.Deadline.After(deadline) || !time.Now().Before(requested.Deadline) {
			return ManagedRuntimeReport{}, time.Time{}, protocol.Envelope{}, errors.New("readiness relay challenge differs from held effect")
		}
		nonce, deadline = requested.Nonce, requested.Deadline
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	caller, desired, err := c.readinessAuthority(ctx, effect, nonce)
	if err != nil {
		return ManagedRuntimeReport{}, time.Time{}, protocol.Envelope{}, err
	}
	if requested != nil && requested.Deadline.After(caller.ExpiresAt()) {
		return ManagedRuntimeReport{}, time.Time{}, protocol.Envelope{}, authority.ErrFenced
	}
	deadline = minReadinessDeadline(deadline, caller.ExpiresAt())
	ctx, cancelSession := context.WithDeadline(ctx, deadline)
	defer cancelSession()
	if err := verify(ctx, caller); err != nil {
		return ManagedRuntimeReport{}, time.Time{}, protocol.Envelope{}, err
	}
	pending := &containerReadinessPending{effect: effect, result: make(chan ManagedRuntimeReport, 1), challenge: ContainerReadinessChallenge{
		Nonce: nonce, TaskID: effect.TaskID, TaskSHA256: effect.TaskSHA256, AdmissionSHA256: effect.AdmissionSHA256, EffectID: effect.EffectID, Deadline: deadline}}
	c.readinessMu.Lock()
	if c.readiness == nil {
		c.readiness = make(map[string]*containerReadinessPending)
	}
	if c.readiness[nonce] != nil {
		c.readinessMu.Unlock()
		return ManagedRuntimeReport{}, time.Time{}, protocol.Envelope{}, errors.New("readiness nonce is already pending")
	}
	c.readiness[nonce] = pending
	c.readinessMu.Unlock()
	defer func() { c.readinessMu.Lock(); delete(c.readiness, nonce); c.readinessMu.Unlock() }()
	select {
	case <-ctx.Done():
		return ManagedRuntimeReport{}, time.Time{}, protocol.Envelope{}, ctx.Err()
	case report := <-pending.result:
		if !time.Now().Before(deadline) {
			return ManagedRuntimeReport{}, time.Time{}, protocol.Envelope{}, authority.ErrFenced
		}
		current, confirmed, err := c.readinessAuthority(ctx, effect, nonce)
		if err != nil || !sameJSON(confirmed, desired) || current.ExpiresAt().Before(caller.ExpiresAt()) {
			return ManagedRuntimeReport{}, time.Time{}, protocol.Envelope{}, errors.Join(authority.ErrFenced, err)
		}
		if err := validateContainerReadinessReport(effect, desired, report); err != nil {
			return ManagedRuntimeReport{}, time.Time{}, protocol.Envelope{}, err
		}
		// Retain the original session deadline even if the session renewed during the challenge.
		if err := verify(ctx, caller); err != nil {
			return ManagedRuntimeReport{}, time.Time{}, protocol.Envelope{}, err
		}
		if !time.Now().Before(deadline) {
			return ManagedRuntimeReport{}, time.Time{}, protocol.Envelope{}, authority.ErrFenced
		}
		return report, deadline, pending.envelope, nil
	}
}

func minReadinessDeadline(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

func (c *Controller) readinessAuthority(ctx context.Context, effect authority.RuntimeEffect, nonce string) (RuntimeEffectCaller, Desired, error) {
	var material executionwire.WorkerGrantMaterial
	var original Registration
	var desired Desired
	if err := protocol.DecodeStrict(effect.Material, &material, 1<<20); err != nil {
		return RuntimeEffectCaller{}, Desired{}, err
	}
	if err := decodeStrict(material.Registration, &original); err != nil {
		return RuntimeEffectCaller{}, Desired{}, err
	}
	if err := decodeStrict(material.Desired, &desired); err != nil {
		return RuntimeEffectCaller{}, Desired{}, err
	}
	current, err := c.registration(ctx, original.Node)
	if err != nil || !sameJSON(current, original) || current.Cell != c.cell || current.ID != effect.RegistrationID ||
		current.Generation != effect.RegistrationGeneration || current.PublicKey != effect.WorkerPublicKey || current.NATSUserPublicKey != effect.NATSUserPublicKey ||
		current.ManagedOCI == nil || current.ManagedOCI.InstanceID != effect.InstanceID {
		return RuntimeEffectCaller{}, Desired{}, errors.Join(authority.ErrFenced, err)
	}
	s, _, found, err := c.sessionSnapshot(ctx, sessionKey(c.cell, current.Node))
	if err != nil || !found || s.SessionID != effect.HostSessionID || s.RegistrationGeneration != effect.RegistrationGeneration || !time.Now().Before(s.ExpiresAt) {
		return RuntimeEffectCaller{}, Desired{}, errors.Join(authority.ErrFenced, err)
	}
	actual, _, found, err := c.readDesired(ctx, current.Node, desired.Role)
	if err != nil || !found || actual.Withdrawn || !sameJSON(actual, desired) || validateDesired(actual, c.cell, current) != nil {
		return RuntimeEffectCaller{}, Desired{}, errors.Join(authority.ErrFenced, err)
	}
	retired, err := c.retired(ctx, current.Node)
	if err != nil || retired || c.authorityEpoch() != effect.Epoch || !time.Now().Before(effect.ExpiresAt) {
		return RuntimeEffectCaller{}, Desired{}, errors.Join(authority.ErrFenced, err)
	}
	if err := c.guard(ctx, effect.Epoch); err != nil {
		return RuntimeEffectCaller{}, Desired{}, err
	}
	return RuntimeEffectCaller{registration: current, sessionID: s.SessionID, epoch: effect.Epoch, expiresAt: minReadinessDeadline(s.ExpiresAt, effect.ExpiresAt), nonce: nonce}, desired, nil
}

func validateContainerReadinessReport(effect authority.RuntimeEffect, desired Desired, report ManagedRuntimeReport) error {
	container := report.Container
	if container == nil || report.ServingProof == nil || container.TaskID != effect.TaskID || container.TaskSHA256 != effect.TaskSHA256 ||
		container.AdmissionSHA256 != effect.AdmissionSHA256 || container.EffectID != effect.EffectID {
		return errors.New("readiness observation differs from the original held container")
	}
	return validateManagedReportForDesired(Report{State: "running", Managed: &report}, desired)
}

func (c *Controller) serveContainerReadiness(ctx context.Context, req request, registration Registration, current session) (any, error) {
	var query containerReadinessQuery
	if err := decodeStrict(req.Payload, &query); err != nil {
		return nil, err
	}
	if query.Challenge == nil && query.Report != nil || query.Challenge != nil && query.Report == nil {
		return nil, errors.New("readiness reply requires the exact challenge and observation")
	}
	c.readinessMu.Lock()
	var pending *containerReadinessPending
	for _, candidate := range c.readiness {
		if candidate.completed || !time.Now().Before(candidate.challenge.Deadline) ||
			candidate.effect.HostSessionID != req.SessionID || candidate.effect.RegistrationID != registration.ID ||
			candidate.effect.RegistrationGeneration != registration.Generation || candidate.effect.WorkerPublicKey != registration.PublicKey ||
			candidate.effect.NATSUserPublicKey != registration.NATSUserPublicKey ||
			candidate.challenge.TaskID != query.TaskID || candidate.challenge.TaskSHA256 != query.TaskSHA256 ||
			candidate.challenge.AdmissionSHA256 != query.AdmissionSHA256 || candidate.challenge.EffectID != query.EffectID {
			continue
		}
		if query.Challenge == nil || sameContainerReadinessChallenge(*query.Challenge, candidate.challenge) {
			pending = candidate
			break
		}
	}
	c.readinessMu.Unlock()
	if pending == nil {
		if query.Challenge != nil {
			return nil, errors.New("readiness challenge expired or was consumed")
		}
		return containerReadinessReply{}, nil
	}
	_, desired, err := c.readinessAuthority(ctx, pending.effect, pending.challenge.Nonce)
	if err != nil || current.SessionID != pending.effect.HostSessionID {
		return nil, errors.Join(authority.ErrFenced, err)
	}
	if query.Challenge == nil {
		return containerReadinessReply{Challenge: &pending.challenge}, nil
	}
	if err := validateContainerReadinessReport(pending.effect, desired, *query.Report); err != nil {
		return nil, err
	}
	c.readinessMu.Lock()
	defer c.readinessMu.Unlock()
	if c.readiness[pending.challenge.Nonce] != pending || pending.completed || !time.Now().Before(pending.challenge.Deadline) {
		return nil, errors.New("readiness challenge expired or was consumed")
	}
	pending.completed = true
	pending.envelope = req.Envelope
	pending.result <- *query.Report
	return containerReadinessReply{Challenge: &pending.challenge}, nil
}

func (a *Agent) ContainerReadinessChallenge(ctx context.Context, binding ManagedContainerRuntime) (*ContainerReadinessChallenge, error) {
	if _, _, err := a.executionLease(); err != nil {
		return nil, err
	}
	var reply containerReadinessReply
	err := a.request(ctx, "runtime-readiness", containerReadinessQuery{TaskID: binding.TaskID, TaskSHA256: binding.TaskSHA256, AdmissionSHA256: binding.AdmissionSHA256, EffectID: binding.EffectID}, &reply)
	if err != nil {
		return nil, err
	}
	if _, _, err := a.executionLease(); err != nil {
		return nil, err
	}
	challenge := reply.Challenge
	if challenge != nil && (challenge.TaskID != binding.TaskID || challenge.TaskSHA256 != binding.TaskSHA256 || challenge.AdmissionSHA256 != binding.AdmissionSHA256 ||
		challenge.EffectID != binding.EffectID || !lowerHex(challenge.Nonce, 32) || !time.Now().Before(challenge.Deadline)) {
		return nil, errors.New("readiness challenge differs from the held local task")
	}
	return challenge, nil
}

func (a *Agent) ContainerReadinessResult(ctx context.Context, challenge ContainerReadinessChallenge, report ManagedRuntimeReport) error {
	if _, _, err := a.executionLease(); err != nil {
		return err
	}
	if !time.Now().Before(challenge.Deadline) {
		return authority.ErrFenced
	}
	var accepted containerReadinessReply
	if err := a.request(ctx, "runtime-readiness", containerReadinessQuery{TaskID: challenge.TaskID, TaskSHA256: challenge.TaskSHA256,
		AdmissionSHA256: challenge.AdmissionSHA256, EffectID: challenge.EffectID, Challenge: &challenge, Report: &report}, &accepted); err != nil {
		return err
	}
	if accepted.Challenge == nil || !sameContainerReadinessChallenge(*accepted.Challenge, challenge) {
		return errors.New("readiness result acknowledgment differs from the challenge")
	}
	_, _, err := a.executionLease()
	return err
}
