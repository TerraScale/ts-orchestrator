//go:build linux

package host

import (
	"context"
	"errors"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/storage/executionwire"
)

// RuntimeReadinessSource pins root's actual original target session and desired
// state. Neither relay bytes nor renewed session expiry can extend this source.
type RuntimeReadinessSource struct {
	reader   *Reader
	original context.Context
	effect   authority.RuntimeEffect
	caller   RuntimeEffectCaller
	desired  Desired
}

func (s *RuntimeReadinessSource) Caller() RuntimeEffectCaller { return s.caller }
func (s *RuntimeReadinessSource) Deadline() time.Time         { return s.caller.ExpiresAt() }

func (r *Reader) AdmitRuntimeReadinessSource(ctx context.Context, effect authority.RuntimeEffect, until time.Time) (*RuntimeReadinessSource, error) {
	if r == nil || r.controller == nil || ctx == nil || ctx.Err() != nil || effect.Phase != authority.RuntimeEffectHeld || !time.Now().Before(effect.ExpiresAt) {
		return nil, authority.ErrFenced
	}
	originalContext := ctx
	deadline := minReadinessDeadline(effect.ExpiresAt, until)
	if callerDeadline, ok := ctx.Deadline(); ok {
		deadline = minReadinessDeadline(deadline, callerDeadline)
	}
	if !time.Now().Before(deadline) {
		return nil, authority.ErrFenced
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	var material executionwire.WorkerGrantMaterial
	var registration Registration
	var desired Desired
	if protocol.DecodeStrict(effect.Material, &material, 1<<20) != nil || decodeStrict(material.Registration, &registration) != nil || decodeStrict(material.Desired, &desired) != nil {
		return nil, errors.New("original runtime readiness material is invalid")
	}
	current, session, err := r.currentContainerGenerationSession(ctx, registration.Node)
	if err != nil || !sameJSON(current, registration) || current.ID != effect.RegistrationID || current.Generation != effect.RegistrationGeneration ||
		current.PublicKey != effect.WorkerPublicKey || current.NATSUserPublicKey != effect.NATSUserPublicKey || current.ManagedOCI == nil ||
		current.ManagedOCI.InstanceID != effect.InstanceID || session.SessionID != effect.HostSessionID || session.Epoch != effect.Epoch {
		return nil, errors.Join(authority.ErrFenced, err)
	}
	deadline = minReadinessDeadline(deadline, session.ExpiresAt)
	source := &RuntimeReadinessSource{reader: r, original: originalContext, effect: effect, desired: desired,
		caller: RuntimeEffectCaller{registration: current, sessionID: session.SessionID, epoch: effect.Epoch, expiresAt: deadline}}
	if err := source.Guard(ctx); err != nil {
		return nil, err
	}
	return source, nil
}

func (s *RuntimeReadinessSource) Guard(ctx context.Context) error {
	if s == nil || s.reader == nil || s.original == nil || ctx == nil || ctx.Err() != nil || s.original.Err() != nil || !time.Now().Before(s.Deadline()) {
		return authority.ErrFenced
	}
	ctx, cancel := context.WithDeadline(ctx, s.Deadline())
	stop := context.AfterFunc(s.original, cancel)
	defer cancel()
	defer stop()
	registration, current, err := s.reader.currentContainerGenerationSession(ctx, s.caller.registration.Node)
	if err != nil || !sameJSON(registration, s.caller.registration) || current.SessionID != s.caller.SessionID() || current.Epoch != s.caller.Epoch() || current.ExpiresAt.Before(s.Deadline()) {
		return errors.Join(authority.ErrFenced, err)
	}
	desired, _, found, err := s.reader.controller.readDesired(ctx, registration.Node, s.desired.Role)
	if err != nil || !found || desired.Withdrawn || !sameJSON(desired, s.desired) || validateDesired(desired, s.reader.controller.cell, registration) != nil {
		return errors.Join(authority.ErrFenced, err)
	}
	if !time.Now().Before(s.Deadline()) || s.original.Err() != nil {
		return authority.ErrFenced
	}
	return ctx.Err()
}

// Verify accepts only the original worker's signature over this root nonce and
// exact held identity, surrounded by reads of the current original source.
func (s *RuntimeReadinessSource) Verify(ctx context.Context, challenge ContainerReadinessChallenge, envelope protocol.Envelope) (ManagedRuntimeReport, error) {
	if s == nil || s.original == nil || ctx == nil || ctx.Err() != nil {
		return ManagedRuntimeReport{}, authority.ErrFenced
	}
	ctx, cancel := context.WithDeadline(ctx, minReadinessDeadline(s.Deadline(), challenge.Deadline))
	stop := context.AfterFunc(s.original, cancel)
	defer cancel()
	defer stop()
	if err := s.Guard(ctx); err != nil {
		return ManagedRuntimeReport{}, err
	}
	if !lowerHex(challenge.Nonce, 32) || challenge.Deadline.After(s.Deadline()) || !time.Now().Before(challenge.Deadline) ||
		challenge.TaskID != s.effect.TaskID || challenge.TaskSHA256 != s.effect.TaskSHA256 ||
		challenge.AdmissionSHA256 != s.effect.AdmissionSHA256 || challenge.EffectID != s.effect.EffectID {
		return ManagedRuntimeReport{}, authority.ErrFenced
	}
	var req request
	if err := protocol.DecodeStrict(envelope.Payload, &req, 64<<10); err != nil {
		return ManagedRuntimeReport{}, err
	}
	req.Envelope = envelope
	if req.Operation != "runtime-readiness" || req.Node != s.caller.registration.Node || req.NATSUserPublicKey != s.effect.NATSUserPublicKey ||
		req.SessionID != s.effect.HostSessionID || req.Epoch != s.effect.Epoch {
		return ManagedRuntimeReport{}, authority.ErrFenced
	}
	registration, _, err := s.reader.currentContainerMaterialSession(ctx, req)
	if err != nil || !sameJSON(registration, s.caller.registration) {
		return ManagedRuntimeReport{}, errors.Join(authority.ErrFenced, err)
	}
	var query containerReadinessQuery
	if err := decodeStrict(req.Payload, &query); err != nil {
		return ManagedRuntimeReport{}, err
	}
	if query.Challenge == nil || query.Report == nil || !sameContainerReadinessChallenge(challenge, *query.Challenge) ||
		query.TaskID != challenge.TaskID || query.TaskSHA256 != challenge.TaskSHA256 || query.AdmissionSHA256 != challenge.AdmissionSHA256 || query.EffectID != challenge.EffectID {
		return ManagedRuntimeReport{}, errors.New("signed Source observation differs from root challenge")
	}
	if err := validateContainerReadinessReport(s.effect, s.desired, *query.Report); err != nil {
		return ManagedRuntimeReport{}, err
	}
	if err := s.Guard(ctx); err != nil {
		return ManagedRuntimeReport{}, err
	}
	if !time.Now().Before(challenge.Deadline) {
		return ManagedRuntimeReport{}, authority.ErrFenced
	}
	return *query.Report, nil
}
