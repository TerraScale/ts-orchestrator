package authority

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/nats.go/jetstream"
)

// IdentityResetCompletion recovers the committed outcome from the immutable
// lease history. Zero means the root-pinned transaction has not completed.
func IdentityResetCompletion(ctx context.Context, js jetstream.JetStream, envelope trust.Envelope, roots trust.Keyring,
	target IdentityResetTarget, now time.Time,
) (uint64, error) {
	reset, err := VerifyIdentityReset(envelope, roots, target, now)
	if err != nil {
		return 0, err
	}
	if js == nil {
		return 0, errors.New("identity reset outcome requires JetStream")
	}
	committed, err := IdentityResetCommitted(ctx, js, envelope, roots, target)
	if err != nil || !committed {
		return 0, err
	}
	return identityResetCompletion(ctx, js, reset, resetDigest(envelope.Payload), target.Replicas)
}

func identityResetCompletion(ctx context.Context, js jetstream.JetStream, reset IdentityReset, pinID string, replicas int) (uint64, error) {
	bounded, cancel := context.WithTimeout(ctx, authorityAPITimeout)
	defer cancel()
	stream, err := js.Stream(bounded, ControlStreamName)
	if err != nil {
		return 0, err
	}
	info, err := stream.Info(bounded)
	if err != nil {
		return 0, err
	}
	if err := verifyControlStreamConfig(info.Config, replicas); err != nil {
		return 0, err
	}
	barrier, err := stream.GetMsg(bounded, reset.LastSequence+1)
	if errors.Is(err, jetstream.ErrMsgNotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	subject := fmt.Sprintf("%s.%s.lease", controlSubjectRoot, reset.Scope)
	wantBarrier, err := identityResetLease(reset, pinID)
	if err != nil {
		return 0, err
	}
	if barrier.Subject != subject || !bytes.Equal(barrier.Data, wantBarrier) {
		return 0, ErrConflict
	}
	// No ordinary lease can follow the hold until completion; other scopes
	// may append between these two records without changing this outcome.
	completed, err := stream.GetMsg(bounded, barrier.Sequence+1, jetstream.WithGetMsgSubject(subject))
	if errors.Is(err, jetstream.ErrMsgNotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	wantCompleted, err := identityResetLease(reset, "")
	if err != nil {
		return 0, err
	}
	if completed.Subject != subject || !bytes.Equal(completed.Data, wantCompleted) {
		return 0, ErrConflict
	}
	if reset.GlobalLease != nil {
		_, globalComplete, err := globalResetOutcome(bounded, stream, reset, pinID)
		if err != nil || globalComplete == 0 {
			return 0, errors.Join(ErrConflict, err)
		}
	}
	return completed.Sequence, nil
}

// IdentityResetCommitted proves that the exact transaction began while its
// root grant was valid. It never publishes an expired or missing barrier.
func IdentityResetCommitted(ctx context.Context, js jetstream.JetStream, envelope trust.Envelope,
	roots trust.Keyring, target IdentityResetTarget,
) (bool, error) {
	_, err := verifyCommittedIdentityReset(ctx, js, envelope, roots, target)
	if errors.Is(err, jetstream.ErrMsgNotFound) {
		return false, nil
	}
	return err == nil, err
}

func verifyCommittedIdentityReset(ctx context.Context, js jetstream.JetStream, envelope trust.Envelope,
	roots trust.Keyring, target IdentityResetTarget,
) (IdentityReset, error) {
	bounded, cancel := context.WithTimeout(ctx, authorityAPITimeout)
	defer cancel()
	reset, stream, messages, err := observeIdentityResetCommitment(bounded, js, envelope, roots, target)
	if err != nil {
		return IdentityReset{}, err
	}
	var lifetimeErr error
	for _, msg := range messages {
		if _, err := VerifyIdentityReset(envelope, roots, target, msg.Time); err != nil {
			lifetimeErr = errors.Join(lifetimeErr, err)
		}
	}
	if lifetimeErr == nil {
		return reset, nil
	}
	// A fresh signed authorization is required for an out-of-window commit.
	msg, err := stream.GetLastMsgForSubject(bounded, resetRecoverySubject(reset))
	if err != nil {
		if errors.Is(err, jetstream.ErrMsgNotFound) {
			return IdentityReset{}, lifetimeErr
		}
		return IdentityReset{}, errors.Join(lifetimeErr, err)
	}
	recovery, err := trust.DecodeEnvelope(msg.Data)
	if err != nil {
		return IdentityReset{}, err
	}
	pins, err := resetRecoveryPins(envelope, messages)
	if err != nil {
		return IdentityReset{}, err
	}
	if err := verifyResetRecovery(recovery, roots, reset, pins, msg.Time); err != nil {
		return IdentityReset{}, err
	}
	return reset, nil
}
