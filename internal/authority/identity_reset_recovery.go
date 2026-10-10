package authority

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/nats.go/jetstream"
)

const identityResetRecoveryDomain = "terrascale.authority.identity-reset-recovery"

type identityResetRecovery struct {
	Version          int    `json:"version"`
	ResetSHA256      string `json:"reset_sha256"`
	CommitmentSHA256 string `json:"commitment_sha256"`
}

func observeIdentityResetCommitment(ctx context.Context, js jetstream.JetStream, envelope trust.Envelope, roots trust.Keyring, target IdentityResetTarget) (IdentityReset, jetstream.Stream, []*jetstream.RawStreamMsg, error) {
	reset, err := VerifyIdentityReset(envelope, roots, target, envelope.IssuedAt)
	if err != nil {
		return IdentityReset{}, nil, nil, err
	}
	if js == nil {
		return IdentityReset{}, nil, nil, errors.New("committed identity reset requires JetStream")
	}
	stream, err := js.Stream(ctx, ControlStreamName)
	if err != nil {
		return IdentityReset{}, nil, nil, err
	}
	info, err := stream.Info(ctx)
	if err != nil {
		return IdentityReset{}, nil, nil, err
	}
	if err := verifyControlStreamConfig(info.Config, target.Replicas); err != nil {
		return IdentityReset{}, nil, nil, err
	}
	regional, err := stream.GetMsg(ctx, reset.LastSequence+1)
	if err != nil {
		return IdentityReset{}, nil, nil, err
	}
	want, err := identityResetLease(reset, resetDigest(envelope.Payload))
	if err != nil || regional.Subject != fmt.Sprintf("%s.%s.lease", controlSubjectRoot, reset.Scope) || regional.Sequence != reset.LastSequence+1 || !bytes.Equal(regional.Data, want) {
		return IdentityReset{}, nil, nil, ErrConflict
	}
	messages := []*jetstream.RawStreamMsg{regional}
	if reset.GlobalLease != nil {
		global, err := stream.GetMsg(ctx, reset.LastSequence+2)
		if err != nil {
			return IdentityReset{}, nil, nil, err
		}
		want, err := globalResetLease(reset, resetDigest(envelope.Payload))
		if err != nil || global.Subject != controlSubjectRoot+".global.lease" || global.Sequence != reset.LastSequence+2 || !bytes.Equal(global.Data, want) {
			return IdentityReset{}, nil, nil, ErrConflict
		}
		messages = append(messages, global)
	}
	return reset, stream, messages, nil
}

func resetRecoveryPins(envelope trust.Envelope, messages []*jetstream.RawStreamMsg) (identityResetRecovery, error) {
	fingerprint, err := trust.Fingerprint(envelope)
	if err != nil {
		return identityResetRecovery{}, err
	}
	type pin struct {
		Sequence uint64
		Subject  string
		Time     time.Time
		SHA256   string
	}
	pins := make([]pin, 0, len(messages))
	for _, msg := range messages {
		pins = append(pins, pin{msg.Sequence, msg.Subject, msg.Time, resetDigest(msg.Data)})
	}
	wire, err := protocol.EncodeJSON(pins)
	return identityResetRecovery{Version: 1, ResetSHA256: fingerprint, CommitmentSHA256: resetDigest(wire)}, err
}

func resetRecoveryScope(reset IdentityReset) trust.Scope {
	scope := reset.trustScope()
	scope.Domain = identityResetRecoveryDomain
	return scope
}

// SignIdentityResetRecovery reauthorizes only the independently observed exact
// hold. It does not change the original reset, target records, CAS or epochs.
func SignIdentityResetRecovery(ctx context.Context, js jetstream.JetStream, envelope trust.Envelope, roots trust.Keyring, target IdentityResetTarget, key ed25519.PrivateKey, now time.Time) (trust.Envelope, error) {
	bounded, cancel := context.WithTimeout(ctx, authorityAPITimeout)
	defer cancel()
	reset, _, messages, err := observeIdentityResetCommitment(bounded, js, envelope, roots, target)
	if err != nil {
		return trust.Envelope{}, err
	}
	if len(key) != ed25519.PrivateKeySize {
		return trust.Envelope{}, trust.ErrUntrustedKey
	}
	public := key.Public().(ed25519.PublicKey)
	id, err := trust.KeyID(public)
	if err != nil || !bytes.Equal(roots[id], public) {
		return trust.Envelope{}, trust.ErrUntrustedKey
	}
	pins, err := resetRecoveryPins(envelope, messages)
	if err != nil {
		return trust.Envelope{}, err
	}
	payload, err := trust.EncodePayload(pins)
	if err != nil {
		return trust.Envelope{}, err
	}
	return trust.Sign(payload, resetRecoveryScope(reset), now, now.Add(identityResetPolicy.MaxLifetime), key)
}

func verifyResetRecovery(envelope trust.Envelope, roots trust.Keyring, reset IdentityReset, expected identityResetRecovery, at time.Time) error {
	payload, err := trust.VerifyCurrent(envelope, resetRecoveryScope(reset), roots, at, identityResetPolicy)
	if err != nil {
		return err
	}
	canonical, err := trust.EncodePayload(expected)
	if err != nil || !bytes.Equal(payload, canonical) {
		return ErrConflict
	}
	return nil
}

func resetRecoverySubject(reset IdentityReset) string {
	return controlSubjectRoot + "." + reset.Scope + ".identity-reset-recovery." + reset.OperationID
}

// CommitIdentityResetRecovery appends fresh current-root authorization. A late
// publish may be retried with fresh authority without replacing the held lease.
func CommitIdentityResetRecovery(ctx context.Context, js jetstream.JetStream, original, recovery trust.Envelope, roots trust.Keyring, target IdentityResetTarget, now time.Time) error {
	bounded, cancel := context.WithTimeout(ctx, authorityAPITimeout)
	defer cancel()
	reset, stream, messages, err := observeIdentityResetCommitment(bounded, js, original, roots, target)
	if err != nil {
		return err
	}
	pins, err := resetRecoveryPins(original, messages)
	if err != nil {
		return err
	}
	if err := verifyResetRecovery(recovery, roots, reset, pins, now); err != nil {
		return err
	}
	wire, err := trust.EncodeEnvelope(recovery)
	if err != nil {
		return err
	}
	fingerprint, err := trust.Fingerprint(recovery)
	if err != nil {
		return err
	}
	subject := resetRecoverySubject(reset)
	_, publishErr := js.PublishMsg(bounded, controlMessage(subject, "identity-reset-recovery", fingerprint, wire))
	probe, stop := context.WithTimeout(context.WithoutCancel(ctx), authorityAPITimeout)
	defer stop()
	msg, err := stream.GetLastMsgForSubject(probe, subject)
	if err != nil || !bytes.Equal(msg.Data, wire) {
		return errors.Join(ErrOutcomeUnknown, publishErr, err)
	}
	return verifyResetRecovery(recovery, roots, reset, pins, msg.Time)
}

// VerifyCommittedIdentityReset proves both exact holds and their original
// lifetime, or an immutable fresh root authorization for those same holds.
func VerifyCommittedIdentityReset(ctx context.Context, js jetstream.JetStream, envelope trust.Envelope, roots trust.Keyring, target IdentityResetTarget) (IdentityReset, error) {
	return verifyCommittedIdentityReset(ctx, js, envelope, roots, target)
}
