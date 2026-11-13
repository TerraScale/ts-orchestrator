package authority

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
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

// VerifyCommittedIdentityReset proves both exact holds and their original
// lifetime, or an immutable fresh root authorization for those same holds.
func VerifyCommittedIdentityReset(ctx context.Context, js jetstream.JetStream, envelope trust.Envelope, roots trust.Keyring, target IdentityResetTarget) (IdentityReset, error) {
	return verifyCommittedIdentityReset(ctx, js, envelope, roots, target)
}
