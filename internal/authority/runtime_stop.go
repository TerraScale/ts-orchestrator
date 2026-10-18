package authority

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"errors"
	"time"
)

// RuntimeStopRecord retains original signed evidence, not detach permission.
// Readers must independently verify it and exclude subsequent writers.
type RuntimeStopRecord struct {
	SignedProof       []byte    `json:"signed_proof"`
	ClosingSequence   uint64    `json:"closing_sequence"`
	ChallengeEpoch    uint64    `json:"challenge_epoch"`
	ChallengeIssuedAt time.Time `json:"challenge_issued_at"`
}

func (stop RuntimeStopRecord) validate(effect RuntimeEffect) error {
	if effect.Phase != RuntimeEffectSettled || stop.ClosingSequence == 0 || stop.ChallengeEpoch < effect.Epoch ||
		stop.ChallengeIssuedAt.Location() != time.UTC || !stop.ChallengeIssuedAt.After(effect.ExpiresAt) ||
		len(stop.SignedProof) == 0 || len(stop.SignedProof) > maxControlPayload ||
		!jsontext.Value(stop.SignedProof).IsValid() || jsontext.Value(stop.SignedProof).Kind() != '{' {
		return errors.New("retained runtime stop has invalid closing provenance")
	}
	return nil
}

// SettleRuntimeEffectWithStop preserves the exact proof checked on every CAS
// attempt. A retained record is evidence only; it confers no restart exclusion.
func (r *Runtime) SettleRuntimeEffectWithStop(ctx context.Context, epoch uint64, scope WorkloadScope,
	effectID string, expected uint64, stop RuntimeStopRecord, verifyStopped func(context.Context, RuntimeEffect) error,
) (uint64, error) {
	if stop.ClosingSequence != expected || stop.ChallengeEpoch != epoch {
		return 0, ErrFenced
	}
	stop.SignedProof = bytes.Clone(stop.SignedProof)
	return r.settleRuntimeEffect(ctx, epoch, scope, effectID, expected, new(stop), verifyStopped)
}
