package bootstrapstart

import (
	"bytes"
	"context"
	"errors"
	"os"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"github.com/nats-io/nats.go/jetstream"
)

var ErrIdentityRekeyPending = errors.New("identity rekey shared completion is pending")

// VerifyIdentityRekeyCompletion reads immutable completion without authorizing
// replay. The supplied record must still equal the root-owned installation.
func VerifyIdentityRekeyCompletion(ctx context.Context, accepted AcceptedIdentity, js jetstream.JetStream) error {
	if err := accepted.Validate(); err != nil {
		return err
	}
	store := NewMarkerStore()
	actual, err := store.ReadIdentity()
	if err != nil {
		return err
	}
	inputs, err := LoadTrustInputs(actual)
	if err != nil {
		return err
	}
	return store.verifyIdentityRekeyCompletion(ctx, accepted, inputs, js)
}

func (store MarkerStore) verifyIdentityRekeyCompletion(ctx context.Context, accepted AcceptedIdentity, inputs TrustInputs, js jetstream.JetStream) error {
	wire, err := EncodeAcceptedIdentity(accepted)
	if err != nil {
		return err
	}
	actual, err := store.ReadIdentity()
	if err != nil {
		return err
	}
	fresh, err := EncodeAcceptedIdentity(actual)
	if err != nil || !bytes.Equal(wire, fresh) {
		return ErrIdentityRekeyLocalPending
	}
	verified, err := store.verifiedIdentityRekey(actual, inputs)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	envelope, err := verified.ResetEnvelope()
	if err != nil {
		return err
	}
	sequence, err := authority.IdentityResetCompletion(ctx, js, envelope, verified.AcceptedRoots(), verified.ResetTarget(), actual.AcceptedAt)
	if err != nil {
		return err
	}
	if sequence == 0 {
		return ErrIdentityRekeyPending
	}
	// A network wait cannot turn an obsolete local acceptance into readiness.
	_, err = store.verifiedIdentityRekey(actual, inputs)
	return err
}
