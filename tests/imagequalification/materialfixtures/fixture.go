// Package materialfixtures signs native qualification inputs using authority
// supplied by the caller. It never creates a root or a signing identity.
package materialfixtures

import (
	"context"
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/containermaterial"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

type Input struct {
	Spec           cellspec.Spec
	Intent         delivery.Intent
	Roots          trust.Keyring
	RootPrivateKey ed25519.PrivateKey
	Codec          delivery.Ed25519Codec
	IssuedAt       time.Time
	Lifetime       time.Duration
}

type Fixture struct {
	SignedProfile []byte
	SignedIntent  []byte
}

// Sign checks both existing trust domains before returning the exact signed
// no-secret profile and retained container intent used by the native runner.
func Sign(ctx context.Context, input Input) (Fixture, error) {
	if err := ctx.Err(); err != nil {
		return Fixture{}, err
	}
	profile, err := cellspec.Sign(input.Spec, nil, input.Roots, input.IssuedAt, input.Lifetime, input.RootPrivateKey)
	if err != nil {
		return Fixture{}, err
	}
	proof, err := containermaterial.VerifyProfile(profile, input.Roots, input.Spec.Identity, input.Intent)
	if err != nil {
		return Fixture{}, err
	}
	if !proof.NoSecrets() {
		return Fixture{}, errors.New("native container fixture requires an explicit signed no-secret profile")
	}
	payload, err := protocol.EncodeJSON(input.Intent)
	if err != nil {
		return Fixture{}, err
	}
	intent, err := input.Codec.Sign(ctx, payload)
	if err != nil {
		return Fixture{}, err
	}
	verified, err := input.Codec.Verify(ctx, intent)
	if err != nil {
		return Fixture{}, err
	}
	retained, err := delivery.DecodeIntent(verified.Payload)
	if err != nil {
		return Fixture{}, err
	}
	before, beforeErr := input.Intent.Fingerprint()
	after, afterErr := retained.Fingerprint()
	if beforeErr != nil || afterErr != nil || before != after {
		return Fixture{}, errors.New("native fixture intent changed during signing")
	}
	return Fixture{SignedProfile: profile, SignedIntent: intent}, nil
}
