package delivery

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

const (
	intentKind            = "delivery.intent"
	artifactKind          = "delivery.artifact"
	MaxArtifactClaimBytes = 8 << 10
)

// TrustedSigner binds a public key to the actor identity authorized by the
// regional operator policy. Lookup is by protocol.KeyID(publicKey).
type TrustedSigner struct {
	Actor     string
	PublicKey ed25519.PublicKey
}

// Ed25519Codec signs CLI submissions and verifies both deployment intents and
// artifact admission claims against configured operator/CI trust roots.
type Ed25519Codec struct {
	Cell       string
	Actor      string
	PrivateKey ed25519.PrivateKey
	Trusted    map[string]TrustedSigner
	// Lookup, when set, finds trusted signers instead of Trusted, so they
	// can change while the codec is in use.
	Lookup      func(keyID string) (TrustedSigner, bool)
	Lifetime    time.Duration
	MaxLifetime time.Duration
	ClockSkew   time.Duration
	Now         func() time.Time
}

func (c Ed25519Codec) clock() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c Ed25519Codec) policy() (protocol.VerifyPolicy, error) {
	if !nameRE.MatchString(c.Cell) || c.MaxLifetime <= 0 || c.ClockSkew < 0 {
		return protocol.VerifyPolicy{}, fmt.Errorf("%w: signed delivery codec configuration", ErrInvalid)
	}
	return protocol.VerifyPolicy{MaxLifetime: c.MaxLifetime, ClockSkew: c.ClockSkew}, nil
}

func (c Ed25519Codec) Sign(ctx context.Context, payload []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if c.Lifetime <= 0 || c.Lifetime > c.MaxLifetime || len(c.PrivateKey) != ed25519.PrivateKeySize || c.Actor == "" {
		return nil, ErrInvalid
	}
	i, err := DecodeIntent(payload)
	if err != nil {
		return nil, err
	}
	if i.Cell != c.Cell {
		return nil, ErrInvalid
	}
	issued := c.clock().UTC()
	e, err := protocol.SignEnvelope(payload, protocol.EnvelopeScope{Region: i.Cell, Kind: intentKind, Actor: c.Actor, OperationID: i.OperationID, Generation: i.Generation, Epoch: i.AuthorityEpoch}, issued, issued.Add(c.Lifetime), c.PrivateKey)
	if err != nil {
		return nil, err
	}
	return protocol.EncodeJSON(e)
}

func (c Ed25519Codec) Verify(ctx context.Context, wire []byte) (VerifiedEnvelope, error) {
	if err := ctx.Err(); err != nil {
		return VerifiedEnvelope{}, err
	}
	var e protocol.Envelope
	if err := protocol.DecodeStrict(wire, &e, MaxIntentBytes+8192); err != nil {
		return VerifiedEnvelope{}, err
	}
	i, err := DecodeIntent(e.Payload)
	if err != nil {
		return VerifiedEnvelope{}, err
	}
	if i.Cell != c.Cell {
		return VerifiedEnvelope{}, ErrInvalid
	}
	trusted, err := c.verifyScopeAt(e, protocol.EnvelopeScope{Region: i.Cell, Kind: intentKind, OperationID: i.OperationID, Generation: i.Generation, Epoch: i.AuthorityEpoch}, c.clock().UTC())
	if err != nil {
		return VerifiedEnvelope{}, err
	}
	return VerifiedEnvelope{Payload: e.Payload, Actor: trusted.Actor}, nil
}

func (c Ed25519Codec) SignArtifact(ctx context.Context, record ArtifactRecord) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := record.validate(); err != nil {
		return nil, err
	}
	if record.Cell != c.Cell {
		return nil, ErrInvalid
	}
	if c.Lifetime <= 0 || c.Lifetime > c.MaxLifetime || len(c.PrivateKey) != ed25519.PrivateKeySize || c.Actor == "" {
		return nil, ErrInvalid
	}
	b, err := protocol.EncodeJSON(record)
	if err != nil {
		return nil, err
	}
	issued := c.clock().UTC()
	e, err := protocol.SignEnvelope(b, protocol.EnvelopeScope{Region: c.Cell, Kind: artifactKind, Actor: c.Actor, OperationID: entityid.Derive("artifact-admission", record.Digest), Generation: 1}, issued, issued.Add(c.Lifetime), c.PrivateKey)
	if err != nil {
		return nil, err
	}
	return protocol.EncodeJSON(e)
}

func (c Ed25519Codec) VerifyArtifact(ctx context.Context, wire []byte) (ArtifactRecord, string, error) {
	return c.verifyArtifactAt(ctx, wire, c.clock().UTC())
}

// VerifyArchivedArtifact validates an already admitted signed claim at its
// issuance instant, so later delivery does not depend on transport expiry.
func (c Ed25519Codec) VerifyArchivedArtifact(ctx context.Context, wire []byte) (ArtifactRecord, string, error) {
	var e protocol.Envelope
	if err := protocol.DecodeStrict(wire, &e, MaxArtifactClaimBytes); err != nil {
		return ArtifactRecord{}, "", err
	}
	return c.verifyArtifactAt(ctx, wire, e.IssuedAt)
}

func (c Ed25519Codec) verifyArtifactAt(ctx context.Context, wire []byte, now time.Time) (ArtifactRecord, string, error) {
	if err := ctx.Err(); err != nil {
		return ArtifactRecord{}, "", err
	}
	var e protocol.Envelope
	if err := protocol.DecodeStrict(wire, &e, MaxArtifactClaimBytes); err != nil {
		return ArtifactRecord{}, "", err
	}
	var record ArtifactRecord
	if err := protocol.DecodeStrict(e.Payload, &record, MaxArtifactClaimBytes); err != nil {
		return ArtifactRecord{}, "", err
	}
	if err := record.validate(); err != nil {
		return ArtifactRecord{}, "", err
	}
	if record.Cell != c.Cell {
		return ArtifactRecord{}, "", ErrInvalid
	}
	trusted, err := c.verifyScopeAt(e, protocol.EnvelopeScope{Region: c.Cell, Kind: artifactKind, OperationID: entityid.Derive("artifact-admission", record.Digest), Generation: 1}, now)
	if err != nil {
		return ArtifactRecord{}, "", err
	}
	return record, trusted.Actor, nil
}

func (c Ed25519Codec) verifyScopeAt(e protocol.Envelope, expected protocol.EnvelopeScope, now time.Time) (TrustedSigner, error) {
	policy, err := c.policy()
	if err != nil {
		return TrustedSigner{}, err
	}
	trusted, ok := c.Trusted[e.KeyID]
	if c.Lookup != nil {
		trusted, ok = c.Lookup(e.KeyID)
	}
	if !ok || trusted.Actor == "" || len(trusted.PublicKey) != ed25519.PublicKeySize {
		return TrustedSigner{}, errors.New("untrusted delivery signing key")
	}
	expected.Actor = trusted.Actor
	if err := protocol.VerifyEnvelope(e, expected, trusted.PublicKey, now, policy); err != nil {
		return TrustedSigner{}, err
	}
	return trusted, nil
}
