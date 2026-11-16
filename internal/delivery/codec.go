package delivery

import (
	"crypto/ed25519"
	"time"
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
