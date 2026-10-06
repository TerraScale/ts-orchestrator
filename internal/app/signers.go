package app

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/delivery"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

var grantToken = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

type signerPolicy struct {
	// codec finds signers in the current set (its Lookup).
	codec delivery.Ed25519Codec
	// signers is the current set. A controller replaces it when the cell
	// spec changes the signers, and every check reads it.
	signers *atomic.Pointer[signerSet]
	cell    string
	// services adds the release grants of the cell's adopted spec.
	services *specRegistry
	// rollouts answers the operator's rollout requests.
	rollouts *rolloutControl
}

// ValidateTrustedSignerGrant applies the same actor, scope, and key checks used
// by the controller and operator runtime before an offline role config is made.
func ValidateTrustedSignerGrant(grant TrustedSignerConfig) error {
	_, err := buildSignerPolicy(Config{Controller: ControllerConfig{TrustedSigners: []TrustedSignerConfig{grant}}})
	return err
}

// signerSet is one immutable set of trusted signers, by key ID and by actor.
type signerSet struct {
	trusted map[string]delivery.TrustedSigner
	grants  map[string]TrustedSignerConfig
}

func buildSignerPolicy(cfg Config) (signerPolicy, error) {
	set, err := newSignerSet(cfg.Controller.TrustedSigners)
	if err != nil {
		return signerPolicy{}, err
	}
	signers := &atomic.Pointer[signerSet]{}
	signers.Store(&set)
	return signerPolicy{
		codec: delivery.Ed25519Codec{Cell: cfg.NATS.Cell, Lifetime: time.Minute, MaxLifetime: 5 * time.Minute,
			ClockSkew: 30 * time.Second, Lookup: func(keyID string) (delivery.TrustedSigner, bool) {
				trusted, ok := signers.Load().trusted[keyID]
				return trusted, ok
			}},
		signers: signers, cell: cfg.NATS.Cell,
	}, nil
}

// trusted returns the current signer of keyID.
func (p signerPolicy) trusted(keyID string) (delivery.TrustedSigner, bool) {
	return p.codec.Lookup(keyID)
}

// grant returns actor's current grant.
func (p signerPolicy) grant(actor string) (TrustedSignerConfig, bool) {
	grant, ok := p.signers.Load().grants[actor]
	return grant, ok
}

// replaceSigners validates grants and makes them the current set. A request
// verified under the previous set finishes; every later check reads the
// new one.
func (p signerPolicy) replaceSigners(grants []TrustedSignerConfig) error {
	set, err := newSignerSet(grants)
	if err != nil {
		return err
	}
	p.signers.Store(&set)
	return nil
}

func newSignerSet(signers []TrustedSignerConfig) (signerSet, error) {
	if len(signers) == 0 {
		return signerSet{}, errors.New("controller needs explicit trusted signers")
	}
	trusted := make(map[string]delivery.TrustedSigner, len(signers))
	grants := make(map[string]TrustedSignerConfig, len(signers))
	for _, grant := range signers {
		if !grantToken.MatchString(grant.Actor) || len(grant.Roles) == 0 || len(grant.Environments) == 0 {
			return signerSet{}, errors.New("each signer requires an actor, roles, and environments")
		}
		if _, exists := grants[grant.Actor]; exists {
			return signerSet{}, fmt.Errorf("duplicate trusted signer actor %q", grant.Actor)
		}
		for _, values := range [][]string{grant.Roles, grant.Environments} {
			seen := make(map[string]struct{}, len(values))
			for _, value := range values {
				if !grantToken.MatchString(value) {
					return signerSet{}, fmt.Errorf("invalid signer grant token %q", value)
				}
				if _, exists := seen[value]; exists {
					return signerSet{}, fmt.Errorf("duplicate signer grant token %q", value)
				}
				seen[value] = struct{}{}
			}
		}
		if (grant.CanUpdateTerraBaseRuntime || grant.CanCertifyTerraBaseCompatibility) &&
			(!slices.Contains(grant.Roles, "terrabase") || !slices.Contains(grant.Environments, "production")) {
			return signerSet{}, fmt.Errorf("trusted signer %s needs terrabase and production grants for managed runtime updates", grant.Actor)
		}
		for _, repository := range grant.Repositories {
			if !strings.HasPrefix(repository, "https://") {
				return signerSet{}, fmt.Errorf("trusted signer %s has a non-HTTPS repository grant", grant.Actor)
			}
		}
		if grant.CanManageClientKeys != (len(grant.ClientKeyScopes) > 0) {
			return signerSet{}, fmt.Errorf("trusted signer %s needs explicit client-key scopes", grant.Actor)
		}
		seenClientScopes := make(map[string]bool, len(grant.ClientKeyScopes))
		for _, scope := range grant.ClientKeyScopes {
			database, partition, ok := strings.Cut(scope, ".")
			if !ok || !grantToken.MatchString(database) || !grantToken.MatchString(partition) ||
				seenClientScopes[scope] || !slices.Contains(grant.Roles, "terrabase") ||
				!slices.Contains(grant.Environments, "production") {
				return signerSet{}, fmt.Errorf("trusted signer %s has invalid client-key scope", grant.Actor)
			}
			seenClientScopes[scope] = true
		}
		public, err := decodePublicKey(grant.PublicKey)
		if err != nil {
			return signerSet{}, fmt.Errorf("trusted signer %s: %w", grant.Actor, err)
		}
		keyID, err := protocol.KeyID(public)
		if err != nil {
			return signerSet{}, err
		}
		if _, exists := trusted[keyID]; exists {
			return signerSet{}, fmt.Errorf("public key is bound to multiple actors")
		}
		trusted[keyID] = delivery.TrustedSigner{Actor: grant.Actor, PublicKey: public}
		grants[grant.Actor] = grant
	}
	return signerSet{trusted: trusted, grants: grants}, nil
}

func (p signerPolicy) canManageClientKeys(actor, database, partition string) bool {
	grant, ok := p.grant(actor)
	return ok && grant.CanManageClientKeys &&
		slices.Contains(grant.ClientKeyScopes, database+"."+partition)
}

func (p signerPolicy) withOperator(cfg OperatorConfig) (delivery.Ed25519Codec, error) {
	grant, exists := p.grant(cfg.Actor)
	if !exists {
		return delivery.Ed25519Codec{}, errors.New("operator actor is not trusted")
	}
	private, err := readPrivateKey(cfg.SigningKeyFile)
	if err != nil {
		return delivery.Ed25519Codec{}, err
	}
	public, err := decodePublicKey(grant.PublicKey)
	if err != nil {
		return delivery.Ed25519Codec{}, err
	}
	if !ed25519.PublicKey(private.Public().(ed25519.PublicKey)).Equal(public) {
		return delivery.Ed25519Codec{}, errors.New("operator signing key does not match trusted actor")
	}
	codec := p.codec
	codec.Actor = cfg.Actor
	codec.PrivateKey = private
	return codec, nil
}

func (p signerPolicy) authorizeIntent(_ context.Context, actor string, intent delivery.Intent) error {
	if intent.Cell != p.cell || !p.mayRelease(actor, intent.Role, intent.Environment, intent.Source.Repository) {
		return delivery.ErrUnauthorized
	}
	return nil
}

func (p signerPolicy) authorizeArtifact(_ context.Context, actor string, record delivery.ArtifactRecord) error {
	if record.Cell != p.cell || !p.mayRelease(actor, record.Role, record.Environment, record.Source.Repository) {
		return delivery.ErrUnauthorized
	}
	return nil
}

// mayRelease applies the signer's grant, or a releaser entry of the cell
// spec, within the signer's repository grant.
func (p signerPolicy) mayRelease(actor, role, environment, repository string) bool {
	grant, exists := p.grant(actor)
	if !exists || len(grant.Repositories) > 0 && !slices.Contains(grant.Repositories, repository) {
		return false
	}
	return slices.Contains(grant.Roles, role) && slices.Contains(grant.Environments, environment) ||
		p.services.releaser(actor, role, environment)
}
