package app

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/delivery"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

var grantToken = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

type signerPolicy struct {
	codec  delivery.Ed25519Codec
	grants map[string]TrustedSignerConfig
	cell   string
}

// ValidateTrustedSignerGrant applies the same actor, scope, and key checks used
// by the controller and operator runtime before an offline role config is made.
func ValidateTrustedSignerGrant(grant TrustedSignerConfig) error {
	_, err := buildSignerPolicy(Config{Controller: ControllerConfig{TrustedSigners: []TrustedSignerConfig{grant}}})
	return err
}

func buildSignerPolicy(cfg Config) (signerPolicy, error) {
	if len(cfg.Controller.TrustedSigners) == 0 {
		return signerPolicy{}, errors.New("controller needs explicit trusted signers")
	}
	trusted := make(map[string]delivery.TrustedSigner, len(cfg.Controller.TrustedSigners))
	grants := make(map[string]TrustedSignerConfig, len(cfg.Controller.TrustedSigners))
	for _, grant := range cfg.Controller.TrustedSigners {
		if !grantToken.MatchString(grant.Actor) || len(grant.Roles) == 0 || len(grant.Environments) == 0 {
			return signerPolicy{}, errors.New("each signer requires an actor, roles, and environments")
		}
		if _, exists := grants[grant.Actor]; exists {
			return signerPolicy{}, fmt.Errorf("duplicate trusted signer actor %q", grant.Actor)
		}
		for _, values := range [][]string{grant.Roles, grant.Environments} {
			seen := make(map[string]struct{}, len(values))
			for _, value := range values {
				if !grantToken.MatchString(value) {
					return signerPolicy{}, fmt.Errorf("invalid signer grant token %q", value)
				}
				if _, exists := seen[value]; exists {
					return signerPolicy{}, fmt.Errorf("duplicate signer grant token %q", value)
				}
				seen[value] = struct{}{}
			}
		}
		if (grant.CanUpdateTerraBaseRuntime || grant.CanCertifyTerraBaseCompatibility) &&
			(!slices.Contains(grant.Roles, "terrabase") || !slices.Contains(grant.Environments, "production")) {
			return signerPolicy{}, fmt.Errorf("trusted signer %s needs terrabase and production grants for managed runtime updates", grant.Actor)
		}
		for _, repository := range grant.Repositories {
			if !strings.HasPrefix(repository, "https://") {
				return signerPolicy{}, fmt.Errorf("trusted signer %s has a non-HTTPS repository grant", grant.Actor)
			}
		}
		if grant.CanManageClientKeys != (len(grant.ClientKeyScopes) > 0) {
			return signerPolicy{}, fmt.Errorf("trusted signer %s needs explicit client-key scopes", grant.Actor)
		}
		seenClientScopes := make(map[string]bool, len(grant.ClientKeyScopes))
		for _, scope := range grant.ClientKeyScopes {
			database, partition, ok := strings.Cut(scope, ".")
			if !ok || !grantToken.MatchString(database) || !grantToken.MatchString(partition) ||
				seenClientScopes[scope] || !slices.Contains(grant.Roles, "terrabase") ||
				!slices.Contains(grant.Environments, "production") {
				return signerPolicy{}, fmt.Errorf("trusted signer %s has invalid client-key scope", grant.Actor)
			}
			seenClientScopes[scope] = true
		}
		public, err := decodePublicKey(grant.PublicKey)
		if err != nil {
			return signerPolicy{}, fmt.Errorf("trusted signer %s: %w", grant.Actor, err)
		}
		keyID, err := protocol.KeyID(public)
		if err != nil {
			return signerPolicy{}, err
		}
		if _, exists := trusted[keyID]; exists {
			return signerPolicy{}, fmt.Errorf("public key is bound to multiple actors")
		}
		trusted[keyID] = delivery.TrustedSigner{Actor: grant.Actor, PublicKey: public}
		grants[grant.Actor] = grant
	}
	return signerPolicy{
		codec: delivery.Ed25519Codec{Cell: cfg.NATS.Cell, Trusted: trusted,
			Lifetime: time.Minute, MaxLifetime: 5 * time.Minute, ClockSkew: 30 * time.Second},
		grants: grants, cell: cfg.NATS.Cell,
	}, nil
}

func (p signerPolicy) canManageClientKeys(actor, database, partition string) bool {
	grant, ok := p.grants[actor]
	return ok && grant.CanManageClientKeys &&
		slices.Contains(grant.ClientKeyScopes, database+"."+partition)
}

func (p signerPolicy) withOperator(cfg OperatorConfig) (delivery.Ed25519Codec, error) {
	grant, exists := p.grants[cfg.Actor]
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
	grant, exists := p.grants[actor]
	if !exists || intent.Cell != p.cell || !slices.Contains(grant.Roles, intent.Role) || !slices.Contains(grant.Environments, intent.Environment) || len(grant.Repositories) > 0 && !slices.Contains(grant.Repositories, intent.Source.Repository) {
		return delivery.ErrUnauthorized
	}
	return nil
}

func (p signerPolicy) authorizeArtifact(_ context.Context, actor string, record delivery.ArtifactRecord) error {
	grant, exists := p.grants[actor]
	if !exists || record.Cell != p.cell || !slices.Contains(grant.Roles, record.Role) || !slices.Contains(grant.Environments, record.Environment) || len(grant.Repositories) > 0 && !slices.Contains(grant.Repositories, record.Source.Repository) {
		return delivery.ErrUnauthorized
	}
	return nil
}
