// Package serviceset is a cell's amendable set of generic services: each
// service's delivery profile and, for a reconciled stateless service, its
// spec. The signed controller config holds the initial set (generation 0).
// Running controllers accept a later set when the release leaf signed it
// under a root delegation for the exact deployment, cell and environment
// (the trust chain of releases) and its generation follows the current one,
// so unsigned sets, replays and rollbacks are refused.
package serviceset

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"regexp"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/workload"
)

const (
	Domain = "terrascale.controller.service-set"
	Schema = "terrascale.controller.service-set.v1"
	// MaxDelegationLifetime bounds the root's grant to the release leaf; the
	// root re-issues it offline.
	MaxDelegationLifetime = 31 * 24 * time.Hour
	// MaxSetLifetime bounds how long a signed set may wait to be applied.
	// Once accepted it stays in force until a later generation replaces it.
	MaxSetLifetime = 24 * time.Hour
	MaxSetBytes    = 32 << 10
	MaxSignedBytes = 48 << 10
	clockSkew      = time.Minute
	scopeRole      = "service-set"
	scopeSlot      = "services"
)

var (
	ErrInvalid  = errors.New("service set is invalid")
	tokenRE     = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	deploymentR = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

// Profile is a role's signed delivery profile: the resources placement
// reserves and the arguments and environment every replica starts with.
type Profile struct {
	Resources placement.Resources `json:"resources"`
	Args      []string            `json:"args,omitempty"`
	Env       map[string]string   `json:"env,omitempty"`
}

// Service is one generic workload. Spec is set when the controller's
// workload reconciler owns the role; without it releases place the role.
// Releasers are actors, already trusted signers of the signed controller
// config, that may release the role and register its hosts in the set's
// environment.
type Service struct {
	Role      string                `json:"role"`
	Profile   Profile               `json:"profile"`
	Spec      *workload.ServiceSpec `json:"spec,omitempty"`
	Releasers []string              `json:"releasers,omitempty"`
}

// Identity is the deployment, cell and environment a controller accepts
// service sets for. Production controllers take it from their image.
type Identity struct {
	DeploymentID string `json:"deployment_id"`
	Cell         string `json:"cell"`
	Environment  string `json:"environment"`
}

// Set is the complete service list of one cell at one generation, sorted
// by role.
type Set struct {
	Schema string `json:"schema"`
	Identity
	Generation uint64    `json:"generation"`
	Services   []Service `json:"services"`
}

// Signed is what an operator applies and what controllers store: the
// root-signed delegation and the set envelope its leaf signed, as exact
// canonical bytes.
type Signed struct {
	Delegation jsontext.Value `json:"delegation"`
	Set        jsontext.Value `json:"set"`
}

func (id Identity) Validate() error {
	if !deploymentR.MatchString(id.DeploymentID) || !tokenRE.MatchString(id.Cell) || !tokenRE.MatchString(id.Environment) {
		return fmt.Errorf("%w: deployment, cell or environment", ErrInvalid)
	}
	return nil
}

// Scope is the exact signature scope of a set for this identity.
func (id Identity) Scope() trust.Scope {
	return trust.Scope{Domain: Domain, DeploymentID: id.DeploymentID, Cell: id.Cell,
		Environment: id.Environment, Role: scopeRole, Slot: scopeSlot}
}

// Validate checks the set's structure. Controllers also check every profile
// and spec against the cell's own rules before they accept it.
func (s Set) Validate() error {
	if s.Schema != Schema {
		return fmt.Errorf("%w: schema", ErrInvalid)
	}
	if err := s.Identity.Validate(); err != nil {
		return err
	}
	for index, service := range s.Services {
		if !tokenRE.MatchString(service.Role) {
			return fmt.Errorf("%w: role %q", ErrInvalid, service.Role)
		}
		if index > 0 && s.Services[index-1].Role >= service.Role {
			return fmt.Errorf("%w: services must be sorted by role without repeats", ErrInvalid)
		}
		for i, actor := range service.Releasers {
			if !tokenRE.MatchString(actor) || i > 0 && service.Releasers[i-1] >= actor {
				return fmt.Errorf("%w: service %q releasers must be sorted actor names without repeats", ErrInvalid, service.Role)
			}
		}
		if service.Spec != nil {
			if service.Spec.Role != service.Role {
				return fmt.Errorf("%w: service %q has a spec for role %q", ErrInvalid, service.Role, service.Spec.Role)
			}
			if err := service.Spec.Validate(); err != nil {
				return fmt.Errorf("service %q: %w", service.Role, err)
			}
		}
	}
	return nil
}

// Find returns the service of role.
func (s Set) Find(role string) (Service, bool) {
	for _, service := range s.Services {
		if service.Role == role {
			return service, true
		}
	}
	return Service{}, false
}

// Encode returns the canonical payload bytes of the set.
func Encode(set Set) ([]byte, error) {
	if err := set.Validate(); err != nil {
		return nil, err
	}
	encoded, err := trust.EncodePayload(set)
	if err != nil {
		return nil, err
	}
	if len(encoded) > MaxSetBytes {
		return nil, fmt.Errorf("%w: set exceeds %d bytes", ErrInvalid, MaxSetBytes)
	}
	return encoded, nil
}

// Decode strictly decodes canonical set payload bytes.
func Decode(encoded []byte) (Set, error) {
	var set Set
	if err := protocol.DecodeStrict(encoded, &set, MaxSetBytes); err != nil {
		return Set{}, fmt.Errorf("decode service set: %w", err)
	}
	canonical, err := Encode(set)
	if err != nil {
		return Set{}, err
	}
	if !bytes.Equal(canonical, encoded) {
		return Set{}, fmt.Errorf("%w: set is not canonical JSON", ErrInvalid)
	}
	return set, nil
}

// Digest is the SHA-256 of the set's canonical payload.
func Digest(set Set) (string, error) {
	encoded, err := Encode(set)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

// SignDelegation is the offline root operation: it lets leaf sign service
// sets for one identity.
func SignDelegation(leaf ed25519.PublicKey, id Identity, issuedAt, expiresAt time.Time,
	root ed25519.PrivateKey,
) (trust.Envelope, error) {
	if err := id.Validate(); err != nil {
		return trust.Envelope{}, err
	}
	if !expiresAt.After(issuedAt) || expiresAt.Sub(issuedAt) > MaxDelegationLifetime {
		return trust.Envelope{}, fmt.Errorf("service set delegation must expire within %s", MaxDelegationLifetime)
	}
	keyID, err := trust.KeyID(leaf)
	if err != nil {
		return trust.Envelope{}, err
	}
	encoded, err := trust.EncodeDelegatedPublicKey(leaf)
	if err != nil {
		return trust.Envelope{}, err
	}
	scope := id.Scope()
	return trust.SignDelegation(trust.Delegation{SchemaVersion: trust.SchemaVersion, SubjectKeyID: keyID,
		SubjectPublicKey: encoded, Capabilities: []trust.Capability{{Domain: scope.Domain,
			DeploymentID: scope.DeploymentID, Cell: scope.Cell, Environment: scope.Environment,
			Role: scope.Role, Slots: []string{scope.Slot}, Actions: []string{"sign"}}}}, issuedAt, expiresAt, root)
}

// Sign is the leaf operation. It signs a set of generation one or later and
// checks the result as a controller would, so a set signed under a wrong or
// expired delegation fails here instead of on the cell.
func Sign(set Set, delegationWire []byte, roots trust.Keyring, now time.Time, validFor time.Duration,
	leaf ed25519.PrivateKey,
) ([]byte, error) {
	if set.Generation == 0 {
		return nil, fmt.Errorf("%w: generation 0 is the signed controller config's set", ErrInvalid)
	}
	if validFor <= 0 || validFor > MaxSetLifetime {
		return nil, fmt.Errorf("service set validity must be positive and at most %s", MaxSetLifetime)
	}
	payload, err := Encode(set)
	if err != nil {
		return nil, err
	}
	issuedAt := now.Round(0).UTC().Truncate(time.Second)
	envelope, err := trust.Sign(payload, set.Identity.Scope(), issuedAt, issuedAt.Add(validFor), leaf)
	if err != nil {
		return nil, err
	}
	setWire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		return nil, err
	}
	wire, err := protocol.EncodeJSON(Signed{Delegation: bytes.Clone(delegationWire), Set: setWire})
	if err != nil {
		return nil, err
	}
	if _, err := VerifyCurrent(wire, roots, set.Identity, now); err != nil {
		return nil, err
	}
	return wire, nil
}

// VerifyCurrent is the controller's admission check: a currently valid root
// delegation, a currently valid leaf signature for exactly id, and a valid
// set of generation one or later.
func VerifyCurrent(wire []byte, roots trust.Keyring, id Identity, now time.Time) (Set, error) {
	return verify(wire, roots, id, &now)
}

// VerifyHistorical re-checks an accepted set without expiry: a controller
// reloads it after the signatures' validity ended. Removing the root from
// the image still revokes it.
func VerifyHistorical(wire []byte, roots trust.Keyring, id Identity) (Set, error) {
	return verify(wire, roots, id, nil)
}

func verify(wire []byte, roots trust.Keyring, id Identity, now *time.Time) (Set, error) {
	if err := id.Validate(); err != nil {
		return Set{}, err
	}
	var signed Signed
	if err := protocol.DecodeStrict(wire, &signed, MaxSignedBytes); err != nil {
		return Set{}, fmt.Errorf("decode signed service set: %w", err)
	}
	// One signed set has one wire form, so its digest names it.
	if canonical, err := protocol.EncodeJSON(signed); err != nil || !bytes.Equal(canonical, wire) {
		return Set{}, fmt.Errorf("%w: signed service set is not canonical JSON", ErrInvalid)
	}
	delegationEnvelope, err := trust.DecodeEnvelope(signed.Delegation)
	if err != nil {
		return Set{}, fmt.Errorf("service set delegation: %w", err)
	}
	setEnvelope, err := trust.DecodeEnvelope(signed.Set)
	if err != nil {
		return Set{}, fmt.Errorf("service set envelope: %w", err)
	}
	delegationPolicy := trust.Policy{MaxLifetime: MaxDelegationLifetime, ClockSkew: clockSkew}
	setPolicy := trust.Policy{MaxLifetime: MaxSetLifetime, ClockSkew: clockSkew}
	var payload []byte
	if now != nil {
		delegation, err := trust.VerifyDelegationCurrent(delegationEnvelope, roots, *now, delegationPolicy)
		if err != nil {
			return Set{}, fmt.Errorf("verify service set delegation: %w", err)
		}
		payload, err = trust.VerifyDelegatedCurrent(setEnvelope, id.Scope(), delegation, *now, setPolicy)
		if err != nil {
			return Set{}, fmt.Errorf("verify service set signature: %w", err)
		}
	} else {
		delegation, err := trust.VerifyDelegationHistorical(delegationEnvelope, roots, delegationPolicy)
		if err != nil {
			return Set{}, fmt.Errorf("verify service set delegation: %w", err)
		}
		payload, err = trust.VerifyDelegatedHistorical(setEnvelope, id.Scope(), delegation, setPolicy)
		if err != nil {
			return Set{}, fmt.Errorf("verify service set signature: %w", err)
		}
	}
	set, err := Decode(payload)
	if err != nil {
		return Set{}, err
	}
	if set.Identity != id || set.Generation == 0 {
		return Set{}, fmt.Errorf("%w: signed set names another identity or generation 0", ErrInvalid)
	}
	return set, nil
}

// Plan is the change from one set to the next, for review before signing.
type Plan struct {
	Identity
	From    uint64   `json:"from_generation"`
	To      uint64   `json:"to_generation"`
	Added   []string `json:"added,omitempty"`
	Updated []string `json:"updated,omitempty"`
	Removed []string `json:"removed,omitempty"`
}

// Diff lists the roles next adds, changes and removes relative to current.
func Diff(current, next Set) (Plan, error) {
	plan := Plan{Identity: next.Identity, From: current.Generation, To: next.Generation}
	for _, service := range next.Services {
		previous, exists := current.Find(service.Role)
		if !exists {
			plan.Added = append(plan.Added, service.Role)
			continue
		}
		before, err := protocol.EncodeJSON(previous)
		if err != nil {
			return Plan{}, err
		}
		after, err := protocol.EncodeJSON(service)
		if err != nil {
			return Plan{}, err
		}
		if !bytes.Equal(before, after) {
			plan.Updated = append(plan.Updated, service.Role)
		}
	}
	for _, service := range current.Services {
		if _, exists := next.Find(service.Role); !exists {
			plan.Removed = append(plan.Removed, service.Role)
		}
	}
	return plan, nil
}

// Empty reports whether the plan changes nothing.
func (p Plan) Empty() bool { return len(p.Added)+len(p.Updated)+len(p.Removed) == 0 }
