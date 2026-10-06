// Package cellspec is a cell's signed desired state: the amendable sections
// of its configuration that running controllers adopt without a rebuild or a
// config edit. The signed controller config holds generation 0. Running
// controllers accept a later spec when it is signed for the exact
// deployment, cell and environment and its generation follows the current
// one, so unsigned specs, replays and rollbacks are refused.
//
// The release leaf, under a root delegation, signs ordinary amendments. An
// amendment that widens authority (AuthorityChanges) needs a root to sign
// the spec itself. Every amendment names the spec level it needs
// (requires_binary): a controller whose binary understands less refuses it
// gracefully and keeps the spec it has.
package cellspec

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"reflect"
	"regexp"
	"slices"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/terrabase"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/vaultsecret"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/workload"
)

const (
	Domain = "terrascale.controller.cell-spec"
	Schema = "terrascale.controller.cell-spec.v1"
	// BinaryLevel is the highest requires_binary this binary understands.
	// A change that adds a section raises it, and amendments that use the
	// section require the new level.
	// Level 2 adds profile secrets.
	BinaryLevel = 2
	// MaxDelegationLifetime bounds the root's grant to the release leaf; the
	// root re-issues it offline.
	MaxDelegationLifetime = 31 * 24 * time.Hour
	// MaxSpecLifetime bounds how long a signed spec may wait to be applied.
	// Once accepted it stays in force until a later generation replaces it.
	MaxSpecLifetime = 24 * time.Hour
	MaxSpecBytes    = 32 << 10
	MaxSignedBytes  = 48 << 10
	clockSkew       = time.Minute
	scopeRole       = "cell-spec"
	scopeSlot       = "spec"
)

var (
	ErrInvalid  = errors.New("cell spec is invalid")
	tokenRE     = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	hostRE      = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}[a-z0-9]$`)
	deploymentR = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

// NewerBinaryError refuses an amendment that needs a newer binary. It is
// expected while a binary rolls out: the controller keeps its current spec.
type NewerBinaryError struct {
	Generation     uint64
	RequiresBinary uint64
}

func (e *NewerBinaryError) Error() string {
	return fmt.Sprintf("cell spec generation %d requires binary level %d; this binary understands level %d",
		e.Generation, e.RequiresBinary, BinaryLevel)
}

// Profile is a role's signed delivery profile: the resources placement
// reserves and the arguments and environment every replica starts with.
// Secrets are environment settings the host reads from OCI Vault at each
// start; the profile holds only their names.
type Profile struct {
	Resources placement.Resources        `json:"resources"`
	Args      []string                   `json:"args,omitempty"`
	Env       map[string]string          `json:"env,omitempty"`
	Secrets   map[string]vaultsecret.Ref `json:"secrets,omitempty"`
}

// Service is one generic workload. Spec is set when the controller's
// workload reconciler owns the role; without it releases place the role.
// Releasers are actors, already trusted signers of the signed controller
// config, that may release the role and register its hosts in the spec's
// environment.
type Service struct {
	Role      string                `json:"role"`
	Profile   Profile               `json:"profile"`
	Spec      *workload.ServiceSpec `json:"spec,omitempty"`
	Releasers []string              `json:"releasers,omitempty"`
}

// HostGrant lets one static host outside TerraBase membership enroll: the
// host named Node, at PrivateIP, registers Roles in Environment, with one
// replica's resources per role. Controller VMs run their own ts-auth host
// agents this way.
type HostGrant struct {
	Node        string   `json:"node"`
	PrivateIP   string   `json:"private_ip"`
	Roles       []string `json:"roles"`
	Environment string   `json:"environment"`
}

// Identity is the deployment, cell and environment a controller accepts
// specs for. Production controllers take it from their image.
type Identity struct {
	DeploymentID string `json:"deployment_id"`
	Cell         string `json:"cell"`
	Environment  string `json:"environment"`
}

// Spec is the complete desired state of one cell at one generation. Its
// sections replace the cell's previous ones as a whole. Services are sorted
// by role.
type Spec struct {
	Schema string `json:"schema"`
	Identity
	Generation uint64 `json:"generation"`
	// RequiresBinary is the lowest spec level a controller binary must
	// understand to adopt this amendment.
	RequiresBinary uint64      `json:"requires_binary"`
	Services       []Service   `json:"services"`
	HostGrants     []HostGrant `json:"host_grants,omitempty"`
}

// Signed is what an operator applies and what controllers store, as exact
// canonical bytes: the spec envelope and, when the release leaf signed it,
// the root's delegation to the leaf. A spec without a delegation is signed
// by a root itself.
type Signed struct {
	Delegation jsontext.Value `json:"delegation,omitzero"`
	Spec       jsontext.Value `json:"spec"`
}

// Verified is a spec that passed verification and who signed it.
type Verified struct {
	Spec
	// RootSigned is set when a root signed the spec itself, which
	// authority-widening amendments need.
	RootSigned bool
}

func (id Identity) Validate() error {
	if !deploymentR.MatchString(id.DeploymentID) || !tokenRE.MatchString(id.Cell) || !tokenRE.MatchString(id.Environment) {
		return fmt.Errorf("%w: deployment, cell or environment", ErrInvalid)
	}
	return nil
}

// Scope is the exact signature scope of a spec for this identity.
func (id Identity) Scope() trust.Scope {
	return trust.Scope{Domain: Domain, DeploymentID: id.DeploymentID, Cell: id.Cell,
		Environment: id.Environment, Role: scopeRole, Slot: scopeSlot}
}

// Validate checks the spec's structure. Controllers also check every profile
// and service spec against the cell's own rules before they accept it.
func (s Spec) Validate() error {
	if s.Schema != Schema {
		return fmt.Errorf("%w: schema", ErrInvalid)
	}
	if err := s.Identity.Validate(); err != nil {
		return err
	}
	if s.RequiresBinary < s.Level() || s.RequiresBinary > BinaryLevel {
		return fmt.Errorf("%w: requires_binary must be between %d and %d", ErrInvalid, s.Level(), BinaryLevel)
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
	addresses := map[string]bool{}
	for index, grant := range s.HostGrants {
		address, err := netip.ParseAddr(grant.PrivateIP)
		if !hostRE.MatchString(grant.Node) || index > 0 && s.HostGrants[index-1].Node >= grant.Node ||
			err != nil || !address.Is4() || !address.IsPrivate() || address.String() != grant.PrivateIP ||
			addresses[grant.PrivateIP] || len(grant.Roles) == 0 || !tokenRE.MatchString(grant.Environment) {
			return fmt.Errorf("%w: host grants must be sorted by node with one private IPv4 address, roles and an environment each", ErrInvalid)
		}
		addresses[grant.PrivateIP] = true
		for i, role := range grant.Roles {
			if !tokenRE.MatchString(role) || i > 0 && grant.Roles[i-1] >= role {
				return fmt.Errorf("%w: host grant %q roles must be sorted without repeats", ErrInvalid, grant.Node)
			}
		}
	}
	return nil
}

// Grant returns the host grant of node.
func (s Spec) Grant(node string) (HostGrant, bool) {
	index := slices.IndexFunc(s.HostGrants, func(grant HostGrant) bool { return grant.Node == node })
	if index < 0 {
		return HostGrant{}, false
	}
	return s.HostGrants[index], true
}

// Level is the lowest requires_binary the spec's sections need: 2 once a
// profile names Vault secrets, which an older binary could not read.
func (s Spec) Level() uint64 {
	for _, service := range s.Services {
		if len(service.Profile.Secrets) != 0 {
			return 2
		}
	}
	return 1
}

// Find returns the service of role.
func (s Spec) Find(role string) (Service, bool) {
	for _, service := range s.Services {
		if service.Role == role {
			return service, true
		}
	}
	return Service{}, false
}

// Encode returns the canonical payload bytes of the spec.
func Encode(spec Spec) ([]byte, error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	encoded, err := trust.EncodePayload(spec)
	if err != nil {
		return nil, err
	}
	if len(encoded) > MaxSpecBytes {
		return nil, fmt.Errorf("%w: spec exceeds %d bytes", ErrInvalid, MaxSpecBytes)
	}
	return encoded, nil
}

// Decode strictly decodes canonical spec payload bytes. An amendment for a
// newer binary is refused with a NewerBinaryError before its sections are
// read; an unknown section is refused as invalid.
func Decode(encoded []byte) (Spec, error) {
	if len(encoded) > MaxSpecBytes {
		return Spec{}, fmt.Errorf("%w: spec exceeds %d bytes", ErrInvalid, MaxSpecBytes)
	}
	var header struct {
		Schema         string `json:"schema"`
		Generation     uint64 `json:"generation"`
		RequiresBinary uint64 `json:"requires_binary"`
	}
	if err := json.Unmarshal(encoded, &header); err == nil && header.Schema == Schema && header.RequiresBinary > BinaryLevel {
		return Spec{}, &NewerBinaryError{Generation: header.Generation, RequiresBinary: header.RequiresBinary}
	}
	var spec Spec
	if err := protocol.DecodeStrict(encoded, &spec, MaxSpecBytes); err != nil {
		return Spec{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	canonical, err := Encode(spec)
	if err != nil {
		return Spec{}, err
	}
	if !bytes.Equal(canonical, encoded) {
		return Spec{}, fmt.Errorf("%w: spec is not canonical JSON", ErrInvalid)
	}
	return spec, nil
}

// Candidate reads the spec of an unsigned candidate or of a signed file
// without verifying any signature, for review before apply.
func Candidate(data []byte) (Spec, error) {
	var signed Signed
	if protocol.DecodeStrict(data, &signed, MaxSignedBytes) != nil || len(signed.Spec) == 0 {
		return Decode(data)
	}
	envelope, err := trust.DecodeEnvelope(signed.Spec)
	if err != nil {
		return Spec{}, fmt.Errorf("signed spec envelope: %w", err)
	}
	return Decode(envelope.Payload)
}

// Digest is the SHA-256 of the spec's canonical payload.
func Digest(spec Spec) (string, error) {
	encoded, err := Encode(spec)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

// SignDelegation is the offline root operation: it lets leaf sign ordinary
// amendments for one identity.
func SignDelegation(leaf ed25519.PublicKey, id Identity, issuedAt, expiresAt time.Time,
	root ed25519.PrivateKey,
) (trust.Envelope, error) {
	if err := id.Validate(); err != nil {
		return trust.Envelope{}, err
	}
	if !expiresAt.After(issuedAt) || expiresAt.Sub(issuedAt) > MaxDelegationLifetime {
		return trust.Envelope{}, fmt.Errorf("cell spec delegation must expire within %s", MaxDelegationLifetime)
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

// Sign signs a spec of generation one or later and checks the result as a
// controller would, so a spec signed under a wrong or expired delegation, or
// by a key that is not a root, fails here instead of on the cell. With a
// delegation the signer is the release leaf; without one it is a root.
func Sign(spec Spec, delegationWire []byte, roots trust.Keyring, now time.Time, validFor time.Duration,
	signer ed25519.PrivateKey,
) ([]byte, error) {
	if spec.Generation == 0 {
		return nil, fmt.Errorf("%w: generation 0 is the signed controller config's spec", ErrInvalid)
	}
	if validFor <= 0 || validFor > MaxSpecLifetime {
		return nil, fmt.Errorf("cell spec validity must be positive and at most %s", MaxSpecLifetime)
	}
	payload, err := Encode(spec)
	if err != nil {
		return nil, err
	}
	issuedAt := now.Round(0).UTC().Truncate(time.Second)
	envelope, err := trust.Sign(payload, spec.Identity.Scope(), issuedAt, issuedAt.Add(validFor), signer)
	if err != nil {
		return nil, err
	}
	specWire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		return nil, err
	}
	wire, err := protocol.EncodeJSON(Signed{Delegation: bytes.Clone(delegationWire), Spec: specWire})
	if err != nil {
		return nil, err
	}
	if _, err := VerifyCurrent(wire, roots, spec.Identity, now); err != nil {
		return nil, err
	}
	return wire, nil
}

// VerifyCurrent is the controller's admission check: currently valid
// signatures for exactly id and a valid spec of generation one or later.
func VerifyCurrent(wire []byte, roots trust.Keyring, id Identity, now time.Time) (Verified, error) {
	return verify(wire, roots, id, &now)
}

// VerifyHistorical re-checks an accepted spec without expiry: a controller
// reloads it after the signatures' validity ended. Removing the root from
// the image still revokes it.
func VerifyHistorical(wire []byte, roots trust.Keyring, id Identity) (Verified, error) {
	return verify(wire, roots, id, nil)
}

func verify(wire []byte, roots trust.Keyring, id Identity, now *time.Time) (Verified, error) {
	if err := id.Validate(); err != nil {
		return Verified{}, err
	}
	var signed Signed
	if err := protocol.DecodeStrict(wire, &signed, MaxSignedBytes); err != nil {
		return Verified{}, fmt.Errorf("decode signed cell spec: %w", err)
	}
	// One signed spec has one wire form, so its digest names it.
	if canonical, err := protocol.EncodeJSON(signed); err != nil || !bytes.Equal(canonical, wire) {
		return Verified{}, fmt.Errorf("%w: signed cell spec is not canonical JSON", ErrInvalid)
	}
	specEnvelope, err := trust.DecodeEnvelope(signed.Spec)
	if err != nil {
		return Verified{}, fmt.Errorf("cell spec envelope: %w", err)
	}
	specPolicy := trust.Policy{MaxLifetime: MaxSpecLifetime, ClockSkew: clockSkew}
	var payload []byte
	rootSigned := len(signed.Delegation) == 0
	switch {
	case rootSigned && now != nil:
		payload, err = trust.VerifyCurrent(specEnvelope, id.Scope(), roots, *now, specPolicy)
	case rootSigned:
		payload, err = trust.VerifyHistorical(specEnvelope, id.Scope(), roots, specPolicy)
	default:
		payload, err = verifyDelegated(signed.Delegation, specEnvelope, roots, id, now, specPolicy)
	}
	if err != nil {
		return Verified{}, fmt.Errorf("verify cell spec signature: %w", err)
	}
	spec, err := Decode(payload)
	if err != nil {
		return Verified{}, err
	}
	if spec.Identity != id || spec.Generation == 0 {
		return Verified{}, fmt.Errorf("%w: signed spec names another identity or generation 0", ErrInvalid)
	}
	return Verified{Spec: spec, RootSigned: rootSigned}, nil
}

func verifyDelegated(delegationWire []byte, specEnvelope trust.Envelope, roots trust.Keyring, id Identity,
	now *time.Time, specPolicy trust.Policy,
) ([]byte, error) {
	delegationEnvelope, err := trust.DecodeEnvelope(delegationWire)
	if err != nil {
		return nil, fmt.Errorf("delegation: %w", err)
	}
	delegationPolicy := trust.Policy{MaxLifetime: MaxDelegationLifetime, ClockSkew: clockSkew}
	if now != nil {
		delegation, err := trust.VerifyDelegationCurrent(delegationEnvelope, roots, *now, delegationPolicy)
		if err != nil {
			return nil, fmt.Errorf("delegation: %w", err)
		}
		return trust.VerifyDelegatedCurrent(specEnvelope, id.Scope(), delegation, *now, specPolicy)
	}
	delegation, err := trust.VerifyDelegationHistorical(delegationEnvelope, roots, delegationPolicy)
	if err != nil {
		return nil, fmt.Errorf("delegation: %w", err)
	}
	return trust.VerifyDelegatedHistorical(specEnvelope, id.Scope(), delegation, specPolicy)
}

// AuthorityChanges lists what next widens relative to current; a non-empty
// list needs a root's signature. signed holds the signed controller config's
// profiles, which a role without a service entry keeps. Widening is:
//
//   - a releaser a service did not have, since releasers may release the
//     role and register its hosts;
//   - a new or changed Vault secret ref, since the host reads that secret
//     for the role with an identity that may read more;
//   - a new or changed host grant, since the host receives credentials;
//   - any change to TerraBase's profile (resources, arguments or a setting),
//     which binds membership, listeners, member certificates and the
//     credentials and token issuers TerraBase trusts.
//
// Everything else is an ordinary change.
func AuthorityChanges(current, next Spec, signed map[string]Profile) []string {
	var changes []string
	for _, service := range next.Services {
		before, _ := current.Find(service.Role)
		for _, actor := range service.Releasers {
			if !slices.Contains(before.Releasers, actor) {
				changes = append(changes, fmt.Sprintf("service %s releaser %s", service.Role, actor))
			}
		}
		for key, ref := range service.Profile.Secrets {
			if before.Profile.Secrets[key] != ref {
				changes = append(changes, fmt.Sprintf("service %s Vault secrets", service.Role))
				break
			}
		}
	}
	for _, grant := range next.HostGrants {
		if before, ok := current.Grant(grant.Node); !ok || !reflect.DeepEqual(before, grant) {
			changes = append(changes, "host grant "+grant.Node)
		}
	}
	effective := func(spec Spec) Profile {
		if service, ok := spec.Find(terrabase.Role); ok {
			return service.Profile
		}
		return signed[terrabase.Role]
	}
	before, after := effective(current), effective(next)
	if before.Resources != after.Resources {
		changes = append(changes, "terrabase resources")
	}
	if !slices.Equal(before.Args, after.Args) {
		changes = append(changes, "terrabase args")
	}
	keys := slices.Sorted(maps.Keys(before.Env))
	for key := range after.Env {
		if _, found := before.Env[key]; !found {
			keys = append(keys, key)
		}
	}
	slices.Sort(keys)
	for _, key := range keys {
		old, hadOld := before.Env[key]
		value, hasValue := after.Env[key]
		if hadOld != hasValue || old != value {
			changes = append(changes, "terrabase setting "+key)
		}
	}
	return changes
}

// Plan is the change from one spec to the next, for review before signing.
type Plan struct {
	Identity
	From           uint64   `json:"from_generation"`
	To             uint64   `json:"to_generation"`
	RequiresBinary uint64   `json:"requires_binary"`
	Added          []string `json:"added,omitempty"`
	Updated        []string `json:"updated,omitempty"`
	Removed        []string `json:"removed,omitempty"`
	// HostGrants names each node whose host grant is added, changed or
	// removed.
	HostGrants []string `json:"host_grants,omitempty"`
	// RootRequired lists the authority-widening changes; the amendment
	// applies only when a root signed it.
	RootRequired []string `json:"root_required,omitempty"`
}

// Diff lists the services next adds, changes and removes relative to
// current and what it widens.
func Diff(current, next Spec, signed map[string]Profile) (Plan, error) {
	plan := Plan{Identity: next.Identity, From: current.Generation, To: next.Generation,
		RequiresBinary: next.RequiresBinary, RootRequired: AuthorityChanges(current, next, signed)}
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
	nodes := map[string]bool{}
	for _, grants := range [][]HostGrant{current.HostGrants, next.HostGrants} {
		for _, grant := range grants {
			nodes[grant.Node] = true
		}
	}
	for _, node := range slices.Sorted(maps.Keys(nodes)) {
		before, _ := current.Grant(node)
		after, _ := next.Grant(node)
		if !reflect.DeepEqual(before, after) {
			plan.HostGrants = append(plan.HostGrants, node)
		}
	}
	return plan, nil
}

// Empty reports whether the plan changes nothing.
func (p Plan) Empty() bool {
	return len(p.Added)+len(p.Updated)+len(p.Removed)+len(p.HostGrants) == 0
}
