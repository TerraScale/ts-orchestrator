// Package keyrotation contains the production composition boundary for the
// D-70 capability-key rotation.  The rotation state machine lives in
// security; this package only resolves the authorities that are allowed to
// cross that boundary.
package keyrotation

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/cloudflare"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

// Config is the production dependency graph.  All provider and authority
// seams are intentionally explicit: a missing seam must stop startup rather
// than cause the composition root to manufacture a key or a proof.
type Config struct {
	Issuer       security.IdentityIssuer
	Vault        security.CapabilityVault
	Members      security.MemberGateway
	Secrets      security.SecretsStore
	Publisher    security.AtomicPublisher
	Reloader     security.Reloader
	State        security.StateStore
	Audit        security.AuditSink
	Regions      []string
	Clock        func() time.Time
	ExpirySafety time.Duration
}

// NewProduction is the one parent wiring hook. It validates that all
// authority/provider seams are present and then delegates to the tested,
// durable security coordinator. No key material is accepted in Config.
func NewProduction(config Config) (*security.Coordinator, error) {
	if isNil(config.Issuer) {
		return nil, configurationError("identity authority is missing")
	}
	if isNil(config.Vault) {
		return nil, configurationError("capability authority is missing")
	}
	if isNil(config.Secrets) {
		return nil, configurationError("Cloudflare Secrets Store authority is missing")
	}
	if isNil(config.Members) {
		return nil, configurationError("member authority is missing")
	}
	if isNil(config.Reloader) {
		return nil, configurationError("member reloader authority is missing")
	}
	if isNil(config.State) {
		return nil, configurationError("durable rotation state store is missing")
	}
	if err := validateRegions(config.Regions); err != nil {
		return nil, configurationError("rotation regions are invalid")
	}
	publisher := config.Publisher
	if isNil(publisher) {
		publisher = nil
	}
	audit := config.Audit
	if isNil(audit) {
		audit = nil
	}
	clock := config.Clock
	if isNil(clock) {
		clock = nil
	}
	return security.NewCoordinator(security.Config{
		Issuer: config.Issuer, Vault: config.Vault, Members: config.Members, Secrets: config.Secrets,
		Publisher: publisher, Reloader: config.Reloader, State: config.State,
		Audit: audit, Regions: append([]string(nil), config.Regions...),
		Clock: clock, ExpirySafety: config.ExpirySafety,
	})
}

func isNil(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}

func validateRegions(regions []string) error {
	if len(regions) == 0 {
		return errors.New("missing")
	}
	seen := make(map[string]struct{}, len(regions))
	for _, region := range regions {
		if strings.TrimSpace(region) != region || region == "" || len(region) > 64 {
			return errors.New("invalid")
		}
		if _, exists := seen[region]; exists {
			return errors.New("duplicate")
		}
		seen[region] = struct{}{}
	}
	return nil
}

func configurationError(message string) error {
	// Keep startup errors bounded and free of provider details, credentials, or
	// arbitrary environment values.
	return errors.New("key rotation: configuration invalid: " + message)
}

// CloudflareCapabilityObserver is the authority that proves the generation
// currently accepted by the Snippet/Secrets Store. A list of secret metadata
// is not sufficient: Cloudflare metadata has no TerraScale generation.
type CloudflareCapabilityObserver interface {
	VerifyCapability(context.Context, uint64, string, string) (security.ConsumerObservation, error)
}

// CloudflareCapabilityFencer is separate from observation because fencing is
// required for failed or ambiguous transitions as well as normal rotation.
type CloudflareCapabilityFencer interface {
	FenceCapability(context.Context, string) error
}

// CloudflareSecretsConfig binds the existing Cloudflare value API to the
// security.SecretsStore seam. CurrentName and PreviousName are explicit so a
// caller cannot silently widen the key ring by deriving names from a secret.
// Observer and Fencer are mandatory production authorities.
type CloudflareSecretsConfig struct {
	Values       cloudflare.SecretValueAPI
	Store        string
	CurrentName  string
	PreviousName string
	Observer     CloudflareCapabilityObserver
	Fencer       CloudflareCapabilityFencer
}

// CloudflareSecretsStore stages and activates exactly one current+previous
// key ring. It keeps only provider version identifiers in memory; key bytes
// are borrowed for the duration of Distribute and are never retained.
type CloudflareSecretsStore struct {
	values       cloudflare.SecretValueAPI
	store        string
	currentName  string
	previousName string
	observer     CloudflareCapabilityObserver
	fencer       CloudflareCapabilityFencer

	mu     sync.Mutex
	staged map[uint64]cloudflareSecretVersions
}

type cloudflareSecretVersions struct {
	current      int
	previous     int
	operationKey string
}

// NewCloudflareSecretsStore requires the observer and fencer explicitly. A
// missing authority is a startup error, never an invitation to synthesize a
// successful generation observation.
func NewCloudflareSecretsStore(config CloudflareSecretsConfig) (*CloudflareSecretsStore, error) {
	if isNil(config.Values) || isNil(config.Observer) || isNil(config.Fencer) {
		return nil, configurationError("Cloudflare values, observer, and fencer are required")
	}
	if !validCoordinate(config.Store) || !validCoordinate(config.CurrentName) || !validCoordinate(config.PreviousName) {
		return nil, configurationError("Cloudflare Secrets Store coordinates are required")
	}
	if config.CurrentName == config.PreviousName {
		return nil, configurationError("Cloudflare current and previous secret names must differ")
	}
	return &CloudflareSecretsStore{
		values: config.Values, store: config.Store, currentName: config.CurrentName,
		previousName: config.PreviousName, observer: config.Observer, fencer: config.Fencer,
		staged: make(map[uint64]cloudflareSecretVersions),
	}, nil
}

func validCoordinate(value string) bool {
	return value != "" && len(value) <= 128 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n")
}

var _ security.SecretsStore = (*CloudflareSecretsStore)(nil)

func (s *CloudflareSecretsStore) Distribute(ctx context.Context, credentials security.CredentialSet, operationKey string) error {
	if s == nil || isNil(s.values) {
		return errors.New("key rotation: Cloudflare Secrets Store unavailable")
	}
	if ctx == nil {
		return errors.New("key rotation: context is required")
	}
	if !validOperationKey(operationKey) {
		return errors.New("key rotation: operation key is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateCapability(credentials.Capability); err != nil {
		return err
	}
	if err := validatePrevious(credentials.Capability, credentials.PreviousCapability); err != nil {
		return err
	}
	generation := credentials.Capability.Version
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.staged[generation]; ok {
		// A resumed operation must not write a second provider version.
		if existing.current > 0 && (existing.previous > 0 || len(credentials.PreviousCapability.Key) == 0) {
			if existing.operationKey != operationKey {
				return errors.New("key rotation: conflicting Cloudflare operation")
			}
			return nil
		}
	}

	current, err := s.values.WriteSecretValue(ctx, s.store, s.currentName, credentials.Capability.Key)
	if err != nil || current.Version <= 0 || current.Name != "" && current.Name != s.currentName {
		return errors.New("key rotation: Cloudflare current secret staging failed")
	}
	versions := cloudflareSecretVersions{current: current.Version, operationKey: operationKey}
	if len(credentials.PreviousCapability.Key) != 0 {
		previous, previousErr := s.values.WriteSecretValue(ctx, s.store, s.previousName, credentials.PreviousCapability.Key)
		if previousErr != nil || previous.Version <= 0 || previous.Name != "" && previous.Name != s.previousName {
			_ = s.values.RetireSecretVersion(ctx, s.store, s.currentName, current.Version)
			return errors.New("key rotation: Cloudflare previous secret staging failed")
		}
		versions.previous = previous.Version
	}
	s.staged[generation] = versions
	return nil
}

func (s *CloudflareSecretsStore) Verify(ctx context.Context, generation uint64) (security.ConsumerObservation, error) {
	if s == nil || isNil(s.observer) {
		return security.ConsumerObservation{}, errors.New("key rotation: Cloudflare generation authority unavailable")
	}
	if ctx == nil {
		return security.ConsumerObservation{}, errors.New("key rotation: context is required")
	}
	if generation == 0 {
		return security.ConsumerObservation{}, errors.New("key rotation: Cloudflare generation verification failed")
	}
	observation, err := s.observer.VerifyCapability(ctx, generation, s.currentName, s.previousName)
	if err != nil || observation.Generation != generation {
		return security.ConsumerObservation{}, errors.New("key rotation: Cloudflare generation verification failed")
	}
	return observation, nil
}

func (s *CloudflareSecretsStore) Activate(ctx context.Context, generation uint64, operationKey string) error {
	if s == nil || isNil(s.values) {
		return errors.New("key rotation: Cloudflare Secrets Store unavailable")
	}
	if ctx == nil {
		return errors.New("key rotation: context is required")
	}
	if !validOperationKey(operationKey) {
		return errors.New("key rotation: operation key is required")
	}
	versions, ok := s.versions(generation)
	if !ok {
		return errors.New("key rotation: Cloudflare staged generation is unavailable")
	}
	if err := s.values.ActivateSecretVersion(ctx, s.store, s.currentName, versions.current); err != nil {
		return errors.New("key rotation: Cloudflare current secret activation failed")
	}
	if versions.previous > 0 {
		if err := s.values.ActivateSecretVersion(ctx, s.store, s.previousName, versions.previous); err != nil {
			return errors.New("key rotation: Cloudflare previous secret activation failed")
		}
	}
	return nil
}

func (s *CloudflareSecretsStore) Retire(ctx context.Context, generation uint64, operationKey string) error {
	if s == nil || isNil(s.values) {
		return errors.New("key rotation: Cloudflare Secrets Store unavailable")
	}
	if ctx == nil {
		return errors.New("key rotation: context is required")
	}
	if !validOperationKey(operationKey) {
		return errors.New("key rotation: operation key is required")
	}
	versions, ok := s.versions(generation)
	if !ok {
		return errors.New("key rotation: Cloudflare retired generation is unavailable")
	}
	if err := retireSecretVersion(ctx, s.values, s.store, s.currentName, versions.current); err != nil {
		return errors.New("key rotation: Cloudflare current secret retirement failed")
	}
	if versions.previous > 0 {
		if err := retireSecretVersion(ctx, s.values, s.store, s.previousName, versions.previous); err != nil {
			return errors.New("key rotation: Cloudflare previous secret retirement failed")
		}
	}
	s.mu.Lock()
	delete(s.staged, generation)
	s.mu.Unlock()
	return nil
}

func (s *CloudflareSecretsStore) Rollback(ctx context.Context, generation uint64, operationKey string) error {
	if s == nil || isNil(s.values) {
		return errors.New("key rotation: Cloudflare Secrets Store unavailable")
	}
	if ctx == nil {
		return errors.New("key rotation: context is required")
	}
	if !validOperationKey(operationKey) {
		return errors.New("key rotation: operation key is required")
	}
	versions, ok := s.versions(generation)
	if !ok {
		return nil
	}
	var first error
	if err := retireSecretVersion(ctx, s.values, s.store, s.currentName, versions.current); err != nil {
		first = err
	}
	if versions.previous > 0 {
		if err := retireSecretVersion(ctx, s.values, s.store, s.previousName, versions.previous); err != nil && first == nil {
			first = err
		}
	}
	s.mu.Lock()
	delete(s.staged, generation)
	s.mu.Unlock()
	if first != nil {
		return errors.New("key rotation: Cloudflare rollback failed")
	}
	return nil
}

func (s *CloudflareSecretsStore) Fence(ctx context.Context, idempotencyKey string) error {
	if s == nil || isNil(s.fencer) {
		return errors.New("key rotation: Cloudflare fence authority unavailable")
	}
	if ctx == nil {
		return errors.New("key rotation: context is required")
	}
	if !validOperationKey(idempotencyKey) {
		return errors.New("key rotation: operation key is required")
	}
	if err := s.fencer.FenceCapability(ctx, idempotencyKey); err != nil {
		return errors.New("key rotation: Cloudflare fencing failed")
	}
	return nil
}

func validOperationKey(value string) bool {
	return value != "" && len(value) <= 512 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n")
}

func (s *CloudflareSecretsStore) versions(generation uint64) (cloudflareSecretVersions, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	versions, ok := s.staged[generation]
	return versions, ok
}

func retireSecretVersion(ctx context.Context, values cloudflare.SecretValueAPI, store, name string, version int) error {
	if version <= 0 {
		return errors.New("invalid secret version")
	}
	return values.RetireSecretVersion(ctx, store, name, version)
}

func validateCapability(capability security.CapabilityMaterial) error {
	if !validCoordinate(capability.ID) || !validCoordinate(capability.Reference) || capability.Version == 0 || len(capability.Key) == 0 || capability.NotBefore.IsZero() || capability.ExpiresAt.IsZero() || !capability.ExpiresAt.After(capability.NotBefore) {
		return errors.New("key rotation: current capability material is unavailable")
	}
	return nil
}

func validatePrevious(current, previous security.CapabilityMaterial) error {
	if len(previous.Key) == 0 {
		return nil
	}
	if !validCoordinate(previous.ID) || !validCoordinate(previous.Reference) || previous.Version == 0 || previous.Version >= current.Version || previous.ID == current.ID || previous.Reference == current.Reference || previous.NotBefore.IsZero() || previous.ExpiresAt.IsZero() || !previous.ExpiresAt.After(previous.NotBefore) {
		return errors.New("key rotation: previous capability material is invalid")
	}
	return nil
}
