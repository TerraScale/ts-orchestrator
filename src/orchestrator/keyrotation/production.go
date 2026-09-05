// Package keyrotation contains the production composition boundary for the
// D-70 capability-key rotation.  The rotation state machine lives in
// security; this package only resolves the authorities that are allowed to
// cross that boundary.
package keyrotation

import (
	"errors"
	"reflect"
	"strings"
	"time"

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
	State        *NATSStateStoreConfig
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
	if config.State == nil {
		return nil, configurationError("durable rotation state store is missing")
	}
	state, err := NewNATSStateStore(*config.State)
	if err != nil {
		return nil, err
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
		Publisher: publisher, Reloader: config.Reloader, State: state,
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

func validOperationKey(value string) bool {
	return value != "" && len(value) <= 512 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n")
}
