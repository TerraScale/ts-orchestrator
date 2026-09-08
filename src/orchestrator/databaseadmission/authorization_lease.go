package databaseadmission

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"terrascale.tech/orchestrator/src/orchestrator/authorityjournal"
)

const authorizationLeaseDomain = "terrascale-authorization-lease-v1"

var (
	ErrAuthorizationLeaseInvalid  = errors.New("database admission: invalid authorization lease")
	ErrAuthorizationLeaseConflict = errors.New("database admission: authorization lease conflict")
	ErrAuthorizationLeaseRevoked  = errors.New("database admission: authorization lease revoked")
)

// AuthorizationLease is the ordinary customer request lease. It is separate
// from deletion authorization and carries the exact scope and credential
// generations consumed by regional TerraBase and edge verifiers.
type AuthorizationLease struct {
	Version                 int    `json:"version"`
	TenantID                string `json:"tenantId"`
	Scope                   string `json:"scope"`
	CredentialGeneration    uint64 `json:"epoch"`
	PermissionSetGeneration uint64 `json:"featureEpoch"`
	Audience                string `json:"audience"`
	Region                  string `json:"region"`
	IssuedAt                int64  `json:"issuedAt"`
	ValidUntil              int64  `json:"validUntil"`
	KeyID                   string `json:"keyId"`
	Signature               string `json:"signature"`
}

type AuthorizationLeaseRequest struct {
	OperationID             string
	TenantID                string
	Scope                   string
	CredentialGeneration    uint64
	PermissionSetGeneration uint64
	Audience                string
	Region                  string
	IssuedAt                time.Time
	ValidUntil              time.Time
}

// MarshalJSON keeps Go's numeric generation API while emitting the string
// generations required by the Rust and TypeScript lease consumers.
func (lease AuthorizationLease) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Version    int    `json:"version"`
		TenantID   string `json:"tenantId"`
		Epoch      string `json:"epoch"`
		Feature    string `json:"featureEpoch"`
		Audience   string `json:"audience"`
		Region     string `json:"region"`
		IssuedAt   int64  `json:"issuedAt"`
		ValidUntil int64  `json:"validUntil"`
		KeyID      string `json:"keyId"`
		Signature  string `json:"signature"`
	}{
		Version:    lease.Version,
		TenantID:   lease.TenantID,
		Epoch:      strconv.FormatUint(lease.CredentialGeneration, 10),
		Feature:    strconv.FormatUint(lease.PermissionSetGeneration, 10),
		Audience:   lease.Audience,
		Region:     lease.Region,
		IssuedAt:   lease.IssuedAt,
		ValidUntil: lease.ValidUntil,
		KeyID:      lease.KeyID,
		Signature:  lease.Signature,
	})
}

func (lease *AuthorizationLease) UnmarshalJSON(data []byte) error {
	var wire struct {
		Version    int    `json:"version"`
		TenantID   string `json:"tenantId"`
		Epoch      string `json:"epoch"`
		Feature    string `json:"featureEpoch"`
		Audience   string `json:"audience"`
		Region     string `json:"region"`
		IssuedAt   int64  `json:"issuedAt"`
		ValidUntil int64  `json:"validUntil"`
		KeyID      string `json:"keyId"`
		Signature  string `json:"signature"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return err
	}
	credential, err := strconv.ParseUint(wire.Epoch, 10, 64)
	if err != nil {
		return err
	}
	permission, err := strconv.ParseUint(wire.Feature, 10, 64)
	if err != nil {
		return err
	}
	*lease = AuthorizationLease{Version: wire.Version, TenantID: wire.TenantID, CredentialGeneration: credential, PermissionSetGeneration: permission, Audience: wire.Audience, Region: wire.Region, IssuedAt: wire.IssuedAt, ValidUntil: wire.ValidUntil, KeyID: wire.KeyID, Signature: wire.Signature}
	return nil
}

type authorizationLeaseState struct {
	Leases          map[string]AuthorizationLease `json:"leases"`
	CredentialFloor map[string]uint64             `json:"credentialFloor"`
	PermissionFloor map[string]uint64             `json:"permissionFloor"`
}

// The public lease omits Scope because regional consumers derive it from the
// tenant and generation fields. The authority still persists Scope privately
// so an operation replay with changed admission scope is rejected.
type authorizationLeaseRecord struct {
	Version      int    `json:"version"`
	TenantID     string `json:"tenantId"`
	Scope        string `json:"scope"`
	Epoch        string `json:"epoch"`
	FeatureEpoch string `json:"featureEpoch"`
	Audience     string `json:"audience"`
	Region       string `json:"region"`
	IssuedAt     int64  `json:"issuedAt"`
	ValidUntil   int64  `json:"validUntil"`
	KeyID        string `json:"keyId"`
	Signature    string `json:"signature"`
}

func (state authorizationLeaseState) MarshalJSON() ([]byte, error) {
	records := make(map[string]authorizationLeaseRecord, len(state.Leases))
	for operation, lease := range state.Leases {
		records[operation] = authorizationLeaseRecord{Version: lease.Version, TenantID: lease.TenantID, Scope: lease.Scope, Epoch: strconv.FormatUint(lease.CredentialGeneration, 10), FeatureEpoch: strconv.FormatUint(lease.PermissionSetGeneration, 10), Audience: lease.Audience, Region: lease.Region, IssuedAt: lease.IssuedAt, ValidUntil: lease.ValidUntil, KeyID: lease.KeyID, Signature: lease.Signature}
	}
	return json.Marshal(struct {
		Leases          map[string]authorizationLeaseRecord `json:"leases"`
		CredentialFloor map[string]uint64                   `json:"credentialFloor"`
		PermissionFloor map[string]uint64                   `json:"permissionFloor"`
	}{records, state.CredentialFloor, state.PermissionFloor})
}

func (state *authorizationLeaseState) UnmarshalJSON(data []byte) error {
	var wire struct {
		Leases          map[string]authorizationLeaseRecord `json:"leases"`
		CredentialFloor map[string]uint64                   `json:"credentialFloor"`
		PermissionFloor map[string]uint64                   `json:"permissionFloor"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return err
	}
	leases := make(map[string]AuthorizationLease, len(wire.Leases))
	for operation, record := range wire.Leases {
		credential, err := strconv.ParseUint(record.Epoch, 10, 64)
		if err != nil {
			return err
		}
		permission, err := strconv.ParseUint(record.FeatureEpoch, 10, 64)
		if err != nil {
			return err
		}
		leases[operation] = AuthorizationLease{Version: record.Version, TenantID: record.TenantID, Scope: record.Scope, CredentialGeneration: credential, PermissionSetGeneration: permission, Audience: record.Audience, Region: record.Region, IssuedAt: record.IssuedAt, ValidUntil: record.ValidUntil, KeyID: record.KeyID, Signature: record.Signature}
	}
	*state = authorizationLeaseState{Leases: leases, CredentialFloor: wire.CredentialFloor, PermissionFloor: wire.PermissionFloor}
	return nil
}

func newAuthorizationLeaseState() authorizationLeaseState {
	return authorizationLeaseState{Leases: map[string]AuthorizationLease{}, CredentialFloor: map[string]uint64{}, PermissionFloor: map[string]uint64{}}
}

func validateAuthorizationLeaseState(state authorizationLeaseState) error {
	if state.Leases == nil || len(state.Leases) > 100000 {
		return ErrAuthorizationLeaseInvalid
	}
	if state.CredentialFloor == nil || state.PermissionFloor == nil {
		return ErrAuthorizationLeaseInvalid
	}
	for operation, lease := range state.Leases {
		if operation == "" || validateAuthorizationLease(lease, time.Unix(lease.IssuedAt, 0)) != nil {
			return ErrAuthorizationLeaseInvalid
		}
	}
	return nil
}

// AuthorizationLeasePublisher durably records a signed lease before returning
// it. Reusing an operation ID replays the exact original bytes after restart.
type AuthorizationLeasePublisher struct {
	journal  *authorityjournal.Journal[authorizationLeaseState]
	keyID    string
	private  []byte
	audience string
}

type AuthorizationLeasePublisherConfig struct {
	Connection     *nats.Conn
	CandidateID    string
	AuthorityEpoch uint64
	LeaseID        string
	KeyID          string
	PrivateKey     []byte
	Audience       string
}

func NewAuthorizationLeasePublisher(config AuthorizationLeasePublisherConfig) (*AuthorizationLeasePublisher, error) {
	if config.Connection == nil || len(config.PrivateKey) != 32 || config.KeyID == "" || config.Audience == "" {
		return nil, ErrAuthorizationLeaseInvalid
	}
	journal, err := authorityjournal.New(authorityjournal.Config{Connection: config.Connection, CandidateID: config.CandidateID, AuthorityEpoch: config.AuthorityEpoch, LeaseID: config.LeaseID, StateKey: "authorization.leases"}, newAuthorizationLeaseState, validateAuthorizationLeaseState)
	if err != nil {
		return nil, err
	}
	return &AuthorizationLeasePublisher{journal: journal, keyID: config.KeyID, private: slices.Clone(config.PrivateKey), audience: config.Audience}, nil
}

func (p *AuthorizationLeasePublisher) Issue(ctx context.Context, request AuthorizationLeaseRequest) (AuthorizationLease, error) {
	if p == nil || p.journal == nil || request.OperationID == "" || request.Audience != p.audience {
		return AuthorizationLease{}, ErrAuthorizationLeaseInvalid
	}
	lease, err := SignAuthorizationLease(request, p.keyID, p.private)
	if err != nil {
		return AuthorizationLease{}, err
	}
	err = p.journal.Transact(ctx, true, func(state *authorizationLeaseState) error {
		if request.CredentialGeneration <= state.CredentialFloor[request.TenantID] || request.PermissionSetGeneration <= state.PermissionFloor[request.TenantID] {
			return ErrAuthorizationLeaseRevoked
		}
		if prior, found := state.Leases[request.OperationID]; found {
			if authorizationLeaseDigest(prior) != authorizationLeaseDigest(lease) {
				return ErrAuthorizationLeaseConflict
			}
			return nil
		}
		state.Leases[request.OperationID] = lease
		return nil
	})
	if err != nil {
		return AuthorizationLease{}, err
	}
	return lease, nil
}

// Revoke raises durable generation floors atomically. All leases for the
// tenant at or below either floor fail on subsequent issue/replay after a
// restart; concurrent reducers are serialized by the journal CAS.
func (p *AuthorizationLeasePublisher) Revoke(ctx context.Context, tenantID string, credentialGeneration, permissionSetGeneration uint64) error {
	if p == nil || p.journal == nil || !tenantIDPattern.MatchString(tenantID) || credentialGeneration > maxSafeJSONInteger || permissionSetGeneration > maxSafeJSONInteger || (credentialGeneration == 0 && permissionSetGeneration == 0) {
		return ErrAuthorizationLeaseInvalid
	}
	return p.journal.Transact(ctx, true, func(state *authorizationLeaseState) error {
		if credentialGeneration > state.CredentialFloor[tenantID] {
			state.CredentialFloor[tenantID] = credentialGeneration
		}
		if permissionSetGeneration > state.PermissionFloor[tenantID] {
			state.PermissionFloor[tenantID] = permissionSetGeneration
		}
		return nil
	})
}

// Reduce raises only the permission floor, preserving the credential
// generation. It is the durable CAS path for an authorization reduction.
func (p *AuthorizationLeasePublisher) Reduce(ctx context.Context, tenantID string, permissionSetGeneration uint64) error {
	return p.Revoke(ctx, tenantID, 0, permissionSetGeneration)
}

// SignAuthorizationLease produces the exact wire object consumed by regional
// verifiers. Lifetime is bounded to thirty seconds. Scope is internal
// admission evidence and is excluded from the published lease contract.
func SignAuthorizationLease(request AuthorizationLeaseRequest, keyID string, private []byte) (AuthorizationLease, error) {
	scope := canonicalAuthorizationScope(request.Scope)
	lease := AuthorizationLease{Version: 1, TenantID: request.TenantID, Scope: scope, CredentialGeneration: request.CredentialGeneration, PermissionSetGeneration: request.PermissionSetGeneration, Audience: request.Audience, Region: request.Region, IssuedAt: request.IssuedAt.Unix(), ValidUntil: request.ValidUntil.Unix(), KeyID: keyID}
	if scope == "" || validateAuthorizationLease(lease, time.Now()) != nil || len(private) != 32 {
		return AuthorizationLease{}, ErrAuthorizationLeaseInvalid
	}
	mac := hmac.New(sha256.New, private)
	mac.Write(authorizationLeasePayload(lease))
	lease.Signature = hex.EncodeToString(mac.Sum(nil))
	return lease, nil
}

func (lease AuthorizationLease) Verify(key []byte, now time.Time) error {
	if validateAuthorizationLease(lease, now) != nil || len(key) != 32 {
		return ErrAuthorizationLeaseInvalid
	}
	signature, err := hex.DecodeString(lease.Signature)
	mac := hmac.New(sha256.New, key)
	mac.Write(authorizationLeasePayload(lease))
	if err != nil || !hmac.Equal(mac.Sum(nil), signature) {
		return ErrAuthorizationLeaseInvalid
	}
	return nil
}

func validateAuthorizationLease(lease AuthorizationLease, now time.Time) error {
	audience, err := url.Parse(lease.Audience)
	validAudience := err == nil && audience.Scheme == "https" && audience.Hostname() != "" && audience.User == nil && audience.RawQuery == "" && audience.Fragment == "" && audience.String() == lease.Audience
	validRegion := lease.Region == "GRU" || lease.Region == "SFO" || lease.Region == "FRA"
	if lease.Version != 1 || canonicalAuthorizationScope(lease.Scope) != lease.Scope || !tenantIDPattern.MatchString(lease.TenantID) || strings.TrimSpace(lease.TenantID) != lease.TenantID || lease.CredentialGeneration == 0 || lease.PermissionSetGeneration == 0 || lease.CredentialGeneration > maxSafeJSONInteger || lease.PermissionSetGeneration > maxSafeJSONInteger || !validAudience || !validRegion || !validKeyID(lease.KeyID) || lease.IssuedAt <= 0 || lease.ValidUntil <= lease.IssuedAt || lease.ValidUntil-lease.IssuedAt > 30 || now.Unix() < lease.IssuedAt || now.Unix() >= lease.ValidUntil {
		return ErrAuthorizationLeaseInvalid
	}
	return nil
}

func authorizationLeasePayload(lease AuthorizationLease) []byte {
	return []byte(fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s\n%s\n%d\n%d", authorizationLeaseDomain, lease.KeyID, lease.TenantID, strconv.FormatUint(lease.CredentialGeneration, 10), strconv.FormatUint(lease.PermissionSetGeneration, 10), lease.Audience, lease.Region, lease.IssuedAt, lease.ValidUntil))
}

const maxSafeJSONInteger = uint64(9_007_199_254_740_991)

var tenantIDPattern = regexp.MustCompile(`^[0-7][0-9A-HJKMNP-TV-Z]{25}$`)
var keyIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)

func authorizationLeaseScope(tenant string, credential, permission uint64) string {
	return "authz-" + tenant + "-" + strconv.FormatUint(credential, 10) + "-" + strconv.FormatUint(permission, 10)
}

func validKeyID(value string) bool { return keyIDPattern.MatchString(value) }

func canonicalAuthorizationScope(scope string) string {
	if strings.TrimSpace(scope) != scope || scope == "" || !json.Valid([]byte(scope)) || scope[0] != '{' {
		return ""
	}
	var value map[string]any
	if json.Unmarshal([]byte(scope), &value) != nil || len(value) == 0 {
		return ""
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return string(encoded)
}

func authorizationLeaseDigest(lease AuthorizationLease) string {
	// Scope is internal admission evidence and is deliberately excluded from
	// the published HMAC contract, but it remains part of operation identity.
	payload := append(append([]byte(nil), authorizationLeasePayload(lease)...), '\n')
	payload = append(payload, lease.Scope...)
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}
