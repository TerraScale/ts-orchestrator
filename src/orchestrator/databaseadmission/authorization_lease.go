package databaseadmission

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"terrascale.tech/orchestrator/src/orchestrator/authorityjournal"
)

const authorizationLeaseDomain = "terrascale-authorization-lease-v1"

var (
	ErrAuthorizationLeaseInvalid  = errors.New("database admission: invalid authorization lease")
	ErrAuthorizationLeaseConflict = errors.New("database admission: authorization lease conflict")
)

// AuthorizationLease is the ordinary customer request lease. It is separate
// from deletion authorization and carries the exact scope and credential
// generations consumed by regional TerraBase and edge verifiers.
type AuthorizationLease struct {
	Version                 int    `json:"version"`
	TenantID                string `json:"tenantId"`
	Scope                   string `json:"-"`
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

type authorizationLeaseState struct {
	Leases map[string]AuthorizationLease `json:"leases"`
}

func newAuthorizationLeaseState() authorizationLeaseState {
	return authorizationLeaseState{Leases: map[string]AuthorizationLease{}}
}

func validateAuthorizationLeaseState(state authorizationLeaseState) error {
	if state.Leases == nil || len(state.Leases) > 100000 {
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

// SignAuthorizationLease produces the exact wire object consumed by regional
// verifiers. Lifetime is bounded to thirty seconds and all scope fields are
// included in the signed preimage.
func SignAuthorizationLease(request AuthorizationLeaseRequest, keyID string, private []byte) (AuthorizationLease, error) {
	if request.Scope == "" {
		return AuthorizationLease{}, ErrAuthorizationLeaseInvalid
	}
	lease := AuthorizationLease{Version: 1, TenantID: request.TenantID, Scope: request.Scope, CredentialGeneration: request.CredentialGeneration, PermissionSetGeneration: request.PermissionSetGeneration, Audience: request.Audience, Region: request.Region, IssuedAt: request.IssuedAt.Unix(), ValidUntil: request.ValidUntil.Unix(), KeyID: keyID}
	if validateAuthorizationLease(lease, request.IssuedAt) != nil || len(private) != 32 {
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
	if lease.Version != 1 || strings.TrimSpace(lease.TenantID) != lease.TenantID || lease.TenantID == "" || lease.CredentialGeneration == 0 || lease.PermissionSetGeneration == 0 || !validAudience || !validRegion || lease.KeyID == "" || lease.IssuedAt <= 0 || lease.ValidUntil <= lease.IssuedAt || lease.ValidUntil-lease.IssuedAt > 30 || now.Unix() < lease.IssuedAt || now.Unix() >= lease.ValidUntil {
		return ErrAuthorizationLeaseInvalid
	}
	return nil
}

func authorizationLeasePayload(lease AuthorizationLease) []byte {
	return []byte(fmt.Sprintf("%s\n%s\n%s\n%d\n%d\n%s\n%s\n%d\n%d", authorizationLeaseDomain, lease.KeyID, lease.TenantID, lease.CredentialGeneration, lease.PermissionSetGeneration, lease.Audience, lease.Region, lease.IssuedAt, lease.ValidUntil))
}

func authorizationLeaseDigest(lease AuthorizationLease) string {
	sum := sha256.Sum256(authorizationLeasePayload(lease))
	return hex.EncodeToString(sum[:])
}
