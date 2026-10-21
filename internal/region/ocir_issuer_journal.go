package region

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"slices"
	"strings"
	"time"
	"uuid"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

// OCIRIssuanceState contains public operation metadata, never token bytes.
type OCIRIssuanceState struct {
	ScopeHash      string    `json:"scope_hash"`
	Generation     uint64    `json:"generation"`
	GrantDigest    string    `json:"grant_digest"`
	OperationID    string    `json:"operation_id"`
	LeaseID        string    `json:"lease_id"`
	LeaseUntil     time.Time `json:"lease_until,omitzero"`
	UserID         string    `json:"user_id,omitempty"`
	RepositoryID   string    `json:"repository_id,omitempty"`
	GroupID        string    `json:"group_id,omitempty"`
	PolicyID       string    `json:"policy_id,omitempty"`
	MembershipID   string    `json:"membership_id,omitempty"`
	TokenID        string    `json:"token_id,omitempty"`
	PriorTokenID   string    `json:"prior_token_id,omitempty"`
	TokenOperation string    `json:"token_operation,omitempty"`
	TokenStarted   time.Time `json:"token_started,omitzero"`
	TokenExpires   time.Time `json:"token_expires,omitzero"`
	BeforeTokens   []string  `json:"before_tokens,omitempty"`
	PendingHash    string    `json:"pending_hash,omitempty"`
	SecretID       string    `json:"secret_id,omitempty"`
	Version        int64     `json:"version,omitzero"`
	Hash           string    `json:"hash,omitempty"`
	PublishedAt    time.Time `json:"published_at,omitzero"`
	Stage          string    `json:"stage"`
}

// OCIRCredentialAttempt retains the original authorization and once-returned
// credential operation after publication, retirement and grant succession.
type OCIRCredentialAttempt struct {
	OperationID         string    `json:"operationId"`
	GrantSHA256         string    `json:"grantSha256"`
	Generation          uint64    `json:"generation"`
	FoundationOperation string    `json:"foundationOperation"`
	Epoch               uint64    `json:"epoch"`
	LeaseID             string    `json:"leaseId,omitempty"`
	LeaseUntil          time.Time `json:"leaseUntil,omitzero"`
	ExpiresAt           time.Time `json:"expiresAt"`
	TokenOperation      string    `json:"tokenOperation"`
	TokenStarted        time.Time `json:"tokenStarted"`
	BeforeTokens        []string  `json:"beforeTokens,omitempty"`
	RequestSHA256       string    `json:"requestSha256"`
	TokenID             string    `json:"tokenId,omitempty"`
	PendingHash         string    `json:"pendingHash,omitempty"`
	SecretID            string    `json:"secretId,omitempty"`
	VaultID             string    `json:"vaultId"`
	SecretName          string    `json:"secretName"`
	Version             int64     `json:"version,omitzero"`
	Hash                string    `json:"hash,omitempty"`
	PublishedAt         time.Time `json:"publishedAt,omitzero"`
	RetiredAt           time.Time `json:"retiredAt,omitzero"`
}

type OCIRIssuanceOrigin struct {
	GrantSHA256         string    `json:"grantSha256"`
	Generation          uint64    `json:"generation"`
	FoundationOperation string    `json:"foundationOperation"`
	Epoch               uint64    `json:"epoch"`
	LeaseID             string    `json:"leaseId"`
	ExpiresAt           time.Time `json:"expiresAt"`
}

type OCIRIssuerDispatch struct {
	StartedAt  time.Time `json:"startedAt"`
	Sent       bool      `json:"sent,omitzero"`
	Status     int       `json:"status,omitzero"`
	FinishedAt time.Time `json:"finishedAt,omitzero"`
}

type OCIRIssuerRequest struct {
	Dispatches     []OCIRIssuerDispatch `json:"dispatches"`
	Method         string               `json:"method"`
	URL            string               `json:"url"`
	BodySHA256     string               `json:"bodySha256"`
	IfMatch        string               `json:"ifMatch,omitempty"`
	RetryToken     string               `json:"retryToken,omitempty"`
	FirstAttemptAt time.Time            `json:"firstAttemptAt"`
	Deadline       time.Time            `json:"deadline"`
	GrantSHA256    string               `json:"grantSha256"`
	Epoch          uint64               `json:"epoch"`
	LeaseID        string               `json:"leaseId,omitempty"`
}

type OCIRIssuanceEntry struct {
	Requests map[string]OCIRIssuerRequest     `json:"requests,omitempty"`
	Origin   OCIRIssuanceOrigin               `json:"origin"`
	Revision uint64                           `json:"revision"`
	State    OCIRIssuanceState                `json:"state"`
	Attempts map[string]OCIRCredentialAttempt `json:"attempts,omitempty"`
}

func (s OCIRIssuanceState) Validate(key string) error {
	if key != "ocir-issuer."+s.ScopeHash || !validFoundationDigest(s.ScopeHash) ||
		s.Generation == 0 || !validFoundationDigest(s.GrantDigest) || !validIssuerUUID(s.OperationID) ||
		len(s.BeforeTokens) > 2 || s.Version < 0 || s.LeaseID != "" && (!validIssuerUUID(s.LeaseID) || s.LeaseUntil.IsZero()) || s.LeaseID == "" && !s.LeaseUntil.IsZero() {
		return errors.New("OCIR issuance has invalid original scope or lease")
	}
	switch s.Stage {
	case "identity", "token-pending", "vault-pending", "ready":
	default:
		return errors.New("OCIR issuance has unknown stage")
	}
	if s.TokenOperation != "" && (!validIssuerUUID(s.TokenOperation) || s.TokenStarted.IsZero() || !s.TokenExpires.After(s.TokenStarted)) || (s.Stage == "token-pending" || s.Stage == "vault-pending") && s.TokenOperation == "" {
		return errors.New("OCIR issuance has invalid pending credential operation")
	}
	for _, value := range []string{s.PendingHash, s.Hash} {
		if value != "" && !validFoundationDigest(value) {
			return errors.New("OCIR issuance has invalid credential digest")
		}
	}
	for _, value := range append(slices.Clone(s.BeforeTokens), s.UserID, s.RepositoryID, s.GroupID, s.PolicyID, s.MembershipID, s.TokenID, s.PriorTokenID, s.SecretID) {
		if value != "" && (!strings.HasPrefix(value, "ocid1.") || len(value) > 512 || strings.ContainsAny(value, "\r\n")) {
			return errors.New("OCIR issuance has invalid public resource identity")
		}
	}
	return nil
}

func (r FoundationRecord) validateOCIRIssuances() error {
	if len(r.OCIRIssuances) > 64 {
		return errors.New("OCIR issuance history exceeds fixed bound")
	}
	for key, entry := range r.OCIRIssuances {
		if !validFoundationDigest(entry.Origin.GrantSHA256) || entry.Origin.Generation == 0 || entry.Origin.Generation > r.Generation || !entityid.Valid(entry.Origin.FoundationOperation) || entry.Origin.Epoch == 0 || entry.Origin.ExpiresAt.IsZero() || entry.Origin.LeaseID != "" && !validIssuerUUID(entry.Origin.LeaseID) {
			return errors.New("OCIR issuance has invalid original foundation authority")
		}
		if entry.Revision == 0 || len(entry.Attempts) > 64 || len(entry.Requests) > 256 || entry.State.Generation > r.Generation {
			return errors.New("OCIR issuance revision or retained attempt bound invalid")
		}
		if err := entry.State.Validate(key); err != nil {
			return err
		}
		wire, err := json.Marshal(entry)
		if err != nil || len(wire) > 32<<10 {
			return errors.New("OCIR protected issuance entry exceeds fixed 32 KiB bound")
		}
		for hash, request := range entry.Requests {
			if len(request.Dispatches) == 0 || len(request.Dispatches) > 16 {
				return errors.New("OCIR wire dispatch history exceeds fixed bound")
			}
			for _, dispatch := range request.Dispatches {
				if dispatch.StartedAt.IsZero() || dispatch.StartedAt.Before(request.FirstAttemptAt) || !dispatch.StartedAt.Before(request.Deadline) || !dispatch.FinishedAt.IsZero() && dispatch.FinishedAt.Before(dispatch.StartedAt) || dispatch.Status < 0 || dispatch.Status > 599 {
					return errors.New("OCIR dispatch history invalid")
				}
			}
			if !validFoundationDigest(hash) || !validFoundationDigest(request.BodySHA256) || !validFoundationDigest(request.GrantSHA256) || request.Epoch == 0 || request.FirstAttemptAt.IsZero() || !request.Deadline.After(request.FirstAttemptAt) || len(request.URL) > 2048 || !strings.HasPrefix(request.URL, "https://") || len(request.RetryToken) > 128 || len(request.IfMatch) > 512 || request.LeaseID != "" && !validIssuerUUID(request.LeaseID) {
				return errors.New("OCIR wire attempt has invalid original request authority")
			}
			switch request.Method {
			case "POST", "PUT", "DELETE", "PATCH":
			default:
				return errors.New("OCIR wire attempt method invalid")
			}
		}
		for operation, a := range entry.Attempts {
			if operation != a.TokenOperation || !validIssuerUUID(operation) || !validIssuerUUID(a.OperationID) || !entityid.Valid(a.FoundationOperation) || !validFoundationDigest(a.GrantSHA256) || !validFoundationDigest(a.RequestSHA256) || a.Generation == 0 || a.Generation > r.Generation || a.Epoch == 0 || a.TokenStarted.IsZero() || !a.ExpiresAt.After(a.TokenStarted) || len(a.BeforeTokens) > 2 || a.Version < 0 || !strings.HasPrefix(a.VaultID, "ocid1.vault.") || a.SecretName == "" || len(a.SecretName) > 255 {
				return errors.New("OCIR credential history has invalid original authority")
			}
			for _, digest := range []string{a.PendingHash, a.Hash} {
				if digest != "" && !validFoundationDigest(digest) {
					return errors.New("OCIR history has invalid credential digest")
				}
			}
			for _, id := range append(slices.Clone(a.BeforeTokens), a.TokenID, a.SecretID) {
				if id != "" && (!strings.HasPrefix(id, "ocid1.") || len(id) > 512) {
					return errors.New("OCIR history has invalid public identity")
				}
			}
		}
	}
	return nil
}

// JournalKey fixes the complete exact intent, tenancy and installation.
func (s VerifiedOCIRIssuer) JournalKey() (string, error) {
	if !s.IsVerified() {
		return "", errors.New("OCIR journal key requires sealed scope")
	}
	wire, err := json.Marshal(struct {
		Tenancy, Installation string
		Intent                OCIRIssuerIntent
	}{s.TenancyID(), s.InstallationID(), s.Intent()}, json.Deterministic(true))
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(wire)
	return "ocir-issuer." + hex.EncodeToString(sum[:]), nil
}

func validIssuerUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.UUID{} && parsed.String() == value
}
