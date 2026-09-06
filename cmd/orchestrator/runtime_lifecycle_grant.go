package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"strings"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/placementtransition"
)

const (
	lifecycleGrantDomain = "terrascale-lifecycle-operation-v1"
	maxLifecycleGrantAge = 5 * time.Minute
)

// lifecycleOperationGrant is the exact wire contract sent to a member. Times
// are milliseconds so signatures are stable across language runtimes.
type lifecycleOperationGrant struct {
	Version                   int    `json:"version"`
	Domain                    string `json:"domain"`
	Environment               string `json:"environment"`
	Tenant                    string `json:"tenant"`
	Project                   string `json:"project"`
	Database                  string `json:"database"`
	Region                    string `json:"region"`
	Member                    string `json:"member"`
	Action                    string `json:"action"`
	OperationID               string `json:"operation_id"`
	AcceptedProofDigest       string `json:"accepted_proof_digest"`
	AcceptedPlacementRevision uint64 `json:"accepted_placement_revision"`
	AuthorityEpoch            uint64 `json:"authority_epoch"`
	AuthorityLease            string `json:"authority_lease"`
	IssuedAtUnixMillis        int64  `json:"issued_at_unix_millis"`
	ExpiresAtUnixMillis       int64  `json:"expires_at_unix_millis"`
}

var lifecycleActions = map[string]struct{}{
	"ensure_snapshot":           {},
	"verify_snapshot_placement": {},
	"close_database":            {},
	"stop_native_backup":        {},
	"reactivate":                {},
	"delete_owned_data":         {},
}

// issueLifecycleOperationGrant runs the fresh authority check before signing
// and bounds the grant by the currently observed authority lease.
func issueLifecycleOperationGrant(keyID string, key ed25519.PrivateKey, check func() error, grant lifecycleOperationGrant, now, leaseExpiresAt time.Time, minLease time.Duration) (placementtransition.Signed, error) {
	now = now.UTC()
	// The wire contract is millisecond precision; validate against the same
	// precision used for the signed timestamps.
	now = time.UnixMilli(now.UnixMilli()).UTC()
	leaseExpiresAt = leaseExpiresAt.UTC()
	issued := time.UnixMilli(grant.IssuedAtUnixMillis).UTC()
	expires := time.UnixMilli(grant.ExpiresAtUnixMillis).UTC()
	_, actionOK := lifecycleActions[grant.Action]
	digest, digestErr := hex.DecodeString(grant.AcceptedProofDigest)
	if check == nil || digestErr != nil || keyID == "" || len(key) != ed25519.PrivateKeySize || grant.Version != 1 || grant.Domain != lifecycleGrantDomain || grant.Environment == "" || grant.Tenant == "" || grant.Project == "" || grant.Database == "" || grant.Region == "" || grant.Member == "" || !actionOK || grant.OperationID == "" || len(digest) != 32 || strings.ToLower(grant.AcceptedProofDigest) != grant.AcceptedProofDigest || grant.AcceptedPlacementRevision == 0 || grant.AuthorityEpoch == 0 || grant.AuthorityLease == "" || grant.IssuedAtUnixMillis <= 0 || grant.ExpiresAtUnixMillis <= grant.IssuedAtUnixMillis || issued.Before(now) || !now.Before(expires) || expires.After(leaseExpiresAt) || minLease <= 0 || !leaseExpiresAt.After(now) || leaseExpiresAt.Sub(now) < minLease || expires.Sub(issued) > maxLifecycleGrantAge {
		return placementtransition.Signed{}, errors.New("lifecycle grant is incomplete or outside authority lease")
	}
	if err := check(); err != nil {
		return placementtransition.Signed{}, err
	}
	if _, err := json.Marshal(grant); err != nil {
		return placementtransition.Signed{}, err
	}
	return placementtransition.SignEvidence(keyID, key, grant)
}
