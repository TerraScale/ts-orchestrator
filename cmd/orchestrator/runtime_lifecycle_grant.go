package main

import (
	"crypto/ed25519"
	"encoding/json/v2"
	"errors"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/placementtransition"
)

const lifecycleGrantDomain = "terrascale-lifecycle-operation-v1"

type lifecycleOperationGrant struct {
	Version                                                int    `json:"version"`
	Domain                                                 string `json:"domain"`
	Environment, Tenant, Project, Database, Region, Member string
	Action, OperationID, AcceptedProofDigest               string
	AcceptedPlacementRevision, AuthorityEpoch              uint64
	AuthorityLease                                         string
	ValidUntil                                             time.Time
}

func issueLifecycleOperationGrant(keyID string, key ed25519.PrivateKey, check func() error, grant lifecycleOperationGrant) (placementtransition.Signed, error) {
	if check == nil || keyID == "" || len(key) != ed25519.PrivateKeySize || grant.Version != 1 || grant.Domain != lifecycleGrantDomain || grant.Environment == "" || grant.Tenant == "" || grant.Project == "" || grant.Database == "" || grant.Region == "" || grant.Member == "" || grant.Action == "" || grant.OperationID == "" || grant.AcceptedPlacementRevision == 0 || grant.AuthorityEpoch == 0 || grant.AuthorityLease == "" || grant.ValidUntil.Before(time.Now().UTC()) {
		return placementtransition.Signed{}, errors.New("lifecycle grant is incomplete")
	}
	if err := check(); err != nil {
		return placementtransition.Signed{}, err
	}
	grant.ValidUntil = grant.ValidUntil.UTC()
	if _, err := json.Marshal(grant); err != nil {
		return placementtransition.Signed{}, err
	}
	return placementtransition.SignEvidence(keyID, key, grant)
}
