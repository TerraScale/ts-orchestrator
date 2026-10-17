package rootoci

import (
	"context"
	"time"
)

// NetBirdIntentRequest names a proposal already committed through the regional
// lease CAS. Every field is an expectation; root derives process and authority.
type NetBirdIntentRequest struct {
	Cell           string    `json:"cell"`
	IntentRevision uint64    `json:"intent_revision"`
	OperationID    string    `json:"operation_id"`
	RuntimeID      string    `json:"runtime_id"`
	OwnerID        string    `json:"owner_id"`
	Epoch          uint64    `json:"epoch"`
	LeaseRevision  uint64    `json:"lease_revision"`
	ExpiresAt      time.Time `json:"expires_at"`
}

// NetBirdIntentHost is one adopted host, never an arbitrary policy or API path.
type NetBirdIntentHost struct {
	Name      string `json:"name"`
	PrivateIP string `json:"private_ip"`
	Role      string `json:"role"`
}

// NetBirdIntent is the closed regional input to the dedicated manager. Access
// policy, groups and DNS conventions are derived in code from these facts.
type NetBirdIntent struct {
	Cell                   string              `json:"cell"`
	InstallationID         string              `json:"installation_id"`
	DeploymentID           string              `json:"deployment_id"`
	SourceGrantSHA256      string              `json:"source_grant_sha256"`
	MaterialGeneration     uint64              `json:"material_generation"`
	SpecGeneration         uint64              `json:"spec_generation"`
	SpecSHA256             string              `json:"spec_sha256"`
	SubnetCIDR             string              `json:"subnet_cidr"`
	Hosts                  []NetBirdIntentHost `json:"hosts"`
	SourceSlot             string              `json:"source_slot"`
	SourceInstanceID       string              `json:"source_instance_id"`
	ManagerStoreGeneration string              `json:"manager_store_generation"`
	OperationID            string              `json:"operation_id"`
	RuntimeID              string              `json:"runtime_id"`
	OwnerID                string              `json:"owner_id"`
	Epoch                  uint64              `json:"epoch"`
	LeaseRevision          uint64              `json:"lease_revision"`
	IntentRevision         uint64              `json:"intent_revision"`
	IssuedAt               time.Time           `json:"issued_at"`
	ExpiresAt              time.Time           `json:"expires_at"`
}

// NetBirdIntentReceipt contains public attestation only. Its certificate never
// supplies a trust anchor; the receiver authenticates it against current source.
type NetBirdIntentReceipt struct {
	Intent          NetBirdIntent `json:"intent"`
	NodeCertificate []byte        `json:"node_certificate"`
	Signature       []byte        `json:"signature"`
}

// NetBird authorizes only the current committed regional proposal. It must
// rederive the payload and target, bind the supervised process to its original
// leader lease, and check Call.Guard immediately before the finite attestation.
type NetBird interface {
	AuthorizeNetBirdIntent(context.Context, Call, NetBirdIntentRequest) (NetBirdIntentReceipt, error)
}
