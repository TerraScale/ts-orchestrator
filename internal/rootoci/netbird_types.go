package rootoci

import (
	"context"
	"time"
)

// NetBirdIntentRequest prepares public desired facts at revision zero, then
// verifies the exact committed proposal at its lease-CAS revision. Every field
// is an expectation; root derives process, source and actual lease authority.
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
	SpecRevision           uint64              `json:"spec_revision"`
	RootRevision           uint64              `json:"root_revision"`
	SubnetCIDR             string              `json:"subnet_cidr"`
	Hosts                  []NetBirdIntentHost `json:"hosts"`
	SignedSpec             []byte              `json:"signed_spec"`
	RootChain              []byte              `json:"root_chain"`
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

// NetBirdIntentReceipt contains rederived public facts. It grants no remote
// authority: the manager independently reads the committed intent and lease.
type NetBirdIntentReceipt struct {
	Intent NetBirdIntent `json:"intent"`
}

// NetBird authorizes only the current committed regional proposal. It must
// rederive the payload and target, bind the supervised process to its original
// leader lease, and check Call.Guard before returning the finite public facts.
type NetBird interface {
	AuthorizeNetBirdIntent(context.Context, Call, NetBirdIntentRequest) (NetBirdIntentReceipt, error)
}
