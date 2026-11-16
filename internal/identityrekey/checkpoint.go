// Package identityrekey authorizes an existing cell's identity replacement
// without deriving authority from its retired bootstrap documents.
package identityrekey

import (
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
)

const (
	CheckpointSchemaVersion = 1
	MaxCheckpointBytes      = 128 << 10
	MaxCheckpointWireBytes  = 192 << 10
	MaxCheckpointLifetime   = 365 * 24 * time.Hour
	CheckpointDomain        = "terrascale.identity-rekey.accepted-checkpoint"
	acceptanceDomain        = "terrascale.identity-rekey.slot-acceptance.v1\x00"
	AcceptanceOriginInitial = "initial-formation"
	AcceptanceOriginRekey   = "identity-rekey"
)

var (
	ErrCheckpointInvalid  = errors.New("accepted identity checkpoint is invalid")
	ErrCheckpointMismatch = errors.New("accepted identity checkpoint does not match observed installation")
	digestRE              = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// AcceptedIdentityCheckpoint is root authority for the observed existing
// images and installations, not an assertion about their launch history.
type AcceptedIdentityCheckpoint struct {
	SchemaVersion            int                              `json:"schemaVersion"`
	OperationID              string                           `json:"operationId"`
	DeploymentID             string                           `json:"deploymentId"`
	ClusterID                string                           `json:"clusterId"`
	Environment              string                           `json:"environment"`
	Cell                     string                           `json:"cell"`
	SeedSlot                 string                           `json:"seedSlot"`
	MaterialGenerationSHA256 string                           `json:"materialGenerationSha256"`
	ManagedMaterial          *bootstrap.ManagedMaterialDomain `json:"managedMaterial,omitempty"`
	Broker                   BrokerIdentity                   `json:"broker"`
	Slots                    []SlotBinding                    `json:"slots"`
}

// BrokerIdentity keeps the public keys already pinned by the serving cell.
type BrokerIdentity struct {
	Operator           string `json:"operator"`
	SystemAccount      string `json:"systemAccount"`
	CellAccount        string `json:"cellAccount"`
	HostSigner         string `json:"hostSigner"`
	AccountSigner      string `json:"accountSigner"`
	RoleSigner         string `json:"roleSigner"`
	InterRegionAccount string `json:"interRegionAccount"`
}

type BinaryPin struct {
	SHA256       string `json:"sha256"`
	Size         int64  `json:"size"`
	Architecture string `json:"architecture"`
}

// StoreIdentity pins existing JetStream ownership; it never authorizes a rename
// or recreation of the store, server name, or Raft node identity.
type StoreIdentity struct {
	Directory          string `json:"directory"`
	ServerName         string `json:"serverName"`
	RaftNodeID         string `json:"raftNodeId"`
	ServerNameSHA256   string `json:"serverNameSha256"`
	NodeIdentitySHA256 string `json:"nodeIdentitySha256"`
}

type SlotBinding struct {
	Slot                     string                      `json:"slot"`
	PreviousAcceptanceSHA256 string                      `json:"previousAcceptanceSha256"`
	PreviousMaterialSHA256   map[string]string           `json:"previousMaterialSha256"`
	InstanceOCID             string                      `json:"instanceOcid"`
	ImageOCID                string                      `json:"imageOcid"`
	PrimaryVNICOCID          string                      `json:"primaryVnicOcid"`
	PrimaryPrivateIP         string                      `json:"primaryPrivateIp"`
	Binary                   BinaryPin                   `json:"binary"`
	ConfigSHA256             map[string]string           `json:"configSha256"`
	LaunchMaterialSHA256     map[string]string           `json:"launchMaterialSha256"`
	MaterialReferences       []bootstrap.SecretReference `json:"materialReferences"`
	Store                    StoreIdentity               `json:"store"`
}

// CheckpointExpectation comes from the installer journal and independently
// observed local facts. The material generation must be verified separately.
// PreviousAcceptanceSHA256 is only SHA-256 of the exact old bytes: those bytes
// are never parsed or verified as an identity or signing authority here.
type CheckpointExpectation struct {
	OperationID, DeploymentID, ClusterID, Environment, Cell, SeedSlot string
	MaterialGenerationSHA256                                          string
	ManagedMaterial                                                   *bootstrap.ManagedMaterialDomain
	Broker                                                            BrokerIdentity
	Slot                                                              SlotBinding
}

// VerifiedIdentityCheckpoint can only be populated by verification.
type VerifiedIdentityCheckpoint struct {
	checkpoint  AcceptedIdentityCheckpoint
	wire        []byte
	fingerprint string
	slot        string
	expiresAt   time.Time
	verified    bool
}

// ValidateLaunchMaterialPins validates DATA inventories only; consumers must
// authenticate an original companion before using its no-SSH provenance.
func ValidateLaunchMaterialPins(pins map[string]string) error {
	if len(pins) != 4 {
		return fmt.Errorf("%w: complete public launch input pins are required", ErrCheckpointInvalid)
	}
	names := []string{"host-enrollment-public.json", "operator-ssh-key.pub", "managed-host-image-receipt.json", "managed-host-image-delegation.json"}
	if _, present := pins["original-startup-origin.json"]; present {
		names[1] = "original-startup-origin.json"
	}
	for _, name := range names {
		if !digestRE.MatchString(pins[name]) {
			return fmt.Errorf("%w: public launch input %s", ErrCheckpointInvalid, name)
		}
	}
	return nil
}
