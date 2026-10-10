// Package identityrekey authorizes an existing cell's identity replacement
// without deriving authority from its retired bootstrap documents.
package identityrekey

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/release"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/nkeys"
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
	nameRE                = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	nodeIDRE              = regexp.MustCompile(`^[A-Za-z0-9]{8}$`)
	ociSuffixRE           = regexp.MustCompile(`^[a-z0-9-]+$`)
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

func (verified VerifiedIdentityCheckpoint) IsVerified() bool     { return verified.verified }
func (verified VerifiedIdentityCheckpoint) Fingerprint() string  { return verified.fingerprint }
func (verified VerifiedIdentityCheckpoint) Slot() string         { return verified.slot }
func (verified VerifiedIdentityCheckpoint) ExpiresAt() time.Time { return verified.expiresAt }
func (verified VerifiedIdentityCheckpoint) Wire() []byte         { return bytes.Clone(verified.wire) }
func (verified VerifiedIdentityCheckpoint) Checkpoint() AcceptedIdentityCheckpoint {
	checkpoint := verified.checkpoint
	checkpoint.Slots = slices.Clone(checkpoint.Slots)
	for i := range checkpoint.Slots {
		checkpoint.Slots[i].ConfigSHA256 = maps.Clone(checkpoint.Slots[i].ConfigSHA256)
		checkpoint.Slots[i].LaunchMaterialSHA256 = maps.Clone(checkpoint.Slots[i].LaunchMaterialSHA256)
		checkpoint.Slots[i].PreviousMaterialSHA256 = maps.Clone(checkpoint.Slots[i].PreviousMaterialSHA256)
		checkpoint.Slots[i].MaterialReferences = slices.Clone(checkpoint.Slots[i].MaterialReferences)
	}
	if checkpoint.ManagedMaterial != nil {
		checkpoint.ManagedMaterial = new(*checkpoint.ManagedMaterial)
	}
	return checkpoint
}

// AcceptanceSHA256 is the acyclic per-slot acceptance identity a signed
// MaterialGeneration pins. Config, material and previous-acceptance digests are
// excluded so it can be computed before either signed document is issued.
func (checkpoint AcceptedIdentityCheckpoint) AcceptanceSHA256(slot string) (string, error) {
	if err := checkpoint.validateAcceptance(); err != nil {
		return "", err
	}
	for _, binding := range checkpoint.Slots {
		if binding.Slot != slot {
			continue
		}
		projection := struct {
			SchemaVersion int            `json:"schemaVersion"`
			Origin        string         `json:"origin"`
			OperationID   string         `json:"operationId"`
			DeploymentID  string         `json:"deploymentId"`
			ClusterID     string         `json:"clusterId"`
			Environment   string         `json:"environment"`
			Cell          string         `json:"cell"`
			SeedSlot      string         `json:"seedSlot"`
			Broker        BrokerIdentity `json:"broker"`
			Slot          string         `json:"slot"`
			InstanceOCID  string         `json:"instanceOcid"`
			ImageOCID     string         `json:"imageOcid"`
			VNICOCID      string         `json:"primaryVnicOcid"`
			PrivateIP     string         `json:"primaryPrivateIp"`
			Binary        BinaryPin      `json:"binary"`
			Store         StoreIdentity  `json:"store"`
		}{SchemaVersion: checkpoint.SchemaVersion, Origin: AcceptanceOriginRekey, OperationID: checkpoint.OperationID,
			DeploymentID: checkpoint.DeploymentID, ClusterID: checkpoint.ClusterID, Environment: checkpoint.Environment,
			Cell: checkpoint.Cell, SeedSlot: checkpoint.SeedSlot, Broker: checkpoint.Broker, Slot: binding.Slot, InstanceOCID: binding.InstanceOCID,
			ImageOCID: binding.ImageOCID, VNICOCID: binding.PrimaryVNICOCID, PrivateIP: binding.PrimaryPrivateIP,
			Binary: binding.Binary, Store: binding.Store}
		wire, err := trust.EncodePayload(projection)
		if err != nil {
			return "", err
		}
		return sha256Hex(append([]byte(acceptanceDomain), wire...)), nil
	}
	return "", fmt.Errorf("%w: unknown controller slot", ErrCheckpointInvalid)
}

// IssueAcceptedIdentityCheckpoint signs only v1 with a bounded interval.
func IssueAcceptedIdentityCheckpoint(checkpoint AcceptedIdentityCheckpoint, issuedAt, expiresAt time.Time,
	rootPrivateKey ed25519.PrivateKey,
) (trust.Envelope, error) {
	if err := checkpoint.Validate(); err != nil {
		return trust.Envelope{}, err
	}
	if !expiresAt.After(issuedAt) || expiresAt.Sub(issuedAt) > MaxCheckpointLifetime {
		return trust.Envelope{}, fmt.Errorf("%w: invalid signature interval", ErrCheckpointInvalid)
	}
	payload, err := trust.EncodePayload(checkpoint)
	if err != nil {
		return trust.Envelope{}, err
	}
	return trust.Sign(payload, checkpoint.scope(), issuedAt, expiresAt, rootPrivateKey)
}

// VerifyAcceptedIdentityCheckpoint verifies canonical v1 wire bytes using only
// the current roots of the supplied chain. The caller pins the genesis and
// chain against its durable root/rollback policy; historical roots and delegated
// signers cannot authorize this checkpoint.
func VerifyAcceptedIdentityCheckpoint(wire []byte, genesis trust.Keyring, chain trust.RootChain,
	expected CheckpointExpectation, now time.Time,
) (VerifiedIdentityCheckpoint, error) {
	if len(wire) == 0 || len(wire) > MaxCheckpointWireBytes {
		return VerifiedIdentityCheckpoint{}, fmt.Errorf("%w: wire size", ErrCheckpointInvalid)
	}
	if !validIdentity(expected.OperationID, expected.DeploymentID, expected.ClusterID, expected.Environment, expected.Cell) ||
		!digestRE.MatchString(expected.MaterialGenerationSHA256) || expected.Broker.validate() != nil ||
		expected.Slot.validate(expected.Cell, true) != nil {
		return VerifiedIdentityCheckpoint{}, fmt.Errorf("%w: expectation", ErrCheckpointInvalid)
	}
	envelope, err := trust.DecodeEnvelope(wire)
	if err != nil {
		return VerifiedIdentityCheckpoint{}, err
	}
	roots, err := trust.VerifyRootChain(genesis, trust.ChainIdentity{DeploymentID: expected.DeploymentID,
		Cell: strings.ToLower(expected.Cell), Environment: expected.Environment}, chain)
	if err != nil {
		return VerifiedIdentityCheckpoint{}, err
	}
	identity := AcceptedIdentityCheckpoint{OperationID: expected.OperationID, DeploymentID: expected.DeploymentID,
		ClusterID: expected.ClusterID, Environment: expected.Environment, Cell: expected.Cell}
	payload, err := trust.VerifyCurrent(envelope, identity.scope(), roots.Current, now,
		trust.Policy{MaxLifetime: MaxCheckpointLifetime})
	if err != nil {
		return VerifiedIdentityCheckpoint{}, err
	}
	var checkpoint AcceptedIdentityCheckpoint
	if err := protocol.DecodeStrict(payload, &checkpoint, MaxCheckpointBytes); err != nil {
		return VerifiedIdentityCheckpoint{}, err
	}
	if err := checkpoint.Validate(); err != nil {
		return VerifiedIdentityCheckpoint{}, err
	}
	canonical, err := trust.EncodePayload(checkpoint)
	if err != nil || !bytes.Equal(canonical, payload) {
		return VerifiedIdentityCheckpoint{}, fmt.Errorf("%w: noncanonical payload", ErrCheckpointInvalid)
	}
	if checkpoint.OperationID != expected.OperationID || checkpoint.DeploymentID != expected.DeploymentID ||
		checkpoint.ClusterID != expected.ClusterID || checkpoint.Environment != expected.Environment ||
		checkpoint.Cell != expected.Cell || checkpoint.SeedSlot != expected.SeedSlot ||
		(checkpoint.ManagedMaterial == nil) != (expected.ManagedMaterial == nil) ||
		checkpoint.ManagedMaterial != nil && *checkpoint.ManagedMaterial != *expected.ManagedMaterial ||
		checkpoint.MaterialGenerationSHA256 != expected.MaterialGenerationSHA256 ||
		checkpoint.Broker != expected.Broker {
		return VerifiedIdentityCheckpoint{}, ErrCheckpointMismatch
	}
	for _, binding := range checkpoint.Slots {
		if binding.Slot != expected.Slot.Slot {
			continue
		}
		want, err := trust.EncodePayload(expected.Slot)
		got, gotErr := trust.EncodePayload(binding)
		if err != nil || gotErr != nil || !bytes.Equal(want, got) {
			return VerifiedIdentityCheckpoint{}, ErrCheckpointMismatch
		}
		return VerifiedIdentityCheckpoint{checkpoint: checkpoint, wire: bytes.Clone(wire),
			fingerprint: sha256Hex(wire), slot: expected.Slot.Slot, expiresAt: envelope.ExpiresAt, verified: true}, nil
	}
	return VerifiedIdentityCheckpoint{}, ErrCheckpointMismatch
}

func (checkpoint AcceptedIdentityCheckpoint) scope() trust.Scope {
	return trust.Scope{Domain: CheckpointDomain, DeploymentID: checkpoint.DeploymentID, Environment: checkpoint.Environment,
		Cell: checkpoint.Cell, Role: "controller", Slot: checkpoint.OperationID}
}

func (checkpoint AcceptedIdentityCheckpoint) Validate() error {
	if err := checkpoint.validateAcceptance(); err != nil {
		return err
	}
	if !digestRE.MatchString(checkpoint.MaterialGenerationSHA256) {
		return fmt.Errorf("%w: material generation fingerprint", ErrCheckpointInvalid)
	}
	if checkpoint.ManagedMaterial != nil && checkpoint.ManagedMaterial.Validate() != nil {
		return fmt.Errorf("%w: managed material domain", ErrCheckpointInvalid)
	}
	for _, binding := range checkpoint.Slots {
		if err := binding.validate(checkpoint.Cell, true); err != nil {
			return err
		}
	}
	payload, err := trust.EncodePayload(checkpoint)
	if err != nil || len(payload) > MaxCheckpointBytes {
		return fmt.Errorf("%w: payload size or encoding", ErrCheckpointInvalid)
	}
	return nil
}

func (checkpoint AcceptedIdentityCheckpoint) validateAcceptance() error {
	if checkpoint.SchemaVersion != CheckpointSchemaVersion ||
		!validIdentity(checkpoint.OperationID, checkpoint.DeploymentID, checkpoint.ClusterID, checkpoint.Environment, checkpoint.Cell) ||
		len(checkpoint.Slots) != 3 || checkpoint.Broker.validate() != nil ||
		checkpoint.SeedSlot != "controller-a" && checkpoint.SeedSlot != "controller-b" && checkpoint.SeedSlot != "controller-c" {
		return fmt.Errorf("%w: v1 identity, broker or slot count", ErrCheckpointInvalid)
	}
	for i, binding := range checkpoint.Slots {
		if binding.Slot != "controller-"+string(rune('a'+i)) || binding.validate(checkpoint.Cell, false) != nil {
			return fmt.Errorf("%w: slots must be exactly controller-a/b/c in order with valid physical bindings", ErrCheckpointInvalid)
		}
		for _, prior := range checkpoint.Slots[:i] {
			if prior.InstanceOCID == binding.InstanceOCID || prior.PrimaryVNICOCID == binding.PrimaryVNICOCID ||
				prior.PrimaryPrivateIP == binding.PrimaryPrivateIP || prior.Store.ServerName == binding.Store.ServerName ||
				prior.Store.RaftNodeID == binding.Store.RaftNodeID {
				return fmt.Errorf("%w: duplicate physical or broker target", ErrCheckpointInvalid)
			}
		}
	}
	return nil
}

func validIdentity(operation, deployment, cluster, environment, cell string) bool {
	return entityid.Valid(operation) && entityid.Valid(deployment) && entityid.Valid(cluster) &&
		release.ValidEnvironment(environment) && catalog.IsCell(cell)
}

func (broker BrokerIdentity) validate() error {
	if !nkeys.IsValidPublicOperatorKey(broker.Operator) {
		return ErrCheckpointInvalid
	}
	accounts := []string{broker.SystemAccount, broker.CellAccount, broker.HostSigner, broker.RoleSigner}
	for _, optional := range []string{broker.AccountSigner, broker.InterRegionAccount} {
		if optional != "" {
			accounts = append(accounts, optional)
		}
	}
	for i, account := range accounts {
		if !nkeys.IsValidPublicAccountKey(account) || slices.Contains(accounts[:i], account) {
			return ErrCheckpointInvalid
		}
	}
	return nil
}

func (binding SlotBinding) validate(cell string, pins bool) error {
	address, err := netip.ParseAddr(binding.PrimaryPrivateIP)
	if !slices.Contains([]string{"controller-a", "controller-b", "controller-c"}, binding.Slot) ||
		!regionalOCID(binding.InstanceOCID, "instance", cell) || !regionalOCID(binding.PrimaryVNICOCID, "vnic", cell) ||
		!release.ValidOCIImageIDForRegion(binding.ImageOCID, cell) || err != nil || !address.Is4() ||
		!address.IsPrivate() || address.String() != binding.PrimaryPrivateIP ||
		!digestRE.MatchString(binding.Binary.SHA256) || binding.Binary.Size <= 0 || binding.Binary.Size > release.MaxArtifactBytes ||
		(binding.Binary.Architecture != "amd64" && binding.Binary.Architecture != "arm64") ||
		!filepath.IsAbs(binding.Store.Directory) || filepath.Clean(binding.Store.Directory) != binding.Store.Directory ||
		binding.Store.Directory == "/" || len(binding.Store.Directory) > 1024 || strings.ContainsAny(binding.Store.Directory, "\x00\r\n") ||
		!nameRE.MatchString(binding.Store.ServerName) || !nodeIDRE.MatchString(binding.Store.RaftNodeID) ||
		!digestRE.MatchString(binding.Store.ServerNameSHA256) || !digestRE.MatchString(binding.Store.NodeIdentitySHA256) {
		return fmt.Errorf("%w: slot physical, binary or store identity", ErrCheckpointInvalid)
	}
	if pins {
		if err := ValidatePreviousMaterialPins(binding.PreviousMaterialSHA256); err != nil {
			return err
		}
		if !digestRE.MatchString(binding.PreviousAcceptanceSHA256) || len(binding.ConfigSHA256) == 0 || len(binding.ConfigSHA256) > 64 ||
			!digestRE.MatchString(binding.ConfigSHA256["controller.json"]) {
			return fmt.Errorf("%w: previous acceptance or installed controller config", ErrCheckpointInvalid)
		}
		for name, digest := range binding.ConfigSHA256 {
			if !nameRE.MatchString(name) || strings.Contains(name, "..") || !digestRE.MatchString(digest) {
				return fmt.Errorf("%w: installed config inventory", ErrCheckpointInvalid)
			}
		}
		for _, name := range bootstrap.ControllerConfigFileNames {
			if !digestRE.MatchString(binding.ConfigSHA256[name]) {
				return fmt.Errorf("%w: required controller sidecar %s", ErrCheckpointInvalid, name)
			}
		}
		if err := validateMaterialReferences(binding.MaterialReferences, binding.Slot); err != nil {
			return err
		}
		if err := ValidateLaunchMaterialPins(binding.LaunchMaterialSHA256); err != nil {
			return err
		}
	}
	return nil
}

// ValidatePreviousMaterialPins binds the two existing local chain copies as
// opaque predecessors, never as admitted generations or signing authority.
func ValidatePreviousMaterialPins(pins map[string]string) error {
	if len(pins) != 2 || !digestRE.MatchString(pins["installed"]) || !digestRE.MatchString(pins["durable"]) {
		return fmt.Errorf("%w: exact installed and durable material predecessors are required", ErrCheckpointInvalid)
	}
	return nil
}

// ValidateLaunchMaterialPins requires the exact public launch input inventory.
func ValidateLaunchMaterialPins(pins map[string]string) error {
	if len(pins) != 4 {
		return fmt.Errorf("%w: complete public launch input pins are required", ErrCheckpointInvalid)
	}
	for _, name := range []string{"host-enrollment-public.json", "operator-ssh-key.pub",
		"managed-host-image-receipt.json", "managed-host-image-delegation.json"} {
		if !digestRE.MatchString(pins[name]) {
			return fmt.Errorf("%w: public launch input %s", ErrCheckpointInvalid, name)
		}
	}
	return nil
}

func validateMaterialReferences(references []bootstrap.SecretReference, slot string) error {
	if len(references) == 0 || len(references) > 64 {
		return fmt.Errorf("%w: complete material baseline is required", ErrCheckpointInvalid)
	}
	seen := make(map[string]bool, len(references))
	for _, reference := range references {
		if reference.ValidateIdentity() != nil || seen[reference.TargetFile] || reference.Slot != "" && reference.Slot != slot {
			return fmt.Errorf("%w: material reference identity, duplicate or foreign slot", ErrCheckpointInvalid)
		}
		seen[reference.TargetFile] = true
		switch reference.Purpose {
		case bootstrap.SecretRegionalShared:
			if reference.Slot != "" {
				return fmt.Errorf("%w: slot-bound shared material", ErrCheckpointInvalid)
			}
		case bootstrap.SecretHostIssuer:
			if reference.Slot != "" || !slices.Contains([]string{"host-nats-issuer.seed", "host-tls-issuer-key.pem",
				"host-tls-issuer-cert.pem", "terrabase-member-ca.pem", "terrabase-member-ca.key"}, reference.TargetFile) {
				return fmt.Errorf("%w: host issuer material role", ErrCheckpointInvalid)
			}
		case bootstrap.SecretControllerIssuer:
			if reference.Slot != "" || bootstrap.MaterialGenerationFiles()[reference.TargetFile] != reference.Purpose {
				return fmt.Errorf("%w: controller issuer material role", ErrCheckpointInvalid)
			}
		case bootstrap.SecretController:
			if reference.Slot != slot {
				return fmt.Errorf("%w: controller material must be slot-bound", ErrCheckpointInvalid)
			}
		case bootstrap.SecretInterRegion:
			cert, key := bootstrap.InterRegionTLSFiles(slot)
			if reference.Slot != "" && reference.TargetFile != cert && reference.TargetFile != key ||
				reference.Slot == "" && reference.TargetFile != "interregion.jwt" && reference.TargetFile != "interregion-ca.pem" &&
					!(strings.HasPrefix(reference.TargetFile, "leaf-") && strings.HasSuffix(reference.TargetFile, ".creds")) {
				return fmt.Errorf("%w: interregion material role", ErrCheckpointInvalid)
			}
		default:
			return fmt.Errorf("%w: obsolete or unknown material purpose", ErrCheckpointInvalid)
		}
		if slices.Contains([]string{"issuer-operator.seed", "issuer-system.seed", "issuer-cell.seed", "issuer-ca.key",
			"operator.creds", "operator-tls-cert.pem", "operator-tls-key.pem", "interregion-ca.key"}, reference.TargetFile) {
			return fmt.Errorf("%w: offline signing material", ErrCheckpointInvalid)
		}
	}
	return nil
}

func regionalOCID(value, resource, cell string) bool {
	parts := strings.Split(value, ".")
	return len(value) <= 255 && len(parts) == 5 && parts[0] == "ocid1" && parts[1] == resource && parts[2] == "oc1" &&
		parts[3] == catalog.OCIRegion(cell) && ociSuffixRE.MatchString(parts[4])
}

func sha256Hex(wire []byte) string {
	digest := sha256.Sum256(wire)
	return hex.EncodeToString(digest[:])
}
