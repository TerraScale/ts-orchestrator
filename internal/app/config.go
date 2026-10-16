package app

import (
	"errors"
	"fmt"
	"os"

	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/machinesapi"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

const maxConfigBytes = 1 << 20

// ConfigVersion is the only supported role-config contract.
// Removed settings must be deleted from signed configs before rollout.
const ConfigVersion = 1

// Config is the one binary's role-specific configuration. A controller and a
// host can share the same schema while holding separate credentials and files.
type Config struct {
	// Version must explicitly name ConfigVersion; unknown members are rejected.
	Version       int                  `json:"version"`
	NATS          natscell.Config      `json:"nats"`
	Controller    ControllerConfig     `json:"controller"`
	Host          HostConfig           `json:"host"`
	Operator      OperatorConfig       `json:"operator"`
	Observability observability.Config `json:"observability,omitzero"`
	// wire is the exact bytes the config was read from. A signed controller
	// config's digest covers them, not a re-encoding, so a binary with a new
	// or defaulted member still matches the signature.
	wire []byte
}

type ControllerConfig struct {
	CandidateID                 string                     `json:"candidate_id"`
	ArtifactStoreMaxBytes       int64                      `json:"artifact_store_max_bytes,omitzero"`
	LeaseSeconds                int                        `json:"lease_seconds,omitzero"`
	RenewSeconds                int                        `json:"renew_seconds,omitzero"`
	ResponseKeyFile             string                     `json:"response_key_file,omitempty"`
	BrokerTicketKeyFile         string                     `json:"broker_ticket_key_file,omitempty"`
	HostNATSIssuerSeedFile      string                     `json:"host_nats_issuer_seed_file,omitempty"`
	HostTLSIssuerKeyFile        string                     `json:"host_tls_issuer_key_file,omitempty"`
	HostTLSIssuerCertFile       string                     `json:"host_tls_issuer_cert_file,omitempty"`
	HostEnrollmentListenAddress string                     `json:"host_enrollment_listen_address,omitempty"`
	TrustKeyFile                string                     `json:"trust_key_file,omitempty"`
	OciRegionConfig             string                     `json:"oci_region_config,omitempty"`
	OciRegionIntentFile         string                     `json:"oci_region_intent_file,omitempty"`
	PlacementConfig             string                     `json:"placement_config,omitempty"`
	TrustedSigners              []TrustedSignerConfig      `json:"trusted_signers,omitempty"`
	Workloads                   map[string]WorkloadProfile `json:"workloads,omitempty"`
	// TerraBaseCACertFile and TerraBaseCAKeyFile are the cell's C# TerraBase
	// member CA (ts-orch terrabase member-ca). Hosts' member certificate
	// requests are refused while they are unset.
	TerraBaseCACertFile string `json:"terrabase_ca_cert_file,omitempty"`
	TerraBaseCAKeyFile  string `json:"terrabase_ca_key_file,omitempty"`
	// OciReconcile enables the declarative OCI resource reconcilers; nil or
	// disabled keeps them off.
	OciReconcile *OciReconcileConfig `json:"oci_reconcile,omitempty"`
	// TerraBaseSeats restarts static TerraBase members one seat at a time,
	// drained on the public load balancer first (TS-571). Off when nil or
	// not enabled.
	TerraBaseSeats *TerraBaseSeatsConfig `json:"terrabase_seats,omitempty"`
	// SelfUpdateProofFile is where a ready controller writes the version
	// proof for a pending self-update activation, signed with its response
	// key; empty means selfupdate.DefaultProofFile, which the image's
	// watchdog reads.
	SelfUpdateProofFile string `json:"self_update_proof_file,omitempty"`
	// SelfUpdateRoot is the release root the selfupdate prepare and watchdog
	// steps use (their --root); empty means selfupdate.DefaultRoot.
	SelfUpdateRoot string `json:"self_update_root,omitempty"`
	// ManagedHostImageReceiptFile and ManagedHostImageDelegationFile, when
	// both set, qualify the managed-host image from its own root-delegated
	// image receipt instead of the controller's accepted boot image, so
	// hosts can move to a newer qualified image independently.
	ManagedHostImageReceiptFile    string           `json:"managed_host_image_receipt_file,omitempty"`
	ManagedHostImageDelegationFile string           `json:"managed_host_image_delegation_file,omitempty"`
	Autoscale                      *AutoscaleConfig `json:"autoscale,omitempty"`
	// Global optionally pins the home derived from the signed interregion
	// topology; global control always starts.
	Global    *GlobalControlConfig `json:"global,omitempty"`
	SpecTrust *SpecTrustConfig     `json:"spec_trust,omitempty"`
	// MachinesAPI serves the Machines REST API (docs/machines-api.md); nil
	// keeps it off.
	MachinesAPI *machinesapi.Config `json:"machines_api,omitempty"`
}

// WorkloadProfile is the cell spec's profile type, so a signed controller
// config and a signed cell spec describe a role the same way.
type WorkloadProfile = cellspec.Profile

// SpecTrustConfig lets a lab controller, which has no image trust roots,
// verify cell specs. Signed production configs refuse it: production
// controllers use the image's baked roots and deployment identity.
type SpecTrustConfig struct {
	RootPublicKeyFile string `json:"root_public_key_file"`
	DeploymentID      string `json:"deployment_id"`
	Environment       string `json:"environment"`
}

// TrustedSignerConfig is the cell spec's signer type, so the signed config
// and a cell spec signers section grant actors alike.
type TrustedSignerConfig = cellspec.TrustedSigner

type OperatorConfig struct {
	Actor                     string `json:"actor"`
	SigningKeyFile            string `json:"signing_key_file"`
	ControllerPublicKey       string `json:"controller_public_key,omitempty"`
	BrokerTicketPublicKeyFile string `json:"broker_ticket_public_key_file,omitempty"`
}

type HostConfig struct {
	Node                string   `json:"node"`
	Environment         string   `json:"environment"`
	Roles               []string `json:"roles"`
	IdentityKeyFile     string   `json:"identity_key_file"`
	ControllerPublicKey string   `json:"controller_public_key"`
	InstallRoot         string   `json:"install_root"`
	StateRoot           string   `json:"state_root"`
	ManagedRuntimeRoot  string   `json:"managed_runtime_root,omitempty"`
	TerraBaseRoot       string   `json:"terrabase_root,omitempty"` // C# TerraBase member data and TLS files.
	TSAuthRoot          string   `json:"ts_auth_root,omitempty"`   // ts-auth's extracted libraries.
	WorkloadUID         uint32   `json:"workload_uid"`
	WorkloadGID         uint32   `json:"workload_gid"`
	PollMillis          int      `json:"poll_millis,omitzero"`
	// TerraBaseDataVolume keeps the C# member's data directory on its OCI
	// block volume (<node>-data at /dev/oracleoci/oraclevdb), mounted by the
	// root volume initializer; the member never starts without it.
	TerraBaseDataVolume   bool   `json:"terrabase_data_volume,omitzero"`
	TerraBaseDataVolumeID string `json:"terrabase_data_volume_id,omitempty"`
	// SelfUpdateProofFile is where a started host agent writes the version
	// proof for a pending self-update activation, signed with its identity
	// key; empty means selfupdate.DefaultProofFile, which the image's
	// watchdog reads.
	SelfUpdateProofFile string `json:"self_update_proof_file,omitempty"`
	// SelfUpdateRoot is the release root the selfupdate prepare and watchdog
	// steps use (their --root); empty means selfupdate.DefaultRoot.
	SelfUpdateRoot string `json:"self_update_root,omitempty"`
	// RoleMemoryMaxBytes caps a native role's cgroup memory.max on this host
	// from its next start (TS-578), for example terrabase and ts-auth beside
	// a controller, so neither can push the controller's NATS into the OOM
	// killer. A role without an entry keeps the unlimited default.
	RoleMemoryMaxBytes map[string]uint64 `json:"role_memory_max_bytes,omitempty"`
}

func LoadConfig(path string) (Config, error) {
	if path == "" {
		return Config{}, errors.New("--config is required")
	}
	info, err := os.Stat(path)
	if err != nil {
		return Config{}, fmt.Errorf("stat config: %w", err)
	}
	if info.Size() > maxConfigBytes {
		return Config{}, errors.New("config is too large")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	cfg, err := decodeConfig(data)
	if err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	if err := cfg.Observability.Validate(); err != nil {
		return Config{}, fmt.Errorf("observability config: %w", err)
	}
	if api := cfg.Controller.MachinesAPI; api != nil {
		if err := api.Validate(); err != nil {
			return Config{}, err
		}
	}
	return cfg, nil
}

// decodeConfig strictly decodes config bytes and keeps them as the config's wire.
func decodeConfig(data []byte) (Config, error) {
	var cfg Config
	if err := protocol.DecodeStrict(data, &cfg, maxConfigBytes); err != nil {
		return Config{}, err
	}
	if cfg.Version != ConfigVersion {
		return Config{}, fmt.Errorf("config version must be %d, got %d", ConfigVersion, cfg.Version)
	}
	cfg.wire = data
	return cfg, nil
}

// signedWire returns the exact bytes the config was read from, or its
// canonical encoding when code built it.
func (c Config) signedWire() ([]byte, error) {
	if c.wire != nil {
		return c.wire, nil
	}
	if c.Version != 0 && c.Version != ConfigVersion {
		return nil, fmt.Errorf("unsupported config version %d; want %d", c.Version, ConfigVersion)
	}
	c.Version = ConfigVersion
	return protocol.EncodeJSON(c)
}
