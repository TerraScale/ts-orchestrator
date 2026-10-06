package app

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/cellspec"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/kvsnapshot"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/machinesapi"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/membership"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/storage/backup"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/storage/capacity"
)

const maxConfigBytes = 1 << 20

// ConfigVersion is the config schema this binary writes. Raise it with every
// new member (TestConfigVersionCoversEveryMember names the digest to record):
// an older binary then skips the members it lacks instead of refusing them as
// typos. Never rename or remove a member; an older config still names it.
const ConfigVersion = 2

// Config is the one binary's role-specific configuration. A controller and a
// host can share the same schema while holding separate credentials and files.
type Config struct {
	// Version is the ConfigVersion of the binary that wrote the config. A
	// binary decodes a config of its own version or older strictly and skips
	// the unknown members of a newer one, so a rolled-back binary starts.
	Version    int              `json:"version,omitzero"`
	NATS       natscell.Config  `json:"nats"`
	Controller ControllerConfig `json:"controller"`
	Host       HostConfig       `json:"host"`
	Operator   OperatorConfig   `json:"operator"`
	// Observability is omitted when zero, so configs signed before it
	// existed keep their exact canonical bytes.
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
	// OfflineRestartAdmission lets a restarted production controller form
	// broker routes after local, OCI-free admission (root-owned marker, IMDS
	// instance ID, signed manifest and config digest, installed materials).
	// Full OCI restart admission and NTP still gate authority, the broker gate,
	// the founder, and every mutation. It is part of the signed controller
	// config, so enabling it is a signed operator decision. Default off.
	//
	// It applies to controller process restarts, where the install and
	// bootstrap oneshots stay active. A VM reboot still reruns those units,
	// which require systemd-time-wait-sync and verify the signed config
	// against the wall clock, so a reboot without NTP does not reach the
	// offline path; relaxing those boot units is a separate trust decision.
	OfflineRestartAdmission bool `json:"offline_restart_admission,omitzero"`
	// StorageCapacity publishes this node's boot root and JetStream StoreDir
	// usage to the regional TTL'd usage bucket. Off by default.
	StorageCapacity capacity.Config `json:"storage_capacity,omitzero"`
	// VolumeBackup applies the OCI volume backup policy to placed members'
	// retained volumes on the authority leader. Off by default.
	VolumeBackup backup.Policy `json:"volume_backup,omitzero"`
	// OciObserveVerifyCacheSeconds lets placement's periodic Observe reuse a
	// member host's boot volume and VNIC verification while its instance ETag
	// is unchanged, for at most this many seconds (0 disables, max 60).
	OciObserveVerifyCacheSeconds int `json:"oci_observe_verify_cache_seconds,omitzero"`
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
	ManagedHostImageReceiptFile    string `json:"managed_host_image_receipt_file,omitempty"`
	ManagedHostImageDelegationFile string `json:"managed_host_image_delegation_file,omitempty"`
	// Membership enables controller slot supervision; nil keeps it off.
	Membership *membership.Config `json:"membership,omitempty"`
	Autoscale  *AutoscaleConfig   `json:"autoscale,omitempty"`
	// Global enables the global control plane; nil or disabled keeps every
	// region standalone, exactly as before.
	Global *GlobalControlConfig `json:"global,omitempty"`
	// Rollouts opens the rollout store for the dashboard and insights; nil
	// or disabled keeps it off.
	Rollouts *RolloutsConfig `json:"rollouts,omitempty"`
	// RegionPlanner runs the region planner in the global home; nil or
	// disabled keeps it off.
	RegionPlanner *RegionPlannerConfig `json:"region_planner,omitempty"`
	SpecTrust     *SpecTrustConfig     `json:"spec_trust,omitempty"`
	// KVSnapshot keeps the configuration KV buckets in OCI Object Storage
	// and restores them into a rebuilt cell. Off by default.
	KVSnapshot kvsnapshot.Config `json:"kv_snapshot,omitzero"`
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

type TrustedSignerConfig struct {
	Actor                            string   `json:"actor"`
	PublicKey                        string   `json:"public_key"`
	Roles                            []string `json:"roles"`
	Environments                     []string `json:"environments"`
	CanRegisterHosts                 bool     `json:"can_register_hosts,omitzero"`
	CanPlaceTerraBase                bool     `json:"can_place_terrabase,omitzero"`
	CanUpdateTerraBaseRuntime        bool     `json:"can_update_terrabase_runtime,omitzero"`
	CanCertifyTerraBaseCompatibility bool     `json:"can_certify_terrabase_compatibility,omitzero"`
	CanTeardownTerraBase             bool     `json:"can_teardown_terrabase,omitzero"`
	CanPrepareManagedMaterial        bool     `json:"can_prepare_managed_material,omitzero"`
	CanOperateBackup                 bool     `json:"can_operate_backup,omitzero"`
	CanManageClientKeys              bool     `json:"can_manage_client_keys,omitzero"`
	ClientKeyScopes                  []string `json:"client_key_scopes,omitempty"`
	CanRotateBrokerAccount           bool     `json:"can_rotate_broker_account,omitzero"`
	// CanRollOutOrchestrator lets the signer publish, pause, resume and roll
	// back the cell's orchestrator release (ts-orch rollout).
	CanRollOutOrchestrator bool     `json:"can_roll_out_orchestrator,omitzero"`
	Repositories           []string `json:"repositories,omitempty"`
}

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
	SessionTrace        bool     `json:"session_trace,omitzero"`
	// TerraBaseDataVolume keeps the C# member's data directory on its OCI
	// block volume (<node>-data at /dev/oracleoci/oraclevdb), mounted by the
	// root volume initializer; the member never starts without it.
	TerraBaseDataVolume   bool   `json:"terrabase_data_volume,omitzero"`
	TerraBaseDataVolumeID string `json:"terrabase_data_volume_id,omitempty"`
	// ManagedVolumeOnlineGrow lets the root volume initializer grow a managed
	// member filesystem to its resized OCI volume. Off by default; the C#
	// TerraBase data volume always grows.
	ManagedVolumeOnlineGrow bool `json:"managed_volume_online_grow,omitzero"`
	// SelfUpdateProofFile is where a started host agent writes the version
	// proof for a pending self-update activation, signed with its identity
	// key; empty means selfupdate.DefaultProofFile, which the image's
	// watchdog reads.
	SelfUpdateProofFile string `json:"self_update_proof_file,omitempty"`
	// SelfUpdateRoot is the release root the selfupdate prepare and watchdog
	// steps use (their --root); empty means selfupdate.DefaultRoot.
	SelfUpdateRoot string `json:"self_update_root,omitempty"`
	// LoadTelemetrySeconds, when nonzero (5..3600), makes the host agent
	// publish cgroup, disk and TerraBase load to its controller that often.
	// Off by default; the controller also needs
	// controller.autoscale.host_telemetry to accept it.
	LoadTelemetrySeconds int `json:"load_telemetry_seconds,omitzero"`
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
	if err := cfg.Controller.KVSnapshot.Validate(); err != nil {
		return Config{}, err
	}
	if api := cfg.Controller.MachinesAPI; api != nil {
		if err := api.Validate(); err != nil {
			return Config{}, err
		}
	}
	return cfg, nil
}

// decodeConfig decodes config bytes, strictly unless a newer binary wrote
// them, and keeps them as the config's wire.
func decodeConfig(data []byte) (Config, error) {
	var header struct {
		Version int `json:"version"`
	}
	_ = json.Unmarshal(data, &header)
	decode := protocol.DecodeStrict
	if header.Version > ConfigVersion {
		slog.Warn("config is newer than this binary; skipping the members it does not know",
			"config_version", header.Version, "binary_config_version", ConfigVersion)
		decode = protocol.DecodeTolerant
	}
	var cfg Config
	if err := decode(data, &cfg, maxConfigBytes); err != nil {
		return Config{}, err
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
	return protocol.EncodeJSON(c)
}
