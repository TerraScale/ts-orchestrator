package app

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
)

const maxConfigBytes = 1 << 20

// Config is the one binary's role-specific configuration. A controller and a
// host can share the same schema while holding separate credentials and files.
type Config struct {
	NATS       natscell.Config  `json:"nats"`
	Controller ControllerConfig `json:"controller"`
	Host       HostConfig       `json:"host"`
	Operator   OperatorConfig   `json:"operator"`
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
	// OfflineRestartAdmission lets a restarted production controller form
	// broker routes after local, OCI-free admission (root-owned marker, IMDS
	// instance ID, signed manifest and config digest, installed materials).
	// Full OCI restart admission and NTP still gate authority, the broker gate,
	// the founder, and every mutation. It is part of the signed controller
	// config, so enabling it is a signed operator decision. Default off.
	OfflineRestartAdmission bool `json:"offline_restart_admission,omitzero"`
}

type WorkloadProfile struct {
	Resources placement.Resources `json:"resources"`
	Args      []string            `json:"args,omitempty"`
	Env       map[string]string   `json:"env,omitempty"`
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
	Repositories                     []string `json:"repositories,omitempty"`
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
	WorkloadUID         uint32   `json:"workload_uid"`
	WorkloadGID         uint32   `json:"workload_gid"`
	PollMillis          int      `json:"poll_millis,omitzero"`
	SessionTrace        bool     `json:"session_trace,omitzero"`
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
	var cfg Config
	if err := json.Unmarshal(data, &cfg, json.RejectUnknownMembers(true)); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	return cfg, nil
}
