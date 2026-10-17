// Package protocol is the private SSH wire contract for disposable NetBird image tests.
package protocol

import (
	"encoding/json/jsontext"

	native "github.com/TerraScale/ts-orchestrator/tests/imagequalification/host"
)

// Command credentials travel through authenticated SSH stdin and are never evidence.
type Command struct {
	Operation      string         `json:"operation"`
	RunID          string         `json:"run_id"`
	SourceRevision string         `json:"source_revision"`
	Host           native.Host    `json:"host"`
	ContainerdPath string         `json:"containerd_path,omitempty"`
	RuncPath       string         `json:"runc_path,omitempty"`
	Artifacts      []Artifact     `json:"artifacts,omitempty"`
	ClientSHA256   string         `json:"client_sha256,omitempty"`
	Private        jsontext.Value `json:"private,omitempty"`
}

type Artifact struct {
	Role          string `json:"role"`
	Image         string `json:"image"`
	ArchiveSHA256 string `json:"archive_sha256"`
}

// Account records upstream identifiers and observed access, without PATs or keys.
type Account struct {
	AccountID             string   `json:"account_id"`
	OwnerID               string   `json:"owner_id"`
	ServiceID             string   `json:"service_id"`
	ServiceTokenID        string   `json:"service_token_id"`
	PeerID                string   `json:"peer_id"`
	PeerKeySHA256         string   `json:"peer_key_sha256"`
	PeerAddress           string   `json:"peer_address"`
	PolicyIDs             []string `json:"policy_ids"`
	PolicySHA256          string   `json:"policy_sha256"`
	UnrestrictedPolicyIDs []string `json:"unrestricted_policy_ids,omitempty"`
	StoreID               string   `json:"store_id"`
	SetupHTTPStatus       int      `json:"setup_http_status"`
	ServiceHTTPStatus     int      `json:"service_http_status"`
	PeerHTTPStatus        int      `json:"peer_http_status"`
}

type Component struct {
	Name       string `json:"name"`
	Image      string `json:"image"`
	PID        uint32 `json:"pid"`
	Containers int    `json:"containers"`
}

type Copy struct {
	Region string `json:"region"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

// Observation is generated from native process, HTTP and persistent-store state.
// Validation compares these values across operations; a worker cannot return a gate boolean.
type Observation struct {
	Identity             native.Identity `json:"identity"`
	WorkerSHA256         string          `json:"worker_sha256"`
	WorkerSourceRevision string          `json:"worker_source_revision"`
	Account              Account         `json:"account"`
	Components           []Component     `json:"components"`
	BackupObject         string          `json:"backup_object,omitempty"`
	BackupSHA256         string          `json:"backup_sha256,omitempty"`
	BackupBytes          int64           `json:"backup_bytes,omitzero"`
	BackupRegions        []string        `json:"backup_regions,omitempty"`
	BackupStorage        string          `json:"backup_storage,omitempty"`
	BackupCopies         []Copy          `json:"backup_copies,omitempty"`
	RestoredSHA256       string          `json:"restored_sha256,omitempty"`
	CredentialVersion    string          `json:"credential_version,omitempty"`
	DeniedHTTPStatus     int             `json:"denied_http_status,omitzero"`
	TLSProtocol          string          `json:"tls_protocol,omitempty"`
	TLSAuthority         string          `json:"tls_authority,omitempty"`
	GRPCStatus           string          `json:"grpc_status,omitempty"`
	STUNTransaction      string          `json:"stun_transaction,omitempty"`
}

type Response struct {
	Observation Observation    `json:"observation"`
	Private     jsontext.Value `json:"private,omitempty"`
	Error       string         `json:"error,omitempty"`
}
