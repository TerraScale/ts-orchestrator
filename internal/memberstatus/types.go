// Package memberstatus consumes the root-only TerraBase member control API.
// Every observation is bound to an independently verified process and signed
// member identity before it can be used as lifecycle evidence.
package memberstatus

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strings"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
)

type Process struct {
	PID        int    `json:"pid"`
	StartNonce string `json:"start_nonce"`
}

type Scope struct {
	ClusterID   string `json:"cluster_id"`
	TenantID    string `json:"tenant_id"`
	DatabaseID  string `json:"database_id"`
	ShardID     uint64 `json:"shard_id"`
	MemberID    string `json:"member_id"`
	Incarnation string `json:"incarnation"`
}

type Authority struct {
	Epoch             uint64 `json:"epoch"`
	ConfigurationID   string `json:"configuration_id"`
	CertificateSHA256 string `json:"certificate_sha256"`
	TLSLeafSHA256     string `json:"tls_leaf_sha256"`
}

type Identity struct {
	Process   Process   `json:"process"`
	Scope     Scope     `json:"scope"`
	Authority Authority `json:"authority"`
}

type Local struct {
	StorageRecovered         bool `json:"storage_recovered"`
	ReplicationListenerReady bool `json:"replication_listener_ready"`
	Healthy                  bool `json:"healthy"`
	Ready                    bool `json:"ready"`
}

type Capabilities struct {
	ServingProof bool `json:"serving_proof"`
	DurableDrain bool `json:"durable_drain"`
}

type Status struct {
	SchemaVersion        uint64       `json:"schema_version"`
	Nonce                string       `json:"nonce"`
	Process              Process      `json:"process"`
	Scope                Scope        `json:"scope"`
	Authority            Authority    `json:"authority"`
	Local                Local        `json:"local"`
	ReceiverOnly         bool         `json:"receiver_only"`
	Serving              bool         `json:"serving"`
	Capabilities         Capabilities `json:"capabilities"`
	CredentialGeneration uint64       `json:"client_credential_generation,omitzero"`
	// Load is optional operational telemetry; see Load.
	Load     *Load `json:"load,omitempty"`
	verified bool
}

type Listeners struct {
	Client      bool `json:"client"`
	Replication bool `json:"replication"`
}

type ObjectProof struct {
	RootSHA256                   string `json:"root_sha256"`
	TargetSHA256                 string `json:"target_sha256"`
	NativeCommitSeqAtRecovery    uint64 `json:"native_commit_seq_at_recovery"`
	InboxArchiveSHA256AtRecovery string `json:"inbox_archive_sha256_at_recovery"`
	LocalSourceSequence          uint64 `json:"local_source_sequence"`
	RemoteInboxDurableSequence   uint64 `json:"remote_inbox_durable_sequence"`
	RemoteAppliedSequence        uint64 `json:"remote_applied_sequence"`
}

// ReplicationProof carries both directions' received, durable and applied
// prefixes. TerraBase releases before the received prefixes omit them.
type ReplicationProof struct {
	LocalSourceSequence        uint64  `json:"local_source_sequence"`
	PeerMemberID               string  `json:"peer_member_id"`
	PeerIncarnation            string  `json:"peer_incarnation"`
	CurrentAuthenticated       bool    `json:"current_authenticated"`
	PeerReceivedSequence       *uint64 `json:"peer_received_sequence,omitzero"`
	PeerDurableSequence        uint64  `json:"peer_durable_sequence"`
	PeerAppliedSequence        uint64  `json:"peer_applied_sequence"`
	LocalInboxReceivedSequence *uint64 `json:"local_inbox_received_sequence,omitzero"`
	LocalInboxDurableSequence  uint64  `json:"local_inbox_durable_sequence"`
	LocalInboxAppliedSequence  uint64  `json:"local_inbox_applied_sequence"`
}

// ordered reports whether each direction's prefixes satisfy
// received >= durable >= applied. Both received prefixes are present, or both
// are omitted by an older TerraBase release.
func (r ReplicationProof) ordered() bool {
	return (r.PeerReceivedSequence == nil) == (r.LocalInboxReceivedSequence == nil) &&
		r.PeerAppliedSequence <= r.PeerDurableSequence &&
		(r.PeerReceivedSequence == nil || r.PeerDurableSequence <= *r.PeerReceivedSequence) &&
		r.LocalInboxAppliedSequence <= r.LocalInboxDurableSequence &&
		(r.LocalInboxReceivedSequence == nil || r.LocalInboxDurableSequence <= *r.LocalInboxReceivedSequence)
}

type ServingProof struct {
	SchemaVersion uint64           `json:"schema_version"`
	Nonce         string           `json:"nonce"`
	Process       Process          `json:"process"`
	Scope         Scope            `json:"scope"`
	Authority     Authority        `json:"authority"`
	Serving       bool             `json:"serving"`
	Listeners     Listeners        `json:"listeners"`
	Object        ObjectProof      `json:"object"`
	Replication   ReplicationProof `json:"replication"`
	verified      bool
}

type Origin struct {
	MemberID    string `json:"member_id"`
	Incarnation string `json:"incarnation"`
}

type DrainRequest struct {
	SchemaVersion uint64   `json:"schema_version"`
	OperationID   string   `json:"operation_id"`
	Nonce         string   `json:"nonce"`
	Expected      Identity `json:"expected"`
}

type DrainPeer struct {
	Origin                    Origin `json:"origin"`
	DurableSequence           uint64 `json:"durable_sequence"`
	AppliedSequence           uint64 `json:"applied_sequence"`
	LocalInboxDurableSequence uint64 `json:"local_inbox_durable_sequence"`
	LocalInboxAppliedSequence uint64 `json:"local_inbox_applied_sequence"`
}

type DrainReceipt struct {
	SchemaVersion              uint64    `json:"schema_version"`
	OperationID                string    `json:"operation_id"`
	RequestNonce               string    `json:"request_nonce"`
	RequestedProcess           Process   `json:"requested_process"`
	DrainedProcess             Process   `json:"drained_process"`
	Scope                      Scope     `json:"scope"`
	Authority                  Authority `json:"authority"`
	LocalSourceOrigin          Origin    `json:"local_source_origin"`
	LocalSourceDurableSequence uint64    `json:"local_source_durable_sequence"`
	ArchivedSourceSequence     uint64    `json:"archived_source_sequence"`
	ObjectRootSHA256           string    `json:"object_root_sha256"`
	Peer                       DrainPeer `json:"peer"`
	ReplicationQuiesced        bool      `json:"replication_quiesced"`
}

type DrainEnvelope struct {
	SchemaVersion uint64        `json:"schema_version"`
	Nonce         string        `json:"nonce"`
	Process       Process       `json:"process"`
	OperationID   string        `json:"operation_id"`
	State         string        `json:"state"`
	ReceiptSHA256 *string       `json:"receipt_sha256"`
	Receipt       *DrainReceipt `json:"receipt"`
}

// Survivor is the named peer that must have acknowledged the source event
// frontier. Its identity must come from the signed placement assignment.
type Survivor struct {
	MemberID    string `json:"member_id"`
	Incarnation string `json:"incarnation"`
}

func (s Scope) valid() bool {
	return entityid.Valid(s.ClusterID) && entityid.Valid(s.Incarnation) && s.ShardID != 0 &&
		canonicalID(s.TenantID) && canonicalID(s.DatabaseID) && canonicalID(s.MemberID)
}

func (a Authority) valid() bool {
	return a.Epoch != 0 && lowerHex(a.ConfigurationID, 64) &&
		lowerHex(a.CertificateSHA256, 64) && lowerHex(a.TLSLeafSHA256, 64)
}

func (p Process) valid() bool { return p.PID >= 2 && entityid.Valid(p.StartNonce) }

func (s Survivor) valid() bool {
	return canonicalID(s.MemberID) && entityid.Valid(s.Incarnation)
}

func lowerHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for i := range len(value) {
		if value[i] < '0' || value[i] > '9' {
			if value[i] < 'a' || value[i] > 'f' {
				return false
			}
		}
	}
	return true
}

func canonicalID(value string) bool { return entityid.Valid(value) }

// decodeRequired rejects duplicate, unknown, null, and absent contract fields.
func decodeRequired(data []byte, into any, paths ...string) error {
	if err := json.Unmarshal(data, into, json.RejectUnknownMembers(true)); err != nil {
		return fmt.Errorf("decode member evidence: %w", err)
	}
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		return fmt.Errorf("decode member fields: %w", err)
	}
	for _, path := range paths {
		current := any(root)
		for _, part := range splitPath(path) {
			object, ok := current.(map[string]any)
			if !ok {
				return fmt.Errorf("member evidence omits %s", path)
			}
			current, ok = object[part]
			if !ok || current == nil {
				return fmt.Errorf("member evidence omits %s", path)
			}
		}
	}
	return nil
}

// rejectNull rejects an explicit JSON null at any present optional path.
func rejectNull(data []byte, paths ...string) error {
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		return fmt.Errorf("decode member fields: %w", err)
	}
	for _, path := range paths {
		current, present := any(root), true
		for _, part := range splitPath(path) {
			object, ok := current.(map[string]any)
			if !ok {
				present = false
				break
			}
			if current, ok = object[part]; !ok {
				present = false
				break
			}
		}
		if present && current == nil {
			return fmt.Errorf("member evidence has null %s", path)
		}
	}
	return nil
}

func requirePresent(data []byte, paths ...string) error {
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		return err
	}
	for _, path := range paths {
		current := any(root)
		for _, part := range splitPath(path) {
			object, ok := current.(map[string]any)
			if !ok {
				return fmt.Errorf("member evidence omits %s", path)
			}
			current, ok = object[part]
			if !ok {
				return fmt.Errorf("member evidence omits %s", path)
			}
		}
	}
	return nil
}

func splitPath(path string) []string {
	return strings.Split(path, ".")
}

func (r DrainReceipt) digest() (string, error) {
	data, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

var ErrNotServing = errors.New("member is not serving with current proof")
var ErrStaleBinding = errors.New("member process or authority binding changed")
var ErrOperationConflict = errors.New("member drain operation conflicts with persisted intent")
var ErrOutcomeUnknown = errors.New("member drain outcome requires reconciliation")
