package nodeauthority

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"terrascale.tech/orchestrator/src/orchestrator/control/authority"
	"terrascale.tech/orchestrator/src/orchestrator/protocol"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

// SignedNodeCommand is the payload of the existing signed command envelope.
// The complete payload binds the host, NATS subject and exact lease holder.
type SignedNodeCommand struct {
	NodeID      string          `json:"nodeId"`
	Subject     string          `json:"subject"`
	AuthorityID string          `json:"authorityId"`
	CandidateID string          `json:"candidateId"`
	LeaseID     string          `json:"leaseId"`
	Command     json.RawMessage `json:"command"`
}

type CommandAuthorization struct {
	BootstrapGrantSHA256    string
	BootstrapManifestSHA256 string
	NodeID                  string
	AuthorityID             string
	Epoch                   int64
	CandidateID             string
	LeaseID                 string
	Command                 []byte
	ExpiresAt               time.Time
}

// CommandAuthorizer is mandatory at the receiver. Production composition uses
// RegionalCommandAuthorizer; test doubles belong in test files only.
type CommandAuthorizer interface {
	Authorize(context.Context, string, []byte) (CommandAuthorization, error)
}

type CommandAuthorityConfig struct {
	Connection *nats.Conn
	NodeID     string
	Bucket     string
	Trust      *security.CommandSignatureVerifier
	// SignerCandidates binds each admitted signing key fingerprint to one exact
	// authority candidate ID. Possession of another candidate's key is insufficient.
	SignerCandidates map[string]string
}

type RegionalCommandAuthorizer struct{ config CommandAuthorityConfig }

func NewRegionalCommandAuthorizer(config CommandAuthorityConfig) (*RegionalCommandAuthorizer, error) {
	if config.Connection == nil || config.Trust == nil || len(config.SignerCandidates) == 0 || len(config.SignerCandidates) > 4 || !authorityBucket(config.Bucket) {
		return nil, errors.New("nodeauthority: command trust, candidate bindings and authority bucket are required")
	}
	if len(config.NodeID) > 63 || !regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`).MatchString(config.NodeID) {
		return nil, errors.New("nodeauthority: invalid host identity")
	}
	copied := make(map[string]string, len(config.SignerCandidates))
	for key, candidate := range config.SignerCandidates {
		_, keyErr := hex.DecodeString(key)
		if len(key) != 64 || keyErr != nil || key != strings.ToLower(key) || candidate == "" || len(candidate) > 256 {
			return nil, errors.New("nodeauthority: invalid command signer candidate binding")
		}
		copied[key] = candidate
	}
	config.SignerCandidates = copied
	if err := commandAuthorityTLS(config.Connection); err != nil {
		return nil, err
	}
	return &RegionalCommandAuthorizer{config: config}, nil
}
func authorityBucket(bucket string) bool {
	if len(bucket) == 0 || len(bucket) > 128 {
		return false
	}
	for _, r := range bucket {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}
func commandAuthorityTLS(connection *nats.Conn) error {
	if connection == nil || !connection.IsConnected() || !connection.AuthRequired() || connection.Opts.TLSConfig == nil || connection.Opts.TLSConfig.InsecureSkipVerify || (len(connection.Opts.TLSConfig.Certificates) == 0 && connection.Opts.TLSConfig.GetClientCertificate == nil && connection.Opts.TLSCertCB == nil) || (connection.Opts.AllowReconnect && connection.Opts.ReconnectBufSize >= 0) || connection.Opts.SignatureCB == nil || (connection.Opts.Nkey == "" && connection.Opts.UserJWT == nil) {
		return errors.New("nodeauthority: authority reads require authenticated verified NATS TLS")
	}
	state, err := connection.TLSConnectionState()
	if err != nil || state.Version != tls.VersionTLS13 || len(state.VerifiedChains) == 0 {
		return errors.New("nodeauthority: authority reads require TLS 1.3")
	}
	return nil
}

// ReadRegionalCommandLease uses the ordinary stream MSG.GET API. The pinned
// NATS server routes it to the assigned stream leader; KV.Get can use a follower
// direct-read path and is deliberately not used here. This is not a claim of
// a per-read consensus barrier beyond the server's leader-only API semantics.
func ReadRegionalCommandLease(ctx context.Context, connection *nats.Conn, bucket string) (authority.RegionalAuthorityLeaseDocument, uint64, error) {
	var lease authority.RegionalAuthorityLeaseDocument
	if err := commandAuthorityTLS(connection); err != nil {
		return lease, 0, err
	}
	data, sequence, err := ReadLeaderKV(ctx, connection, bucket, "authority.regional")
	if err != nil {
		return lease, 0, err
	}
	if len(data) > 16*1024 {
		return lease, 0, errors.New("nodeauthority: authority lease exceeds bound")
	}
	fields, err := decodeObject(data, "SchemaVersion", "AuthorityId", "Epoch", "CandidateId", "LeaseId", "IssuedAt", "DurationMilliseconds")
	if err != nil || len(fields) != 7 {
		return lease, 0, errors.New("nodeauthority: invalid authoritative lease document")
	}
	if json.Unmarshal(data, &lease) != nil || lease.Validate() != nil {
		return lease, 0, errors.New("nodeauthority: invalid authoritative lease document")
	}
	return lease, sequence, nil
}

func (a *RegionalCommandAuthorizer) Authorize(ctx context.Context, subject string, wire []byte) (CommandAuthorization, error) {
	var result CommandAuthorization
	envelope, err := protocol.DecodeCommandEnvelope(wire)
	if err != nil {
		return result, err
	}
	now := time.Now().UTC()
	if envelope.ProtocolVersion.Value != int64(protocol.ProtocolVersion.Current()) || envelope.WriterEpoch.Value <= 0 || envelope.DesiredGeneration.Value <= 0 || !now.Before(envelope.ExpiresAt) || now.Before(envelope.IssuedAt) || envelope.ExpiresAt.Sub(envelope.IssuedAt) > time.Minute {
		return result, errors.New("nodeauthority: command envelope is expired or has invalid bounds")
	}
	digest := sha256.Sum256(envelope.Payload.Bytes())
	if !bytes.Equal(digest[:], envelope.PayloadDigest.Bytes()) || a.config.Trust.VerifyAt(envelope.SignedMaterial, envelope.Signature, now) != protocol.VerificationOutcomeValid {
		return result, errors.New("nodeauthority: command signature or digest refused")
	}
	fields, err := decodeObject(envelope.Payload.Bytes(), "nodeId", "subject", "authorityId", "candidateId", "leaseId", "command")
	if err != nil {
		return result, err
	}
	var binding SignedNodeCommand
	if json.Unmarshal(envelope.Payload.Bytes(), &binding) != nil || len(fields["command"]) == 0 {
		return result, errors.New("nodeauthority: invalid signed host command")
	}
	cell := strings.SplitN(a.config.NodeID, "-", 2)[0]
	keyID, _, _, ok := security.DecodeCommandSignature(envelope.Signature)
	if !ok || a.config.SignerCandidates[keyID] != binding.CandidateID || binding.NodeID != a.config.NodeID || binding.Subject != subject || envelope.Cell.Value != cell || envelope.AggregateId.Value != binding.NodeID || binding.AuthorityID != cell+"-regional" || binding.LeaseID == "" {
		return result, errors.New("nodeauthority: signed command host, subject or authority identity differs")
	}
	var command struct {
		CommandID string `json:"commandId"`
	}
	if json.Unmarshal(binding.Command, &command) != nil || command.CommandID == "" || command.CommandID != envelope.OperationId.Value || command.CommandID != envelope.IdempotencyKey.Value {
		return result, errors.New("nodeauthority: signed command identity differs from payload")
	}
	lease, _, err := ReadRegionalCommandLease(ctx, a.config.Connection, a.config.Bucket)
	if err != nil {
		return result, err
	}
	now = time.Now().UTC()
	expiry := lease.IssuedAt.Add(time.Duration(lease.DurationMilliseconds) * time.Millisecond)
	if lease.AuthorityId != binding.AuthorityID || lease.Epoch != envelope.WriterEpoch.Value || lease.CandidateId != binding.CandidateID || lease.LeaseId != binding.LeaseID || now.Before(lease.IssuedAt) || !now.Before(expiry) || !now.Before(envelope.ExpiresAt) || envelope.ExpiresAt.After(expiry) {
		return result, errors.New("nodeauthority: command authority lease is stale or differs")
	}
	return CommandAuthorization{NodeID: binding.NodeID, AuthorityID: binding.AuthorityID, Epoch: lease.Epoch, CandidateID: binding.CandidateID, LeaseID: binding.LeaseID, Command: append([]byte(nil), binding.Command...), ExpiresAt: envelope.ExpiresAt}, nil
}

func decodeObject(data []byte, required ...string) (map[string]json.RawMessage, error) {
	if len(data) == 0 || len(data) > (1<<20)+4096 {
		return nil, errors.New("nodeauthority: invalid object bound")
	}
	allowed := map[string]bool{}
	for _, key := range required {
		allowed[key] = true
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errors.New("nodeauthority: expected object")
	}
	fields := map[string]json.RawMessage{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		key, ok := token.(string)
		if !ok || !allowed[key] || fields[key] != nil {
			return nil, errors.New("nodeauthority: unknown or duplicate field")
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil || bytes.Equal(value, []byte("null")) {
			return nil, errors.New("nodeauthority: invalid field")
		}
		fields[key] = value
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') {
		return nil, errors.New("nodeauthority: incomplete object")
	}
	if _, err = decoder.Token(); err != io.EOF || len(fields) != len(required) {
		return nil, errors.New("nodeauthority: trailing or missing data")
	}
	return fields, nil
}
