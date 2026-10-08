package memberstatus

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
)

// DrainRecord is written durably before the first POST. Its request nonce and
// original process binding must be replayed byte-for-byte after uncertainty.
type DrainRecord struct {
	Request        DrainRequest `json:"request"`
	Survivor       Survivor     `json:"survivor"`
	SourceSequence uint64       `json:"source_sequence"`
}

type DrainStore interface {
	Load() (DrainRecord, bool, error)
	Create(DrainRecord) error
}

// PrepareDrain saves an exact idempotent request only after a live serving
// proof names the required survivor and its applied ACK covers the source.
func (c *Client) PrepareDrain(status Status, proof ServingProof, survivor Survivor, operationID string, store DrainStore) (DrainRecord, error) {
	if store == nil || !status.verified || !proof.verified || !entityid.Valid(operationID) || !survivor.valid() ||
		status.Process != proof.Process || status.Scope != proof.Scope || status.Authority != proof.Authority ||
		status.Scope != c.scope || status.Authority != c.authority || status.ReceiverOnly || !status.Serving ||
		proof.Replication.PeerMemberID != survivor.MemberID || proof.Replication.PeerIncarnation != survivor.Incarnation ||
		proof.Replication.PeerAppliedSequence < proof.Replication.LocalSourceSequence ||
		proof.Replication.PeerDurableSequence < proof.Replication.PeerAppliedSequence ||
		proof.Object.LocalSourceSequence != proof.Replication.LocalSourceSequence {
		return DrainRecord{}, ErrNotServing
	}
	challenge, err := nonce()
	if err != nil {
		return DrainRecord{}, err
	}
	record := DrainRecord{
		Request: DrainRequest{
			SchemaVersion: 1, OperationID: operationID, Nonce: challenge,
			Expected: Identity{Process: status.Process, Scope: c.scope, Authority: c.authority},
		},
		Survivor: survivor, SourceSequence: proof.Replication.LocalSourceSequence,
	}
	if err := store.Create(record); err != nil {
		return DrainRecord{}, fmt.Errorf("persist member drain request: %w", err)
	}
	return record, nil
}

// ReconcileDrain polls the Rust operation first. A 404 can be retried with
// the exact persisted POST only while the original process is still current.
// An ambiguous transport result remains unknown until a later status poll.
func (c *Client) ReconcileDrain(ctx context.Context, store DrainStore) (DrainEnvelope, error) {
	if store == nil {
		return DrainEnvelope{}, errors.New("member drain has no durable store")
	}
	record, found, err := store.Load()
	if err != nil {
		return DrainEnvelope{}, err
	}
	if !found || !record.valid(c.scope, c.authority) {
		return DrainEnvelope{}, ErrStaleBinding
	}
	status, err := c.Status(ctx)
	if err != nil {
		return DrainEnvelope{}, err
	}
	observation, code, err := c.drainStatus(ctx, record, status)
	if err != nil {
		return DrainEnvelope{}, errors.Join(ErrOutcomeUnknown, err)
	}
	if code != http.StatusNotFound {
		return observation, nil
	}
	if status.Process != record.Request.Expected.Process {
		return DrainEnvelope{}, ErrOutcomeUnknown
	}
	body, err := encodeRequest(record.Request)
	if err != nil {
		return DrainEnvelope{}, err
	}
	code, response, observed, err := c.exchange(ctx, http.MethodPost, "/v1/member/drain", body)
	if err != nil {
		return DrainEnvelope{}, errors.Join(ErrOutcomeUnknown, err)
	}
	if observed.PID != status.Process.PID {
		return DrainEnvelope{}, ErrStaleBinding
	}
	switch code {
	case http.StatusOK, http.StatusAccepted:
		return validateDrainEnvelope(response, code, record.Request.Nonce, status, record)
	case http.StatusConflict:
		return DrainEnvelope{}, ErrOperationConflict
	case http.StatusPreconditionFailed:
		// A process switch or an uncertain earlier POST can race the 404. Poll
		// again before classifying; never construct a new request in this path.
		current, statusErr := c.Status(ctx)
		if statusErr != nil {
			return DrainEnvelope{}, errors.Join(ErrOutcomeUnknown, statusErr)
		}
		observation, pollCode, pollErr := c.drainStatus(ctx, record, current)
		if pollErr == nil && pollCode != http.StatusNotFound {
			return observation, nil
		}
		return DrainEnvelope{}, ErrStaleBinding
	default:
		return DrainEnvelope{}, fmt.Errorf("member drain HTTP %d: %w", code, ErrOutcomeUnknown)
	}
}

func (c *Client) drainStatus(ctx context.Context, record DrainRecord, current Status) (DrainEnvelope, int, error) {
	challenge, err := nonce()
	if err != nil {
		return DrainEnvelope{}, 0, err
	}
	path := "/v1/member/drain-status?operation_id=" + record.Request.OperationID + "&nonce=" + challenge
	code, body, process, err := c.exchange(ctx, http.MethodGet, path, nil)
	if err != nil {
		return DrainEnvelope{}, 0, err
	}
	if process.PID != current.Process.PID {
		return DrainEnvelope{}, 0, ErrStaleBinding
	}
	if code == http.StatusNotFound {
		return DrainEnvelope{}, code, nil
	}
	if code != http.StatusOK && code != http.StatusAccepted {
		return DrainEnvelope{}, code, fmt.Errorf("member drain status HTTP %d", code)
	}
	observation, err := validateDrainEnvelope(body, code, challenge, current, record)
	return observation, code, err
}

func (r DrainRecord) valid(scope Scope, authority Authority) bool {
	return r.Request.SchemaVersion == 1 && entityid.Valid(r.Request.OperationID) && lowerHex(r.Request.Nonce, 32) &&
		r.Request.Expected.Process.valid() && r.Request.Expected.Scope == scope && r.Request.Expected.Authority == authority &&
		r.Survivor.valid() && r.Survivor.MemberID != scope.MemberID
}

func validateDrainEnvelope(body []byte, code int, challenge string, current Status, record DrainRecord) (DrainEnvelope, error) {
	var envelope DrainEnvelope
	if err := decodeRequired(body, &envelope, drainEnvelopePaths...); err != nil {
		return DrainEnvelope{}, err
	}
	if err := requirePresent(body, "receipt_sha256", "receipt"); err != nil {
		return DrainEnvelope{}, err
	}
	if envelope.SchemaVersion != 1 || envelope.Nonce != challenge || envelope.OperationID != record.Request.OperationID ||
		envelope.Process != current.Process {
		return DrainEnvelope{}, ErrStaleBinding
	}
	if envelope.State == "pending" && code == http.StatusAccepted && envelope.Receipt == nil && envelope.ReceiptSHA256 == nil {
		return envelope, nil
	}
	if envelope.State != "complete" || code != http.StatusOK || envelope.Receipt == nil || envelope.ReceiptSHA256 == nil ||
		!lowerHex(*envelope.ReceiptSHA256, 64) {
		return DrainEnvelope{}, errors.New("inconsistent member drain state")
	}
	var required map[string]any
	if err := json.Unmarshal(body, &required); err != nil {
		return DrainEnvelope{}, err
	}
	if err := requireReceiptFields(required); err != nil {
		return DrainEnvelope{}, err
	}
	receipt := envelope.Receipt
	digest, err := receipt.digest()
	if err != nil || digest != *envelope.ReceiptSHA256 || receipt.SchemaVersion != 1 ||
		receipt.OperationID != record.Request.OperationID || receipt.RequestNonce != record.Request.Nonce ||
		receipt.RequestedProcess != record.Request.Expected.Process || !receipt.DrainedProcess.valid() ||
		receipt.Scope != record.Request.Expected.Scope || receipt.Authority != record.Request.Expected.Authority ||
		receipt.LocalSourceOrigin != (Origin{MemberID: receipt.Scope.MemberID, Incarnation: receipt.Scope.Incarnation}) ||
		receipt.LocalSourceDurableSequence < record.SourceSequence ||
		receipt.ArchivedSourceSequence != receipt.LocalSourceDurableSequence ||
		!lowerHex(receipt.ObjectRootSHA256, 64) ||
		receipt.Peer.Origin != (Origin{MemberID: record.Survivor.MemberID, Incarnation: record.Survivor.Incarnation}) ||
		receipt.Peer.DurableSequence < receipt.LocalSourceDurableSequence ||
		receipt.Peer.AppliedSequence < receipt.LocalSourceDurableSequence ||
		receipt.Peer.AppliedSequence > receipt.Peer.DurableSequence ||
		receipt.Peer.LocalInboxAppliedSequence > receipt.Peer.LocalInboxDurableSequence ||
		!receipt.ReplicationQuiesced {
		return DrainEnvelope{}, errors.New("member drain receipt violates signed survivor or root frontier")
	}
	return envelope, nil
}

var drainEnvelopePaths = []string{
	"schema_version", "nonce", "process.pid", "process.start_nonce", "operation_id", "state",
}

func requireReceiptFields(root map[string]any) error {
	paths := []string{
		"receipt_sha256", "receipt.schema_version", "receipt.operation_id", "receipt.request_nonce",
		"receipt.requested_process.pid", "receipt.requested_process.start_nonce",
		"receipt.drained_process.pid", "receipt.drained_process.start_nonce",
		"receipt.scope.cluster_id", "receipt.scope.tenant_id", "receipt.scope.database_id", "receipt.scope.shard_id",
		"receipt.scope.member_id", "receipt.scope.incarnation",
		"receipt.authority.epoch", "receipt.authority.configuration_id", "receipt.authority.certificate_sha256", "receipt.authority.tls_leaf_sha256",
		"receipt.local_source_origin.member_id", "receipt.local_source_origin.incarnation",
		"receipt.local_source_durable_sequence", "receipt.archived_source_sequence", "receipt.object_root_sha256",
		"receipt.peer.origin.member_id", "receipt.peer.origin.incarnation", "receipt.peer.durable_sequence", "receipt.peer.applied_sequence",
		"receipt.peer.local_inbox_durable_sequence", "receipt.peer.local_inbox_applied_sequence", "receipt.replication_quiesced",
	}
	for _, path := range paths {
		current := any(root)
		for _, part := range splitPath(path) {
			object, ok := current.(map[string]any)
			if !ok {
				return fmt.Errorf("member drain omits %s", path)
			}
			current, ok = object[part]
			if !ok || current == nil {
				return fmt.Errorf("member drain omits %s", path)
			}
		}
	}
	return nil
}
