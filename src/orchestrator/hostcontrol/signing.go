package hostcontrol

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/contracts"
	"terrascale.tech/orchestrator/src/orchestrator/delivery"
	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
	"terrascale.tech/orchestrator/src/orchestrator/protocol"
)

func (c *Client) signCommand(ctx context.Context, host Host, subject string, command []byte) ([]byte, error) {
	var lease delivery.RegionalCommandAuthority
	var err error
	if c.config.CommandAuthority != nil {
		lease, err = c.config.CommandAuthority(ctx, host)
	} else {
		lease, err = delivery.RegionalCommandAuthorityFromContext(ctx)
	}
	if err != nil {
		return nil, err
	}
	cell := strings.ToLower(host.Region)
	if lease.AuthorityID != cell+"-regional" || lease.Epoch <= 0 || lease.DesiredGeneration <= 0 || lease.CandidateID == "" || lease.LeaseID == "" {
		return nil, errors.New("hostcontrol: actual regional command authority is required")
	}
	now := time.Now().UTC()
	expiry := now.Add(30 * time.Second)
	if lease.ExpiresAt.Before(expiry) {
		expiry = lease.ExpiresAt
	}
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(expiry) {
		expiry = deadline
	}
	if now.Before(lease.IssuedAt) || !now.Before(expiry) {
		return nil, errors.New("hostcontrol: regional command authority expired")
	}
	var identity struct {
		CommandID string `json:"commandId"`
	}
	if json.Unmarshal(command, &identity) != nil || identity.CommandID == "" {
		return nil, errors.New("hostcontrol: mutation command identity missing")
	}
	binding := nodeauthority.SignedNodeCommand{NodeID: host.NodeID.Value, Subject: subject, AuthorityID: lease.AuthorityID, CandidateID: lease.CandidateID, LeaseID: lease.LeaseID, Command: command}
	payload, err := json.Marshal(binding)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(payload)
	revision, _ := protocol.ProtocolRevisionTryCreate(int64(protocol.ProtocolVersion.Current()))
	cellID, _ := contracts.CellIdTryCreate(cell)
	aggregate, _ := contracts.AggregateIdTryCreate(host.NodeID.Value)
	generation, _ := protocol.DesiredGenerationTryCreate(lease.DesiredGeneration)
	epoch, _ := protocol.WriterEpochTryCreate(lease.Epoch)
	operation, ok := contracts.OperationIdTryCreate(identity.CommandID)
	if !ok {
		return nil, errors.New("hostcontrol: invalid command operation")
	}
	idempotency, _ := contracts.IdempotencyKeyTryCreate(identity.CommandID)
	attempt, _ := protocol.DeliveryAttemptTryCreate(1)
	digest, _ := protocol.PayloadDigestTryCopyFrom(sum[:])
	envelope := protocol.NewCommandEnvelope(revision, cellID, aggregate, generation, epoch, operation, idempotency, now, expiry, attempt, protocol.OpaquePayloadCopyFrom(payload), digest, protocol.OpaqueSignature{})
	envelope.Signature, err = c.config.SigningKey.Sign(envelope.SignedMaterial)
	if err != nil {
		return nil, err
	}
	return protocol.EncodeCommandEnvelope(envelope)
}
