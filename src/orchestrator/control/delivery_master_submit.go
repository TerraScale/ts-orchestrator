package control

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/contracts"
	"terrascale.tech/orchestrator/src/orchestrator/control/authority"
	"terrascale.tech/orchestrator/src/orchestrator/delivery"
	"terrascale.tech/orchestrator/src/orchestrator/natspolicy"
	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
	"terrascale.tech/orchestrator/src/orchestrator/protocol"
)

type masterDeliveryDigestVerifier struct{}

func (masterDeliveryDigestVerifier) Verify(payload protocol.OpaquePayload, expected protocol.PayloadDigest) protocol.VerificationOutcome {
	hash := sha256.Sum256(payload.Bytes())
	value, _ := protocol.PayloadDigestTryCopyFrom(hash[:])
	if value.Equal(expected) {
		return protocol.VerificationOutcomeValid
	}
	return protocol.VerificationOutcomeInvalid
}

func (m *MasterDelivery) Submit(ctx context.Context, wire []byte) (*MasterDeliveryReceipt, error) {
	if m == nil || ctx == nil {
		return nil, errors.New("master delivery: live context and adapter are required")
	}
	if len(wire) == 0 || len(wire) > MasterDeliveryMaximumEnvelopeBytes {
		return nil, errors.New("master delivery: signed envelope exceeds the master bound")
	}
	select {
	case m.gate <- struct{}{}:
		defer func() { <-m.gate }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	envelope, err := protocol.DecodeCommandEnvelope(wire)
	if err != nil {
		return nil, errors.New("master delivery: malformed signed intent")
	}
	if !protocol.CommandEnvelopeValidator.Validate(&envelope, m.validation, time.Now()).IsValid() || m.config.IntentVerifier.VerifyAt(envelope.SignedMaterial, envelope.Signature, time.Now()) != protocol.VerificationOutcomeValid || envelope.ExpiresAt.Sub(envelope.IssuedAt) > 10*time.Minute {
		return nil, errors.New("master delivery: signed intent was rejected")
	}
	if len(envelope.Payload.Bytes()) > MasterDeliveryMaximumIntentBytes {
		return nil, errors.New("master delivery: intent exceeds the delegated payload bound")
	}
	request, err := delivery.ParseRequest(string(envelope.Payload.Bytes()))
	if err != nil {
		return nil, err
	}
	if err := delivery.ValidateRequest(request); err != nil || request.OperationID != envelope.OperationId.Value || request.Artifact == nil || request.Artifact.Architecture == "" {
		return nil, errors.New("master delivery: original request identity is invalid")
	}
	for _, cell := range request.Target.Regions {
		if _, ok := m.config.Regions[cell]; !ok {
			return nil, errors.New("master delivery: target has no admitted regional route")
		}
	}
	ctx, cancel := context.WithDeadline(ctx, envelope.ExpiresAt)
	defer cancel()
	epoch := envelope.WriterEpoch.Value
	if err := m.checkGlobal(ctx, epoch); err != nil {
		return nil, err
	}
	record, revision, err := m.admitMaster(ctx, envelope, wire, request)
	if err != nil {
		return nil, err
	}
	receipt := func() *MasterDeliveryReceipt { return record.receipt() }
	check := func(delivery.OperationFence) error { return m.checkMaster(ctx, record, epoch) }
	fence := delivery.OperationFence{OperationID: record.OperationID, RequestDigest: record.PayloadDigest, OwnerID: m.config.Instance, Generation: uint64(epoch)}
	if record.receipt().Complete {
		return receipt(), check(fence)
	}
	if err := check(fence); err != nil {
		return receipt(), err
	}
	artifact, err := delivery.LoadMasterRelease(ctx, request, m.config.Fetcher, m.config.Trust(), m.config.Mirror, record.ReleaseSignature, record.Prepared)
	if err != nil {
		return receipt(), err
	}
	if len(record.ReleaseSignature) == 0 {
		record.ReleaseSignature = append([]byte(nil), artifact.Signature...)
		revision, err = m.saveMaster(ctx, record, revision, epoch)
		if err != nil {
			record.ReleaseSignature = nil
			return receipt(), err
		}
	}
	if err := delivery.PrepareMasterRelease(ctx, artifact, m.config.Mirror, record.Prepared, fence, check); err != nil {
		return receipt(), err
	}
	if !record.Prepared {
		record.Prepared = true
		revision, err = m.saveMaster(ctx, record, revision, epoch)
		if err != nil {
			record.Prepared = false
			return receipt(), err
		}
	}
	for index := range record.Children {
		child := &record.Children[index]
		if child.Accepted {
			continue
		}
		if child.Attempt >= 1000 {
			return receipt(), errors.New("master delivery: regional retry bound exhausted")
		}
		child.Attempt++
		revision, err = m.saveMaster(ctx, record, revision, epoch)
		if err != nil {
			return receipt(), err
		}
		route := m.config.Regions[child.Cell]
		lease, _, err := nodeauthority.ReadRegionalCommandLease(ctx, route.Connection, route.Leaders.Bucket())
		if err != nil {
			return receipt(), err
		}
		if lease.AuthorityId != child.Cell+"-regional" || lease.IssuedAt.After(time.Now()) || !time.Now().Before(lease.IssuedAt.Add(time.Duration(lease.DurationMilliseconds)*time.Millisecond)) {
			return receipt(), errors.New("master delivery: regional lease scope differs")
		}
		globalLease, err := m.readGlobal(ctx, epoch)
		if err != nil {
			return receipt(), err
		}
		command, err := m.childEnvelope(envelope, request, *child, lease.Epoch, globalLease, record.ReleaseSignature)
		if err != nil {
			return receipt(), err
		}
		if err := m.checkMaster(ctx, record, epoch); err != nil {
			return receipt(), err
		}
		subject, err := natspolicy.NatsSubjectTaxonomy.DirectDeliverySubject(child.Cell)
		if err != nil {
			return receipt(), err
		}
		sendCtx, stop := context.WithTimeout(ctx, m.config.RequestTimeout)
		reply, sendErr := route.Connection.RequestWithContext(sendCtx, subject, command)
		stop()
		if sendErr != nil {
			return receipt(), errors.New("master delivery: regional result is indeterminate; resume the same intent")
		}
		if reply == nil || len(reply.Data) > 64 || string(reply.Data) != string(CommandIngressCodeAccepted) {
			return receipt(), errors.New("master delivery: regional command did not prove durable acceptance")
		}
		child.Accepted = true
		revision, err = m.saveMaster(ctx, record, revision, epoch)
		if err != nil {
			child.Accepted = false
			return receipt(), err
		}
	}
	return receipt(), nil
}

func (m *MasterDelivery) childEnvelope(parent protocol.CommandEnvelope, request *delivery.Request, child masterDeliveryChild, epochValue int64, globalLease authority.RegionalAuthorityLeaseDocument, releaseSignature []byte) ([]byte, error) {
	payload, err := masterChildPayload(request, child.Cell, child.OperationID)
	if err != nil {
		return nil, err
	}
	if delivery.SHA256Digest(payload) != child.PayloadDigest {
		return nil, errors.New("master delivery: child lineage differs")
	}
	cell, _ := contracts.CellIdTryCreate(child.Cell)
	aggregate, _ := contracts.AggregateIdTryCreate("delivery")
	operation, _ := contracts.OperationIdTryCreate(child.OperationID)
	key, _ := contracts.IdempotencyKeyTryCreate(child.OperationID)
	epoch, ok := protocol.WriterEpochTryCreate(epochValue)
	if !ok {
		return nil, errors.New("master delivery: regional epoch is invalid")
	}
	attempt, _ := protocol.DeliveryAttemptTryCreate(child.Attempt)
	parentWire, err := protocol.EncodeCommandEnvelope(parent)
	if err != nil {
		return nil, err
	}
	wrapped, err := json.Marshal(masterRegionalDelivery{Version: 1, ParentEnvelope: parentWire, GlobalLease: globalLease, ReleaseSignature: releaseSignature, Request: payload})
	if err != nil {
		return nil, err
	}
	opaque := protocol.OpaquePayloadCopyFrom(wrapped)
	sum := sha256.Sum256(wrapped)
	digest, _ := protocol.PayloadDigestTryCopyFrom(sum[:])
	now := time.Now().UTC()
	envelope := protocol.NewCommandEnvelope(parent.ProtocolVersion, cell, aggregate, parent.DesiredGeneration, epoch, operation, key, now, parent.ExpiresAt, attempt, opaque, digest, protocol.OpaqueSignature{})
	signature, err := m.config.Signer.Sign(envelope.SignedMaterial)
	if err != nil {
		return nil, err
	}
	envelope = protocol.NewCommandEnvelope(parent.ProtocolVersion, cell, aggregate, parent.DesiredGeneration, epoch, operation, key, now, parent.ExpiresAt, attempt, opaque, digest, signature)
	return protocol.EncodeCommandEnvelope(envelope)
}

func masterChildPayload(parent *delivery.Request, cell, operation string) ([]byte, error) {
	raw, err := json.Marshal(parent)
	if err != nil {
		return nil, err
	}
	child, err := delivery.ParseRequest(string(raw))
	if err != nil {
		return nil, err
	}
	child.OperationID = operation
	child.Target.Regions = []string{cell}
	return json.Marshal(child)
}
func masterKey(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
