package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"terrascale.tech/orchestrator/src/orchestrator/control/messaging"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/control/authority"
	"terrascale.tech/orchestrator/src/orchestrator/delivery"
	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
	"terrascale.tech/orchestrator/src/orchestrator/protocol"
)

type masterDeliveryChild struct {
	Cell          string `json:"cell"`
	OperationID   string `json:"operationId"`
	PayloadDigest string `json:"payloadDigest"`
	Attempt       int64  `json:"attempt"`
	Accepted      bool   `json:"accepted"`
}
type masterDeliveryEdge struct {
	ArtifactDigest string `json:"artifactDigest"`
	Attempt        int64  `json:"attempt"`
	Accepted       bool   `json:"accepted"`
}
type masterDeliveryRecord struct {
	GlobalEdge               *masterDeliveryEdge   `json:"globalEdge,omitempty"`
	Version                  int                   `json:"version"`
	OperationID              string                `json:"operationId"`
	PayloadDigest            string                `json:"payloadDigest"`
	IdempotencyDigest        string                `json:"idempotencyDigest"`
	Generation               int64                 `json:"generation"`
	OwnerEpoch               int64                 `json:"ownerEpoch"`
	OriginalEnvelope         []byte                `json:"originalEnvelope"`
	ReleaseSignature         []byte                `json:"releaseSignature"`
	ReleaseSignatureKey      string                `json:"releaseSignatureKey"`
	ReleaseManifest          []byte                `json:"releaseManifest"`
	ReleaseManifestSignature []byte                `json:"releaseManifestSignature"`
	ReleaseManifestKey       string                `json:"releaseManifestKey"`
	Prepared                 bool                  `json:"prepared"`
	Children                 []masterDeliveryChild `json:"children"`
}
type masterDeliveryHead struct {
	OperationID   string `json:"operationId"`
	PayloadDigest string `json:"payloadDigest"`
	Generation    int64  `json:"generation"`
}

func (r *masterDeliveryRecord) receipt() *MasterDeliveryReceipt {
	result := &MasterDeliveryReceipt{OperationID: r.OperationID, IntentDigest: r.PayloadDigest, Generation: r.Generation, Complete: r.Prepared && len(r.Children) > 0, Regions: make([]MasterRegionReceipt, 0, len(r.Children))}
	if r.GlobalEdge != nil {
		result.GlobalEdge = &MasterGlobalEdgeReceipt{OperationID: r.OperationID, PayloadDigest: r.PayloadDigest, ArtifactDigest: r.GlobalEdge.ArtifactDigest, Accepted: r.GlobalEdge.Accepted}
		result.Complete = r.Prepared && r.GlobalEdge.Accepted && len(r.Children) == 0
	}
	for _, child := range r.Children {
		result.Regions = append(result.Regions, MasterRegionReceipt{Cell: child.Cell, OperationID: child.OperationID, PayloadDigest: child.PayloadDigest, Accepted: child.Accepted})
		result.Complete = result.Complete && child.Accepted
	}
	return result
}
func (r *masterDeliveryRecord) head() masterDeliveryHead {
	return masterDeliveryHead{r.OperationID, r.PayloadDigest, r.Generation}
}
func masterRecordKey(operation string) string { return "master.operation." + masterKey(operation) }

func (m *MasterDelivery) checkGlobal(ctx context.Context, epoch int64) error {
	_, err := m.readGlobal(ctx, epoch)
	return err
}
func (m *MasterDelivery) readGlobal(ctx context.Context, epoch int64) (authority.RegionalAuthorityLeaseDocument, error) {
	if err := ctx.Err(); err != nil {
		return authority.RegionalAuthorityLeaseDocument{}, err
	}
	if err := masterDeliveryTransport(m.config.Connection); err != nil {
		return authority.RegionalAuthorityLeaseDocument{}, err
	}
	snapshot := m.config.Authority()
	if !snapshot.Ready() || !snapshot.IsLeader || snapshot.State != "leader" || snapshot.Epoch != epoch {
		return authority.RegionalAuthorityLeaseDocument{}, errors.New("master delivery: global writer is fenced")
	}
	raw, _, err := nodeauthority.ReadLeaderKV(ctx, m.config.Connection, m.config.Leaders.Bucket(), "authority.global")
	if err != nil {
		return authority.RegionalAuthorityLeaseDocument{}, err
	}
	if len(raw) > 16*1024 {
		return authority.RegionalAuthorityLeaseDocument{}, errors.New("master delivery: global lease exceeds bound")
	}
	lease, decodeErr := decodeMasterLease(raw)
	if decodeErr != nil || !masterLeaseLive(lease, time.Now()) || lease.AuthorityId != "global" || lease.CandidateId != "global-controller-gru-"+m.config.Instance || lease.Epoch != epoch || !time.Now().Before(lease.IssuedAt.Add(time.Duration(lease.DurationMilliseconds)*time.Millisecond)) {
		return authority.RegionalAuthorityLeaseDocument{}, errors.New("master delivery: authoritative global lease differs")
	}
	return lease, nil
}

func (m *MasterDelivery) checkMaster(ctx context.Context, record *masterDeliveryRecord, epoch int64) error {
	if err := m.checkGlobal(ctx, epoch); err != nil {
		return err
	}
	headEntry, err := m.store.Get("master.head")
	if err != nil {
		return err
	}
	var head masterDeliveryHead
	if json.Unmarshal(headEntry.Value, &head) != nil || head != record.head() {
		return errors.New("master delivery: global desired generation differs")
	}
	entry, err := m.store.Get(masterRecordKey(record.OperationID))
	if err != nil {
		return err
	}
	var current masterDeliveryRecord
	if json.Unmarshal(entry.Value, &current) != nil || (!sameReleaseEvidence(&current, record) && !releaseEvidenceEmpty(&current)) || current.OwnerEpoch != epoch || current.head() != record.head() || !bytes.Equal(current.OriginalEnvelope, record.OriginalEnvelope) {
		return errors.New("master delivery: durable operation owner or lineage differs")
	}
	return nil
}

func (m *MasterDelivery) saveMaster(ctx context.Context, record *masterDeliveryRecord, revision uint64, epoch int64) (uint64, error) {
	if err := m.checkMaster(ctx, record, epoch); err != nil {
		return 0, err
	}
	body, err := json.Marshal(record)
	if err != nil {
		return 0, err
	}
	entry, err := m.store.Update(masterRecordKey(record.OperationID), revision, body)
	if err != nil {
		return 0, err
	}
	return entry.Revision, nil
}

func (m *MasterDelivery) admitMaster(ctx context.Context, envelope protocol.CommandEnvelope, wire []byte, request *delivery.Request) (*masterDeliveryRecord, uint64, error) {
	epoch := envelope.WriterEpoch.Value
	expected := &masterDeliveryRecord{Version: 1, OperationID: request.OperationID, PayloadDigest: delivery.SHA256Digest(envelope.Payload.Bytes()), IdempotencyDigest: masterKey(envelope.IdempotencyKey.Value), Generation: envelope.DesiredGeneration.Value, OwnerEpoch: epoch, OriginalEnvelope: append([]byte(nil), wire...)}
	if masterIsEdge(request) {
		expected.GlobalEdge = &masterDeliveryEdge{ArtifactDigest: request.Artifact.Digest}
	}
	targets := request.Target.Regions
	if expected.GlobalEdge != nil {
		targets = nil
	}
	for _, cell := range targets {
		operation := "delivery-" + masterKey(request.OperationID + "\x00" + expected.PayloadDigest + "\x00" + cell)[:54]
		payload, err := masterChildPayload(request, cell, operation)
		if err != nil {
			return nil, 0, err
		}
		expected.Children = append(expected.Children, masterDeliveryChild{Cell: cell, OperationID: operation, PayloadDigest: delivery.SHA256Digest(payload)})
	}
	// Validate the complete journal and every expanded child envelope before
	// even claiming the intent, so an unsendable child cannot follow mirror PUTs.
	preflightRecord := *expected
	preflightRecord.ReleaseSignature = make([]byte, 64)
	preflightBody, err := json.Marshal(&preflightRecord)
	if err != nil || len(preflightBody) > messaging.DeliveryOperationMaxDocumentBytes {
		return nil, 0, errors.New("master delivery: original lineage exceeds the durable record bound")
	}
	proof, err := m.readGlobal(ctx, epoch)
	if err != nil {
		return nil, 0, err
	}
	for _, child := range expected.Children {
		child.Attempt = 1000
		if _, err := m.childEnvelope(envelope, request, child, math.MaxInt64, proof, make([]byte, 64)); err != nil {
			return nil, 0, errors.New("master delivery: expanded child envelope exceeds its protocol bound")
		}
	}
	claimKey := "master.idempotency." + expected.IdempotencyDigest
	claim := []byte(expected.OperationID + "\x00" + expected.PayloadDigest)
	if err := m.checkGlobal(ctx, epoch); err != nil {
		return nil, 0, err
	}
	if _, err := m.store.Create(claimKey, claim); err != nil {
		if !errors.Is(err, delivery.ErrStoreConflict) {
			return nil, 0, err
		}
		prior, err := m.store.Get(claimKey)
		if err != nil || !bytes.Equal(prior.Value, claim) {
			return nil, 0, errors.New("master delivery: idempotency identity conflicts")
		}
	}
	record := expected
	key := masterRecordKey(record.OperationID)
	body, _ := json.Marshal(record)
	if err := m.checkGlobal(ctx, epoch); err != nil {
		return nil, 0, err
	}
	entry, err := m.store.Create(key, body)
	if errors.Is(err, delivery.ErrStoreConflict) {
		entry, err = m.store.Get(key)
		if err != nil {
			return nil, 0, err
		}
		var prior masterDeliveryRecord
		if json.Unmarshal(entry.Value, &prior) != nil || !masterSameLineage(&prior, expected) {
			return nil, 0, errors.New("master delivery: original intent or child lineage conflicts")
		}
		record = &prior
	} else if err != nil {
		return nil, 0, err
	}
	revision := entry.Revision
	// No later desired generation may strand an incompletely acknowledged
	// fanout. It must first recover this exact parent and its existing children.
	headEntry, err := m.store.Get("master.head")
	if errors.Is(err, delivery.ErrStoreNotFound) {
		if err := m.checkGlobal(ctx, epoch); err != nil {
			return nil, 0, err
		}
		body, _ := json.Marshal(record.head())
		if _, err := m.store.Create("master.head", body); err != nil {
			return nil, 0, err
		}
	} else if err != nil {
		return nil, 0, err
	} else {
		var head masterDeliveryHead
		if json.Unmarshal(headEntry.Value, &head) != nil || head.Generation <= 0 {
			return nil, 0, errors.New("master delivery: durable generation head is invalid")
		}
		if head != record.head() {
			if record.Generation <= head.Generation {
				return nil, 0, errors.New("master delivery: stale or conflicting desired generation")
			}
			prior, err := m.store.Get(masterRecordKey(head.OperationID))
			if err != nil {
				return nil, 0, err
			}
			var previous masterDeliveryRecord
			if json.Unmarshal(prior.Value, &previous) != nil || previous.head() != head || !previous.receipt().Complete {
				return nil, 0, errors.New("master delivery: previous regional fanout requires recovery")
			}
			if err := m.checkGlobal(ctx, epoch); err != nil {
				return nil, 0, err
			}
			body, _ := json.Marshal(record.head())
			if _, err := m.store.Update("master.head", headEntry.Revision, body); err != nil {
				return nil, 0, err
			}
		}
	}
	if record.OwnerEpoch != epoch {
		if err := m.checkGlobal(ctx, epoch); err != nil {
			return nil, 0, err
		}
		record.OwnerEpoch = epoch
		body, _ := json.Marshal(record)
		updated, err := m.store.Update(key, revision, body)
		if err != nil {
			return nil, 0, err
		}
		revision = updated.Revision
	}
	return record, revision, nil
}

func masterSameLineage(prior, expected *masterDeliveryRecord) bool {
	if !validReleaseEvidence(prior) || prior.Version != 1 || prior.head() != expected.head() || prior.IdempotencyDigest != expected.IdempotencyDigest || prior.OwnerEpoch <= 0 || len(prior.Children) != len(expected.Children) {
		return false
	}
	if (prior.GlobalEdge == nil) != (expected.GlobalEdge == nil) {
		return false
	}
	if edge := prior.GlobalEdge; edge != nil {
		if edge.ArtifactDigest != expected.GlobalEdge.ArtifactDigest || edge.Attempt < 0 || edge.Attempt > 1000 || edge.Accepted && !prior.Prepared || len(prior.Children) != 0 {
			return false
		}
	}
	original, err := protocol.DecodeCommandEnvelope(prior.OriginalEnvelope)
	if err != nil || original.Cell.Value != "gru" || original.AggregateId.Value != "delivery-master" || original.OperationId.Value != prior.OperationID || original.DesiredGeneration.Value != prior.Generation || delivery.SHA256Digest(original.Payload.Bytes()) != prior.PayloadDigest || masterKey(original.IdempotencyKey.Value) != prior.IdempotencyDigest {
		return false
	}
	for i, child := range prior.Children {
		want := expected.Children[i]
		if child.Cell != want.Cell || child.OperationID != want.OperationID || child.PayloadDigest != want.PayloadDigest || child.Attempt < 0 || child.Attempt > 1000 || child.Accepted && (!prior.Prepared || child.Attempt == 0) {
			return false
		}
	}
	return true
}

func validReleaseEvidence(record *masterDeliveryRecord) bool {
	if record == nil {
		return false
	}
	if len(record.ReleaseSignature) == 0 {
		return len(record.ReleaseSignatureKey) == 0 && len(record.ReleaseManifest) == 0 && len(record.ReleaseManifestSignature) == 0 && record.ReleaseManifestKey == ""
	}
	return len(record.ReleaseSignature) == 64 && record.ReleaseSignatureKey != "" && len(record.ReleaseManifest) > 0 && len(record.ReleaseManifestSignature) == 64 && record.ReleaseManifestKey == record.ReleaseSignatureKey
}

func sameReleaseEvidence(left, right *masterDeliveryRecord) bool {
	return bytes.Equal(left.ReleaseSignature, right.ReleaseSignature) && left.ReleaseSignatureKey == right.ReleaseSignatureKey && bytes.Equal(left.ReleaseManifest, right.ReleaseManifest) && bytes.Equal(left.ReleaseManifestSignature, right.ReleaseManifestSignature) && left.ReleaseManifestKey == right.ReleaseManifestKey
}

func releaseEvidenceEmpty(record *masterDeliveryRecord) bool {
	return record != nil && len(record.ReleaseSignature) == 0 && record.ReleaseSignatureKey == "" && len(record.ReleaseManifest) == 0 && len(record.ReleaseManifestSignature) == 0 && record.ReleaseManifestKey == ""
}
