package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"terrascale.tech/orchestrator/src/orchestrator/contracts"
	"terrascale.tech/orchestrator/src/orchestrator/control/authority"
	"terrascale.tech/orchestrator/src/orchestrator/delivery"
	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
	"terrascale.tech/orchestrator/src/orchestrator/protocol"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

// MasterDeliveryAdmissionConfig requires the parent/lease-bound delegated
// delivery contract and explicit master and original-intent signing trust.
type MasterDeliveryAdmissionConfig struct {
	Connection                     *nats.Conn
	Leaders                        jetstream.KeyValue
	MasterVerifier, IntentVerifier *security.CommandSignatureVerifier
}

func (c *MasterDeliveryAdmissionConfig) Validate() error {
	if c == nil || c.Connection == nil || c.Leaders == nil || c.MasterVerifier == nil || c.IntentVerifier == nil {
		return errors.New("signed delivery: explicit global lease and delegated signing trust are required")
	}
	return nil
}

type masterRegionalDelivery struct {
	ReleaseSignature []byte                                   `json:"releaseSignature"`
	Version          int                                      `json:"version"`
	ParentEnvelope   []byte                                   `json:"parentEnvelope"`
	GlobalLease      authority.RegionalAuthorityLeaseDocument `json:"globalLease"`
	Request          json.RawMessage                          `json:"request"`
}
type masterDeliveryProofKey struct{}

func (c *MasterDeliveryAdmissionConfig) resolve(ctx context.Context, envelope protocol.CommandEnvelope) (context.Context, *delivery.Request, []byte, error) {
	now := time.Now()
	if c.MasterVerifier.VerifyAt(envelope.SignedMaterial, envelope.Signature, now) != protocol.VerificationOutcomeValid {
		return ctx, nil, nil, errors.New("signed delivery: signer is not an admitted global master")
	}
	wrapper, err := decodeMasterRegionalDelivery(envelope.Payload.Bytes())
	if err != nil {
		return ctx, nil, nil, err
	}
	if len(wrapper.ReleaseSignature) != 64 || len(wrapper.ParentEnvelope) > MasterDeliveryMaximumEnvelopeBytes || wrapper.Version != 1 || !masterLeaseLive(wrapper.GlobalLease, now) {
		return ctx, nil, nil, errors.New("signed delivery: delegated global lease is invalid or expired")
	}
	parent, err := protocol.DecodeCommandEnvelope(wrapper.ParentEnvelope)
	if err != nil {
		return ctx, nil, nil, err
	}
	cell, _ := contracts.CellIdTryCreate("gru")
	aggregate, _ := contracts.AggregateIdTryCreate("delivery-master")
	generation, _ := protocol.DesiredGenerationTryCreate(1)
	epoch, _ := protocol.WriterEpochTryCreate(1)
	version, _ := protocol.ProtocolRevisionTryCreate(int64(protocol.ProtocolVersion.Current()))
	validation, err := protocol.NewCommandValidationContext(cell, aggregate, generation, epoch, []protocol.ProtocolRevision{version}, 0, masterDeliveryDigestVerifier{}, c.IntentVerifier)
	if err != nil {
		return ctx, nil, nil, err
	}
	if len(parent.Payload.Bytes()) > MasterDeliveryMaximumIntentBytes || !protocol.CommandEnvelopeValidator.Validate(&parent, validation, now).IsValid() || c.IntentVerifier.VerifyAt(parent.SignedMaterial, parent.Signature, now) != protocol.VerificationOutcomeValid || parent.ExpiresAt.Sub(parent.IssuedAt) > 10*time.Minute || parent.WriterEpoch.Value != wrapper.GlobalLease.Epoch || parent.DesiredGeneration != envelope.DesiredGeneration || envelope.ExpiresAt.After(parent.ExpiresAt) {
		return ctx, nil, nil, errors.New("signed delivery: original global intent was rejected")
	}
	original, err := delivery.ParseRequest(string(parent.Payload.Bytes()))
	if err != nil {
		return ctx, nil, nil, err
	}
	if err := delivery.ValidateRequest(original); err != nil || original.OperationID != parent.OperationId.Value {
		return ctx, nil, nil, errors.New("signed delivery: original request identity differs")
	}
	targeted := false
	for _, region := range original.Target.Regions {
		targeted = targeted || region == envelope.Cell.Value
	}
	if !targeted {
		return ctx, nil, nil, errors.New("signed delivery: regional child extends original targets")
	}
	operation := "delivery-" + masterKey(original.OperationID + "\x00" + delivery.SHA256Digest(parent.Payload.Bytes()) + "\x00" + envelope.Cell.Value)[:54]
	expected, err := masterChildPayload(original, envelope.Cell.Value, operation)
	if err != nil {
		return ctx, nil, nil, err
	}
	if envelope.OperationId.Value != operation || envelope.IdempotencyKey.Value != operation || !bytes.Equal(expected, wrapper.Request) {
		return ctx, nil, nil, errors.New("signed delivery: regional child differs from immutable parent lineage")
	}
	if err := c.checkGlobal(ctx, wrapper.GlobalLease); err != nil {
		return ctx, nil, nil, err
	}
	request, err := delivery.ParseRequest(string(wrapper.Request))
	if err != nil {
		return ctx, nil, nil, err
	}
	return delivery.WithPreparedReleaseSignature(context.WithValue(ctx, masterDeliveryProofKey{}, wrapper.GlobalLease), wrapper.ReleaseSignature), request, append([]byte(nil), wrapper.Request...), nil
}

func (c *MasterDeliveryAdmissionConfig) checkGlobal(ctx context.Context, proof authority.RegionalAuthorityLeaseDocument) error {
	if err := masterDeliveryTransport(c.Connection); err != nil {
		return err
	}
	raw, _, err := nodeauthority.ReadLeaderKV(ctx, c.Connection, c.Leaders.Bucket(), "authority.global")
	if err != nil {
		return err
	}
	if len(raw) > 16*1024 {
		return errors.New("signed delivery: global lease exceeds bound")
	}
	current, decodeErr := decodeMasterLease(raw)
	if decodeErr != nil || !masterLeaseLive(current, time.Now()) || current.AuthorityId != proof.AuthorityId || current.Epoch != proof.Epoch || current.CandidateId != proof.CandidateId || current.LeaseId != proof.LeaseId || current.IssuedAt.Before(proof.IssuedAt) {
		return errors.New("signed delivery: delegated global writer was replaced")
	}
	return nil
}

func masterLeaseLive(lease authority.RegionalAuthorityLeaseDocument, now time.Time) bool {
	return lease.Validate() == nil && lease.AuthorityId == "global" && strings.HasPrefix(lease.CandidateId, "global-controller-gru-") && !lease.IssuedAt.After(now) && now.Before(lease.IssuedAt.Add(time.Duration(lease.DurationMilliseconds)*time.Millisecond))
}

func decodeMasterRegionalDelivery(raw []byte) (masterRegionalDelivery, error) {
	var result masterRegionalDelivery
	fields, err := decodeMasterObject(raw, []string{"version", "parentEnvelope", "globalLease", "request", "releaseSignature"})
	if err != nil {
		return result, err
	}
	lease, err := decodeMasterLease(fields["globalLease"])
	if err != nil {
		return result, err
	}
	normalized, _ := json.Marshal(fields)
	if err := json.Unmarshal(normalized, &result); err != nil {
		return result, err
	}
	result.GlobalLease = lease
	return result, nil
}

func decodeMasterLease(raw []byte) (authority.RegionalAuthorityLeaseDocument, error) {
	var lease authority.RegionalAuthorityLeaseDocument
	if len(raw) > 16*1024 {
		return lease, errors.New("signed delivery: global lease exceeds bound")
	}
	fields, err := decodeMasterObject(raw, []string{"SchemaVersion", "AuthorityId", "Epoch", "CandidateId", "LeaseId", "IssuedAt", "DurationMilliseconds"})
	if err != nil {
		return lease, err
	}
	normalized, _ := json.Marshal(fields)
	if err := json.Unmarshal(normalized, &lease); err != nil {
		return lease, err
	}
	if err := lease.Validate(); err != nil {
		return lease, errors.New("signed delivery: global lease is invalid")
	}
	return lease, nil
}

func decodeMasterObject(raw []byte, required []string) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errors.New("signed delivery: delegated value is not an object")
	}
	allowed := map[string]bool{}
	for _, key := range required {
		allowed[key] = true
	}
	fields := map[string]json.RawMessage{}
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || !allowed[key] {
			return nil, errors.New("signed delivery: delegated field is invalid or unknown")
		}
		if _, exists := fields[key]; exists {
			return nil, errors.New("signed delivery: duplicate delegated field")
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		fields[key] = value
	}
	if _, err := decoder.Token(); err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF || len(fields) != len(required) {
		return nil, errors.New("signed delivery: delegated value has trailing or missing fields")
	}
	return fields, nil
}
