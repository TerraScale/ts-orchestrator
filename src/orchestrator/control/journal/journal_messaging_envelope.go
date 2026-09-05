package journal

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/natspolicy"
	"terrascale.tech/orchestrator/src/orchestrator/protocol"
)

const (
	journalPayloadOperationCreate = "operation-journal-create"
	journalPayloadOperationUpdate = "operation-journal-update"
	journalPayloadOperationReply  = "operation-journal-reply"
	journalPayloadRuntimeRead     = "runtime-lifecycle-journal-read"
	journalPayloadRuntimeWrite    = "runtime-lifecycle-journal-write"
	journalPayloadRuntimeReply    = "runtime-lifecycle-journal-reply"
)

func journalPayloadTypeForOperation(request any) string {
	switch request.(type) {
	case NatsOperationJournalCreateRequest:
		return journalPayloadOperationCreate
	case NatsOperationJournalUpdateRequest:
		return journalPayloadOperationUpdate
	default:
		return ""
	}
}

func journalPayloadTypeForRuntime(request any) string {
	switch request.(type) {
	case NatsRuntimeLifecycleJournalReadRequest:
		return journalPayloadRuntimeRead
	case NatsRuntimeLifecycleJournalWriteRequest:
		return journalPayloadRuntimeWrite
	default:
		return ""
	}
}

func marshalJournalEnvelope(
	subject string,
	payloadType string,
	cell string,
	instance string,
	messageID string,
	correlationID string,
	causationID string,
	payload any,
) ([]byte, error) {
	message, messageOK := protocol.MessageIdentityTokenTryCreate(messageID)
	correlation, correlationOK := protocol.MessageIdentityTokenTryCreate(correlationID)
	if !messageOK || !message.IsValid() || !correlationOK || !correlation.IsValid() {
		return nil, errors.New("journal envelope identity is invalid")
	}

	var causation *protocol.MessageIdentityToken
	if causationID != "" {
		value, ok := protocol.MessageIdentityTokenTryCreate(causationID)
		if !ok || !value.IsValid() {
			return nil, errors.New("journal envelope causation identity is invalid")
		}
		causation = &value
	}

	targetCell := cell
	return protocol.MarshalMessagingEnvelope(&protocol.MessagingEnvelope{
		SchemaVersion: protocol.MessagingSchemaVersionCurrent,
		MessageId:     message,
		CorrelationId: &correlation,
		CausationId:   causation,
		Source: protocol.MessagingSource{
			Instance: instance,
			Session:  messageID,
			Cell:     cell,
			Cluster:  "orchestrator-control-" + cell,
		},
		Target: protocol.MessagingTargetScope{
			Namespace: natspolicy.NatsSubjectTaxonomy.Classify(subject),
			Subject:   subject,
			Cell:      &targetCell,
		},
		PayloadType: payloadType,
		ObservedAt:  time.Now().UTC(),
	}, payload)
}

func unmarshalJournalEnvelope(
	document []byte,
	subject string,
	payloadType string,
	target any,
) (*protocol.MessagingEnvelope, error) {
	envelope, payload, err := protocol.UnmarshalMessagingEnvelope(
		document,
		subject,
		map[string]struct{}{payloadType: {}},
	)
	if err != nil {
		return nil, err
	}

	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return nil, errors.New("journal envelope payload is invalid")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, errors.New("journal envelope payload is invalid")
	}
	return envelope, nil
}

func journalEnvelopeBindsProof(
	envelope *protocol.MessagingEnvelope,
	proof NatsOperationJournalMutationAuthorityProof,
) bool {
	return envelope != nil && envelope.MessageId.Value == proof.Nonce &&
		envelope.Source.Instance == proof.CallerIdentity && envelope.Source.Cell == proof.Cell &&
		envelope.CorrelationId != nil &&
		envelope.CorrelationId.Value == NatsOperationJournalMutationRequestDigestCreate(proof)
}

func journalReplyEnvelopeBindsProof(
	envelope *protocol.MessagingEnvelope,
	proof NatsOperationJournalMutationAuthorityProof,
) bool {
	return envelope != nil && envelope.MessageId.Value == proof.Nonce+"-reply" &&
		envelope.Source.Instance == "journal-writer" && envelope.Source.Cell == proof.Cell &&
		envelope.CorrelationId != nil &&
		envelope.CorrelationId.Value == NatsOperationJournalMutationRequestDigestCreate(proof) &&
		envelope.CausationId != nil && envelope.CausationId.Value == proof.Nonce
}
