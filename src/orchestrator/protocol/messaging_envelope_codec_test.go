package protocol

import "terrascale.tech/orchestrator/src/orchestrator/natspolicy"

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestMessagingEnvelopeCodecRoundTripsTheBoundV1Document(t *testing.T) {
	subject, err := natspolicy.NatsSubjectTaxonomy.RuntimeStartupSubject("gru", "controller-1")
	if err != nil {
		t.Fatal(err)
	}
	messageId, _ := MessageIdentityTokenTryCreate("message-1")
	correlationId, _ := MessageIdentityTokenTryCreate("correlation-1")
	cell := "gru"
	trace := &MessagingTraceContext{
		TraceId: "0123456789abcdef0123456789abcdef",
		SpanId:  "0123456789abcdef",
	}
	envelope := &MessagingEnvelope{
		SchemaVersion: MessagingSchemaVersionCurrent,
		MessageId:     messageId,
		CorrelationId: &correlationId,
		Source: MessagingSource{
			Instance: "controller-1",
			Session:  "session-1",
			Cell:     cell,
			Cluster:  "orchestrator-control-gru",
		},
		Target: MessagingTargetScope{
			Namespace: natspolicy.NatsSubjectNamespaceRegionalControl,
			Subject:   subject,
			Cell:      &cell,
		},
		PayloadType:  "runtime-startup-proof",
		TraceContext: trace,
		ObservedAt:   time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC),
	}
	payload := struct {
		Nonce string `json:"nonce"`
	}{Nonce: "proof-1"}

	document, err := MarshalMessagingEnvelope(envelope, payload)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(document, []byte(`"protocolRoot":"ts.orch.v1"`)) ||
		!bytes.Contains(document, []byte(`"schemaVersion":{"major":1,"minor":0}`)) {
		t.Fatalf("document is not bound to v1: %s", document)
	}

	decoded, rawPayload, err := UnmarshalMessagingEnvelope(
		document, subject, map[string]struct{}{"runtime-startup-proof": {}})
	if err != nil {
		t.Fatal(err)
	}
	if decoded.SchemaVersion != MessagingSchemaVersionCurrent || decoded.Target.Subject != subject ||
		decoded.MessageId != messageId || decoded.CorrelationId == nil || *decoded.CorrelationId != correlationId ||
		decoded.TraceContext == nil || *decoded.TraceContext != *trace {
		t.Fatalf("decoded envelope = %#v", decoded)
	}
	var decodedPayload struct {
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(rawPayload, &decodedPayload); err != nil || decodedPayload != payload {
		t.Fatalf("decoded payload = %#v, err = %v", decodedPayload, err)
	}
}

func TestMessagingEnvelopeCodecRejectsPayloadBeyondTheNestingBound(t *testing.T) {
	subject := natspolicy.NatsSubjectTaxonomy.GlobalDirectoryQuerySubject()
	messageId, _ := MessageIdentityTokenTryCreate("message-deep")
	deepPayload := json.RawMessage(
		strings.Repeat("[", messagingEnvelopeMaximumNestingDepth) + "0" +
			strings.Repeat("]", messagingEnvelopeMaximumNestingDepth))

	_, err := MarshalMessagingEnvelope(&MessagingEnvelope{
		SchemaVersion: MessagingSchemaVersionCurrent,
		MessageId:     messageId,
		Source: MessagingSource{
			Instance: "directory-service",
			Session:  "session-deep",
			Cell:     "gru",
			Cluster:  "orchestrator-control-global",
		},
		Target: MessagingTargetScope{
			Namespace: natspolicy.NatsSubjectNamespaceGlobalDirectory,
			Subject:   subject,
		},
		PayloadType: "global-cell-directory-snapshot",
		ObservedAt:  time.Now().UTC(),
	}, deepPayload)
	if err == nil {
		t.Fatal("payload beyond the messaging envelope nesting bound was accepted")
	}
}

func TestMessagingEnvelopeCodecRejectsProtocolAndSubjectSubstitution(t *testing.T) {
	subject := natspolicy.NatsSubjectTaxonomy.GlobalDirectoryQuerySubject()
	messageId, _ := MessageIdentityTokenTryCreate("message-2")
	document, err := MarshalMessagingEnvelope(&MessagingEnvelope{
		SchemaVersion: MessagingSchemaVersionCurrent,
		MessageId:     messageId,
		Source: MessagingSource{
			Instance: "directory-service",
			Session:  "session-2",
			Cell:     "gru",
			Cluster:  "orchestrator-control-global",
		},
		Target: MessagingTargetScope{
			Namespace: natspolicy.NatsSubjectNamespaceGlobalDirectory,
			Subject:   subject,
		},
		PayloadType: "global-cell-directory-snapshot",
		ObservedAt:  time.Now().UTC(),
	}, map[string]int{"activeCells": 3})
	if err != nil {
		t.Fatal(err)
	}
	permitted := map[string]struct{}{"global-cell-directory-snapshot": {}}
	if _, _, err := UnmarshalMessagingEnvelope(document, natspolicy.NatsSubjectTaxonomy.GlobalDeliverySubject(), permitted); err == nil {
		t.Fatal("subject substitution was accepted")
	}
	foreignRoot := bytes.Replace(document, []byte(`"ts.orch.v1"`), []byte(`"ts.orch.old"`), 1)
	if _, _, err := UnmarshalMessagingEnvelope(foreignRoot, subject, permitted); err == nil {
		t.Fatal("foreign protocol root was accepted")
	}
	unknownMember := append(append([]byte(nil), document[:len(document)-1]...), []byte(`,"unknown":true}`)...)
	if _, _, err := UnmarshalMessagingEnvelope(unknownMember, subject, permitted); err == nil {
		t.Fatal("unknown envelope member was accepted")
	}
	duplicateRoot := bytes.Replace(document, []byte(`{"protocolRoot":"ts.orch.v1",`), []byte(`{"protocolRoot":"ts.orch.old","protocolRoot":"ts.orch.v1",`), 1)
	if _, _, err := UnmarshalMessagingEnvelope(duplicateRoot, subject, permitted); err == nil {
		t.Fatal("duplicate protocol root was accepted")
	}
}
