package protocol

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func TestMessagingEnvelopeCodecRoundTripsTheBoundV2Document(t *testing.T) {
	subject, err := NatsSubjectTaxonomy.RuntimeStartupSubject("gru", "controller-1")
	if err != nil {
		t.Fatal(err)
	}
	messageId, _ := MessageIdentityTokenTryCreate("message-1")
	correlationId, _ := MessageIdentityTokenTryCreate("correlation-1")
	cell := "gru"
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
			Namespace: NatsSubjectNamespaceRegionalControl,
			Subject:   subject,
			Cell:      &cell,
		},
		PayloadType: "runtime-startup-proof",
		ObservedAt:  time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC),
	}
	payload := struct {
		Nonce string `json:"nonce"`
	}{Nonce: "proof-1"}

	document, err := MarshalMessagingEnvelope(envelope, payload)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(document, []byte(`"protocolRoot":"ts.orch.v2"`)) ||
		!bytes.Contains(document, []byte(`"schemaVersion":{"major":2,"minor":0}`)) {
		t.Fatalf("document is not bound to v2: %s", document)
	}

	decoded, rawPayload, err := UnmarshalMessagingEnvelope(
		document, subject, map[string]struct{}{"runtime-startup-proof": {}})
	if err != nil {
		t.Fatal(err)
	}
	if decoded.SchemaVersion != MessagingSchemaVersionCurrent || decoded.Target.Subject != subject ||
		decoded.MessageId != messageId || decoded.CorrelationId == nil || *decoded.CorrelationId != correlationId {
		t.Fatalf("decoded envelope = %#v", decoded)
	}
	var decodedPayload struct {
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(rawPayload, &decodedPayload); err != nil || decodedPayload != payload {
		t.Fatalf("decoded payload = %#v, err = %v", decodedPayload, err)
	}
}

func TestMessagingEnvelopeCodecRejectsProtocolAndSubjectSubstitution(t *testing.T) {
	subject := NatsSubjectTaxonomy.GlobalDirectoryQuerySubject()
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
			Namespace: NatsSubjectNamespaceGlobalDirectory,
			Subject:   subject,
		},
		PayloadType: "global-cell-directory-snapshot",
		ObservedAt:  time.Now().UTC(),
	}, map[string]int{"activeCells": 3})
	if err != nil {
		t.Fatal(err)
	}
	permitted := map[string]struct{}{"global-cell-directory-snapshot": {}}
	if _, _, err := UnmarshalMessagingEnvelope(document, NatsSubjectTaxonomy.CiForgejoTriggerSubject(), permitted); err == nil {
		t.Fatal("subject substitution was accepted")
	}
	foreignRoot := bytes.Replace(document, []byte(`"ts.orch.v2"`), []byte(`"ts.orch.old"`), 1)
	if _, _, err := UnmarshalMessagingEnvelope(foreignRoot, subject, permitted); err == nil {
		t.Fatal("foreign protocol root was accepted")
	}
	unknownMember := append(append([]byte(nil), document[:len(document)-1]...), []byte(`,"unknown":true}`)...)
	if _, _, err := UnmarshalMessagingEnvelope(unknownMember, subject, permitted); err == nil {
		t.Fatal("unknown envelope member was accepted")
	}
	duplicateRoot := bytes.Replace(document, []byte(`{"protocolRoot":"ts.orch.v2",`), []byte(`{"protocolRoot":"ts.orch.old","protocolRoot":"ts.orch.v2",`), 1)
	if _, _, err := UnmarshalMessagingEnvelope(duplicateRoot, subject, permitted); err == nil {
		t.Fatal("duplicate protocol root was accepted")
	}
}
