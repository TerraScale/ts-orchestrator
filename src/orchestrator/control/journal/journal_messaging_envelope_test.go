package journal

import (
	"encoding/json"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/control/messaging"
	"terrascale.tech/orchestrator/src/orchestrator/protocol"
)

func TestJournalEnvelopeRejectsRawPayloadAndSubjectSubstitution(t *testing.T) {
	topology := messaging.NewNatsTopology("gru", 3, "controller-1")
	subject, err := topology.OperationJournalCreateSubject()
	if err != nil {
		t.Fatal(err)
	}
	proof := NatsOperationJournalMutationAuthorityProof{
		Cell: "gru", CallerIdentity: "controller-1", Nonce: "0123456789abcdef0123456789abcdef",
	}
	request := NatsOperationJournalCreateRequest{
		SchemaVersion: protocol.ProtocolVersion.Current(),
		Key:           "operation." + "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0",
		Value:         "ciphertext",
		Authority:     proof,
	}
	digest := NatsOperationJournalMutationRequestDigestCreate(proof)
	document, err := marshalJournalEnvelope(
		subject, journalPayloadOperationCreate, "gru", "controller-1",
		proof.Nonce, digest, "", request)
	if err != nil {
		t.Fatal(err)
	}

	var decoded NatsOperationJournalCreateRequest
	envelope, err := unmarshalJournalEnvelope(document, subject, journalPayloadOperationCreate, &decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !journalEnvelopeBindsProof(envelope, decoded.Authority) || decoded.SchemaVersion != protocol.ProtocolVersion.Current() {
		t.Fatalf("decoded journal request is not bound to v1: %#v", decoded)
	}
	envelope.Source.Instance = "other-controller"
	if journalEnvelopeBindsProof(envelope, decoded.Authority) {
		t.Fatal("journal envelope source substitution was accepted")
	}

	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unmarshalJournalEnvelope(raw, subject, journalPayloadOperationCreate, &decoded); err == nil {
		t.Fatal("raw journal payload was accepted without a v1 envelope")
	}
	updateSubject, err := topology.OperationJournalUpdateSubject()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unmarshalJournalEnvelope(document, updateSubject, journalPayloadOperationCreate, &decoded); err == nil {
		t.Fatal("journal subject substitution was accepted")
	}
}

func TestJournalEnvelopeRejectsUnknownPayloadMembers(t *testing.T) {
	topology := messaging.NewNatsTopology("sfo", 3, "controller-2")
	subject, err := topology.OperationJournalCreateSubject()
	if err != nil {
		t.Fatal(err)
	}
	document, err := marshalJournalEnvelope(
		subject,
		journalPayloadOperationCreate,
		"sfo",
		"controller-2",
		"0123456789abcdef0123456789abcdef",
		"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		"",
		json.RawMessage(`{"SchemaVersion":2,"Unknown":true}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	var decoded NatsOperationJournalCreateRequest
	if _, err := unmarshalJournalEnvelope(document, subject, journalPayloadOperationCreate, &decoded); err == nil {
		t.Fatal("unknown journal payload member was accepted")
	}
}
