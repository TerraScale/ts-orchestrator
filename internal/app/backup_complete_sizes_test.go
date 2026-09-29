package app

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json/v2"
	"os"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

func sizeOnlyBackupEnvelopeAtMost(t *testing.T, limit int, signer ed25519.PrivateKey) []byte {
	t.Helper()
	type envelope struct {
		Version   uint64 `json:"version"`
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}
	for payloadSize := 3 * limit / 4; payloadSize >= 0; payloadSize-- {
		payload := bytes.Repeat([]byte("p"), payloadSize)
		wire, err := json.Marshal(envelope{Version: 1,
			Payload:   base64.RawURLEncoding.EncodeToString(payload),
			Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(signer, payload))})
		if err != nil {
			t.Fatal(err)
		}
		if len(wire) <= limit {
			return wire
		}
	}
	t.Fatalf("could not construct signed-envelope-shaped size model at %d bytes", limit)
	return nil
}

func TestBackupStatusReplyExposesCompleteEvidenceOnlyAfterRelease(t *testing.T) {
	data, err := os.ReadFile("../../testdata/backup-complete-wire-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		PublishedHead struct {
			EnvelopeJSON string `json:"envelope_json"`
		} `json:"published_head"`
		CompleteRelease struct {
			EnvelopeJSON string `json:"envelope_json"`
		} `json:"complete_release"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	record := authority.BackupOperationRecord{
		DatabaseID: "database-a", PartitionID: "partition-a",
		OperationID:        "77777777-7777-7777-7777-777777777777",
		PublicationReceipt: []byte(fixture.PublishedHead.EnvelopeJSON),
		CompleteRelease:    []byte(fixture.CompleteRelease.EnvelopeJSON),
	}
	for _, state := range []string{"held", "barrier", "publishing", "aborting", "aborted"} {
		t.Run(state, func(t *testing.T) {
			record.State = state
			reply := backupStatusReplyFor(record, 42)
			if reply.PublicationReceipt != "" || reply.CompleteRelease != "" {
				t.Fatalf("%s status exposed committed publication evidence before release", state)
			}
		})
	}
	for _, state := range []string{"releasing", "complete"} {
		t.Run(state, func(t *testing.T) {
			record.State = state
			reply := backupStatusReplyFor(record, 42)
			if reply.PublicationReceipt != fixture.PublishedHead.EnvelopeJSON ||
				reply.CompleteRelease != fixture.CompleteRelease.EnvelopeJSON {
				t.Fatalf("%s status did not preserve exact committed proof bytes", state)
			}
		})
	}
}

func TestBackupStatusOperatorRejectsSignedReplyOver64KiB(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := protocol.EncodeJSON(backupOperationReply{
		DatabaseID: "database-a", PartitionID: "partition-a",
		OperationID: "77777777-7777-7777-7777-777777777777", State: "complete",
		PublicationReceipt: strings.Repeat("r", maxBackupStatusReplyBytes),
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	signed, err := protocol.SignEnvelope(payload, protocol.EnvelopeScope{
		Region: "gru", Kind: "backup.operation.reply", Actor: "controller",
		OperationID: "88888888-8888-8888-8888-888888888888", Generation: 1, Epoch: 1,
	}, now, now.Add(time.Minute), private)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := protocol.EncodeJSON(signed)
	if err != nil || len(wire) <= maxBackupStatusReplyBytes {
		t.Fatalf("test reply did not cross 64 KiB bound: %d bytes, %v", len(wire), err)
	}
	var decoded protocol.Envelope
	if err := protocol.DecodeStrict(wire, &decoded, maxBackupStatusReplyBytes); err == nil {
		t.Fatal("operator status consumer accepted a signed response over 64 KiB")
	}
}

func TestBackupCompleteMaximumStatusFitsSigned64KiBFrameSizeModel(t *testing.T) {
	// Receipt and Release are signed-envelope-shaped size models at their
	// admitted wire limits; their payloads are not backup publication proofs.
	const maxUint = ^uint64(0)
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	reply := backupOperationReply{
		DatabaseID: strings.Repeat("d", 63), PartitionID: strings.Repeat("p", 63),
		OperationID: "77777777-7777-7777-7777-777777777777", State: "complete",
		Ordinal: maxUint, Attempt: maxUint, Sequence: maxUint,
		PublicationReceipt: string(sizeOnlyBackupEnvelopeAtMost(t, 18<<10, private)),
		CompleteRelease:    string(sizeOnlyBackupEnvelopeAtMost(t, 30<<10, private)),
	}
	payload, err := protocol.EncodeJSON(reply)
	if err != nil || len(payload) > maxBackupStatusReplyBytes {
		t.Fatalf("maximum Complete status payload exceeds 64 KiB: %d bytes, %v", len(payload), err)
	}
	now := time.Now().UTC()
	signed, err := protocol.SignEnvelope(payload, protocol.EnvelopeScope{
		Region: "gru", Kind: "backup.operation.reply", Actor: "controller",
		OperationID: "88888888-8888-8888-8888-888888888888", Generation: 1, Epoch: 1,
	}, now, now.Add(time.Minute), private)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := protocol.EncodeJSON(signed)
	if err != nil || len(wire) > maxBackupStatusReplyBytes {
		t.Fatalf("signed maximum Complete status exceeds 64 KiB: %d bytes, %v", len(wire), err)
	}
	var decoded protocol.Envelope
	if err := protocol.DecodeStrict(wire, &decoded, maxBackupStatusReplyBytes); err != nil {
		t.Fatalf("operator status consumer rejected the maximum-size frame: %v", err)
	}
	if err := protocol.VerifyEnvelope(decoded, protocol.EnvelopeScope{
		Region: "gru", Kind: "backup.operation.reply", Actor: "controller",
		OperationID: "88888888-8888-8888-8888-888888888888", Generation: 1, Epoch: 1,
	}, private.Public().(ed25519.PublicKey), time.Now().UTC(), protocol.VerifyPolicy{
		MaxLifetime: time.Minute, ClockSkew: 30 * time.Second,
	}); err != nil {
		t.Fatalf("signed maximum Complete status did not verify: %v", err)
	}
	var decodedReply backupOperationReply
	if err := protocol.DecodeStrict(decoded.Payload, &decodedReply, maxBackupStatusReplyBytes); err != nil ||
		decodedReply.PublicationReceipt != reply.PublicationReceipt ||
		decodedReply.CompleteRelease != reply.CompleteRelease {
		t.Fatalf("maximum Complete status did not round-trip: %v", err)
	}
	t.Logf("size-only Complete receipt=%d B Release=%d B status payload=%d B signed frame=%d B (64 KiB cap)",
		len(reply.PublicationReceipt), len(reply.CompleteRelease), len(payload), len(wire))
}
