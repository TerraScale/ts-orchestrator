package app

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json/v2"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

func TestBackupHistoryCursorBindsActorQueryAndExpiry(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cursor := backupHistoryCursor{Actor: "operator-a", Cell: "gru",
		Stream: authority.ControlStreamName, DatabaseID: "0000000000WVSMBJNMAWCDJBSK",
		PartitionID: "0000000000Z3WK359G2W66CVT8", OperationID: "3QEXVQEXVQEXVQEXVQEXVQEXVQ",
		Watermark: 500, NextSequence: 129, LatestMatchSequence: 7}
	token, err := signBackupHistoryCursor(cursor, private)
	if err != nil || len(token) > 8<<10 {
		t.Fatalf("sign bounded history cursor: %v", err)
	}
	parsed, err := verifyBackupHistoryCursor(token, public, time.Now().UTC(),
		cursor.Actor, cursor.Cell, cursor.DatabaseID, cursor.PartitionID, cursor.OperationID)
	if err != nil || parsed.NextSequence != cursor.NextSequence ||
		parsed.LatestMatchSequence != cursor.LatestMatchSequence {
		t.Fatalf("verify cursor: %+v, %v", parsed, err)
	}
	if _, err := verifyBackupHistoryCursor(token, public, time.Now().UTC(),
		"other-actor", cursor.Cell, cursor.DatabaseID, cursor.PartitionID, cursor.OperationID); err == nil {
		t.Fatal("cursor authorized another actor")
	}
	if _, err := verifyBackupHistoryCursor(token, public, time.Now().UTC(),
		cursor.Actor, cursor.Cell, cursor.DatabaseID, "other-partition", cursor.OperationID); err == nil {
		t.Fatal("cursor authorized another partition")
	}
	if _, err := verifyBackupHistoryCursor(token, public, time.Now().Add(16*time.Minute),
		cursor.Actor, cursor.Cell, cursor.DatabaseID, cursor.PartitionID, cursor.OperationID); err == nil {
		t.Fatal("expired cursor was accepted")
	}
	altered := token[:len(token)-1] + strings.Repeat("A", 1)
	if altered == token {
		altered = token[:len(token)-1] + "B"
	}
	if _, err := verifyBackupHistoryCursor(altered, public, time.Now().UTC(),
		cursor.Actor, cursor.Cell, cursor.DatabaseID, cursor.PartitionID, cursor.OperationID); err == nil {
		t.Fatal("tampered cursor was accepted")
	}
}

func TestBackupCompleteStatusFitsSignedReplyBound(t *testing.T) {
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
	record := authority.BackupOperationRecord{DatabaseID: "0000000000WVSMBJNMAWCDJBSK", PartitionID: "0000000000Z3WK359G2W66CVT8",
		OperationID: "3QEXVQEXVQEXVQEXVQEXVQEXVQ", State: "complete",
		Ordinal: 1, Attempt: 1, PublicationReceipt: []byte(fixture.PublishedHead.EnvelopeJSON),
		CompleteRelease: []byte(fixture.CompleteRelease.EnvelopeJSON)}
	payload, err := protocol.EncodeJSON(backupStatusReplyFor(record, 42))
	if err != nil {
		t.Fatal(err)
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	signed, err := protocol.SignEnvelope(payload, protocol.EnvelopeScope{Region: "gru",
		Kind: "backup.operation.reply", Actor: "controller",
		OperationID: "48H248H248H248H248H248H248", Generation: 1, Epoch: 1},
		now, now.Add(time.Minute), private)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := protocol.EncodeJSON(signed)
	if err != nil || len(wire) > maxBackupStatusReplyBytes {
		t.Fatalf("signed Complete status exceeds 64 KiB: %d, %v", len(wire), err)
	}
	var decoded protocol.Envelope
	if err := protocol.DecodeStrict(wire, &decoded, maxBackupStatusReplyBytes); err != nil {
		t.Fatalf("operator cannot decode signed Complete status: %v", err)
	}
}
