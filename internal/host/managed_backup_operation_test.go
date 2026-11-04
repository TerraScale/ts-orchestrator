//go:build linux

package host

import (
	"bytes"
	"context"

	"crypto/sha256"
	"encoding/hex"

	"strings"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
)

type backupTestMutationReader struct {
	authority.HostMutationStore
	authority.VerifiedHostMutationStore
	record authority.BackupOperationRecord
}

type verifiedMemoryMutations struct{ *memoryMutations }

func (mutations verifiedMemoryMutations) CommitHostMutationVerified(ctx context.Context, epoch uint64,
	kind authority.HostMutationKind, subject, operation string, expected uint64, payload []byte,
	verify func(context.Context) error,
) (uint64, error) {
	m := mutations.memoryMutations
	m.mu.Lock()
	defer m.mu.Unlock()
	key := m.key(kind, subject)
	if m.entries[key].Sequence != expected {
		return 0, authority.ErrConflict
	}
	if verify != nil {
		if err := verify(ctx); err != nil {
			return 0, err
		}
	}
	ack, err := m.js.Publish(ctx, "ts.control.gru.host."+string(kind)+"."+subject, payload)
	if err != nil {
		return 0, err
	}
	m.sequence = ack.Sequence
	m.entries[key] = authority.LogEntry{Kind: kind, SubjectKey: subject, OperationID: operation,
		Epoch: epoch, Sequence: m.sequence, Payload: bytes.Clone(payload)}
	return m.sequence, nil
}

func (reader backupTestMutationReader) ReadBackupOperation(_ context.Context,
	databaseID, partitionID string,
) (authority.BackupOperationRecord, uint64, error) {
	if reader.record.DatabaseID != databaseID || reader.record.PartitionID != partitionID {
		return authority.BackupOperationRecord{}, 0, authority.ErrNotFound
	}
	return reader.record, 1, nil
}

func TestBackupHostCommandOnlyRelaysExactR3Envelope(t *testing.T) {
	prepare := []byte(`{"version":1,"payload":"prepare"}`)
	sum := sha256.Sum256(prepare)
	prepareSHA := hex.EncodeToString(sum[:])
	memberID := "1K6CSK6CSK6CSK6CSK6CSK6CSK"
	incarnation := strings.Repeat("5", 32)
	leafSHA := strings.Repeat("1", 64)
	record := authority.BackupOperationRecord{DatabaseID: "0000000000WVSMBJNMAWCDJBSK", PartitionID: "0000000000Z3WK359G2W66CVT8",
		OperationID: "3QEXVQEXVQEXVQEXVQEXVQEXVQ", State: "accepted",
		PrepareEnvelope: prepare, Roster: []authority.BackupOperationMember{{
			MemberID: memberID, Incarnation: incarnation, Node: "host-a", Role: "terrabase",
			TLSLeafSHA256: leafSHA}}}
	command := ManagedBackupCommand{OperationID: record.OperationID, DatabaseID: record.DatabaseID,
		PartitionID: record.PartitionID, MemberID: memberID, Node: "host-a", Role: "terrabase",
		Kind: "prepare", Envelope: bytes.Clone(prepare), EnvelopeSHA256: prepareSHA,
		Member:    ManagedMemberBinding{Scope: MemberScope{MemberID: memberID, Incarnation: incarnation}},
		Authority: MemberAuthority{TLSLeafSHA256: leafSHA}}
	if !command.matchesRecord(record) {
		t.Fatal("exact R3 Prepare was rejected")
	}
	changed := command
	changed.Envelope = []byte(`{"version":1,"payload":"0000000000V4MRM46HP1SNGDYW"}`)
	if changed.matchesRecord(record) {
		t.Fatal("changed host Prepare envelope was accepted")
	}
	changed = command
	changed.MemberID = "248H248H248H248H248H248H24"
	if changed.matchesRecord(record) {
		t.Fatal("wrong roster member received an envelope")
	}
	changed = command
	changed.Envelope = bytes.Repeat([]byte("x"), maxBackupRelayBytes+1)
	if changed.matchesRecord(record) {
		t.Fatal("oversize host envelope was accepted")
	}
	abort := []byte(`{"version":1,"payload":"abort"}`)
	sum = sha256.Sum256(abort)
	record.State = "aborting"
	record.AbortEnvelope = abort
	command.Kind = "abort"
	command.Envelope = abort
	command.EnvelopeSHA256 = hex.EncodeToString(sum[:])
	if !command.matchesRecord(record) {
		t.Fatal("R3-committed Abort was rejected")
	}
	command.Kind = "prepare"
	command.Envelope = prepare
	command.EnvelopeSHA256 = prepareSHA
	if command.matchesRecord(record) {
		t.Fatal("stale Prepare was relayed after Abort decision")
	}
}
