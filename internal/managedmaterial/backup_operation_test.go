package managedmaterial

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
)

type unknownBackupStore struct {
	record authority.BackupOperationRecord
	read   bool
	alter  bool
}

func (store *unknownBackupStore) ReadBackupOperation(context.Context, string, string) (authority.BackupOperationRecord, uint64, error) {
	if !store.read {
		return authority.BackupOperationRecord{}, 0, authority.ErrNotFound
	}
	record := store.record
	if store.alter {
		record.Nonce = strings.Repeat("0", 32)
	}
	return record, 2, nil
}

func (store *unknownBackupStore) CommitBackupOperation(_ context.Context, _ uint64,
	_, _ string, _ uint64, record authority.BackupOperationRecord,
) (uint64, error) {
	store.record = record
	store.read = true
	return 0, authority.ErrOutcomeUnknown
}

func (store *unknownBackupStore) CommitBackupOperationVerified(ctx context.Context, epoch uint64,
	database, partition string, expected uint64, record authority.BackupOperationRecord,
	verify func(context.Context) error,
) (uint64, error) {
	if err := verify(ctx); err != nil {
		return 0, err
	}
	return store.CommitBackupOperation(ctx, epoch, database, partition, expected, record)
}

func TestBackupUnknownCommitReleasesOnlyExactR3Readback(t *testing.T) {
	signer := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	manifest := BackupManifestPayload{SourceScopeDigest: strings.Repeat("a", 64),
		SourceAuthoritySHA256: strings.Repeat("b", 64),
		SourceConfigurationID: strings.Repeat("c", 64),
		SourceTargetDigest:    strings.Repeat("d", 64), BackupSet: strings.Repeat("e", 32),
		BackupTargetDigest: strings.Repeat("f", 64),
		SignerKeyID:        backupKeyID(signer.Public().(ed25519.PublicKey))}
	roster := []authority.BackupOperationMember{
		{MemberID: "1K6CSK6CSK6CSK6CSK6CSK6CSK", Incarnation: "55555555555555555555555555555555",
			Origin:        strings.Repeat("3", 32) + strings.Repeat("5", 32),
			TLSLeafSHA256: strings.Repeat("1", 64), Node: "host-a", Role: "terrabase"},
		{MemberID: "248H248H248H248H248H248H24", Incarnation: "66666666666666666666666666666666",
			Origin:        strings.Repeat("4", 32) + strings.Repeat("6", 32),
			TLSLeafSHA256: strings.Repeat("2", 64), Node: "host-b", Role: "terrabase"},
	}
	receipt := PreparationReceipt{AuthoritySHA256: manifest.SourceAuthoritySHA256,
		AuthorityConfigurationID: manifest.SourceConfigurationID}
	for index, member := range roster {
		receipt.Spec.Members[index] = InitialMember{MemberID: member.MemberID,
			Incarnation: member.Incarnation}
		receipt.Members[index] = MemberPins{MemberID: member.MemberID,
			TLSLeafSHA256: member.TLSLeafSHA256}
	}
	for _, altered := range []bool{false, true} {
		store := &unknownBackupStore{alter: altered}
		producer := BackupOperationProducer{Store: store}
		record, sequence, err := producer.allocatePrepareWithMaterial(t.Context(), 1,
			"0000000000WVSMBJNMAWCDJBSK", "0000000000Z3WK359G2W66CVT8", 1, roster, time.Now().UTC(), receipt, manifest, signer,
			func(context.Context) error { return nil })
		if altered {
			if !errors.Is(err, authority.ErrOutcomeUnknown) || sequence != 0 ||
				len(record.PrepareEnvelope) != 0 {
				t.Fatalf("mismatched unknown commit released Prepare: record=%+v sequence=%d error=%v",
					record, sequence, err)
			}
			continue
		}
		if err != nil || sequence != 2 || record.OperationID != store.record.OperationID ||
			!bytes.Equal(record.PrepareEnvelope, store.record.PrepareEnvelope) {
			t.Fatalf("exact unknown-commit readback was not confirmed: sequence=%d error=%v", sequence, err)
		}
	}
}
