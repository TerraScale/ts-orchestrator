package managedmaterial

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
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
		{MemberID: "33333333-3333-3333-3333-333333333333", Incarnation: strings.Repeat("5", 32),
			Origin:        strings.Repeat("3", 32) + strings.Repeat("5", 32),
			TLSLeafSHA256: strings.Repeat("1", 64), Node: "host-a", Role: "terrabase"},
		{MemberID: "44444444-4444-4444-4444-444444444444", Incarnation: strings.Repeat("6", 32),
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
			"database-a", "partition-a", 1, roster, time.Now().UTC(), receipt, manifest, signer,
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

func TestBackupOperationSignerMatchesFrozenRustWire(t *testing.T) {
	data, err := os.ReadFile("../../testdata/backup-operation-wire-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		TestSeedHex string `json:"test_seed_hex"`
		Prepare     struct {
			PayloadJSON  string `json:"payload_json"`
			EnvelopeJSON string `json:"envelope_json"`
		} `json:"prepare"`
		Release struct {
			PayloadJSON  string `json:"payload_json"`
			EnvelopeJSON string `json:"envelope_json"`
		} `json:"release"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	seed, err := hex.DecodeString(fixture.TestSeedHex)
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatal("frozen backup fixture has no 32-byte signing seed")
	}
	signer := ed25519.NewKeyFromSeed(seed)
	var prepare backupPrepareWire
	if err := json.Unmarshal([]byte(fixture.Prepare.PayloadJSON), &prepare,
		json.RejectUnknownMembers(true)); err != nil {
		t.Fatal(err)
	}
	if prepare.Attempt == 0 || prepare.Ordinal == 0 {
		t.Fatal("frozen Prepare fixture omits signed ordinal or attempt")
	}
	wire, err := signBackupOperation(backupPrepareDomain, prepare, signer)
	if err != nil || !bytes.Equal(wire, []byte(fixture.Prepare.EnvelopeJSON)) {
		t.Fatalf("Go Prepare differs from frozen Rust bytes: %v", err)
	}
	var release backupReleaseWire
	if err := json.Unmarshal([]byte(fixture.Release.PayloadJSON), &release,
		json.RejectUnknownMembers(true)); err != nil {
		t.Fatal(err)
	}
	if release.Attempt != prepare.Attempt || release.Ordinal != prepare.Ordinal {
		t.Fatal("frozen Release differs from signed Prepare attempt")
	}
	wire, err = signBackupOperation(backupReleaseDomain, release, signer)
	if err != nil || !bytes.Equal(wire, []byte(fixture.Release.EnvelopeJSON)) {
		t.Fatalf("Go Release differs from frozen Rust bytes: %v", err)
	}
}
