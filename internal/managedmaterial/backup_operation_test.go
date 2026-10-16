package managedmaterial

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"github.com/oklog/ulid/v2"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
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
		Barrier struct {
			PayloadJSON  string `json:"payload_json"`
			EnvelopeJSON string `json:"envelope_json"`
		} `json:"barrier"`
		Completion struct {
			PayloadJSON  string `json:"payload_json"`
			EnvelopeJSON string `json:"envelope_json"`
		} `json:"completion"`
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
	var barrier backupBarrierWire
	if err := json.Unmarshal([]byte(fixture.Barrier.PayloadJSON), &barrier,
		json.RejectUnknownMembers(true)); err != nil {
		t.Fatal(err)
	}
	wire, err = signBackupOperation(backupBarrierDomain, barrier, signer)
	if err != nil || !bytes.Equal(wire, []byte(fixture.Barrier.EnvelopeJSON)) {
		t.Fatalf("Go Barrier differs from frozen Rust bytes: %v", err)
	}
	var completion backupCompletionWire
	if err := json.Unmarshal([]byte(fixture.Completion.PayloadJSON), &completion,
		json.RejectUnknownMembers(true)); err != nil {
		t.Fatal(err)
	}
	wire, err = signBackupOperation(backupCompletionDomain, completion, signer)
	if err != nil || !bytes.Equal(wire, []byte(fixture.Completion.EnvelopeJSON)) {
		t.Fatalf("Go Completion differs from frozen Rust bytes: %v", err)
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

func TestBackupCompleteRustGoldenProofsAndCanonicalHead(t *testing.T) {
	data, err := os.ReadFile("../../testdata/backup-complete-wire-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Version                uint64 `json:"version"`
		ControllerPublicKeyHex string `json:"controller_public_key_hex"`
		OwnerPublicKeyHex      string `json:"owner_public_key_hex"`
		OwnerLeafDERBase64URL  string `json:"owner_leaf_der_base64url"`
		Candidate              struct {
			PayloadJSON    string `json:"payload_json"`
			EnvelopeJSON   string `json:"envelope_json"`
			EnvelopeSHA256 string `json:"envelope_sha256"`
		} `json:"candidate"`
		NegativeCandidateLowerFrontier struct {
			PayloadJSON    string `json:"payload_json"`
			EnvelopeJSON   string `json:"envelope_json"`
			EnvelopeSHA256 string `json:"envelope_sha256"`
		} `json:"negative_candidate_lower_frontier"`
		PublishedHead struct {
			PayloadJSON    string `json:"payload_json"`
			EnvelopeJSON   string `json:"envelope_json"`
			EnvelopeSHA256 string `json:"envelope_sha256"`
		} `json:"published_head"`
		CompleteRelease struct {
			PayloadJSON    string `json:"payload_json"`
			EnvelopeJSON   string `json:"envelope_json"`
			EnvelopeSHA256 string `json:"envelope_sha256"`
		} `json:"complete_release"`
	}
	if err := json.Unmarshal(data, &fixture, json.RejectUnknownMembers(true)); err != nil || fixture.Version != 1 {
		t.Fatalf("Rust Complete fixture is invalid: %v", err)
	}
	controller, controllerErr := hex.DecodeString(fixture.ControllerPublicKeyHex)
	owner, ownerErr := hex.DecodeString(fixture.OwnerPublicKeyHex)
	der, derErr := base64.RawURLEncoding.DecodeString(fixture.OwnerLeafDERBase64URL)
	if controllerErr != nil || ownerErr != nil || derErr != nil ||
		len(controller) != ed25519.PublicKeySize || len(owner) != ed25519.PublicKeySize ||
		len(der) == 0 || len(der) > 4096 {
		t.Fatal("Rust Complete fixture has invalid signing keys or owner leaf")
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil || !bytes.Equal(leaf.PublicKey.(ed25519.PublicKey), owner) {
		t.Fatal("Rust Complete fixture owner key differs from pinned DER")
	}
	var candidate backupCandidateWire
	if err := decodeCanonicalBackupSigned([]byte(fixture.Candidate.EnvelopeJSON),
		backupCandidateDomain, owner, 8<<10, &candidate); err != nil ||
		backupSHA([]byte(fixture.Candidate.EnvelopeJSON)) != fixture.Candidate.EnvelopeSHA256 {
		t.Fatalf("Go Candidate verification differs from Rust: %v", err)
	}
	var receipt backupPublishedHeadWire
	if err := decodeCanonicalBackupSigned([]byte(fixture.PublishedHead.EnvelopeJSON),
		backupPublishedHeadDomain, owner, 18<<10, &receipt); err != nil ||
		backupSHA([]byte(fixture.PublishedHead.EnvelopeJSON)) != fixture.PublishedHead.EnvelopeSHA256 {
		t.Fatalf("Go published-head verification differs from Rust: %v", err)
	}
	var release backupReleaseWire
	if err := decodeCanonicalBackupSigned([]byte(fixture.CompleteRelease.EnvelopeJSON),
		backupReleaseDomain, controller, 30<<10, &release); err != nil ||
		backupSHA([]byte(fixture.CompleteRelease.EnvelopeJSON)) != fixture.CompleteRelease.EnvelopeSHA256 ||
		release.Reason != "complete" ||
		release.PublicationReceiptSHA256 != fixture.PublishedHead.EnvelopeSHA256 ||
		release.PublicationReceipt != base64.RawURLEncoding.EncodeToString([]byte(fixture.PublishedHead.EnvelopeJSON)) {
		t.Fatalf("Go Complete Release verification differs from Rust: %v", err)
	}
	setBytes, err := hex.DecodeString(candidate.BackupSet)
	if err != nil || len(setBytes) != 16 {
		t.Fatal("frozen head set is invalid")
	}
	var setID ulid.ULID
	copy(setID[:], setBytes)
	headBytes, err := base64.RawURLEncoding.DecodeString(receipt.CatalogHeadBytes)
	if err != nil || !verifyBackupCatalogHeadBytes(headBytes,
		authority.BackupOperationRecord{BackupSet: setID.String(),
			BackupTargetDigest: candidate.BackupTargetDigest, Ordinal: candidate.Ordinal},
		candidate.PreviousHeadSHA256) || backupSHA(headBytes) != receipt.CatalogHeadSHA256 {
		t.Fatalf("Go canonical catalog-head verification differs from Rust: %v", err)
	}
	for _, invalidSet := range []string{candidate.BackupSet, strings.ToLower(setID.String()), entityid.New()} {
		if verifyBackupCatalogHeadBytes(headBytes,
			authority.BackupOperationRecord{BackupSet: invalidSet,
				BackupTargetDigest: candidate.BackupTargetDigest, Ordinal: candidate.Ordinal},
			candidate.PreviousHeadSHA256) {
			t.Fatalf("catalog head accepted mismatched/noncanonical set %q", invalidSet)
		}
	}
	if err := decodeCanonicalBackupSigned(append([]byte(fixture.Candidate.EnvelopeJSON), ' '),
		backupCandidateDomain, owner, 8<<10, &candidate); err == nil {
		t.Fatal("noncanonical Candidate envelope was accepted")
	}
	if verifyBackupCatalogHeadBytes(append(bytes.Clone(headBytes), 'x'),
		authority.BackupOperationRecord{BackupSet: setID.String(),
			BackupTargetDigest: candidate.BackupTargetDigest, Ordinal: candidate.Ordinal},
		candidate.PreviousHeadSHA256) {
		t.Fatal("altered catalog head bytes were accepted")
	}
	operationData, err := os.ReadFile("../../testdata/backup-operation-wire-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var operation struct {
		TestSeedHex string `json:"test_seed_hex"`
		Completion  struct {
			EnvelopeJSON string `json:"envelope_json"`
		} `json:"completion"`
	}
	if err := json.Unmarshal(operationData, &operation); err != nil {
		t.Fatal(err)
	}
	seed, err := hex.DecodeString(operation.TestSeedHex)
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatal("frozen Complete signer seed is invalid")
	}
	record := authority.BackupOperationRecord{OperationID: candidate.OperationID,
		Nonce: candidate.Nonce, SourceScopeDigest: candidate.SourceScopeDigest,
		SourceAuthoritySHA256: candidate.SourceAuthoritySHA256,
		SourceConfigurationID: candidate.SourceConfigurationID,
		BackupSet:             candidate.BackupSet, Ordinal: candidate.Ordinal, Attempt: candidate.Attempt,
		CompletionEnvelope: []byte(operation.Completion.EnvelopeJSON)}
	manifest := BackupManifestPayload{SignerKeyID: release.SignerKeyID}
	signedRelease, err := signCompleteRelease(record, []byte(fixture.PublishedHead.EnvelopeJSON),
		release.ExpiresAtMS, manifest, ed25519.NewKeyFromSeed(seed))
	if err != nil || !bytes.Equal(signedRelease, []byte(fixture.CompleteRelease.EnvelopeJSON)) {
		t.Fatalf("Go initial Complete Release differs from Rust: %v", err)
	}
	renewed, err := signCompleteRelease(record, []byte(fixture.PublishedHead.EnvelopeJSON),
		release.ExpiresAtMS+60_000, manifest, ed25519.NewKeyFromSeed(seed))
	if err != nil || bytes.Equal(renewed, signedRelease) {
		t.Fatalf("Go Complete Release renewal did not change signed expiry: %v", err)
	}
	var renewedPayload backupReleaseWire
	if err := decodeCanonicalBackupSigned(renewed, backupReleaseDomain, controller,
		30<<10, &renewedPayload); err != nil ||
		renewedPayload.ExpiresAtMS != release.ExpiresAtMS+60_000 ||
		renewedPayload.PublicationReceipt != release.PublicationReceipt ||
		renewedPayload.CompletionEnvelope != release.CompletionEnvelope {
		t.Fatalf("renewed Release changed immutable publication proof: %v", err)
	}
}

func TestBackupCandidateRejectsSignedLowerFrontier(t *testing.T) {
	completeData, err := os.ReadFile("../../testdata/backup-complete-wire-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var complete struct {
		OwnerPublicKeyHex string `json:"owner_public_key_hex"`
		Candidate         struct {
			EnvelopeJSON string `json:"envelope_json"`
		} `json:"candidate"`
		NegativeCandidateLowerFrontier struct {
			EnvelopeJSON string `json:"envelope_json"`
		} `json:"negative_candidate_lower_frontier"`
	}
	if err := json.Unmarshal(completeData, &complete); err != nil {
		t.Fatal(err)
	}
	ownerPublic, err := hex.DecodeString(complete.OwnerPublicKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	var candidate, lower backupCandidateWire
	for _, item := range []struct {
		wire []byte
		into *backupCandidateWire
	}{
		{[]byte(complete.Candidate.EnvelopeJSON), &candidate},
		{[]byte(complete.NegativeCandidateLowerFrontier.EnvelopeJSON), &lower},
	} {
		if err := decodeCanonicalBackupSigned(item.wire, backupCandidateDomain,
			ownerPublic, 8<<10, item.into); err != nil {
			t.Fatalf("Rust owner-signed Candidate was invalid: %v", err)
		}
	}
	operationData, err := os.ReadFile("../../testdata/backup-operation-wire-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var operation struct {
		PublicKeyHex              string `json:"public_key_hex"`
		MemberOneLeafPublicKeyHex string `json:"member_one_leaf_public_key_hex"`
		MemberTwoLeafPublicKeyHex string `json:"member_two_leaf_public_key_hex"`
		Prepare                   struct {
			EnvelopeJSON string `json:"envelope_json"`
		} `json:"prepare"`
		Barrier struct {
			EnvelopeJSON string `json:"envelope_json"`
		} `json:"barrier"`
		CutOne struct {
			EnvelopeJSON string `json:"envelope_json"`
		} `json:"cut_one"`
		CutTwo struct {
			EnvelopeJSON string `json:"envelope_json"`
		} `json:"cut_two"`
	}
	if err := json.Unmarshal(operationData, &operation); err != nil {
		t.Fatal(err)
	}
	if candidate.PrepareSHA256 != backupSHA([]byte(operation.Prepare.EnvelopeJSON)) ||
		candidate.BarrierSHA256 != backupSHA([]byte(operation.Barrier.EnvelopeJSON)) {
		t.Fatal("Rust Candidate is not bound to the frozen Prepare and Barrier")
	}
	var barrier backupBarrierWire
	controller, err := hex.DecodeString(operation.PublicKeyHex)
	if err != nil || decodeCanonicalBackupSigned([]byte(operation.Barrier.EnvelopeJSON),
		backupBarrierDomain, controller, 8<<10, &barrier) != nil {
		t.Fatal("frozen Barrier signature is invalid")
	}
	if len(barrier.Roster) != 2 {
		t.Fatal("frozen Barrier does not have both members")
	}
	record := authority.BackupOperationRecord{OperationID: candidate.OperationID,
		Nonce: candidate.Nonce, SourceScopeDigest: candidate.SourceScopeDigest,
		SourceAuthoritySHA256: candidate.SourceAuthoritySHA256,
		SourceConfigurationID: candidate.SourceConfigurationID,
		SourceTargetDigest:    candidate.SourceTargetDigest, BackupSet: candidate.BackupSet,
		BackupTargetDigest: candidate.BackupTargetDigest, Ordinal: candidate.Ordinal,
		Attempt: candidate.Attempt, PrepareEnvelope: []byte(operation.Prepare.EnvelopeJSON),
		BarrierEnvelope: []byte(operation.Barrier.EnvelopeJSON)}
	var cuts [2]BackupCut
	for index, item := range []struct {
		publicHex string
		wire      string
	}{
		{operation.MemberOneLeafPublicKeyHex, operation.CutOne.EnvelopeJSON},
		{operation.MemberTwoLeafPublicKeyHex, operation.CutTwo.EnvelopeJSON},
	} {
		public, err := hex.DecodeString(item.publicHex)
		if err != nil || decodeCanonicalBackupSigned([]byte(item.wire), backupCutDomain,
			public, 8<<10, &cuts[index]) != nil {
			t.Fatalf("frozen member %d Cut signature is invalid", index)
		}
		barrierMember := barrier.Roster[index]
		if cuts[index].Origin != barrierMember.Origin ||
			cuts[index].AppliedSequence != barrierMember.AppliedSequence {
			t.Fatalf("signed Cut %d differs from signed Barrier", index)
		}
		record.Roster = append(record.Roster, authority.BackupOperationMember{
			Origin: barrierMember.Origin, MemberID: barrierMember.MemberID,
			Incarnation:   barrierMember.Incarnation,
			TLSLeafSHA256: cuts[index].LeafCertificateSHA256})
	}
	owner := record.Roster[0]
	owner.TLSLeafSHA256 = candidate.OwnerLeafCertificateSHA256
	if !candidateMatches(record, owner, candidate, ownerPublic, cuts[:]) {
		t.Fatal("valid Rust Candidate did not match signed Cuts")
	}
	if len(lower.SelectedFrontier) != len(cuts) ||
		lower.SelectedFrontier[1].AppliedSequence >= cuts[1].AppliedSequence ||
		candidateMatches(record, owner, lower, ownerPublic, cuts[:]) {
		t.Fatal("owner-signed lower frontier passed Candidate admission")
	}
}
