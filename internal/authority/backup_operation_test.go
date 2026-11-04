package authority

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

func backupRecordFixture() BackupOperationRecord {
	return BackupOperationRecord{Version: 1, DatabaseID: "0000000000WVSMBJNMAWCDJBSK", PartitionID: "0000000000Z3WK359G2W66CVT8",
		PlacementSequence: 1,
		SourceScopeDigest: strings.Repeat("a", 64), SourceAuthoritySHA256: strings.Repeat("b", 64),
		SourceConfigurationID: strings.Repeat("c", 64), SourceTargetDigest: strings.Repeat("d", 64),
		BackupSet: "7EXVQEXVQEXVQEXVQEXVQEXVQE", BackupTargetDigest: strings.Repeat("f", 64),
		OwnerMemberID: "1K6CSK6CSK6CSK6CSK6CSK6CSK", OwnerIncarnation: "55555555555555555555555555555555",
		Ordinal: 1, Attempt: 1, AttemptHighWater: 1,
		OperationID: "3QEXVQEXVQEXVQEXVQEXVQEXVQ",
		Nonce:       strings.Repeat("9", 32), PrepareEnvelope: []byte(`{"version":1}`),
		PrepareExpiresAtMS: 1_900_000_060_000, State: "accepted",
		Roster: []BackupOperationMember{
			{Origin: strings.Repeat("3", 32) + strings.Repeat("5", 32),
				MemberID: "1K6CSK6CSK6CSK6CSK6CSK6CSK", Incarnation: "55555555555555555555555555555555",
				TLSLeafSHA256: strings.Repeat("1", 64), Node: "host-a", Role: "terrabase"},
			{Origin: strings.Repeat("4", 32) + strings.Repeat("6", 32),
				MemberID: "248H248H248H248H248H248H24", Incarnation: "66666666666666666666666666666666",
				TLSLeafSHA256: strings.Repeat("2", 64), Node: "host-b", Role: "terrabase"},
		}}
}

func TestBackupCompleteRequiresCommittedProofsAndEveryAcknowledgment(t *testing.T) {
	accepted := backupRecordFixture()
	held := accepted
	held.State = "held"
	held.Roster = slices.Clone(accepted.Roster)
	for index := range held.Roster {
		leaf := []byte{byte(index + 1)}
		digest := sha256.Sum256(leaf)
		held.Roster[index].TLSLeafSHA256 = hex.EncodeToString(digest[:])
		accepted.Roster[index].TLSLeafSHA256 = held.Roster[index].TLSLeafSHA256
		held.Roster[index].CutLeafDER = leaf
		held.Roster[index].CutEnvelope = []byte{byte(index + 3)}
	}
	if err := validateBackupTransition(&accepted, held); err != nil {
		t.Fatal(err)
	}
	barrier := held
	barrier.State = "barrier"
	barrier.BarrierEnvelope = []byte("signed-barrier")
	if err := validateBackupTransition(&held, barrier); err != nil {
		t.Fatal(err)
	}
	premature := barrier
	premature.CandidateEnvelope = []byte("signed-candidate")
	if err := validateBackupTransition(&barrier, premature); err == nil {
		t.Fatalf("candidate before durable Barrier acknowledgments: %v", err)
	}
	acknowledged := barrier
	acknowledged.Roster = slices.Clone(barrier.Roster)
	acknowledged.Roster[0].BarrierAcknowledged = true
	if err := validateBackupTransition(&barrier, acknowledged); err != nil {
		t.Fatal(err)
	}
	allBarrier := acknowledged
	allBarrier.Roster = slices.Clone(acknowledged.Roster)
	allBarrier.Roster[1].BarrierAcknowledged = true
	if err := validateBackupTransition(&acknowledged, allBarrier); err != nil {
		t.Fatal(err)
	}
	candidate := allBarrier
	candidate.CandidateEnvelope = []byte("signed-candidate")
	if err := validateBackupTransition(&allBarrier, candidate); err != nil {
		t.Fatal(err)
	}
	publishing := candidate
	publishing.State = "publishing"
	publishing.CompletionEnvelope = []byte("signed-completion")
	if err := validateBackupTransition(&candidate, publishing); err != nil {
		t.Fatal(err)
	}
	abort := publishing
	abort.State = "aborting"
	abort.AbortEnvelope = []byte("signed-abort")
	abort.AbortExpiresAtMS = publishing.PrepareExpiresAtMS + 1000
	if err := validateBackupTransition(&publishing, abort); err == nil {
		t.Fatalf("Abort after publishing was accepted: %v", err)
	}
	releasing := publishing
	releasing.State = "releasing"
	releasing.PublicationReceipt = []byte("signed-receipt")
	releasing.CompleteRelease = []byte("signed-release")
	releasing.CompleteReleaseExpiresAtMS = 1_900_000_240_000
	releasing.HeadGeneration = 1
	if err := validateBackupTransition(&publishing, releasing); err != nil {
		t.Fatal(err)
	}
	prematureComplete := releasing
	prematureComplete.State = "complete"
	prematureComplete.CompletedOrdinal = 1
	if err := validateBackupTransition(&releasing, prematureComplete); err == nil {
		t.Fatal("Complete advanced ordinal without roster acknowledgments")
	}
	oneAck := releasing
	oneAck.Roster = slices.Clone(releasing.Roster)
	oneAck.Roster[0].CompleteAcknowledged = true
	if err := validateBackupTransition(&releasing, oneAck); err != nil {
		t.Fatal(err)
	}
	renewed := oneAck
	renewed.CompleteRelease = []byte("signed-release-renewed")
	renewed.CompleteReleaseExpiresAtMS += 60_000
	if err := validateBackupTransition(&oneAck, renewed); err != nil {
		t.Fatalf("Release-only renewal after one member ack: %v", err)
	}
	stale := renewed
	stale.CompleteReleaseExpiresAtMS = oneAck.CompleteReleaseExpiresAtMS
	if err := validateBackupTransition(&oneAck, stale); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("Release renewal without later expiry: %v", err)
	}
	changedReceipt := renewed
	changedReceipt.PublicationReceipt = []byte("different-receipt")
	if err := validateBackupTransition(&oneAck, changedReceipt); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("Release renewal changed immutable receipt: %v", err)
	}
	combinedAck := renewed
	combinedAck.Roster = slices.Clone(renewed.Roster)
	combinedAck.Roster[1].CompleteAcknowledged = true
	if err := validateBackupTransition(&oneAck, combinedAck); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("Release renewal shared an acknowledgment commit: %v", err)
	}
	complete := renewed
	complete.Roster = slices.Clone(renewed.Roster)
	complete.Roster[1].CompleteAcknowledged = true
	complete.State = "complete"
	complete.CompletedOrdinal = 1
	if err := validateBackupTransition(&renewed, complete); err != nil {
		t.Fatal(err)
	}
	for _, prior := range []BackupOperationRecord{barrier} {
		injected := prior
		injected.AbortEnvelope = []byte("signed-abort-injected")
		injected.AbortExpiresAtMS = 1_900_000_300_000
		if err := validateBackupTransition(&prior, injected); err == nil {
			t.Fatalf("Abort envelope entered %s without an Abort transition", prior.State)
		}
	}
	next := backupRecordFixture()
	next.CompletedOrdinal = 1
	next.Ordinal = 2
	next.OperationID = "48H248H248H248H248H248H248"
	next.Nonce = strings.Repeat("8", 32)
	next.Terminal = []BackupTerminalReceipt{{OperationID: complete.OperationID,
		Ordinal: 1, Attempt: 1, State: "complete"}}
	if err := validateBackupTransition(&complete, next); err != nil {
		t.Fatalf("next ordinal after all durable acks: %v", err)
	}
}

func TestBackupAndManagedUpdateCommitsFenceEachOtherInBothOrders(t *testing.T) {
	for _, order := range []string{"update-first"} {
		t.Run(order, func(t *testing.T) {
			js := newAuthorityTestJetStream(t)
			ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
			defer cancel()
			runtime, err := Start(ctx, js, Config{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Scope: "gru", CandidateID: entityid.Derive("candidate", order), Replicas: 1})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = runtime.Close() })
			epoch := runtime.Current().Epoch
			initialPlacement := []byte("immutable-initial-placement")
			placementSequence, err := runtime.CommitPlacementIntent(ctx, epoch,
				"0000000000WVSMBJNMAWCDJBSK", "0000000000Z3WK359G2W66CVT8", "0000000000Q2Y4A2RFN6VGFFB1", 0, initialPlacement)
			if err != nil {
				t.Fatal(err)
			}
			backup := backupRecordFixture()
			backup.PlacementSequence = placementSequence
			update := backupFenceManagedUpdateRecord(placementSequence)

			if order == "update-first" {
				preparedSequence, err := runtime.CommitManagedUpdate(ctx, epoch, update, 0, nil)
				if err != nil {
					t.Fatalf("commit prepared managed update: %v", err)
				}
				if _, err := runtime.CommitBackupOperationVerified(ctx, epoch, "0000000000WVSMBJNMAWCDJBSK", "0000000000Z3WK359G2W66CVT8", 0,
					backup, func(context.Context) error { return nil }); !errors.Is(err, ErrFenced) {
					t.Fatalf("backup crossed prepared update: %v", err)
				}
				serving := update
				serving.Phase = ManagedUpdateCanaryServing
				serving.Outcome = string(ManagedUpdateCanaryServing)
				servingSequence, err := runtime.CommitManagedUpdate(ctx, epoch, serving, preparedSequence, nil)
				if err != nil {
					t.Fatalf("commit canary-serving result: %v", err)
				}
				if _, err := runtime.CommitBackupOperationVerified(ctx, epoch, "0000000000WVSMBJNMAWCDJBSK", "0000000000Z3WK359G2W66CVT8", 0,
					backup, func(context.Context) error { return nil }); !errors.Is(err, ErrFenced) {
					t.Fatalf("backup crossed canary-serving update: %v", err)
				}
				latest, err := runtime.ReadManagedUpdate(ctx, "0000000000WVSMBJNMAWCDJBSK", "0000000000Z3WK359G2W66CVT8")
				if err != nil || latest.Sequence != servingSequence ||
					managedUpdatePhaseFromSubject(latest.SubjectKey) != ManagedUpdateCanaryServing {
					t.Fatalf("managed update history changed after rejected backup: %+v, %v", latest, err)
				}
				if _, _, err := runtime.ReadBackupOperation(ctx, "0000000000WVSMBJNMAWCDJBSK", "0000000000Z3WK359G2W66CVT8"); !errors.Is(err, ErrNotFound) {
					t.Fatalf("rejected backup left a durable record: %v", err)
				}
			} else {
				backupSequence, err := runtime.CommitBackupOperationVerified(ctx, epoch,
					"0000000000WVSMBJNMAWCDJBSK", "0000000000Z3WK359G2W66CVT8", 0, backup, func(context.Context) error { return nil })
				if err != nil {
					t.Fatalf("commit backup before update: %v", err)
				}
				if _, err := runtime.CommitManagedUpdate(ctx, epoch, update, 0, nil); !errors.Is(err, ErrFenced) {
					t.Fatalf("managed update crossed accepted backup: %v", err)
				}
				if _, err := runtime.ReadManagedUpdate(ctx, "0000000000WVSMBJNMAWCDJBSK", "0000000000Z3WK359G2W66CVT8"); !errors.Is(err, ErrNotFound) {
					t.Fatalf("rejected update left a durable record: %v", err)
				}
				stored, storedSequence, err := runtime.ReadBackupOperation(ctx, "0000000000WVSMBJNMAWCDJBSK", "0000000000Z3WK359G2W66CVT8")
				if err != nil || storedSequence != backupSequence || stored.OperationID != backup.OperationID {
					t.Fatalf("backup history changed after rejected update: %+v seq=%d err=%v",
						stored, storedSequence, err)
				}
			}

			placement, err := runtime.ReadPlacementIntent(ctx, "0000000000WVSMBJNMAWCDJBSK", "0000000000Z3WK359G2W66CVT8")
			if err != nil || placement.Sequence != placementSequence || !slices.Equal(placement.Payload, initialPlacement) {
				t.Fatalf("reciprocal exclusion changed immutable placement: %+v, %v", placement, err)
			}
		})
	}
}

func backupFenceManagedUpdateRecord(placementSequence uint64) ManagedUpdateRecord {
	request := []byte(`{"version":1,"operation":"backup-fence-test"}`)
	digest := sha256.Sum256(request)
	return ManagedUpdateRecord{
		SchemaVersion: 1, Cell: "gru", DatabaseID: "0000000000WVSMBJNMAWCDJBSK", PartitionID: "0000000000Z3WK359G2W66CVT8",
		OperationID: "0000000000KJ8HRHBVGBDZYCYX", Phase: ManagedUpdatePrepared, SignedRequest: request,
		SignedRequestSHA256: hex.EncodeToString(digest[:]), PlacementGeneration: 1,
		PlacementPayloadDigest: strings.Repeat("a", 64), PlacementSequence: placementSequence,
		CanarySeatID: "000000000077F1R6E1XPKAC2D4", CanaryDesiredGeneration: 2,
		OldArtifactDigest: strings.Repeat("b", 64), CandidateArtifactDigest: strings.Repeat("c", 64),
		CandidateManifestDigest: strings.Repeat("d", 64), CandidateSourceDigest: strings.Repeat("e", 64),
		DurabilityProfileSHA256: strings.Repeat("f", 64),
	}
}
