package authority

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"uuid"

	"github.com/nats-io/nats.go/jetstream"
)

func backupRecordFixture() BackupOperationRecord {
	return BackupOperationRecord{Version: 1, DatabaseID: "database-a", PartitionID: "partition-a",
		PlacementSequence: 1,
		SourceScopeDigest: strings.Repeat("a", 64), SourceAuthoritySHA256: strings.Repeat("b", 64),
		SourceConfigurationID: strings.Repeat("c", 64), SourceTargetDigest: strings.Repeat("d", 64),
		BackupSet: strings.Repeat("e", 32), BackupTargetDigest: strings.Repeat("f", 64),
		OwnerMemberID: "33333333-3333-3333-3333-333333333333", OwnerIncarnation: strings.Repeat("5", 32),
		Ordinal: 1, Attempt: 1, AttemptHighWater: 1,
		OperationID: "77777777-7777-7777-7777-777777777777",
		Nonce:       strings.Repeat("9", 32), PrepareEnvelope: []byte(`{"version":1}`),
		PrepareExpiresAtMS: 1_900_000_060_000, State: "accepted",
		Roster: []BackupOperationMember{
			{Origin: strings.Repeat("3", 32) + strings.Repeat("5", 32),
				MemberID: "33333333-3333-3333-3333-333333333333", Incarnation: strings.Repeat("5", 32),
				TLSLeafSHA256: strings.Repeat("1", 64), Node: "host-a", Role: "terrabase"},
			{Origin: strings.Repeat("4", 32) + strings.Repeat("6", 32),
				MemberID: "44444444-4444-4444-4444-444444444444", Incarnation: strings.Repeat("6", 32),
				TLSLeafSHA256: strings.Repeat("2", 64), Node: "host-b", Role: "terrabase"},
		}}
}

func TestBackupAttemptNeedsRosterWideAbortBeforeReuseOfOrdinal(t *testing.T) {
	first := backupRecordFixture()
	if err := validateBackupTransition(nil, first); err != nil {
		t.Fatal(err)
	}
	second := first
	second.OperationID = "88888888-8888-8888-8888-888888888888"
	second.Nonce = strings.Repeat("8", 32)
	second.Attempt = 2
	second.AttemptHighWater = 2
	second.PrepareEnvelope = []byte(`{"version":2}`)
	if err := validateBackupTransition(&first, second); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("new attempt before abort: %v", err)
	}
	aborting := first
	aborting.State = "aborting"
	aborting.AbortEnvelope = []byte(`{"version":1,"reason":"abort"}`)
	aborting.AbortExpiresAtMS = 1_900_000_120_000
	if err := validateBackupTransition(&first, aborting); err != nil {
		t.Fatal(err)
	}
	uncommittedAck := aborting
	uncommittedAck.Roster = slices.Clone(aborting.Roster)
	uncommittedAck.Roster[0].AbortAcknowledged = true
	if err := validateBackupTransition(&first, uncommittedAck); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("Abort acknowledgment shared its first decision commit: %v", err)
	}
	skipDecision := aborting
	skipDecision.State = "aborted"
	skipDecision.Roster = slices.Clone(aborting.Roster)
	for index := range skipDecision.Roster {
		skipDecision.Roster[index].AbortAcknowledged = true
	}
	if err := validateBackupTransition(&first, skipDecision); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("Abort acknowledgment skipped the committed decision: %v", err)
	}
	partiallyAcked := aborting
	partiallyAcked.Roster = slices.Clone(aborting.Roster)
	partiallyAcked.Roster[0].AbortAcknowledged = true
	if err := validateBackupTransition(&aborting, partiallyAcked); err != nil {
		t.Fatal(err)
	}
	if err := validateBackupTransition(&partiallyAcked, second); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("new attempt before every roster ack: %v", err)
	}
	fullyAcked := partiallyAcked
	fullyAcked.Roster = slices.Clone(partiallyAcked.Roster)
	fullyAcked.Roster[1].AbortAcknowledged = true
	fullyAcked.State = "aborted"
	if err := validateBackupTransition(&partiallyAcked, fullyAcked); err != nil {
		t.Fatal(err)
	}
	second.Terminal = []BackupTerminalReceipt{{OperationID: first.OperationID,
		Ordinal: 1, Attempt: 1, State: "aborted"}}
	second.Roster = slices.Clone(first.Roster)
	if err := validateBackupTransition(&fullyAcked, second); err != nil {
		t.Fatalf("fresh attempt 2 at still-uncompleted ordinal 1: %v", err)
	}
	stale := second
	stale.Attempt = 1
	stale.AttemptHighWater = 1
	if err := validateBackupTransition(&fullyAcked, stale); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("stale attempt accepted: %v", err)
	}
}

func TestBackupHeldRequiresEveryCutAndAbortCannotClearNewerHold(t *testing.T) {
	first := backupRecordFixture()
	held := first
	held.State = "held"
	held.Roster = slices.Clone(first.Roster)
	held.Roster[0].CutEnvelope = []byte("cut-a")
	held.Roster[0].CutLeafDER = []byte("leaf-a")
	firstLeaf := sha256.Sum256(held.Roster[0].CutLeafDER)
	first.Roster[0].TLSLeafSHA256 = hex.EncodeToString(firstLeaf[:])
	held.Roster[0].TLSLeafSHA256 = first.Roster[0].TLSLeafSHA256
	if err := validateBackupTransition(&first, held); err == nil {
		t.Fatal("held state accepted with one missing Cut")
	}
	held.Roster[1].CutEnvelope = []byte("cut-b")
	held.Roster[1].CutLeafDER = []byte("leaf-b")
	secondLeaf := sha256.Sum256(held.Roster[1].CutLeafDER)
	first.Roster[1].TLSLeafSHA256 = hex.EncodeToString(secondLeaf[:])
	held.Roster[1].TLSLeafSHA256 = first.Roster[1].TLSLeafSHA256
	if err := validateBackupTransition(&first, held); err != nil {
		t.Fatal(err)
	}
	changed := held
	changed.Roster = slices.Clone(held.Roster)
	changed.Roster[0].CutEnvelope = []byte("other-cut")
	if err := validateBackupTransition(&held, changed); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("changed Cut accepted: %v", err)
	}
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
	for _, prior := range []BackupOperationRecord{barrier, publishing, releasing, complete} {
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
	next.OperationID = "88888888-8888-8888-8888-888888888888"
	next.Nonce = strings.Repeat("8", 32)
	next.Terminal = []BackupTerminalReceipt{{OperationID: complete.OperationID,
		Ordinal: 1, Attempt: 1, State: "complete"}}
	if err := validateBackupTransition(&complete, next); err != nil {
		t.Fatalf("next ordinal after all durable acks: %v", err)
	}
}

func TestBackupHistoryPagesExactPartitionAndPayloadOperationID(t *testing.T) {
	js := newAuthorityTestJetStream(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	runtime, err := Start(ctx, js, Config{Scope: "gru", CandidateID: "backup-history-page", Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	subject := mutationSubject("gru", MutationBackupOperation, "database-a.partition-a")
	old := backupRecordFixture()
	later := backupRecordFixture()
	later.OperationID = "88888888-8888-8888-8888-888888888888"
	var oldSequence uint64
	for index := range 130 {
		record := later
		if index == 0 {
			record = old
		}
		payload, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		outer, err := json.Marshal(controlRecord{Version: 1, Kind: MutationBackupOperation,
			Scope: "gru", SubjectKey: "database-a.partition-a",
			OperationID: "mutation-record", Epoch: runtime.Current().Epoch, Payload: payload})
		if err != nil {
			t.Fatal(err)
		}
		ack, err := js.Publish(ctx, subject, outer)
		if err != nil {
			t.Fatal(err)
		}
		if index == 0 {
			oldSequence = ack.Sequence
		}
	}
	first, err := runtime.ReadBackupHistoryPage(ctx, old.DatabaseID, old.PartitionID,
		old.OperationID, 0, 0)
	if err != nil || first.Exhausted || first.LatestMatchSequence != oldSequence ||
		first.NextSequence <= oldSequence {
		t.Fatalf("first bounded history page: %+v, %v", first, err)
	}
	second, err := runtime.ReadBackupHistoryPage(ctx, old.DatabaseID, old.PartitionID,
		old.OperationID, first.Watermark, first.NextSequence)
	if err != nil || !second.Exhausted || second.LatestMatchSequence != 0 {
		t.Fatalf("second bounded history page: %+v, %v", second, err)
	}
	recovered, err := runtime.ReadBackupOperationAtSequence(ctx, old.DatabaseID, old.PartitionID,
		old.OperationID, oldSequence)
	if err != nil || recovered.OperationID != old.OperationID {
		t.Fatalf("exact prior operation was lost: %v", err)
	}
	if _, err := runtime.ReadBackupOperationAtSequence(ctx, old.DatabaseID, old.PartitionID,
		old.OperationID, second.Watermark); !errors.Is(err, ErrNotFound) {
		t.Fatalf("different payload operation ID was accepted: %v", err)
	}
	corrupt, err := js.Publish(ctx, subject, []byte(`{"invalid":"control-record"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.ReadBackupOperationAtSequence(ctx, old.DatabaseID, old.PartitionID,
		old.OperationID, corrupt.Sequence); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("corrupt historical entry was reported as not found: %v", err)
	}
}

func TestBackupRosterRequiresOneHostRelayPerMember(t *testing.T) {
	record := backupRecordFixture()
	record.Roster[1].Node = record.Roster[0].Node
	if err := record.validate(); err == nil {
		t.Fatal("two members shared one node and role command slot")
	}
}

func TestBackupAllocationAndPlacementRaceAtPinnedSequence(t *testing.T) {
	js := newAuthorityTestJetStream(t)
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	runtime, err := Start(ctx, js, Config{Scope: "gru", CandidateID: "backup-placement-race", Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	epoch := runtime.Current().Epoch
	initial, err := runtime.CommitPlacementIntent(ctx, epoch, "database-a", "partition-a",
		"initial-placement", 0, []byte("initial"))
	if err != nil {
		t.Fatal(err)
	}
	record := backupRecordFixture()
	record.PlacementSequence = initial
	var placementSequence, backupSequence uint64
	var placementErr, backupErr error
	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		placementSequence, placementErr = runtime.CommitPlacementIntent(ctx, epoch,
			"database-a", "partition-a", "changed-placement", initial, []byte("changed"))
	}()
	go func() {
		defer wait.Done()
		backupSequence, backupErr = runtime.CommitBackupOperationVerified(ctx, epoch,
			"database-a", "partition-a", 0, record, func(context.Context) error { return nil })
	}()
	wait.Wait()
	if (placementErr == nil) == (backupErr == nil) {
		t.Fatalf("placement and backup both committed or both failed: placement=%d/%v backup=%d/%v",
			placementSequence, placementErr, backupSequence, backupErr)
	}
	if placementErr == nil && !errors.Is(backupErr, ErrFenced) ||
		backupErr == nil && !errors.Is(placementErr, ErrFenced) {
		t.Fatalf("losing mutation was not fenced: placement=%v backup=%v", placementErr, backupErr)
	}
}

func TestNewBackupOperationRequiresFinalRosterVerifier(t *testing.T) {
	js := newAuthorityTestJetStream(t)
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	runtime, err := Start(ctx, js, Config{Scope: "gru", CandidateID: "backup-verifier-required", Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	epoch := runtime.Current().Epoch
	placementSequence, err := runtime.CommitPlacementIntent(ctx, epoch, "database-a", "partition-a",
		"initial-placement", 0, []byte("initial"))
	if err != nil {
		t.Fatal(err)
	}
	record := backupRecordFixture()
	record.PlacementSequence = placementSequence
	if _, err := runtime.CommitBackupOperation(ctx, epoch, "database-a", "partition-a", 0, record); !errors.Is(err, ErrFenced) {
		t.Fatalf("new backup operation without final roster proof = %v, want fenced", err)
	}
	if _, _, err := runtime.ReadBackupOperation(ctx, "database-a", "partition-a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unverified backup attempt left an R3 record: %v", err)
	}
}

func TestBackupAndManagedUpdateCommitsFenceEachOtherInBothOrders(t *testing.T) {
	for _, order := range []string{"update-first", "backup-first"} {
		t.Run(order, func(t *testing.T) {
			js := newAuthorityTestJetStream(t)
			ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
			defer cancel()
			runtime, err := Start(ctx, js, Config{Scope: "gru", CandidateID: "update-backup-" + order, Replicas: 1})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = runtime.Close() })
			epoch := runtime.Current().Epoch
			initialPlacement := []byte("immutable-initial-placement")
			placementSequence, err := runtime.CommitPlacementIntent(ctx, epoch,
				"database-a", "partition-a", "initial-placement", 0, initialPlacement)
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
				if _, err := runtime.CommitBackupOperationVerified(ctx, epoch, "database-a", "partition-a", 0,
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
				if _, err := runtime.CommitBackupOperationVerified(ctx, epoch, "database-a", "partition-a", 0,
					backup, func(context.Context) error { return nil }); !errors.Is(err, ErrFenced) {
					t.Fatalf("backup crossed canary-serving update: %v", err)
				}
				latest, err := runtime.ReadManagedUpdate(ctx, "database-a", "partition-a")
				if err != nil || latest.Sequence != servingSequence ||
					managedUpdatePhaseFromSubject(latest.SubjectKey) != ManagedUpdateCanaryServing {
					t.Fatalf("managed update history changed after rejected backup: %+v, %v", latest, err)
				}
				if _, _, err := runtime.ReadBackupOperation(ctx, "database-a", "partition-a"); !errors.Is(err, ErrNotFound) {
					t.Fatalf("rejected backup left a durable record: %v", err)
				}
			} else {
				backupSequence, err := runtime.CommitBackupOperationVerified(ctx, epoch,
					"database-a", "partition-a", 0, backup, func(context.Context) error { return nil })
				if err != nil {
					t.Fatalf("commit backup before update: %v", err)
				}
				if _, err := runtime.CommitManagedUpdate(ctx, epoch, update, 0, nil); !errors.Is(err, ErrFenced) {
					t.Fatalf("managed update crossed accepted backup: %v", err)
				}
				if _, err := runtime.ReadManagedUpdate(ctx, "database-a", "partition-a"); !errors.Is(err, ErrNotFound) {
					t.Fatalf("rejected update left a durable record: %v", err)
				}
				stored, storedSequence, err := runtime.ReadBackupOperation(ctx, "database-a", "partition-a")
				if err != nil || storedSequence != backupSequence || stored.OperationID != backup.OperationID {
					t.Fatalf("backup history changed after rejected update: %+v seq=%d err=%v",
						stored, storedSequence, err)
				}
			}

			placement, err := runtime.ReadPlacementIntent(ctx, "database-a", "partition-a")
			if err != nil || placement.Sequence != placementSequence || !slices.Equal(placement.Payload, initialPlacement) {
				t.Fatalf("reciprocal exclusion changed immutable placement: %+v, %v", placement, err)
			}
		})
	}
}

func TestConcurrentBackupAndManagedUpdateStartsHaveOneWinner(t *testing.T) {
	js := newAuthorityTestJetStream(t)
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	runtime, err := Start(ctx, js, Config{Scope: "gru", CandidateID: "concurrent-update-backup", Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	epoch := runtime.Current().Epoch
	initialPlacement := []byte("immutable-concurrent-placement")
	placementSequence, err := runtime.CommitPlacementIntent(ctx, epoch,
		"database-a", "partition-a", "initial-placement", 0, initialPlacement)
	if err != nil {
		t.Fatal(err)
	}
	backup := backupRecordFixture()
	backup.PlacementSequence = placementSequence
	update := backupFenceManagedUpdateRecord(placementSequence)

	start := make(chan struct{})
	var wait sync.WaitGroup
	wait.Add(2)
	var backupSequence, updateSequence uint64
	var backupErr, updateErr error
	go func() {
		defer wait.Done()
		<-start
		backupSequence, backupErr = runtime.CommitBackupOperationVerified(ctx, epoch,
			"database-a", "partition-a", 0, backup, func(context.Context) error { return nil })
	}()
	go func() {
		defer wait.Done()
		<-start
		updateSequence, updateErr = runtime.CommitManagedUpdate(ctx, epoch, update, 0, nil)
	}()
	close(start)
	wait.Wait()
	if (backupErr == nil) == (updateErr == nil) {
		t.Fatalf("backup and managed update both committed or both failed: backup=%d/%v update=%d/%v",
			backupSequence, backupErr, updateSequence, updateErr)
	}
	if backupErr == nil && !errors.Is(updateErr, ErrFenced) ||
		updateErr == nil && !errors.Is(backupErr, ErrFenced) {
		t.Fatalf("losing workload mutation was not fenced: backup=%v update=%v", backupErr, updateErr)
	}
	placement, err := runtime.ReadPlacementIntent(ctx, "database-a", "partition-a")
	if err != nil || placement.Sequence != placementSequence || !slices.Equal(placement.Payload, initialPlacement) {
		t.Fatalf("concurrent exclusion changed immutable placement: %+v, %v", placement, err)
	}
}

func TestBackupStartAllowsDurableHeldManagedUpdate(t *testing.T) {
	js := newAuthorityTestJetStream(t)
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	runtime, err := Start(ctx, js, Config{Scope: "gru", CandidateID: "backup-after-update-held", Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	epoch := runtime.Current().Epoch
	placementPayload := []byte("immutable-held-placement")
	placementSequence, err := runtime.CommitPlacementIntent(ctx, epoch,
		"database-a", "partition-a", "initial-placement", 0, placementPayload)
	if err != nil {
		t.Fatal(err)
	}
	update := backupFenceManagedUpdateRecord(placementSequence)
	preparedSequence, err := runtime.CommitManagedUpdate(ctx, epoch, update, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	held := update
	held.Phase = ManagedUpdateHeld
	held.Outcome = "candidate-proof-timeout"
	if _, err := runtime.CommitManagedUpdate(ctx, epoch, held, preparedSequence, nil); err != nil {
		t.Fatalf("commit durable held outcome: %v", err)
	}
	backup := backupRecordFixture()
	backup.PlacementSequence = placementSequence
	if _, err := runtime.CommitBackupOperation(ctx, epoch, "database-a", "partition-a", 0, backup); !errors.Is(err, ErrFenced) {
		t.Fatalf("unverified backup after held update was admitted: %v", err)
	}
	currentRosterMatches := false
	if _, err := runtime.CommitBackupOperationVerified(ctx, epoch, "database-a", "partition-a", 0, backup,
		func(context.Context) error {
			if !currentRosterMatches {
				return ErrFenced
			}
			return nil
		}); !errors.Is(err, ErrFenced) {
		t.Fatalf("stale pre-update serving roster was admitted after Held: %v", err)
	}
	if _, _, err := runtime.ReadBackupOperation(ctx, "database-a", "partition-a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rejected stale roster left a backup record: %v", err)
	}
	currentRosterMatches = true
	verified := false
	if _, err := runtime.CommitBackupOperationVerified(ctx, epoch, "database-a", "partition-a", 0, backup,
		func(context.Context) error {
			verified = true
			return nil
		}); err != nil {
		t.Fatalf("terminal held update with verified exact serving roster was fenced: %v", err)
	}
	if !verified {
		t.Fatal("final serving-roster verifier did not run")
	}
	placement, err := runtime.ReadPlacementIntent(ctx, "database-a", "partition-a")
	if err != nil || placement.Sequence != placementSequence || !slices.Equal(placement.Payload, placementPayload) {
		t.Fatalf("backup after held outcome changed immutable placement: %+v, %v", placement, err)
	}
}

type unavailableManagedUpdateHistoryStream struct {
	jetstream.Stream
	err error
}

func (stream unavailableManagedUpdateHistoryStream) Info(
	context.Context, ...jetstream.StreamInfoOpt,
) (*jetstream.StreamInfo, error) {
	return nil, stream.err
}

func TestBackupStartFailsClosedWhenManagedUpdateHistoryIsUnreadable(t *testing.T) {
	js := newAuthorityTestJetStream(t)
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	runtime, err := Start(ctx, js, Config{Scope: "gru", CandidateID: "backup-unreadable-update", Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	epoch := runtime.Current().Epoch
	placementSequence, err := runtime.CommitPlacementIntent(ctx, epoch,
		"database-a", "partition-a", "initial-placement", 0, []byte("immutable-initial-placement"))
	if err != nil {
		t.Fatal(err)
	}
	unavailable := errors.New("managed update history is unavailable")
	runtime.readStream = unavailableManagedUpdateHistoryStream{Stream: runtime.readStream, err: unavailable}
	backup := backupRecordFixture()
	backup.PlacementSequence = placementSequence
	if _, err := runtime.CommitBackupOperationVerified(ctx, epoch, "database-a", "partition-a", 0,
		backup, func(context.Context) error { return nil }); !errors.Is(err, unavailable) {
		t.Fatalf("backup admission did not fail closed on unreadable update history: %v", err)
	}
	if _, _, err := runtime.ReadBackupOperation(ctx, "database-a", "partition-a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unreadable update history left a backup record: %v", err)
	}
}

func backupFenceManagedUpdateRecord(placementSequence uint64) ManagedUpdateRecord {
	request := []byte(`{"version":1,"operation":"backup-fence-test"}`)
	digest := sha256.Sum256(request)
	return ManagedUpdateRecord{
		SchemaVersion: 1, Cell: "gru", DatabaseID: "database-a", PartitionID: "partition-a",
		OperationID: "managed-update-test", Phase: ManagedUpdatePrepared, SignedRequest: request,
		SignedRequestSHA256: hex.EncodeToString(digest[:]), PlacementGeneration: 1,
		PlacementPayloadDigest: strings.Repeat("a", 64), PlacementSequence: placementSequence,
		CanarySeatID: "seat-a", CanaryDesiredGeneration: 2,
		OldArtifactDigest: strings.Repeat("b", 64), CandidateArtifactDigest: strings.Repeat("c", 64),
		CandidateManifestDigest: strings.Repeat("d", 64), CandidateSourceDigest: strings.Repeat("e", 64),
		DurabilityProfileSHA256: strings.Repeat("f", 64),
	}
}

func TestBackupActiveFencesTerminalUntilAllRosterAbort(t *testing.T) {
	js := newAuthorityTestJetStream(t)
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	runtime, err := Start(ctx, js, Config{Scope: "gru", CandidateID: "backup-terminal-gate", Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	epoch := runtime.Current().Epoch
	placementSequence, err := runtime.CommitPlacementIntent(ctx, epoch, "database-a", "partition-a",
		"initial-placement", 0, []byte("initial"))
	if err != nil {
		t.Fatal(err)
	}
	record := backupRecordFixture()
	record.PlacementSequence = placementSequence
	sequence, err := runtime.CommitBackupOperationVerified(ctx, epoch, "database-a", "partition-a", 0,
		record, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	intent := TerminalIntent{Cell: "gru", DatabaseID: "database-a", PartitionID: "partition-a",
		Region: "GRU", Owner: "owner-a", CompartmentID: "ocid1.compartment.oc1..backupgate",
		FleetGeneration: 1, PlacementGeneration: 1, PlacementPayloadDigest: strings.Repeat("a", 64),
		OperationID: "terminal-after-backup", Nonce: uuid.New().String(),
		Targets: []TerminalTarget{{SeatID: "seat-a", MemberID: "member-a",
			HostCreateKey: "host-a", DataCreateKey: "data-a"}},
		DisposableWorkload: true, AcknowledgePermanentDataLoss: true, AuthorizeForcedStop: true}
	payload, err := json.Marshal(intent, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	scope := WorkloadScope{DatabaseID: "database-a", PartitionID: "partition-a"}
	commitTerminal := func() error {
		_, err := runtime.CommitTerminalIntent(ctx, epoch, scope, intent.OperationID,
			payload, func(context.Context) error { return nil })
		return err
	}
	if err := commitTerminal(); !errors.Is(err, ErrFenced) {
		t.Fatalf("terminal action crossed active backup: %v", err)
	}
	record.State = "aborting"
	record.AbortEnvelope = []byte(`{"version":1,"reason":"abort"}`)
	record.AbortExpiresAtMS = 1_900_000_120_000
	sequence, err = runtime.CommitBackupOperation(ctx, epoch, "database-a", "partition-a", sequence, record)
	if err != nil {
		t.Fatal(err)
	}
	record.Roster = slices.Clone(record.Roster)
	record.Roster[0].AbortAcknowledged = true
	sequence, err = runtime.CommitBackupOperation(ctx, epoch, "database-a", "partition-a", sequence, record)
	if err != nil {
		t.Fatal(err)
	}
	if err := commitTerminal(); !errors.Is(err, ErrFenced) {
		t.Fatalf("terminal action crossed partial roster Abort: %v", err)
	}
	record.Roster[1].AbortAcknowledged = true
	record.State = "aborted"
	if _, err := runtime.CommitBackupOperation(ctx, epoch, "database-a", "partition-a", sequence, record); err != nil {
		t.Fatal(err)
	}
	if err := commitTerminal(); err != nil {
		t.Fatalf("terminal action after roster-wide Abort: %v", err)
	}
}
