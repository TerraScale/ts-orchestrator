package bootstrap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

func TestReserveSlotRecoversLostAcknowledgementAndSurvivesRestart(t *testing.T) {
	fixture := newLedgerFixture(t)
	fixture.client.loseAckForBucket("bootstrap-ledger")
	scope := testBootstrapScope()
	intentBytes, _ := fixture.intentBytes(t, scope, 1, "create-key-1", "retry-token-1")
	headBytes := fixture.headBytes(t, scope, intentBytes, 1)

	reserved, err := fixture.ledger.ReserveSlot(t.Context(), scope, intentBytes, headBytes)
	if err != nil {
		t.Fatalf("reserve after lost intent acknowledgement: %v", err)
	}
	if reserved.IntentDigest() != bodyDigest(intentBytes) || reserved.Attempt() != 1 || reserved.HeadETag() == "" {
		t.Fatalf("reservation does not identify the verified slot: %+v", reserved)
	}
	if got := fixture.client.putCalls.Load(); got != 2 {
		t.Fatalf("PUT calls = %d, want immutable intent and initial HEAD", got)
	}
	if got := fixture.client.getCalls.Load(); got != 8 {
		t.Fatalf("exact-key readbacks = %d, want intent/HEAD confirmations, final intent refresh, and verified-slot reads", got)
	}

	restarted := fixture.newLedger(t)
	launch, err := restarted.ReadForLaunch(t.Context(), scope)
	if err != nil {
		t.Fatalf("read launch authorization after restart: %v", err)
	}
	if launch.IntentDigest() != reserved.IntentDigest() || launch.HeadETag() != reserved.HeadETag() {
		t.Fatalf("restart changed durable reservation: before=%+v after=%+v", reserved, launch)
	}

	duplicate, err := restarted.ReserveSlot(t.Context(), scope, intentBytes, headBytes)
	if err != nil {
		t.Fatalf("idempotently reserve exact signed bytes: %v", err)
	}
	if duplicate.HeadETag() != launch.HeadETag() {
		t.Fatalf("idempotent reservation changed HEAD ETag: got %q, want %q", duplicate.HeadETag(), launch.HeadETag())
	}
}

func TestLegacyManagedIntentCannotReserveOrAuthorizeLaunch(t *testing.T) {
	scope := testBootstrapScope()
	fixture := newLedgerFixture(t)
	intentBytes, intent := fixture.intentBytes(t, scope, 1, "legacy-create-key", "legacy-retry-token")
	intent.SchemaVersion = 1
	intent.FounderPlanSHA256 = ""
	intent.PeerRowDigest = ""
	intentBytes = fixture.sign(t, scope, domainBootstrapIntent, intent, fixture.now)
	headBytes := fixture.headBytes(t, scope, intentBytes, 1)
	if err := validateIntent(intent); err != nil {
		t.Fatalf("historical schema-v1 intent should remain readable: %v", err)
	}
	if _, err := fixture.ledger.ReserveSlot(t.Context(), scope, intentBytes, headBytes); !errors.Is(err, ErrFounderPlanRequired) {
		t.Fatalf("ReserveSlot() error = %v, want ErrFounderPlanRequired", err)
	}
	if got := fixture.client.objectCount(); got != 0 {
		t.Fatalf("legacy reservation wrote %d ledger objects before rejection", got)
	}

	// Model an already durable legacy slot. Historical reads remain available,
	// but a current launch token cannot be minted from its schema-v1 intent.
	fixture = newLedgerFixture(t)
	intentBytes, intent = fixture.intentBytes(t, scope, 1, "legacy-create-key", "legacy-retry-token")
	intent.SchemaVersion = 1
	intent.FounderPlanSHA256 = ""
	intent.PeerRowDigest = ""
	intentBytes = fixture.sign(t, scope, domainBootstrapIntent, intent, fixture.now)
	headBytes = fixture.headBytes(t, scope, intentBytes, 1)
	if _, err := fixture.ledger.createOrRead(t.Context(), scope, 1, ledgerIntent, intentBytes); err != nil {
		t.Fatalf("store historical intent fixture: %v", err)
	}
	head, err := fixture.ledger.decodeHead(scope, headBytes, true)
	if err != nil {
		t.Fatalf("decode legacy HEAD fixture: %v", err)
	}
	if _, _, err := fixture.ledger.writeInitialHead(t.Context(), scope, head, headBytes, true); err != nil {
		t.Fatalf("store historical HEAD fixture: %v", err)
	}
	if _, err := fixture.ledger.ReadForLaunch(t.Context(), scope); !errors.Is(err, ErrFounderPlanRequired) {
		t.Fatalf("ReadForLaunch() error = %v, want ErrFounderPlanRequired", err)
	}
	if _, err := fixture.ledger.RecordManagedPeer(t.Context(), scope, nil, nil, InstanceFacts{}, nil, nil,
		fixture.managedPeerProgressSigner(scope), nil); !errors.Is(err, ErrFounderPlanRequired) {
		t.Fatalf("RecordManagedPeer() error = %v, want ErrFounderPlanRequired for a historical intent", err)
	}
}

func TestConcurrentInitialReservationAndManifestConflict(t *testing.T) {
	fixture := newLedgerFixture(t)
	scope := testBootstrapScope()
	intentBytes, intent := fixture.intentBytes(t, scope, 1, "create-key-1", "retry-token-1")
	headBytes := fixture.headBytes(t, scope, intentBytes, 1)

	var group sync.WaitGroup
	errs := make(chan error, 12)
	for range 12 {
		group.Go(func() {
			_, err := fixture.ledger.ReserveSlot(t.Context(), scope, intentBytes, headBytes)
			errs <- err
		})
	}
	group.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("concurrent reservation: %v", err)
		}
	}
	if got := fixture.client.objectCount(); got != 2 {
		t.Fatalf("stored objects = %d, want one intent and one stable HEAD", got)
	}
	if fixture.client.invalidCondition.Load() {
		t.Fatal("a conditional create or update used the wrong Object Storage condition")
	}
	if fixture.client.invalidKMSKey.Load() {
		t.Fatal("a record was not encrypted with its bucket's configured KMS key")
	}

	storedHead, err := fixture.ledger.decodeHead(scope, headBytes, true)
	if err != nil {
		t.Fatalf("decode initial HEAD fixture: %v", err)
	}
	resignedHead := fixture.signInterval(t, scope, domainBootstrapHead, storedHead,
		fixture.now, fixture.now.Add(time.Hour))
	if _, err := fixture.ledger.ReserveSlot(t.Context(), scope, intentBytes, resignedHead); !errors.Is(err, ErrSlotHeadConflict) {
		t.Fatalf("different signed bytes with the same HEAD payload returned %v, want exact-byte conflict", err)
	}

	rotated := intent
	rotated.ManifestDigest = bodyDigest([]byte("rotated manifest"))
	rotatedBytes := fixture.sign(t, scope, domainBootstrapIntent, rotated, fixture.now)
	rotatedHead := fixture.headBytes(t, scope, rotatedBytes, 1)
	if _, err := fixture.ledger.ReserveSlot(t.Context(), scope, rotatedBytes, rotatedHead); !errors.Is(err, ErrImmutableConflict) {
		t.Fatalf("changed intent at the existing attempt returned %v, want immutable conflict", err)
	}
}

func TestRecordResultCASAndAdvanceRequireBoundRetirementEvidence(t *testing.T) {
	fixture := newLedgerFixture(t)
	scope := testBootstrapScope()
	intentBytes, intent := fixture.intentBytes(t, scope, 1, "create-key-1", "retry-token-1")
	initialHead := SlotHead{SchemaVersion: 2, DeploymentID: scope.DeploymentID, Cell: scope.Cell,
		Environment: fixture.environment, Role: roleController, Slot: scope.Slot, Attempt: 1,
		Generation: 1, IntentDigest: bodyDigest(intentBytes)}
	initialHeadBytes := fixture.sign(t, scope, domainBootstrapHead, initialHead, fixture.now)
	reservation, err := fixture.ledger.ReserveSlot(t.Context(), scope, intentBytes, initialHeadBytes)
	if err != nil {
		t.Fatalf("reserve initial attempt: %v", err)
	}
	if _, err := fixture.ledger.AdvanceSlot(t.Context(), scope, reservation.HeadETag(), nil, nil, nil); !errors.Is(err, ErrSlotNotReserved) {
		t.Fatalf("advance without a committed positive result = %v, want ErrSlotNotReserved", err)
	}

	manifestBytes, receiptBytes, facts := fixture.managedProof(t, scope, intent, reservation.IntentDigest())
	candidateWire := fixture.pinManagedPeerCandidate(t, scope, intent, reservation.IntentDigest(), facts)
	result := fixture.result(scope, intent, reservation.IntentDigest())
	result.PeerReceiptDigest = bodyDigest(receiptBytes)
	resultBytes := fixture.sign(t, scope, domainBootstrapResult, result, fixture.now)
	completedHead := initialHead
	completedHead.ResultDigest = bodyDigest(resultBytes)
	completedHead.CandidateDigest = bodyDigest(candidateWire)
	completedHeadBytes := fixture.sign(t, scope, domainBootstrapHead, completedHead, fixture.now)
	if _, err := fixture.ledger.RecordResult(t.Context(), scope, resultBytes, completedHeadBytes); !errors.Is(err, ErrManagedPeerReceiptRequired) {
		t.Fatalf("generic managed result path returned %v, want delegated receipt requirement", err)
	}
	fixture.client.loseAckForBucket("bootstrap-head")
	state, err := fixture.ledger.RecordManagedPeer(t.Context(), scope, manifestBytes, receiptBytes, facts, resultBytes, completedHeadBytes,
		fixture.managedPeerProgressSigner(scope), fixture.managedPeerRefresh(scope))
	if err != nil {
		t.Fatalf("record result after lost HEAD acknowledgement: %v", err)
	}
	if state.Result == nil || state.Head.ResultDigest != bodyDigest(resultBytes) || state.HeadRecord.ETag == reservation.HeadETag() {
		t.Fatalf("positive result was not committed through a new HEAD ETag: %+v", state)
	}
	if _, err := fixture.ledger.ReadForLaunch(t.Context(), scope); !errors.Is(err, ErrSlotAlreadyComplete) {
		t.Fatalf("launch authorization after positive result = %v, want ErrSlotAlreadyComplete", err)
	}

	validEvidence := fixture.retirement(scope, state, "instance-retired")
	retirementBytes := fixture.sign(t, scope, domainSlotRetirement, validEvidence, fixture.now)
	nextIntentBytes, nextIntent := fixture.intentBytes(t, scope, 2, "create-key-2", "retry-token-2")
	nextIntent.RetirementDigest = bodyDigest(retirementBytes)
	nextIntentBytes = fixture.sign(t, scope, domainBootstrapIntent, nextIntent, fixture.now)
	validNextHead := SlotHead{
		SchemaVersion: 2, DeploymentID: scope.DeploymentID, Cell: scope.Cell, Environment: fixture.environment,
		Role: roleController, Slot: scope.Slot, Attempt: 2, Generation: 2,
		IntentDigest: bodyDigest(nextIntentBytes), PreviousAttempt: state.Head.Attempt,
		PreviousGeneration: state.Head.Generation, PreviousIntentDigest: state.Head.IntentDigest,
		PreviousResultDigest: state.Head.ResultDigest, PreviousCandidateDigest: state.Head.CandidateDigest,
		RetirementDigest: bodyDigest(retirementBytes),
	}
	nextHeadBytes := fixture.sign(t, scope, domainBootstrapHead, validNextHead, fixture.now)
	if _, err := fixture.ledger.AdvanceSlot(t.Context(), scope, reservation.HeadETag(), retirementBytes,
		nextIntentBytes, nextHeadBytes); !errors.Is(err, ErrSlotHeadConflict) {
		t.Fatalf("stale HEAD ETag advance returned %v, want conflict", err)
	}

	invalidEvidence := validEvidence
	invalidEvidence.PriorInstanceOCID = "ocid1.instance.oc1.sa-saopaulo-1.different"
	invalidRetirement := fixture.sign(t, scope, domainSlotRetirement, invalidEvidence, fixture.now)
	invalidNextHead := validNextHead
	invalidNextHead.RetirementDigest = bodyDigest(invalidRetirement)
	invalidNextHeadBytes := fixture.sign(t, scope, domainBootstrapHead, invalidNextHead, fixture.now)
	if _, err := fixture.ledger.AdvanceSlot(t.Context(), scope, state.HeadRecord.ETag, invalidRetirement,
		nextIntentBytes, invalidNextHeadBytes); !errors.Is(err, ErrRetirementInvalid) {
		t.Fatalf("retirement for another instance returned %v, want retirement rejection", err)
	}
	wrongCandidateHead := validNextHead
	wrongCandidateHead.PreviousCandidateDigest = bodyDigest([]byte("different pinned candidate"))
	wrongCandidateHeadBytes := fixture.sign(t, scope, domainBootstrapHead, wrongCandidateHead, fixture.now)
	if _, err := fixture.ledger.AdvanceSlot(t.Context(), scope, state.HeadRecord.ETag, retirementBytes,
		nextIntentBytes, wrongCandidateHeadBytes); !errors.Is(err, ErrRetirementInvalid) {
		t.Fatalf("successor HEAD bound to another candidate returned %v, want retirement rejection", err)
	}

	launch, err := fixture.ledger.AdvanceSlot(t.Context(), scope, state.HeadRecord.ETag, retirementBytes,
		nextIntentBytes, nextHeadBytes)
	if err != nil {
		t.Fatalf("advance with current result-bound retirement: %v", err)
	}
	if launch.Attempt() != 2 || launch.IntentDigest() != bodyDigest(nextIntentBytes) {
		t.Fatalf("advanced launch token does not identify attempt two: %+v", launch)
	}
	headBucket := fixture.ledger.config.HeadBucket
	progressObjectName := fixture.ledger.progressObjectName(scope, state.Head.Attempt)
	progressKey := requestKey(new("namespace"), new(headBucket), new(progressObjectName))
	fixture.client.mu.Lock()
	delete(fixture.client.objects, progressKey)
	fixture.client.mu.Unlock()
	if _, err := fixture.ledger.ReadSlot(t.Context(), scope); err != nil {
		t.Fatalf("successor HEAD could not verify immutable predecessor proofs without mutable progress: %v", err)
	}
	if fixture.client.invalidCondition.Load() {
		t.Fatal("ledger used an unconditional write instead of If-None-Match/If-Match")
	}
}

func TestSuccessorHEADRequiresImmutableManagedV2PredecessorProofs(t *testing.T) {
	for _, proof := range []string{"candidate", "result", "receipt"} {
		t.Run(proof, func(t *testing.T) {
			fixture := newLedgerFixture(t)
			scope := testBootstrapScope()
			advanced := advanceManagedAttemptForTest(t, fixture, scope)
			attempt := advanced.Head.PreviousAttempt
			var objectName string
			switch proof {
			case "candidate":
				objectName = fixture.ledger.objectName(scope, attempt, ledgerCandidate)
			case "result":
				objectName = contentAddressedTestObjectName(fixture.ledger, scope, attempt, ledgerResult,
					advanced.Head.PreviousResultDigest)
			case "receipt":
				predecessor, err := fixture.ledger.readContent(t.Context(), scope, attempt,
					ledgerResult, advanced.Head.PreviousResultDigest)
				if err != nil {
					t.Fatalf("read predecessor result: %v", err)
				}
				result, err := fixture.ledger.decodeResult(scope, predecessor.Bytes, false)
				if err != nil {
					t.Fatalf("decode predecessor result: %v", err)
				}
				objectName = contentAddressedTestObjectName(fixture.ledger, scope, attempt,
					ledgerPeerReceipt, result.PeerReceiptDigest)
			}
			bucket := fixture.ledger.config.Bucket
			key := requestKey(new("namespace"), new(bucket), new(objectName))
			fixture.client.mu.Lock()
			delete(fixture.client.objects, key)
			fixture.client.mu.Unlock()
			if _, err := fixture.ledger.ReadSlot(t.Context(), scope); !errors.Is(err, ErrSlotNotReserved) {
				t.Fatalf("successor accepted missing immutable predecessor %s proof: %v", proof, err)
			}
		})
	}
}

func TestAdvanceSlotRequiresCurrentRetirementAndSuccessorIntent(t *testing.T) {
	t.Run("does not create successor HEAD from expired stored proof pair", func(t *testing.T) {
		fixture := newLedgerFixture(t)
		scope := testBootstrapScope()
		state := completeFirstManagedAttempt(t, fixture, scope)
		evidence := fixture.retirement(scope, state, "instance-retired")
		retirementBytes := fixture.signInterval(t, scope, domainSlotRetirement, evidence, fixture.now, fixture.now.Add(time.Minute))
		nextIntentBytes, nextIntent := fixture.intentBytes(t, scope, 2, "create-key-2", "retry-token-2")
		nextIntent.RetirementDigest = bodyDigest(retirementBytes)
		nextIntentBytes = fixture.sign(t, scope, domainBootstrapIntent, nextIntent, fixture.now)
		nextHead := SlotHead{
			SchemaVersion: 2, DeploymentID: scope.DeploymentID, Cell: scope.Cell, Environment: fixture.environment,
			Role: roleController, Slot: scope.Slot, Attempt: 2, Generation: 2,
			IntentDigest: bodyDigest(nextIntentBytes), PreviousAttempt: state.Head.Attempt,
			PreviousGeneration: state.Head.Generation, PreviousIntentDigest: state.Head.IntentDigest,
			PreviousResultDigest: state.Head.ResultDigest, PreviousCandidateDigest: state.Head.CandidateDigest,
			RetirementDigest: bodyDigest(retirementBytes),
		}
		nextHeadBytes := fixture.sign(t, scope, domainBootstrapHead, nextHead, fixture.now)
		if _, err := fixture.ledger.createOrRead(t.Context(), scope, 2, ledgerIntent, nextIntentBytes); err != nil {
			t.Fatalf("persist exact proof-bound next intent: %v", err)
		}
		if _, err := fixture.ledger.createOrRead(t.Context(), scope, 2, ledgerRetirement, retirementBytes); err != nil {
			t.Fatalf("persist current retirement evidence: %v", err)
		}
		fixture.client.setNow(fixture.now.Add(2 * time.Minute))
		objectCount := fixture.client.objectCount()
		if _, err := fixture.ledger.AdvanceSlot(t.Context(), scope, state.HeadRecord.ETag,
			retirementBytes, nextIntentBytes, nextHeadBytes); err == nil {
			t.Fatal("expired stored retirement evidence authorized a new successor HEAD")
		}
		if got := fixture.client.objectCount(); got != objectCount {
			t.Fatalf("expired proof transition wrote records: objects=%d, before=%d", got, objectCount)
		}
		current, err := fixture.ledger.ReadSlot(t.Context(), scope)
		if err != nil || current.Head.Attempt != 1 {
			t.Fatalf("expired proof changed the stable slot HEAD: state=%+v err=%v", current, err)
		}
	})

	t.Run("rejects stale proof for a newly chosen intent without writing it", func(t *testing.T) {
		fixture := newLedgerFixture(t)
		scope := testBootstrapScope()
		state := completeFirstManagedAttempt(t, fixture, scope)
		evidence := fixture.retirement(scope, state, "instance-retired")
		retirementBytes := fixture.signInterval(t, scope, domainSlotRetirement, evidence, fixture.now, fixture.now.Add(time.Minute))
		if _, err := fixture.ledger.createOrRead(t.Context(), scope, 2, ledgerRetirement, retirementBytes); err != nil {
			t.Fatalf("persist original retirement evidence: %v", err)
		}
		objectCount := fixture.client.objectCount()
		fixture.client.setNow(fixture.now.Add(2 * time.Minute))
		nextIntentBytes, nextIntent := fixture.intentBytes(t, scope, 2, "create-key-2", "retry-token-2")
		nextIntent.RetirementDigest = bodyDigest(retirementBytes)
		nextIntent.CreatedAt = fixture.client.currentTime()
		nextIntentBytes = fixture.sign(t, scope, domainBootstrapIntent, nextIntent, nextIntent.CreatedAt)
		nextHead := SlotHead{
			SchemaVersion: 2, DeploymentID: scope.DeploymentID, Cell: scope.Cell, Environment: fixture.environment,
			Role: roleController, Slot: scope.Slot, Attempt: 2, Generation: 2,
			IntentDigest: bodyDigest(nextIntentBytes), PreviousAttempt: state.Head.Attempt,
			PreviousGeneration: state.Head.Generation, PreviousIntentDigest: state.Head.IntentDigest,
			PreviousResultDigest: state.Head.ResultDigest, PreviousCandidateDigest: state.Head.CandidateDigest,
			RetirementDigest: bodyDigest(retirementBytes),
		}
		nextHeadBytes := fixture.sign(t, scope, domainBootstrapHead, nextHead, fixture.client.currentTime())
		if _, err := fixture.ledger.AdvanceSlot(t.Context(), scope, state.HeadRecord.ETag,
			retirementBytes, nextIntentBytes, nextHeadBytes); !errors.Is(err, ErrRecordAuthorization) {
			t.Fatalf("stale retirement proof for a newly chosen intent = %v, want authorization failure", err)
		}
		if got := fixture.client.objectCount(); got != objectCount {
			t.Fatalf("stale proof created ledger records: objects=%d, before=%d", got, objectCount)
		}
		current, err := fixture.ledger.ReadSlot(t.Context(), scope)
		if err != nil || current.Head.Attempt != 1 {
			t.Fatalf("stale proof changed the stable slot HEAD: state=%+v err=%v", current, err)
		}
	})
}

func TestReserveSlotDoesNotCreateHEADFromExpiredIntent(t *testing.T) {
	fixture := newLedgerFixture(t)
	scope := testBootstrapScope()
	intentBytes, _ := fixture.intentBytes(t, scope, 1, "create-key-1", "retry-token-1")
	headBytes := fixture.headBytes(t, scope, intentBytes, 1)
	if _, err := fixture.ledger.createOrRead(t.Context(), scope, 1, ledgerIntent, intentBytes); err != nil {
		t.Fatalf("persist exact intent while current: %v", err)
	}
	fixture.client.setNow(fixture.now.Add(23 * time.Hour))
	if _, err := fixture.ledger.ReserveSlot(t.Context(), scope, intentBytes, headBytes); !errors.Is(err, ErrRetryWindowExpired) {
		t.Fatalf("expired original intent retry window = %v, want ErrRetryWindowExpired", err)
	}
	if got := fixture.client.objectCount(); got != 1 {
		t.Fatalf("expired intent created an initial HEAD: stored objects=%d, want only the persisted intent", got)
	}
}

func TestFirstResultRequiresCurrentManifestAndReceipt(t *testing.T) {
	for _, mode := range []IntentMode{IntentModeManaged, IntentModeExternalSeed} {
		t.Run(string(mode), func(t *testing.T) {
			fixture := newLedgerFixture(t)
			scope := testBootstrapScope()
			intentBytes, intent := fixture.intentBytes(t, scope, 1, "create-key-1", "retry-token-1")
			if mode == IntentModeExternalSeed {
				intent.Mode = mode
				intent.SchemaVersion = 1
				intent.RetryToken = ""
				intent.FounderPlanSHA256 = ""
				intent.PeerRowDigest = ""
				intent.ReviewedPlanDigest = bodyDigest([]byte("reviewed OpenTofu plan"))
				intentBytes, intent = fixture.bindIntentManifest(t, scope, intent, fixture.now)
			}
			reserved, err := fixture.ledger.ReserveSlot(t.Context(), scope, intentBytes, fixture.headBytes(t, scope, intentBytes, 1))
			if err != nil {
				t.Fatalf("reserve proof-gated slot: %v", err)
			}
			var manifestBytes, receiptBytes []byte
			var facts InstanceFacts
			var candidateWire []byte
			if mode == IntentModeExternalSeed {
				manifestBytes, receiptBytes, facts = fixture.seedProof(t, scope, intent, bodyDigest(intentBytes))
			} else {
				manifestBytes, receiptBytes, facts = fixture.managedProof(t, scope, intent, bodyDigest(intentBytes))
				candidateWire = fixture.pinManagedPeerCandidate(t, scope, intent, bodyDigest(intentBytes), facts)
			}
			result := fixture.result(scope, intent, bodyDigest(intentBytes))
			if mode == IntentModeExternalSeed {
				result.Mode = mode
				result.SeedReceiptDigest = bodyDigest(receiptBytes)
			} else {
				result.PeerReceiptDigest = bodyDigest(receiptBytes)
			}
			resultBytes := fixture.sign(t, scope, domainBootstrapResult, result, fixture.now)
			completedHead := reserved.Head
			completedHead.ResultDigest = bodyDigest(resultBytes)
			if candidateWire != nil {
				completedHead.CandidateDigest = bodyDigest(candidateWire)
			}
			completedHeadBytes := fixture.sign(t, scope, domainBootstrapHead, completedHead, fixture.now)
			manifestKind := ledgerManifest
			receiptKind := ledgerPeerReceipt
			if mode == IntentModeExternalSeed {
				receiptKind = ledgerSeedReceipt
			}
			if _, err := fixture.ledger.createOrRead(t.Context(), scope, 1, manifestKind, manifestBytes); err != nil {
				t.Fatalf("persist manifest while current: %v", err)
			}
			if _, err := fixture.ledger.createOrRead(t.Context(), scope, 1, receiptKind, receiptBytes); err != nil {
				t.Fatalf("persist receipt while current: %v", err)
			}
			storedBefore := fixture.client.objectCount()
			fixture.client.setNow(fixture.now.Add(25 * time.Hour))
			if mode == IntentModeExternalSeed {
				_, err = fixture.ledger.RecordExternalSeed(t.Context(), scope, manifestBytes, receiptBytes, facts, resultBytes, completedHeadBytes)
			} else {
				_, err = fixture.ledger.RecordManagedPeer(t.Context(), scope, manifestBytes, receiptBytes, facts, resultBytes, completedHeadBytes,
					fixture.managedPeerProgressSigner(scope), fixture.managedPeerRefresh(scope))
			}
			if err == nil {
				t.Fatal("stored expired manifest/receipt authorized a first result write")
			}
			if got := fixture.client.objectCount(); got != storedBefore {
				t.Fatalf("expired proof pair wrote a result or HEAD: objects=%d, before=%d", got, storedBefore)
			}
			if _, exists, readErr := fixture.ledger.readExistingExact(t.Context(), scope, 1, ledgerResult, resultBytes); readErr != nil || exists {
				t.Fatalf("expired proof pair created a result object: exists=%t err=%v", exists, readErr)
			}
			if mode == IntentModeManaged {
				headRecord, readErr := fixture.ledger.readObject(t.Context(), fixture.ledger.config.HeadBucket,
					fixture.ledger.headObjectName(scope))
				head, decodeErr := fixture.ledger.decodeHead(scope, headRecord.Bytes, false)
				if readErr != nil || decodeErr != nil || head.ResultDigest != "" {
					t.Fatalf("expired proof pair changed HEAD: head=%+v read err=%v decode err=%v", head, readErr, decodeErr)
				}
			} else {
				state, readErr := fixture.ledger.ReadSlot(t.Context(), scope)
				if readErr != nil || state.Head.ResultDigest != "" {
					t.Fatalf("expired proof pair changed HEAD: state=%+v err=%v", state, readErr)
				}
			}
		})
	}
}

func TestRecordManagedPeerRejectsPlanExpiredAtFinalRecoveryHeadRead(t *testing.T) {
	fixture := newPlanBackedManagedPeerFixture(t, "")
	facts := fixture.facts("ocid1.instance.oc1.sa-saopaulo-1.managedpeer")
	candidateWire := managedPeerCandidateWire(t, fixture, facts)
	if err := fixture.ledger.RecordManagedPeerCandidate(t.Context(), fixture.scope, candidateWire,
		managedPeerProgressSigner(fixture), fixture.refreshWith(fixture.plan)); err != nil {
		t.Fatalf("pin managed-peer candidate: %v", err)
	}
	receiptBytes := fixture.receiptBytes(t, facts)
	resultBytes := fixture.resultBytes(t, facts, receiptBytes)
	head := fixture.launch.head
	head.CandidateDigest = digestBytes(candidateWire)
	head.ResultDigest = digestBytes(resultBytes)
	headBytes := fixture.sign(t, domainBootstrapHead, head)
	fixture.client.setClockOnGet(fixture.ledger.config.HeadBucket,
		fixture.ledger.headObjectName(fixture.scope), 3, fixture.selected.plan.LaunchDeadline.Add(time.Second))
	putsBefore, objectsBefore := fixture.client.putCalls.Load(), fixture.client.objectCount()
	_, err := fixture.ledger.RecordManagedPeer(t.Context(), fixture.scope, fixture.manifestWire,
		receiptBytes, facts, resultBytes, headBytes, managedPeerProgressSigner(fixture), fixture.refreshWith(fixture.plan))
	if !errors.Is(err, ErrFounderPlanExpired) {
		t.Fatalf("record after final recovery HEAD Date crossed launch deadline = %v, want ErrFounderPlanExpired", err)
	}
	if putsAfter := fixture.client.putCalls.Load(); putsAfter != putsBefore {
		t.Fatalf("record after final recovery deadline made %d PutObject calls, want none", putsAfter-putsBefore)
	}
	if objectsAfter := fixture.client.objectCount(); objectsAfter != objectsBefore {
		t.Fatalf("record after final recovery deadline stored %d new objects, want none", objectsAfter-objectsBefore)
	}
}

func TestResultCommittedAtExpiredReceiptBoundaryCannotBeCompletedOrRepaired(t *testing.T) {
	for _, mode := range []IntentMode{IntentModeManaged, IntentModeExternalSeed} {
		t.Run(string(mode), func(t *testing.T) {
			fixture := newLedgerFixture(t)
			scope := testBootstrapScope()
			intentBytes, intent := fixture.intentBytes(t, scope, 1, "create-key-1", "retry-token-1")
			if mode == IntentModeExternalSeed {
				intent.Mode = mode
				intent.SchemaVersion = 1
				intent.RetryToken = ""
				intent.FounderPlanSHA256 = ""
				intent.PeerRowDigest = ""
				intent.ReviewedPlanDigest = bodyDigest([]byte("reviewed OpenTofu plan"))
				intentBytes, intent = fixture.bindIntentManifest(t, scope, intent, fixture.now)
			}
			reserved, err := fixture.ledger.ReserveSlot(
				t.Context(), scope, intentBytes, fixture.headBytes(t, scope, intentBytes, 1),
			)
			if err != nil {
				t.Fatalf("reserve proof-gated slot: %v", err)
			}

			var manifestBytes, receiptBytes []byte
			var facts InstanceFacts
			var candidateWire []byte
			if mode == IntentModeExternalSeed {
				manifestBytes, receiptBytes, facts = fixture.seedProof(t, scope, intent, reserved.IntentDigest())
			} else {
				manifestBytes, receiptBytes, facts = fixture.managedProof(t, scope, intent, reserved.IntentDigest())
				candidateWire = fixture.pinManagedPeerCandidate(t, scope, intent, reserved.IntentDigest(), facts)
			}
			receiptExpiry := fixture.now.Add(10*time.Second + 500*time.Millisecond)
			receiptBytes = fixture.resignReceiptUntil(t, receiptBytes, receiptExpiry)
			result := fixture.result(scope, intent, reserved.IntentDigest())
			if mode == IntentModeExternalSeed {
				result.Mode = mode
				result.SeedReceiptDigest = bodyDigest(receiptBytes)
			} else {
				result.PeerReceiptDigest = bodyDigest(receiptBytes)
			}
			resultBytes := fixture.sign(t, scope, domainBootstrapResult, result, fixture.now)
			completedHead := reserved.Head
			completedHead.ResultDigest = bodyDigest(resultBytes)
			if candidateWire != nil {
				completedHead.CandidateDigest = bodyDigest(candidateWire)
			}
			completedHeadBytes := fixture.sign(t, scope, domainBootstrapHead, completedHead, fixture.now)
			resultObjectName := fixture.ledger.objectName(scope, 1, ledgerResult)
			if mode == IntentModeManaged {
				resultObjectName = contentAddressedTestObjectName(fixture.ledger, scope, 1, ledgerResult, bodyDigest(resultBytes))
			}
			fixture.client.setClockBeforePut(fixture.ledger.config.Bucket, resultObjectName, receiptExpiry)

			if mode == IntentModeExternalSeed {
				_, err = fixture.ledger.RecordExternalSeed(t.Context(), scope, manifestBytes, receiptBytes, facts, resultBytes, completedHeadBytes)
			} else {
				_, err = fixture.ledger.RecordManagedPeer(t.Context(), scope, manifestBytes, receiptBytes, facts, resultBytes, completedHeadBytes,
					fixture.managedPeerProgressSigner(scope), fixture.managedPeerRefresh(scope))
			}
			if !errors.Is(err, ErrRecordAuthorization) {
				t.Fatalf("result committed at the expired receipt boundary = %v, want ErrRecordAuthorization", err)
			}
			var resultExists bool
			var resultReadErr error
			if mode == IntentModeManaged {
				_, resultExists, resultReadErr = fixture.ledger.readContentExact(t.Context(), scope, 1, ledgerResult, resultBytes)
			} else {
				_, resultExists, resultReadErr = fixture.ledger.readExistingExact(t.Context(), scope, 1, ledgerResult, resultBytes)
			}
			if resultReadErr != nil || !resultExists {
				t.Fatalf("late result object was not observed exactly: exists=%t err=%v", resultExists, resultReadErr)
			}
			var unchangedHeadETag string
			if mode == IntentModeManaged {
				headRecord, readErr := fixture.ledger.readObject(t.Context(), fixture.ledger.config.HeadBucket,
					fixture.ledger.headObjectName(scope))
				head, decodeErr := fixture.ledger.decodeHead(scope, headRecord.Bytes, false)
				if readErr != nil || decodeErr != nil || head.ResultDigest != "" {
					t.Fatalf("late result changed the unchanged HEAD: head=%+v read err=%v decode err=%v", head, readErr, decodeErr)
				}
				unchangedHeadETag = headRecord.ETag
			} else {
				state, readErr := fixture.ledger.ReadSlot(t.Context(), scope)
				if readErr != nil || state.Head.ResultDigest != "" {
					t.Fatalf("late result was accepted by the unchanged HEAD: state=%+v err=%v", state, readErr)
				}
				unchangedHeadETag = state.HeadRecord.ETag
			}
			wantLaunchErr := ErrRecordAuthorization
			if mode == IntentModeExternalSeed {
				wantLaunchErr = ErrExternalSeedMode
			}
			if _, err := fixture.ledger.ReadForLaunch(t.Context(), scope); !errors.Is(err, wantLaunchErr) {
				t.Fatalf("late orphan did not preserve the launch gate: got %v, want %v", err, wantLaunchErr)
			}
			if _, _, err := fixture.ledger.writeHead(t.Context(), scope, unchangedHeadETag, completedHead, completedHeadBytes, true); err != nil {
				t.Fatalf("simulate a late persisted completion HEAD: %v", err)
			}
			wantQuarantine := ErrRecordAuthorization
			if mode == IntentModeManaged {
				wantQuarantine = ErrManagedPeerProofQuarantined
			}
			if _, err := fixture.ledger.ReadSlot(t.Context(), scope); !errors.Is(err, wantQuarantine) {
				t.Fatalf("read accepted a HEAD referencing a result outside its receipt interval: %v", err)
			}

			if mode == IntentModeExternalSeed {
				_, err = fixture.ledger.RecordExternalSeed(t.Context(), scope, manifestBytes, receiptBytes, facts, resultBytes, completedHeadBytes)
			} else {
				_, err = fixture.ledger.RecordManagedPeer(t.Context(), scope, manifestBytes, receiptBytes, facts, resultBytes, completedHeadBytes,
					fixture.managedPeerProgressSigner(scope), fixture.managedPeerRefresh(scope))
			}
			wantRetryErr := ErrRecordAuthorization
			if mode == IntentModeManaged {
				wantRetryErr = ErrManagedPeerProofQuarantined
			}
			if !errors.Is(err, wantRetryErr) {
				t.Fatalf("retry repaired a result outside its receipt interval: got %v, want %v", err, wantRetryErr)
			}
		})
	}
}

func TestInitialHeadCommittedAfterIntentExpiryIsRejectedOnRead(t *testing.T) {
	fixture := newLedgerFixture(t)
	scope := testBootstrapScope()
	intentBytes, intent := fixture.intentBytes(t, scope, 1, "create-key-1", "retry-token-1")
	intentExpiry := fixture.now.Add(1500 * time.Millisecond)
	intentBytes = fixture.signInterval(t, scope, domainBootstrapIntent, intent, fixture.now, intentExpiry)
	headBytes := fixture.headBytes(t, scope, intentBytes, 1)
	fixture.client.setClockBeforePut(fixture.ledger.config.HeadBucket, fixture.ledger.headObjectName(scope), intentExpiry.Add(500*time.Millisecond))

	if _, err := fixture.ledger.ReserveSlot(t.Context(), scope, intentBytes, headBytes); !errors.Is(err, ErrRecordAuthorization) {
		t.Fatalf("initial HEAD committed after intent expiry = %v, want ErrRecordAuthorization", err)
	}
	if _, err := fixture.ledger.ReadSlot(t.Context(), scope); !errors.Is(err, ErrManagedPeerProofQuarantined) {
		t.Fatalf("read accepted a HEAD committed outside the intent interval: %v", err)
	}
}

func TestAuthorizationHeadsStayInsideOriginalRetryWindow(t *testing.T) {
	t.Run("initial reservation", func(t *testing.T) {
		fixture := newLedgerFixture(t)
		scope := testBootstrapScope()
		intentBytes, _ := fixture.intentBytes(t, scope, 1, "create-key-1", "retry-token-1")
		headBytes := fixture.headBytes(t, scope, intentBytes, 1)
		retryDeadline := fixture.now.Add(maxRetryAge)
		fixture.client.setClockBeforePut(fixture.ledger.config.HeadBucket, fixture.ledger.headObjectName(scope), retryDeadline)

		if _, err := fixture.ledger.ReserveSlot(t.Context(), scope, intentBytes, headBytes); !errors.Is(err, ErrRetryWindowExpired) {
			t.Fatalf("initial HEAD at the original retry deadline = %v, want ErrRetryWindowExpired", err)
		}
		if _, err := fixture.ledger.ReadSlot(t.Context(), scope); !errors.Is(err, ErrRetryWindowExpired) {
			t.Fatalf("read accepted initial HEAD outside the original retry window: %v", err)
		}
	})

	t.Run("successor advance", func(t *testing.T) {
		fixture := newLedgerFixture(t)
		scope := testBootstrapScope()
		state := completeFirstManagedAttempt(t, fixture, scope)
		evidence := fixture.retirement(scope, state, "instance-retired")
		retirementBytes := fixture.sign(t, scope, domainSlotRetirement, evidence, fixture.now)
		nextIntentBytes, nextIntent := fixture.intentBytes(t, scope, 2, "create-key-2", "retry-token-2")
		nextIntent.RetirementDigest = bodyDigest(retirementBytes)
		nextIntentBytes = fixture.sign(t, scope, domainBootstrapIntent, nextIntent, fixture.now)
		nextHead := SlotHead{
			SchemaVersion: 2, DeploymentID: scope.DeploymentID, Cell: scope.Cell, Environment: fixture.environment,
			Role: roleController, Slot: scope.Slot, Attempt: 2, Generation: 2,
			IntentDigest: bodyDigest(nextIntentBytes), PreviousAttempt: state.Head.Attempt,
			PreviousGeneration: state.Head.Generation, PreviousIntentDigest: state.Head.IntentDigest,
			PreviousResultDigest: state.Head.ResultDigest, PreviousCandidateDigest: state.Head.CandidateDigest,
			RetirementDigest: bodyDigest(retirementBytes),
		}
		nextHeadBytes := fixture.sign(t, scope, domainBootstrapHead, nextHead, fixture.now)
		fixture.client.setClockBeforePut(fixture.ledger.config.HeadBucket, fixture.ledger.headObjectName(scope), fixture.now.Add(maxRetryAge))

		if _, err := fixture.ledger.AdvanceSlot(t.Context(), scope, state.HeadRecord.ETag, retirementBytes, nextIntentBytes, nextHeadBytes); !errors.Is(err, ErrRetryWindowExpired) {
			t.Fatalf("successor HEAD at the original retry deadline = %v, want ErrRetryWindowExpired", err)
		}
		if _, err := fixture.ledger.ReadSlot(t.Context(), scope); !errors.Is(err, ErrRetryWindowExpired) {
			t.Fatalf("read accepted successor HEAD outside the original retry window: %v", err)
		}
	})
}

func TestReadForLaunchRefreshesCurrentIntentAndRetryClockAtTokenIssue(t *testing.T) {
	for _, test := range []struct {
		name      string
		elapsed   time.Duration
		wantError error
	}{
		{name: "original retry window expires", elapsed: maxRetryAge, wantError: ErrRetryWindowExpired},
		{name: "signed intent expires", elapsed: 24 * time.Hour, wantError: ErrRecordAuthorization},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newLedgerFixture(t)
			scope := testBootstrapScope()
			intentBytes, _ := fixture.intentBytes(t, scope, 1, "create-key-1", "retry-token-1")
			if _, err := fixture.ledger.ReserveSlot(t.Context(), scope, intentBytes, fixture.headBytes(t, scope, intentBytes, 1)); err != nil {
				t.Fatalf("reserve launch slot: %v", err)
			}
			fixture.client.setClockOnGet(
				fixture.ledger.config.Bucket,
				fixture.ledger.objectName(scope, 1, ledgerIntent),
				2,
				fixture.now.Add(test.elapsed),
			)

			if _, err := fixture.ledger.ReadForLaunch(t.Context(), scope); !errors.Is(err, test.wantError) {
				t.Fatalf("launch authorization after final intent read crossed its deadline = %v, want %v", err, test.wantError)
			}
		})
	}
}

func TestReadForLaunchRejectsPinnedManagedPeerCandidate(t *testing.T) {
	fixture := newPlanBackedManagedPeerFixture(t, "")
	facts := fixture.facts("ocid1.instance.oc1.sa-saopaulo-1.pinned-candidate")
	candidateWire := managedPeerCandidateWire(t, fixture, facts)
	if err := fixture.ledger.RecordManagedPeerCandidate(t.Context(), fixture.scope, candidateWire,
		managedPeerProgressSigner(fixture), fixture.refreshWith(fixture.plan)); err != nil {
		t.Fatalf("pin managed-peer candidate: %v", err)
	}
	if _, err := fixture.ledger.ReadForLaunch(t.Context(), fixture.scope); !errors.Is(err, ErrManagedPeerCandidatePinned) {
		t.Fatalf("ReadForLaunch() after candidate pin = %v, want ErrManagedPeerCandidatePinned", err)
	}
}

func TestReadForLaunchRejectsCandidateWriteCrashBeforeProgressCAS(t *testing.T) {
	fixture := newPlanBackedManagedPeerFixture(t, "")
	facts := fixture.facts("ocid1.instance.oc1.sa-saopaulo-1.candidate-write-crash")
	candidateWire := managedPeerCandidateWire(t, fixture, facts)
	crashManagedPeerCandidateAfterFirstPut(t, &fixture, candidateWire)

	state, err := fixture.ledger.ReadForManagedPeerRecovery(t.Context(), fixture.scope)
	if err != nil {
		t.Fatalf("read candidate-only crash state: %v", err)
	}
	snapshot := state.State()
	if snapshot.CandidateRecord == nil || snapshot.ProgressRecord != nil ||
		snapshot.Head.CandidateDigest != "" || snapshot.Head.ResultDigest != "" {
		t.Fatalf("candidate-write crash did not leave the fixed-key pre-progress state: %+v", snapshot)
	}
	if _, err := fixture.ledger.ReadForLaunch(t.Context(), fixture.scope); !errors.Is(err, ErrManagedPeerCandidatePinned) {
		t.Fatalf("ReadForLaunch() after candidate-only crash = %v, want ErrManagedPeerCandidatePinned", err)
	}
}

func TestExpiredHistoricalResultCannotRecreateMissingReceipt(t *testing.T) {
	for _, mode := range []IntentMode{IntentModeManaged, IntentModeExternalSeed} {
		t.Run(string(mode), func(t *testing.T) {
			fixture := newLedgerFixture(t)
			scope := testBootstrapScope()
			intentBytes, intent := fixture.intentBytes(t, scope, 1, "create-key-1", "retry-token-1")
			if mode == IntentModeExternalSeed {
				intent.Mode = mode
				intent.SchemaVersion = 1
				intent.RetryToken = ""
				intent.FounderPlanSHA256 = ""
				intent.PeerRowDigest = ""
				intent.ReviewedPlanDigest = bodyDigest([]byte("reviewed OpenTofu plan"))
				intentBytes, intent = fixture.bindIntentManifest(t, scope, intent, fixture.now)
			}
			reserved, err := fixture.ledger.ReserveSlot(
				t.Context(), scope, intentBytes, fixture.headBytes(t, scope, intentBytes, 1),
			)
			if err != nil {
				t.Fatalf("reserve proof-gated slot: %v", err)
			}
			var manifestBytes, receiptBytes []byte
			var facts InstanceFacts
			var candidateWire []byte
			if mode == IntentModeExternalSeed {
				manifestBytes, receiptBytes, facts = fixture.seedProof(t, scope, intent, reserved.IntentDigest())
			} else {
				manifestBytes, receiptBytes, facts = fixture.managedProof(t, scope, intent, reserved.IntentDigest())
				candidateWire = fixture.pinManagedPeerCandidate(t, scope, intent, reserved.IntentDigest(), facts)
			}
			result := fixture.result(scope, intent, reserved.IntentDigest())
			if mode == IntentModeExternalSeed {
				result.Mode = mode
				result.SeedReceiptDigest = bodyDigest(receiptBytes)
			} else {
				result.PeerReceiptDigest = bodyDigest(receiptBytes)
			}
			resultBytes := fixture.sign(t, scope, domainBootstrapResult, result, fixture.now)
			completedHead := reserved.Head
			completedHead.ResultDigest = bodyDigest(resultBytes)
			if candidateWire != nil {
				completedHead.CandidateDigest = bodyDigest(candidateWire)
			}
			completedHeadBytes := fixture.sign(t, scope, domainBootstrapHead, completedHead, fixture.now)

			if _, err := fixture.ledger.createOrRead(t.Context(), scope, 1, ledgerManifest, manifestBytes); err != nil {
				t.Fatalf("persist exact manifest: %v", err)
			}
			var resultWriteErr error
			if mode == IntentModeManaged {
				_, resultWriteErr = fixture.ledger.createOrReadContent(t.Context(), scope, 1, ledgerResult, resultBytes)
			} else {
				_, resultWriteErr = fixture.ledger.createOrRead(t.Context(), scope, 1, ledgerResult, resultBytes)
			}
			if resultWriteErr != nil {
				t.Fatalf("persist result before simulated crash: %v", resultWriteErr)
			}
			objectsBeforeRetry := fixture.client.objectCount()
			fixture.client.setNow(fixture.now.Add(6 * time.Minute))

			if mode == IntentModeExternalSeed {
				_, err = fixture.ledger.RecordExternalSeed(t.Context(), scope, manifestBytes, receiptBytes, facts, resultBytes, completedHeadBytes)
			} else {
				_, err = fixture.ledger.RecordManagedPeer(t.Context(), scope, manifestBytes, receiptBytes, facts, resultBytes, completedHeadBytes,
					fixture.managedPeerProgressSigner(scope), fixture.managedPeerRefresh(scope))
			}
			if !errors.Is(err, ErrRecordAuthorization) {
				t.Fatalf("expired repair without a durable receipt = %v, want ErrRecordAuthorization", err)
			}
			if got := fixture.client.objectCount(); got != objectsBeforeRetry {
				t.Fatalf("expired repair created the missing receipt or HEAD: objects=%d, before=%d", got, objectsBeforeRetry)
			}
			receiptKind := ledgerPeerReceipt
			if mode == IntentModeExternalSeed {
				receiptKind = ledgerSeedReceipt
			}
			if _, exists, readErr := fixture.ledger.readExistingExact(t.Context(), scope, 1,
				receiptKind, receiptBytes); readErr != nil || exists {
				t.Fatalf("expired repair created the missing receipt: exists=%t err=%v", exists, readErr)
			}
			headRecord, readErr := fixture.ledger.readObject(t.Context(), fixture.ledger.config.HeadBucket,
				fixture.ledger.headObjectName(scope))
			head, decodeErr := fixture.ledger.decodeHead(scope, headRecord.Bytes, false)
			if readErr != nil || decodeErr != nil || head.ResultDigest != "" {
				t.Fatalf("expired repair changed the stable HEAD: head=%+v read err=%v decode err=%v", head, readErr, decodeErr)
			}
		})
	}
}
func TestSuccessorHeadCommittedAfterIntentOrEvidenceExpiryIsRejectedOnRead(t *testing.T) {
	fixture := newLedgerFixture(t)
	scope := testBootstrapScope()
	state := completeFirstManagedAttempt(t, fixture, scope)
	evidenceExpiry := fixture.now.Add(1500 * time.Millisecond)
	evidence := fixture.retirement(scope, state, "instance-retired")
	retirementBytes := fixture.signInterval(t, scope, domainSlotRetirement, evidence, fixture.now, evidenceExpiry)
	nextIntentBytes, nextIntent := fixture.intentBytes(t, scope, 2, "create-key-2", "retry-token-2")
	nextIntent.RetirementDigest = bodyDigest(retirementBytes)
	nextIntentBytes = fixture.signInterval(t, scope, domainBootstrapIntent, nextIntent, fixture.now, evidenceExpiry)
	nextHead := SlotHead{
		SchemaVersion: 2, DeploymentID: scope.DeploymentID, Cell: scope.Cell, Environment: fixture.environment,
		Role: roleController, Slot: scope.Slot, Attempt: 2, Generation: 2,
		IntentDigest: bodyDigest(nextIntentBytes), PreviousAttempt: state.Head.Attempt,
		PreviousGeneration: state.Head.Generation, PreviousIntentDigest: state.Head.IntentDigest,
		PreviousResultDigest: state.Head.ResultDigest, PreviousCandidateDigest: state.Head.CandidateDigest,
		RetirementDigest: bodyDigest(retirementBytes),
	}
	nextHeadBytes := fixture.sign(t, scope, domainBootstrapHead, nextHead, fixture.now)
	fixture.client.setClockBeforePut(fixture.ledger.config.HeadBucket, fixture.ledger.headObjectName(scope), evidenceExpiry.Add(500*time.Millisecond))

	if _, err := fixture.ledger.AdvanceSlot(t.Context(), scope, state.HeadRecord.ETag, retirementBytes, nextIntentBytes, nextHeadBytes); !errors.Is(err, ErrRecordAuthorization) {
		t.Fatalf("successor HEAD committed after proof expiry = %v, want ErrRecordAuthorization", err)
	}
	if _, err := fixture.ledger.ReadSlot(t.Context(), scope); !errors.Is(err, ErrRecordAuthorization) {
		t.Fatalf("read accepted a successor HEAD committed outside intent/evidence intervals: %v", err)
	}
}

func TestStoredBeforeExpiryUsesWholeOCISeconds(t *testing.T) {
	base := time.Date(2026, time.September, 25, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name      string
		expiresAt time.Time
		want      bool
	}{
		{name: "expiry strictly inside timestamp second", expiresAt: base.Add(time.Second + 500*time.Millisecond), want: false},
		{name: "exclusive second boundary equals expiry", expiresAt: base.Add(2 * time.Second), want: true},
		{name: "expiry after exclusive second boundary", expiresAt: base.Add(2*time.Second + time.Nanosecond), want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := storedBeforeExpiry(base.Add(time.Second), test.expiresAt); got != test.want {
				t.Fatalf("storedBeforeExpiry() = %t, want %t", got, test.want)
			}
		})
	}
}

func (fixture *ledgerFixture) resignReceiptUntil(t *testing.T, body []byte, expiresAt time.Time) []byte {
	t.Helper()
	envelope, err := trust.DecodeEnvelope(body)
	if err != nil {
		t.Fatal(err)
	}
	privateKey := fixture.authority.peerPrivate
	if envelope.Scope.Domain == seedReceiptDomain {
		privateKey = fixture.authority.rootPrivate
	}
	signed, err := trust.Sign([]byte(envelope.Payload), envelope.Scope, envelope.IssuedAt, expiresAt, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := trust.EncodeEnvelope(signed)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestCurrentAnchorExpiryGuardsImmutableAndHEADWrites(t *testing.T) {
	fixture := newLedgerFixture(t)
	scope := testBootstrapScope()
	config := fixture.ledger.config
	config.AnchorExpiresAt = fixture.now.Add(time.Minute)
	ledger, err := NewLedger(fixture.client, config)
	if err != nil {
		t.Fatalf("create anchor-bounded ledger: %v", err)
	}
	fixture.ledger = ledger
	intentBytes, _ := fixture.intentBytes(t, scope, 1, "create-key-1", "retry-token-1")
	headBytes := fixture.headBytes(t, scope, intentBytes, 1)
	if _, err := fixture.ledger.ReserveSlot(t.Context(), scope, intentBytes, headBytes); err != nil {
		t.Fatalf("reserve before anchor expiry: %v", err)
	}
	fixture.client.setNow(config.AnchorExpiresAt)
	putCalls := fixture.client.putCalls.Load()
	if _, _, err := fixture.ledger.writeHead(t.Context(), scope, "", mustDecodeHeadForTest(t, fixture.ledger, scope, headBytes), headBytes, true); !errors.Is(err, ErrRecordAuthorization) {
		t.Fatalf("HEAD write at anchor expiry = %v, want ErrRecordAuthorization", err)
	}
	if _, err := fixture.ledger.createOrRead(t.Context(), scope, 1, ledgerResult, []byte("unused")); !errors.Is(err, ErrRecordAuthorization) {
		t.Fatalf("immutable write at anchor expiry = %v, want ErrRecordAuthorization", err)
	}
	if _, err := fixture.ledger.ReadForLaunch(t.Context(), scope); !errors.Is(err, ErrRecordAuthorization) {
		t.Fatalf("launch authorization at anchor expiry = %v, want ErrRecordAuthorization", err)
	}
	if got := fixture.client.putCalls.Load(); got != putCalls {
		t.Fatalf("expired anchor reached Object Storage PUT: calls=%d, before=%d", got, putCalls)
	}
	if got := fixture.client.objectCount(); got != 2 {
		t.Fatalf("anchor expiry changed durable state: objects=%d, want the original intent and HEAD", got)
	}
}

func mustDecodeHeadForTest(t *testing.T, ledger *Ledger, scope BootstrapScope, headBytes []byte) SlotHead {
	t.Helper()
	head, err := ledger.decodeHead(scope, headBytes, true)
	if err != nil {
		t.Fatal(err)
	}
	return head
}

func contentAddressedTestObjectName(ledger *Ledger, scope BootstrapScope, attempt uint64,
	kind ledgerRecordKind, digest string,
) string {
	base := ledger.objectName(scope, attempt, kind)
	return strings.TrimSuffix(base, ".json") + "-" + digest + ".json"
}

func TestReadForLaunchRejectsUncommittedResultAndExpiredRetryWindow(t *testing.T) {
	t.Run("result exists before HEAD confirmation", func(t *testing.T) {
		fixture := newLedgerFixture(t)
		scope := testBootstrapScope()
		intentBytes, intent := fixture.intentBytes(t, scope, 1, "create-key-1", "retry-token-1")
		head := SlotHead{SchemaVersion: 2, DeploymentID: scope.DeploymentID, Cell: scope.Cell,
			Environment: fixture.environment, Role: roleController, Slot: scope.Slot, Attempt: 1,
			Generation: 1, IntentDigest: bodyDigest(intentBytes)}
		headBytes := fixture.sign(t, scope, domainBootstrapHead, head, fixture.now)
		if _, err := fixture.ledger.ReserveSlot(t.Context(), scope, intentBytes, headBytes); err != nil {
			t.Fatalf("reserve attempt: %v", err)
		}
		_, receiptBytes, _ := fixture.managedProof(t, scope, intent, bodyDigest(intentBytes))
		result := fixture.result(scope, intent, bodyDigest(intentBytes))
		result.PeerReceiptDigest = bodyDigest(receiptBytes)
		resultBytes := fixture.sign(t, scope, domainBootstrapResult, result, fixture.now)
		if _, err := fixture.ledger.createOrRead(t.Context(), scope, 1, ledgerResult, resultBytes); err != nil {
			t.Fatalf("create pending result: %v", err)
		}
		if _, err := fixture.ledger.ReadForLaunch(t.Context(), scope); !errors.Is(err, ErrSlotResultPendingHead) {
			t.Fatalf("launch authorization with uncommitted positive result = %v, want pending-HEAD error", err)
		}
	})

	t.Run("original server timestamp expires", func(t *testing.T) {
		fixture := newLedgerFixture(t)
		scope := testBootstrapScope()
		intentBytes, _ := fixture.intentBytes(t, scope, 1, "create-key-1", "retry-token-1")
		head := SlotHead{SchemaVersion: 2, DeploymentID: scope.DeploymentID, Cell: scope.Cell,
			Environment: fixture.environment, Role: roleController, Slot: scope.Slot, Attempt: 1,
			Generation: 1, IntentDigest: bodyDigest(intentBytes)}
		headBytes := fixture.sign(t, scope, domainBootstrapHead, head, fixture.now)
		if _, err := fixture.ledger.ReserveSlot(t.Context(), scope, intentBytes, headBytes); err != nil {
			t.Fatalf("reserve attempt: %v", err)
		}
		fixture.client.setNow(fixture.now.Add(23 * time.Hour))
		if _, err := fixture.ledger.ReadForLaunch(t.Context(), scope); !errors.Is(err, ErrRetryWindowExpired) {
			t.Fatalf("expired launch retry window = %v, want ErrRetryWindowExpired", err)
		}
	})
}

func TestLedgerFailsClosedOnUnknownPermanentAndMalformedStorageOutcomes(t *testing.T) {
	t.Run("lost acknowledgement with missing readback", func(t *testing.T) {
		fixture := newLedgerFixture(t)
		fixture.client.failBeforeCommit.Store(true)
		scope := testBootstrapScope()
		intentBytes, _ := fixture.intentBytes(t, scope, 1, "create-key-1", "retry-token-1")
		headBytes := fixture.headBytes(t, scope, intentBytes, 1)
		if _, err := fixture.ledger.ReserveSlot(t.Context(), scope, intentBytes, headBytes); !errors.Is(err, ErrOutcomeUnknown) {
			t.Fatalf("missing exact-key readback after lost acknowledgement = %v, want ErrOutcomeUnknown", err)
		}
		if got := fixture.client.objectCount(); got != 0 {
			t.Fatalf("objects after pre-commit failure = %d, want zero", got)
		}
	})

	t.Run("permanent create failure", func(t *testing.T) {
		fixture := newLedgerFixture(t)
		fixture.client.rejectPut = fakeObjectStorageError{status: http.StatusForbidden}
		scope := testBootstrapScope()
		intentBytes, _ := fixture.intentBytes(t, scope, 1, "create-key-1", "retry-token-1")
		headBytes := fixture.headBytes(t, scope, intentBytes, 1)
		if _, err := fixture.ledger.ReserveSlot(t.Context(), scope, intentBytes, headBytes); err == nil || errors.Is(err, ErrOutcomeUnknown) {
			t.Fatalf("permanent storage rejection = %v, want the terminal service error", err)
		}
		if got := fixture.client.getCalls.Load(); got != 0 {
			t.Fatalf("GET calls after permanent storage rejection = %d, want no read after a terminal create error", got)
		}
	})

	t.Run("missing server Date", func(t *testing.T) {
		fixture := newLedgerFixture(t)
		scope := testBootstrapScope()
		intentBytes, _ := fixture.intentBytes(t, scope, 1, "create-key-1", "retry-token-1")
		headBytes := fixture.headBytes(t, scope, intentBytes, 1)
		if _, err := fixture.ledger.ReserveSlot(t.Context(), scope, intentBytes, headBytes); err != nil {
			t.Fatalf("reserve before metadata fault: %v", err)
		}
		fixture.client.omitServerDate.Store(true)
		if _, err := fixture.ledger.ReadSlot(t.Context(), scope); err == nil {
			t.Fatal("slot read accepted missing server Date metadata")
		}
	})
}

func TestLedgerRejectsInvalidScopeConfigurationAndOversizedRecords(t *testing.T) {
	fixture := newLedgerFixture(t)
	for _, scope := range []BootstrapScope{{}, {DeploymentID: "deployment/other", Cell: "GRU", Slot: "controller-a"},
		{DeploymentID: "deployment-a", Cell: "gru", Slot: "controller-a"},
		{DeploymentID: "deployment-a", Cell: "GRU", Slot: "../other"}} {
		if _, err := fixture.ledger.ReadSlot(t.Context(), scope); err == nil {
			t.Errorf("ReadSlot accepted invalid scope %+v", scope)
		}
	}
	if _, err := fixture.ledger.ReadSlot(t.Context(), BootstrapScope{DeploymentID: "deployment-a", Cell: "GRU", Slot: "controller-b"}); !errors.Is(err, ErrRecordAuthorization) {
		t.Fatalf("ReadSlot accepted a slot outside the anchor: %v", err)
	}
	for _, config := range []LedgerConfig{
		{},
		{Namespace: "namespace", Bucket: "bootstrap-ledger", KMSKeyID: "ocid1.key.test", Prefix: "../outside"},
		{Namespace: "namespace", Bucket: "bootstrap-ledger", KMSKeyID: "ocid1.key.test", HeadBucket: "bootstrap-head", HeadKMSKeyID: "ocid1.key.head"},
	} {
		if _, err := NewLedger(fixture.client, config); err == nil {
			t.Errorf("NewLedger accepted invalid storage or trust configuration: %+v", config)
		}
	}

	fixture.ledger.maxRecord = 4
	if _, err := fixture.ledger.createOrRead(t.Context(), testBootstrapScope(), 1, ledgerIntent, []byte("12345")); err == nil || !strings.Contains(err.Error(), "size bound") {
		t.Fatalf("oversized immutable record error = %v, want size bound", err)
	}
	if got := fixture.client.putCalls.Load(); got != 0 {
		t.Fatalf("PUT calls for invalid scopes/config/oversized body = %d, want 0", got)
	}
}

func TestIntentCellRegionBindingAndSeparateRegionalGeneration(t *testing.T) {
	fixture := newLedgerFixture(t)
	scope := testBootstrapScope()
	_, intent := fixture.intentBytes(t, scope, 1, "create-key-1", "retry-token-1")
	if intent.Generation == intent.RegionIntentGeneration {
		t.Fatal("test must distinguish per-slot attempt generation from regional authorization generation")
	}
	intent.OCIRegion = "eu-frankfurt-1"
	wrongRegionBytes := fixture.sign(t, scope, domainBootstrapIntent, intent, fixture.now)
	headBytes := fixture.headBytes(t, scope, wrongRegionBytes, 1)
	if _, err := fixture.ledger.ReserveSlot(t.Context(), scope, wrongRegionBytes, headBytes); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("GRU intent naming Frankfurt returned %v, want region binding rejection", err)
	}
	if got := fixture.client.putCalls.Load(); got != 0 {
		t.Fatalf("PUT calls for cell/region mismatch = %d, want zero", got)
	}
	invalidDigest := intent
	invalidDigest.LaunchRequestDigest = bodyDigest([]byte("not the canonical profile digest"))
	if err := validateIntent(invalidDigest); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("intent with noncanonical launch profile digest passed validation: %v", err)
	}
}

func TestExternalSeedRequiresRootReceiptAndNeverAuthorizesOCIProvisioning(t *testing.T) {
	fixture := newLedgerFixture(t)
	scope := testBootstrapScope()
	intentBytes, intent := fixture.intentBytes(t, scope, 1, "bootstrap-create-a", "retry-token-1")
	intent.Mode = IntentModeExternalSeed
	intent.SchemaVersion = 1
	intent.RetryToken = ""
	intent.FounderPlanSHA256 = ""
	intent.PeerRowDigest = ""
	intent.ReviewedPlanDigest = bodyDigest([]byte("reviewed OpenTofu plan"))
	intentBytes, intent = fixture.bindIntentManifest(t, scope, intent, fixture.now)
	headBytes := fixture.headBytes(t, scope, intentBytes, 1)
	reserved, err := fixture.ledger.ReserveSlot(t.Context(), scope, intentBytes, headBytes)
	if err != nil {
		t.Fatalf("reserve external seed slot: %v", err)
	}
	if reserved.Intent.Mode != IntentModeExternalSeed || reserved.Intent.RetryToken != "" ||
		reserved.Intent.CreateKey != "bootstrap-create-a" || reserved.Intent.ReviewedPlanDigest != bodyDigest([]byte("reviewed OpenTofu plan")) {
		t.Fatalf("stored external seed identity is incomplete: %+v", reserved)
	}
	if _, err := fixture.ledger.ReadForLaunch(t.Context(), scope); !errors.Is(err, ErrExternalSeedMode) {
		t.Fatalf("external seed launch authorization returned %v, want explicit denial", err)
	}
	manifestBytes, receiptBytes, facts := fixture.seedProof(t, scope, intent, bodyDigest(intentBytes))
	result := fixture.result(scope, intent, bodyDigest(intentBytes))
	result.Mode = IntentModeExternalSeed
	result.SeedReceiptDigest = bodyDigest(receiptBytes)
	resultBytes := fixture.sign(t, scope, domainBootstrapResult, result, fixture.now)
	completedHead := reserved.Head
	completedHead.ResultDigest = bodyDigest(resultBytes)
	completedHeadBytes := fixture.sign(t, scope, domainBootstrapHead, completedHead, fixture.now)
	if _, err := fixture.ledger.RecordResult(t.Context(), scope, resultBytes, completedHeadBytes); !errors.Is(err, ErrExternalSeedMode) {
		t.Fatalf("generic OCI result write for external seed returned %v, want receipt-gated refusal", err)
	}
	if got := fixture.client.objectCount(); got != 2 {
		t.Fatalf("external seed generic result path wrote an object: object count = %d, want only intent and HEAD", got)
	}
	fixture.client.loseAckForBucket("bootstrap-head")
	state, err := fixture.ledger.RecordExternalSeed(t.Context(), scope, manifestBytes, receiptBytes, facts, resultBytes, completedHeadBytes)
	if err != nil {
		t.Fatalf("record root-receipt-gated external seed: %v", err)
	}
	if state.Result == nil || state.SeedReceipt == nil || state.SeedReceiptRecord == nil ||
		state.Result.SeedReceiptDigest != state.SeedReceiptRecord.SHA256 || state.Head.ResultDigest != bodyDigest(resultBytes) {
		t.Fatalf("external seed completion did not preserve its root receipt: %+v", state)
	}
	committedObjects := fixture.client.objectCount()
	if _, err := fixture.ledger.RecordExternalSeed(t.Context(), scope, manifestBytes, receiptBytes,
		facts, resultBytes, completedHeadBytes); err != nil || fixture.client.objectCount() != committedObjects {
		t.Fatalf("exact completed seed replay changed ledger: objects=%d prior=%d err=%v",
			fixture.client.objectCount(), committedObjects, err)
	}
	resignedHead := fixture.signInterval(t, scope, domainBootstrapHead, completedHead,
		fixture.now.Add(time.Second), fixture.now.Add(time.Hour))
	if _, err := fixture.ledger.RecordExternalSeed(t.Context(), scope, manifestBytes, receiptBytes,
		facts, resultBytes, resignedHead); !errors.Is(err, ErrSlotHeadConflict) ||
		fixture.client.objectCount() != committedObjects {
		t.Fatalf("re-signed completed HEAD replay changed ledger: objects=%d prior=%d err=%v",
			fixture.client.objectCount(), committedObjects, err)
	}
	if _, err := fixture.ledger.ReadForLaunch(t.Context(), scope); !errors.Is(err, ErrSlotAlreadyComplete) {
		t.Fatalf("completed external seed launch authorization returned %v, want completed-slot denial", err)
	}
	restarted := fixture.newLedger(t)
	recovered, err := restarted.ReadSlot(t.Context(), scope)
	if err != nil || recovered.SeedReceipt == nil || recovered.SeedReceiptRecord == nil ||
		recovered.SeedReceiptRecord.SHA256 != bodyDigest(receiptBytes) {
		t.Fatalf("restart did not recover the exact external seed receipt: state=%+v err=%v", recovered, err)
	}
	evidence := fixture.retirement(scope, recovered, "instance-retired")
	retirementBytes := fixture.sign(t, scope, domainSlotRetirement, evidence, fixture.now)
	nextIntentBytes, nextIntent := fixture.intentBytes(t, scope, 2, "bootstrap-create-b", "retry-token-2")
	nextIntent.Mode = IntentModeExternalSeed
	nextIntent.SchemaVersion = 1
	nextIntent.RetryToken = ""
	nextIntent.FounderPlanSHA256 = ""
	nextIntent.PeerRowDigest = ""
	nextIntent.ReviewedPlanDigest = bodyDigest([]byte("reviewed replacement OpenTofu plan"))
	nextIntent.RetirementDigest = bodyDigest(retirementBytes)
	nextIntentBytes, nextIntent = fixture.bindIntentManifest(t, scope, nextIntent, fixture.now)
	nextHead := SlotHead{
		SchemaVersion: 1, DeploymentID: scope.DeploymentID, Cell: scope.Cell, Environment: fixture.environment,
		Role: roleController, Slot: scope.Slot, Attempt: 2, Generation: 2,
		IntentDigest: bodyDigest(nextIntentBytes), PreviousAttempt: recovered.Head.Attempt,
		PreviousGeneration: recovered.Head.Generation, PreviousIntentDigest: recovered.Head.IntentDigest,
		PreviousResultDigest: recovered.Head.ResultDigest, RetirementDigest: bodyDigest(retirementBytes),
	}
	advanced, err := fixture.ledger.AdvanceSlot(t.Context(), scope, recovered.HeadRecord.ETag,
		retirementBytes, nextIntentBytes, fixture.sign(t, scope, domainBootstrapHead, nextHead, fixture.now))
	if err != nil || advanced.Intent.Mode != IntentModeExternalSeed || advanced.Head.Attempt != 2 {
		t.Fatalf("advance to fresh external-seed successor: state=%+v err=%v", advanced, err)
	}
	if _, err := fixture.ledger.ReadForLaunch(t.Context(), scope); !errors.Is(err, ErrExternalSeedMode) {
		t.Fatalf("external-seed successor launch authorization returned %v, want explicit denial", err)
	}
	previousReceiptName := fixture.ledger.objectName(scope, 1, ledgerSeedReceipt)
	previousReceiptKey := requestKey(new(fixture.ledger.config.Namespace), new(fixture.ledger.config.Bucket), new(previousReceiptName))
	fixture.client.mu.Lock()
	previousReceipt := fixture.client.objects[previousReceiptKey]
	previousReceipt.body = []byte("tampered root receipt")
	fixture.client.objects[previousReceiptKey] = previousReceipt
	fixture.client.mu.Unlock()
	if _, err := fixture.ledger.ReadSlot(t.Context(), scope); !errors.Is(err, ErrSlotNotReserved) {
		t.Fatalf("advanced slot accepted a missing/corrupt predecessor seed receipt: %v", err)
	}

	for _, mutate := range []func(*Intent){
		func(value *Intent) { value.ReviewedPlanDigest = "" },
		func(value *Intent) { value.RetryToken = "retry-token-1" },
	} {
		invalid := intent
		mutate(&invalid)
		if err := validateIntent(invalid); !errors.Is(err, ErrInvalidRecord) {
			t.Errorf("invalid external seed field combination passed validation: %+v", invalid)
		}
	}
}

func TestExternalSeedRepairsOnlyAnAlreadyStoredReceiptAfterExpiry(t *testing.T) {
	fixture := newLedgerFixture(t)
	scope := testBootstrapScope()
	intentBytes, intent := fixture.intentBytes(t, scope, 1, "bootstrap-create-a", "retry-token-1")
	intent.Mode = IntentModeExternalSeed
	intent.SchemaVersion = 1
	intent.RetryToken = ""
	intent.FounderPlanSHA256 = ""
	intent.PeerRowDigest = ""
	intent.ReviewedPlanDigest = bodyDigest([]byte("reviewed OpenTofu plan"))
	intentBytes, intent = fixture.bindIntentManifest(t, scope, intent, fixture.now)
	headBytes := fixture.headBytes(t, scope, intentBytes, 1)
	if _, err := fixture.ledger.ReserveSlot(t.Context(), scope, intentBytes, headBytes); err != nil {
		t.Fatalf("reserve external seed slot: %v", err)
	}
	manifestBytes, receiptBytes, facts := fixture.seedProof(t, scope, intent, bodyDigest(intentBytes))
	result := fixture.result(scope, intent, bodyDigest(intentBytes))
	result.Mode = IntentModeExternalSeed
	result.SeedReceiptDigest = bodyDigest(receiptBytes)
	resultBytes := fixture.sign(t, scope, domainBootstrapResult, result, fixture.now)
	completedHead, err := fixture.ledger.decodeHead(scope, headBytes, true)
	if err != nil {
		t.Fatal(err)
	}
	completedHead.ResultDigest = bodyDigest(resultBytes)
	completedHeadBytes := fixture.sign(t, scope, domainBootstrapHead, completedHead, fixture.now)
	if _, err := fixture.ledger.createOrRead(t.Context(), scope, 1, ledgerManifest, manifestBytes); err != nil {
		t.Fatalf("persist exact root manifest before simulated crash: %v", err)
	}
	if _, err := fixture.ledger.createOrRead(t.Context(), scope, 1, ledgerSeedReceipt, receiptBytes); err != nil {
		t.Fatalf("persist current root receipt before simulated crash: %v", err)
	}
	if _, err := fixture.ledger.createOrRead(t.Context(), scope, 1, ledgerResult, resultBytes); err != nil {
		t.Fatalf("persist matching result before simulated crash: %v", err)
	}
	manifestStored, receiptStored, resultStored, err := fixture.ledger.ExternalSeedProgress(
		t.Context(), scope, manifestBytes, receiptBytes, resultBytes)
	if err != nil || !manifestStored || !receiptStored || !resultStored {
		t.Fatalf("exact stored seed progress was lost: manifest=%t receipt=%t result=%t err=%v",
			manifestStored, receiptStored, resultStored, err)
	}
	if _, _, _, err := fixture.ledger.ExternalSeedProgress(t.Context(), scope,
		manifestBytes, receiptBytes, []byte("different result")); !errors.Is(err, ErrImmutableConflict) {
		t.Fatalf("conflicting persisted seed result was treated as progress: %v", err)
	}
	fixture.client.setNow(fixture.now.Add(6 * time.Minute))
	state, err := fixture.ledger.RecordExternalSeed(t.Context(), scope, manifestBytes, receiptBytes, facts, resultBytes, completedHeadBytes)
	if err != nil {
		t.Fatalf("repair HEAD from exact receipt persisted while current: %v", err)
	}
	if state.Result == nil || state.SeedReceiptRecord == nil || state.Head.ResultDigest != bodyDigest(resultBytes) {
		t.Fatalf("exact persisted receipt did not repair completion: %+v", state)
	}
}

func TestExternalSeedResultClockAllowsOfflineSigningWindowOnly(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	result := Result{Mode: IntentModeExternalSeed, ObservedAt: now}
	for _, test := range []struct {
		name    string
		elapsed time.Duration
		wantErr bool
	}{
		{name: "offline signing", elapsed: 14 * time.Minute},
		{name: "clock tolerance", elapsed: ExternalSeedObservationMaxAge + time.Minute},
		{name: "stale observation", elapsed: ExternalSeedObservationMaxAge + time.Minute + 2*time.Second, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			stored := StoredRecord{LastModified: now.Add(test.elapsed), ServerDate: now.Add(test.elapsed)}
			err := validateResultClock(result, stored, time.Minute)
			if (err != nil) != test.wantErr {
				t.Fatalf("result clock after %s: %v, want error=%t", test.elapsed, err, test.wantErr)
			}
		})
	}
	result.Mode = IntentModeManaged
	stored := StoredRecord{LastModified: now.Add(time.Minute), ServerDate: now.Add(time.Minute)}
	if err := validateResultClock(result, stored, time.Minute); !errors.Is(err, ErrInvalidRetryClock) {
		t.Fatalf("managed peer accepted external seed freshness window: %v", err)
	}
}

func TestCheckRetryWindowUsesOriginalServerTimestamp(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for _, test := range []struct {
		name    string
		record  StoredRecord
		wantErr error
	}{
		{name: "inside", record: StoredRecord{LastModified: now.Add(-22*time.Hour - time.Minute), ServerDate: now}},
		{name: "expired", record: StoredRecord{LastModified: now.Add(-23 * time.Hour), ServerDate: now}, wantErr: ErrRetryWindowExpired},
		{name: "missing clock", record: StoredRecord{LastModified: now}, wantErr: ErrInvalidRetryClock},
		{name: "server clock before create", record: StoredRecord{LastModified: now, ServerDate: now.Add(-time.Second)}, wantErr: ErrInvalidRetryClock},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := CheckRetryWindow(test.record)
			if test.wantErr != nil && !errors.Is(err, test.wantErr) {
				t.Fatalf("CheckRetryWindow error = %v, want %v", err, test.wantErr)
			}
			if test.wantErr == nil && err != nil {
				t.Fatalf("CheckRetryWindow returned unexpected error: %v", err)
			}
		})
	}
}

type ledgerFixture struct {
	client      *fakeObjectStorageClient
	ledger      *Ledger
	authority   testBootstrapAuthority
	environment string
	maxLifetime time.Duration
	now         time.Time
}

type planBackedManagedPeerFixture struct {
	selected     founderPlanFixture
	plan         VerifiedFounderPlan
	client       *fakeObjectStorageClient
	ledger       *Ledger
	scope        BootstrapScope
	row          FounderPeerRow
	launch       LaunchAuthorization
	manifestWire []byte
}

func newPlanBackedManagedPeerFixture(t *testing.T, slot string) planBackedManagedPeerFixture {
	t.Helper()
	selected := newFounderPlanFixture(t)
	plan := selected.verify(t)
	row := selected.plan.Peers[0]
	if slot != "" {
		index := slices.IndexFunc(selected.plan.Peers, func(candidate FounderPeerRow) bool { return candidate.Slot == slot })
		if index < 0 {
			t.Fatalf("founder plan has no peer slot %q", slot)
		}
		row = selected.plan.Peers[index]
	}
	seedLaunch := selected.launchAuthorization(t, plan, row, "", "")
	client := newFakeObjectStorageClient()
	client.setNow(selected.now)
	anchor := selected.anchor.Anchor()
	ledgerGrant := signBootstrapLedgerGrant(t, selected.authority.rootPrivate, selected.authority.peerPublic,
		anchor.DeploymentID, anchor.Cell, anchor.Environment, anchor.ControllerSlots,
		selected.now.Add(-time.Minute), selected.now.Add(23*time.Hour))
	verifiedGrant, err := trust.VerifyDelegationCurrent(ledgerGrant, selected.authority.roots, selected.now, selected.policy)
	if err != nil {
		t.Fatalf("verify integrated ledger grant: %v", err)
	}
	config := LedgerConfig{
		DeploymentID: anchor.DeploymentID, Cell: anchor.Cell, ClusterID: anchor.ClusterID,
		InitialRegionIntentGeneration: anchor.InitialRegionIntentGeneration,
		InitialRegionIntentSHA256:     anchor.InitialRegionIntentSHA256,
		Namespace:                     anchor.StorageDomain.Namespace, Bucket: anchor.StorageDomain.LedgerBucket,
		KMSKeyID: anchor.StorageDomain.LedgerKMSKeyOCID, Prefix: anchor.StorageDomain.Prefix,
		HeadBucket: anchor.StorageDomain.HeadBucket, HeadKMSKeyID: anchor.StorageDomain.HeadKMSKeyOCID,
		Environment: anchor.Environment, ControllerSlots: slices.Clone(anchor.ControllerSlots),
		AnchorExpiresAt: selected.anchor.ExpiresAt(), TrustRoots: selected.authority.roots,
		Delegations: []trust.VerifiedDelegation{verifiedGrant}, TrustPolicy: selected.policy,
		VerificationNow: client.currentTime,
	}
	ledger, err := NewLedger(client, config)
	if err != nil {
		t.Fatalf("construct integrated ledger: %v", err)
	}
	scope := BootstrapScope{DeploymentID: anchor.DeploymentID, Cell: string(anchor.Cell), Slot: row.Slot}
	seedHead := seedLaunch.head
	seedHead.SchemaVersion = 2
	seedHeadPayload, err := trust.EncodePayload(seedHead)
	if err != nil {
		t.Fatalf("encode schema-v2 founder HEAD: %v", err)
	}
	seedHeadEnvelope, err := trust.Sign(seedHeadPayload, trust.Scope{
		Domain: domainBootstrapHead, DeploymentID: scope.DeploymentID, Cell: scope.Cell,
		Environment: anchor.Environment, Role: roleController, Slot: scope.Slot,
	}, selected.now, selected.now.Add(23*time.Hour), selected.authority.peerPrivate)
	if err != nil {
		t.Fatalf("sign schema-v2 founder HEAD: %v", err)
	}
	seedHeadWire, err := trust.EncodeEnvelope(seedHeadEnvelope)
	if err != nil {
		t.Fatalf("encode signed schema-v2 founder HEAD: %v", err)
	}
	if _, err := ledger.ReserveSlot(t.Context(), scope, seedLaunch.intentRecord.Bytes, seedHeadWire); err != nil {
		t.Fatalf("reserve plan-pinned slot in integrated ledger: %v", err)
	}
	launch, err := ledger.ReadForLaunch(t.Context(), scope)
	if err != nil {
		t.Fatalf("read integrated launch authorization: %v", err)
	}
	return planBackedManagedPeerFixture{
		selected: selected, plan: plan, client: client, ledger: ledger, scope: scope,
		row: cloneFounderPeerRow(row), launch: launch, manifestWire: bytes.Clone(selected.manifestWires[row.Slot]),
	}
}

func (fixture planBackedManagedPeerFixture) refreshWith(plan VerifiedFounderPlan) ManagedPeerRecoveryRefresh {
	return func(ctx context.Context) (VerifiedFounderPeer, error) {
		recovery, err := fixture.ledger.ReadForManagedPeerRecovery(ctx, fixture.scope)
		if err != nil {
			return VerifiedFounderPeer{}, err
		}
		return plan.AuthorizePeerRecovery(fixture.scope.Slot, recovery, fixture.selected.authority.roots,
			recovery.AuthorizationTime(), fixture.selected.now.Add(23*time.Hour), fixture.selected.policy)
	}
}

func (fixture planBackedManagedPeerFixture) facts(instanceOCID string) InstanceFacts {
	intent := fixture.launch.intent
	return InstanceFacts{
		DeploymentID: intent.DeploymentID, Environment: intent.Environment,
		ClusterID: fixture.selected.anchor.Anchor().ClusterID, Cell: oci.Region(intent.Cell),
		OCIRegion: intent.OCIRegion, Role: intent.Role, Slot: intent.Slot, InstanceOCID: instanceOCID,
		CompartmentOCID: intent.CompartmentOCID, ImageOCID: intent.ImageOCID, CreateKey: intent.CreateKey,
		IntentSHA256: fixture.launch.intentRecord.SHA256, Profile: launchProfileForIntent(intent),
	}
}

func (fixture planBackedManagedPeerFixture) receiptBytes(t *testing.T, facts InstanceFacts) []byte {
	t.Helper()
	envelope, err := SignPeerReceipt(fixture.plan.manifests[fixture.scope.Slot], facts,
		fixture.selected.now, fixture.selected.now.Add(5*time.Minute), fixture.selected.authority.peerPrivate)
	if err != nil {
		t.Fatalf("sign integrated peer receipt: %v", err)
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatalf("encode integrated peer receipt: %v", err)
	}
	return wire
}

func (fixture planBackedManagedPeerFixture) resultBytes(t *testing.T, facts InstanceFacts, receiptWire []byte) []byte {
	t.Helper()
	intent := fixture.launch.intent
	result := Result{
		SchemaVersion: 1, Mode: IntentModeManaged, DeploymentID: intent.DeploymentID, Cell: intent.Cell,
		Environment: intent.Environment, Role: intent.Role, Slot: intent.Slot, Attempt: intent.Attempt,
		Generation: intent.Generation, RegionIntentGeneration: intent.RegionIntentGeneration,
		IntentDigest: fixture.launch.intentRecord.SHA256, InstanceOCID: facts.InstanceOCID,
		ProviderRequestID: "integrated-request", ETag: "integrated-etag", OCIRegion: intent.OCIRegion,
		CompartmentOCID: intent.CompartmentOCID, ImageOCID: intent.ImageOCID, Shape: intent.Shape,
		ObservedProfileDigest: intent.LaunchRequestDigest, PeerReceiptDigest: digestBytes(receiptWire),
		CreateKey: intent.CreateKey, ObservedAt: fixture.selected.now,
	}
	return fixture.sign(t, domainBootstrapResult, result)
}

func (fixture planBackedManagedPeerFixture) completedHeadBytes(t *testing.T, resultWire []byte) []byte {
	t.Helper()
	head := fixture.launch.head
	head.ResultDigest = digestBytes(resultWire)
	return fixture.sign(t, domainBootstrapHead, head)
}

func (fixture planBackedManagedPeerFixture) sign(t *testing.T, domain string, payload any) []byte {
	t.Helper()
	encoded, err := trust.EncodePayload(payload)
	if err != nil {
		t.Fatalf("encode integrated %s payload: %v", domain, err)
	}
	envelope, err := trust.Sign(encoded, trust.Scope{
		Domain: domain, DeploymentID: fixture.scope.DeploymentID, Cell: fixture.scope.Cell,
		Environment: fixture.selected.plan.Environment, Role: roleController, Slot: fixture.scope.Slot,
	}, fixture.selected.now, fixture.selected.now.Add(23*time.Hour), fixture.selected.authority.peerPrivate)
	if err != nil {
		t.Fatalf("sign integrated %s payload: %v", domain, err)
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatalf("encode integrated %s envelope: %v", domain, err)
	}
	return wire
}

func newLedgerFixture(t *testing.T) *ledgerFixture {
	t.Helper()
	client := newFakeObjectStorageClient()
	authority := newTestBootstrapAuthority(t)
	authority.now = client.currentTime()
	roots := make(trust.Keyring, len(authority.roots))
	for keyID, key := range authority.roots {
		roots[keyID] = bytes.Clone(key)
	}
	fixture := &ledgerFixture{
		client: client, authority: authority,
		environment: "production", maxLifetime: 24 * time.Hour, now: client.currentTime(),
	}
	var err error
	config := LedgerConfig{
		DeploymentID: "deployment-a", Cell: oci.RegionGRU, ClusterID: "cluster-a",
		InitialRegionIntentGeneration: 4, InitialRegionIntentSHA256: bodyDigest([]byte("region-intent")),
		Namespace: "namespace", Bucket: "bootstrap-ledger", KMSKeyID: "ocid1.key.oc1.sa-saopaulo-1.ledger", Prefix: "private/bootstrap",
		HeadBucket: "bootstrap-head", HeadKMSKeyID: "ocid1.key.oc1.sa-saopaulo-1.head", Environment: fixture.environment,
		ControllerSlots: []string{"controller-a", "seed-a"},
		TrustRoots:      roots, TrustPolicy: trust.Policy{MaxLifetime: fixture.maxLifetime, ClockSkew: 2 * time.Minute},
		VerificationNow: client.currentTime,
	}
	peerPublicWire, err := trust.EncodeDelegatedPublicKey(authority.peerPublic)
	if err != nil {
		t.Fatal(err)
	}
	ledgerDelegation, err := trust.SignDelegation(trust.Delegation{
		SchemaVersion: trust.SchemaVersion, SubjectKeyID: keyID(t, authority.peerPublic), SubjectPublicKey: peerPublicWire,
		Capabilities: []trust.Capability{
			{Domain: domainBootstrapHead, DeploymentID: config.DeploymentID, Cell: string(config.Cell), Environment: config.Environment,
				Role: roleController, Slots: slices.Clone(config.ControllerSlots), Actions: []string{"sign"}},
			{Domain: domainBootstrapIntent, DeploymentID: config.DeploymentID, Cell: string(config.Cell), Environment: config.Environment,
				Role: roleController, Slots: slices.Clone(config.ControllerSlots), Actions: []string{"sign"}},
			{Domain: domainBootstrapResult, DeploymentID: config.DeploymentID, Cell: string(config.Cell), Environment: config.Environment,
				Role: roleController, Slots: slices.Clone(config.ControllerSlots), Actions: []string{"sign"}},
			{Domain: domainBootstrapCandidate, DeploymentID: config.DeploymentID, Cell: string(config.Cell), Environment: config.Environment,
				Role: roleController, Slots: slices.Clone(config.ControllerSlots), Actions: []string{"sign"}},
			{Domain: domainBootstrapProgress, DeploymentID: config.DeploymentID, Cell: string(config.Cell), Environment: config.Environment,
				Role: roleController, Slots: slices.Clone(config.ControllerSlots), Actions: []string{"sign"}},
		},
	}, fixture.now, fixture.now.Add(fixture.maxLifetime), authority.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	verifiedLedgerDelegation, err := trust.VerifyDelegationCurrent(ledgerDelegation, roots, fixture.now, config.TrustPolicy)
	if err != nil {
		t.Fatal(err)
	}
	config.Delegations = []trust.VerifiedDelegation{verifiedLedgerDelegation}
	fixture.authority.manifest.StorageDomain = config.storageDomain()
	fixture.authority.manifest.IntentGeneration = config.InitialRegionIntentGeneration
	fixture.authority.manifest.IntentSHA256 = config.InitialRegionIntentSHA256
	fixture.ledger, err = NewLedger(client, config)
	if err != nil {
		t.Fatal(err)
	}
	return fixture
}

func (fixture *ledgerFixture) newLedger(t *testing.T) *Ledger {
	t.Helper()
	ledger, err := NewLedger(fixture.client, fixture.ledger.config)
	if err != nil {
		t.Fatal(err)
	}
	return ledger
}

func (fixture *ledgerFixture) sign(t *testing.T, scope BootstrapScope, domain string, payload any, issuedAt time.Time) []byte {
	t.Helper()
	return fixture.signInterval(t, scope, domain, payload, issuedAt, issuedAt.Add(fixture.maxLifetime))
}

func (fixture *ledgerFixture) signInterval(t *testing.T, scope BootstrapScope, domain string, payload any, issuedAt, expiresAt time.Time) []byte {
	t.Helper()
	privateKey := fixture.authority.peerPrivate
	if domain == domainSlotRetirement || domain == domainSeedHandoff {
		privateKey = fixture.authority.rootPrivate
	}
	encodedPayload, err := trust.EncodePayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := trust.Sign(encodedPayload, trust.Scope{
		Domain: domain, DeploymentID: scope.DeploymentID, Cell: scope.Cell, Environment: fixture.environment,
		Role: roleController, Slot: scope.Slot,
	}, issuedAt, expiresAt, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := trust.EncodeEnvelope(signed)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func completeFirstManagedAttempt(t *testing.T, fixture *ledgerFixture, scope BootstrapScope) SlotState {
	t.Helper()
	intentBytes, intent := fixture.intentBytes(t, scope, 1, "create-key-1", "retry-token-1")
	reserved, err := fixture.ledger.ReserveSlot(t.Context(), scope, intentBytes, fixture.headBytes(t, scope, intentBytes, 1))
	if err != nil {
		t.Fatalf("reserve first managed attempt: %v", err)
	}
	manifestBytes, receiptBytes, facts := fixture.managedProof(t, scope, intent, bodyDigest(intentBytes))
	candidateWire := fixture.pinManagedPeerCandidate(t, scope, intent, bodyDigest(intentBytes), facts)
	result := fixture.result(scope, intent, bodyDigest(intentBytes))
	result.PeerReceiptDigest = bodyDigest(receiptBytes)
	resultBytes := fixture.sign(t, scope, domainBootstrapResult, result, fixture.now)
	completedHead := reserved.Head
	completedHead.ResultDigest = bodyDigest(resultBytes)
	completedHead.CandidateDigest = bodyDigest(candidateWire)
	state, err := fixture.ledger.RecordManagedPeer(t.Context(), scope, manifestBytes, receiptBytes, facts, resultBytes,
		fixture.sign(t, scope, domainBootstrapHead, completedHead, fixture.now),
		fixture.managedPeerProgressSigner(scope), fixture.managedPeerRefresh(scope))
	if err != nil {
		t.Fatalf("complete first managed attempt: %v", err)
	}
	return state
}

func advanceManagedAttemptForTest(t *testing.T, fixture *ledgerFixture, scope BootstrapScope) SlotState {
	t.Helper()
	intentBytes, intent := fixture.intentBytes(t, scope, 1, "create-key-1", "retry-token-1")
	reserved, err := fixture.ledger.ReserveSlot(t.Context(), scope, intentBytes, fixture.headBytes(t, scope, intentBytes, 1))
	if err != nil {
		t.Fatalf("reserve predecessor attempt: %v", err)
	}
	manifestBytes, receiptBytes, facts := fixture.managedProof(t, scope, intent, reserved.IntentDigest())
	candidateWire := fixture.pinManagedPeerCandidate(t, scope, intent, reserved.IntentDigest(), facts)
	result := fixture.result(scope, intent, reserved.IntentDigest())
	result.PeerReceiptDigest = bodyDigest(receiptBytes)
	resultBytes := fixture.sign(t, scope, domainBootstrapResult, result, fixture.now)
	completedHead := reserved.Head
	completedHead.CandidateDigest = bodyDigest(candidateWire)
	completedHead.ResultDigest = bodyDigest(resultBytes)
	completedHeadBytes := fixture.sign(t, scope, domainBootstrapHead, completedHead, fixture.now)
	completed, err := fixture.ledger.RecordManagedPeer(t.Context(), scope, manifestBytes, receiptBytes,
		facts, resultBytes, completedHeadBytes, fixture.managedPeerProgressSigner(scope), fixture.managedPeerRefresh(scope))
	if err != nil {
		t.Fatalf("complete predecessor attempt: %v", err)
	}
	retirementBytes := fixture.sign(t, scope, domainSlotRetirement,
		fixture.retirement(scope, completed, "instance-retired"), fixture.now)
	nextIntentBytes, nextIntent := fixture.intentBytes(t, scope, 2, "create-key-2", "retry-token-2")
	nextIntent.RetirementDigest = bodyDigest(retirementBytes)
	nextIntentBytes = fixture.sign(t, scope, domainBootstrapIntent, nextIntent, fixture.now)
	nextHead := SlotHead{
		SchemaVersion: 2, DeploymentID: scope.DeploymentID, Cell: scope.Cell, Environment: fixture.environment,
		Role: roleController, Slot: scope.Slot, Attempt: 2, Generation: 2,
		IntentDigest: bodyDigest(nextIntentBytes), PreviousAttempt: completed.Head.Attempt,
		PreviousGeneration: completed.Head.Generation, PreviousIntentDigest: completed.Head.IntentDigest,
		PreviousResultDigest: completed.Head.ResultDigest, PreviousCandidateDigest: completed.Head.CandidateDigest,
		RetirementDigest: bodyDigest(retirementBytes),
	}
	advanced, err := fixture.ledger.AdvanceSlot(t.Context(), scope, completed.HeadRecord.ETag,
		retirementBytes, nextIntentBytes, fixture.sign(t, scope, domainBootstrapHead, nextHead, fixture.now))
	if err != nil {
		t.Fatalf("advance completed predecessor: %v", err)
	}
	return advanced
}

// managedPeerRefresh exercises the ledger's per-transition freshness contract
// without rebuilding the separate founder-plan signing fixture for every
// lower-level ledger invariant test. Public authorization tests verify the
// production path that constructs this unforgeable in-process value.
func (fixture *ledgerFixture) managedPeerRefresh(scope BootstrapScope) ManagedPeerRecoveryRefresh {
	return func(ctx context.Context) (VerifiedFounderPeer, error) {
		authorization, err := fixture.ledger.ReadForManagedPeerRecovery(ctx, scope)
		if err != nil {
			return VerifiedFounderPeer{}, err
		}
		state := authorization.state
		recovery := authorization
		recovery.state = cloneSlotState(state)
		intentEnvelope, err := trust.DecodeEnvelope(state.IntentRecord.Bytes)
		if err != nil {
			return VerifiedFounderPeer{}, err
		}
		return VerifiedFounderPeer{
			row:      FounderPeerRow{Slot: scope.Slot, ManifestSHA256: state.Intent.ManifestDigest},
			manifest: VerifiedManifest{digest: state.Intent.ManifestDigest, verified: true},
			launch: LaunchAuthorization{
				scope: scope, intent: state.Intent, intentRecord: cloneStoredRecord(state.IntentRecord),
				head: state.Head, headRecord: cloneStoredRecord(state.HeadRecord),
			},
			recovery: &recovery, planDigest: state.Intent.FounderPlanSHA256,
			rowDigest: state.Intent.PeerRowDigest, effectDeadline: intentEnvelope.ExpiresAt, verified: true,
		}, nil
	}
}

func (fixture *ledgerFixture) pinManagedPeerCandidate(
	t *testing.T,
	scope BootstrapScope,
	intent Intent,
	intentDigest string,
	facts InstanceFacts,
) []byte {
	t.Helper()
	candidate := ManagedPeerCandidate{
		SchemaVersion: 1, DeploymentID: scope.DeploymentID, Cell: scope.Cell,
		Environment: fixture.environment, Role: roleController, Slot: scope.Slot,
		Attempt: intent.Attempt, Generation: intent.Generation, IntentDigest: intentDigest,
		CreateKey: intent.CreateKey, FounderPlanSHA256: intent.FounderPlanSHA256,
		PeerRowDigest: intent.PeerRowDigest, ManifestDigest: intent.ManifestDigest,
		LaunchProfileDigest: intent.LaunchRequestDigest, InstanceOCID: facts.InstanceOCID,
	}
	candidateWire := fixture.sign(t, scope, domainBootstrapCandidate, candidate, fixture.now)
	if err := fixture.ledger.RecordManagedPeerCandidate(t.Context(), scope, candidateWire,
		fixture.managedPeerProgressSigner(scope), fixture.managedPeerRefresh(scope)); err != nil {
		t.Fatalf("pin test managed-peer candidate: %v", err)
	}
	return candidateWire
}

func (fixture *ledgerFixture) managedPeerProgressSigner(scope BootstrapScope) ManagedPeerProgressSigner {
	return func(progress ManagedPeerProgress, issuedAt, expiresAt time.Time) ([]byte, error) {
		payload, err := trust.EncodePayload(progress)
		if err != nil {
			return nil, err
		}
		envelope, err := trust.Sign(payload, trust.Scope{
			Domain: domainBootstrapProgress, DeploymentID: scope.DeploymentID, Cell: scope.Cell,
			Environment: fixture.environment, Role: roleController, Slot: scope.Slot,
		}, issuedAt, expiresAt, fixture.authority.peerPrivate)
		if err != nil {
			return nil, err
		}
		return trust.EncodeEnvelope(envelope)
	}
}

func (fixture *ledgerFixture) intentBytes(t *testing.T, scope BootstrapScope, attempt uint64, createKey, retryToken string) ([]byte, Intent) {
	t.Helper()
	profile := LaunchProfile{
		Slot: scope.Slot, CompartmentOCID: "ocid1.compartment.oc1.sa-saopaulo-1.compartment-a",
		AvailabilityDomain: "AD-1", FaultDomain: "FAULT-DOMAIN-1",
		SubnetOCID:                "ocid1.subnet.oc1.sa-saopaulo-1.subnet-a",
		NetworkSecurityGroupOCIDs: []string{"ocid1.networksecuritygroup.oc1.sa-saopaulo-1.nsg-a"},
		Shape:                     "VM.Standard.E5.Flex",
	}
	launchDigest, err := launchProfileDigest(profile)
	if err != nil {
		t.Fatal(err)
	}
	intent := Intent{
		SchemaVersion: 2, Mode: IntentModeManaged, DeploymentID: scope.DeploymentID, Cell: scope.Cell, Environment: fixture.environment,
		Role: roleController, Slot: scope.Slot, Attempt: attempt, Generation: attempt,
		ReleaseReceiptDigest: bodyDigest([]byte("release")), RegionIntentGeneration: 4,
		ImageOCID: "ocid1.image.oc1.sa-saopaulo-1.image-a", RegionIntentDigest: bodyDigest([]byte("region-intent")),
		LaunchRequestDigest: launchDigest, FounderPlanSHA256: bodyDigest([]byte("founder-plan")),
		PeerRowDigest: bodyDigest([]byte("founder-peer-row")), CreateKey: createKey, RetryToken: retryToken,
		CreatedAt: fixture.now, OCIRegion: "sa-saopaulo-1", CompartmentOCID: "ocid1.compartment.oc1.sa-saopaulo-1.compartment-a",
		AvailabilityDomain: "AD-1", FaultDomain: "FAULT-DOMAIN-1", SubnetOCID: "ocid1.subnet.oc1.sa-saopaulo-1.subnet-a",
		NetworkSecurityGroupIDs: []string{"ocid1.networksecuritygroup.oc1.sa-saopaulo-1.nsg-a"}, Shape: "VM.Standard.E5.Flex", Node: "controller-a",
	}
	intentBytes, intent := fixture.bindIntentManifest(t, scope, intent, fixture.now)
	return intentBytes, intent
}

func (fixture *ledgerFixture) bindIntentManifest(t *testing.T, scope BootstrapScope, intent Intent, issuedAt time.Time) ([]byte, Intent) {
	t.Helper()
	manifestBytes, _ := fixture.manifestBytes(t, scope, intent)
	intent.ManifestDigest = objectDigest(manifestBytes)
	return fixture.sign(t, scope, domainBootstrapIntent, intent, issuedAt), intent
}

func (fixture *ledgerFixture) manifestBytes(t *testing.T, scope BootstrapScope, intent Intent) ([]byte, VerifiedManifest) {
	t.Helper()
	manifest := cloneManifest(fixture.authority.manifest)
	manifest.DeploymentID = intent.DeploymentID
	manifest.Environment = intent.Environment
	manifest.ClusterID = fixture.ledger.config.ClusterID
	manifest.Cell = oci.Region(intent.Cell)
	manifest.OCIRegion = intent.OCIRegion
	manifest.IntentGeneration = intent.RegionIntentGeneration
	manifest.IntentSHA256 = intent.RegionIntentDigest
	manifest.Slot = intent.Slot
	manifest.ImageOCID = intent.ImageOCID
	manifest.StorageDomain = fixture.ledger.config.storageDomain()
	manifest.Secrets = nil
	profile := launchProfileForIntent(intent)
	manifest.ControllerSlots = slices.Clone(fixture.ledger.config.ControllerSlots)
	seedSlot := "seed-a"
	if intent.Mode == IntentModeExternalSeed {
		seedSlot = intent.Slot
	} else if seedSlot == intent.Slot {
		seedSlot = "controller-a"
		if seedSlot == intent.Slot {
			seedSlot = "seed-authority"
		}
	}
	manifest.SeedSlot = seedSlot
	manifest.Profiles = make([]LaunchProfile, 0, len(manifest.ControllerSlots))
	for _, slot := range manifest.ControllerSlots {
		profileForSlot := cloneProfile(profile)
		profileForSlot.Slot = slot
		if slot == seedSlot && slot != intent.Slot {
			profileForSlot = cloneProfile(fixture.authority.manifest.Profiles[0])
			profileForSlot.Slot = slot
		}
		manifest.Profiles = append(manifest.Profiles, profileForSlot)
	}
	peerSlots := make([]string, 0, len(manifest.ControllerSlots)-1)
	for _, slot := range manifest.ControllerSlots {
		if slot != seedSlot {
			peerSlots = append(peerSlots, slot)
		}
	}
	manifest.PeerReceiptDelegation = nil
	if len(peerSlots) > 0 {
		delegation := fixture.peerDelegation(t, peerSlots)
		manifest.PeerReceiptDelegation = &delegation
	}
	envelope, err := SignManifest(manifest, fixture.now, fixture.now.Add(fixture.maxLifetime), fixture.authority.rootPrivate)
	if err != nil {
		t.Fatalf("sign test manifest: %v", err)
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatalf("encode test manifest: %v", err)
	}
	verified, err := VerifyManifest(envelope, fixture.ledger.config.TrustRoots, ManifestExpectation{
		DeploymentID: fixture.ledger.config.DeploymentID, Environment: fixture.environment,
		ClusterID: fixture.ledger.config.ClusterID, Cell: fixture.ledger.config.Cell,
		Slot: scope.Slot, ImageOCID: intent.ImageOCID, StorageDomain: fixture.ledger.config.storageDomain(),
		ControllerSlots:  slices.Clone(fixture.ledger.config.ControllerSlots),
		IntentGeneration: fixture.ledger.config.InitialRegionIntentGeneration,
		IntentSHA256:     fixture.ledger.config.InitialRegionIntentSHA256,
	}, fixture.now, fixture.ledger.config.TrustPolicy)
	if err != nil {
		t.Fatalf("verify test manifest: %v", err)
	}
	return wire, verified
}

func (fixture *ledgerFixture) peerDelegation(t *testing.T, slots []string) trust.Envelope {
	t.Helper()
	peerPublic, err := trust.EncodeDelegatedPublicKey(fixture.authority.peerPublic)
	if err != nil {
		t.Fatal(err)
	}
	delegation, err := trust.SignDelegation(trust.Delegation{
		SchemaVersion: trust.SchemaVersion, SubjectKeyID: keyID(t, fixture.authority.peerPublic), SubjectPublicKey: peerPublic,
		Capabilities: []trust.Capability{{
			Domain: peerReceiptDomain, DeploymentID: fixture.ledger.config.DeploymentID, Cell: string(fixture.ledger.config.Cell),
			Environment: fixture.environment, Role: roleController, Slots: slices.Clone(slots), Actions: []string{"sign"},
		}},
	}, fixture.now, fixture.now.Add(fixture.maxLifetime), fixture.authority.rootPrivate)
	if err != nil {
		t.Fatalf("sign test peer delegation: %v", err)
	}
	return delegation
}

func (fixture *ledgerFixture) managedProof(t *testing.T, scope BootstrapScope, intent Intent, intentDigest string) ([]byte, []byte, InstanceFacts) {
	t.Helper()
	manifestBytes, manifest := fixture.manifestBytes(t, scope, intent)
	facts := InstanceFacts{
		DeploymentID: intent.DeploymentID, Environment: intent.Environment, ClusterID: fixture.ledger.config.ClusterID,
		Cell: oci.Region(intent.Cell), OCIRegion: intent.OCIRegion, Role: intent.Role, Slot: intent.Slot,
		InstanceOCID: "ocid1.instance.oc1.sa-saopaulo-1.instance-a", CompartmentOCID: intent.CompartmentOCID,
		ImageOCID: intent.ImageOCID, CreateKey: intent.CreateKey, IntentSHA256: intentDigest,
		Profile: launchProfileForIntent(intent),
	}
	envelope, err := SignPeerReceipt(manifest, facts, fixture.now, fixture.now.Add(5*time.Minute), fixture.authority.peerPrivate)
	if err != nil {
		t.Fatalf("sign test peer receipt: %v", err)
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatalf("encode test peer receipt: %v", err)
	}
	return manifestBytes, wire, facts
}

func (fixture *ledgerFixture) seedProof(t *testing.T, scope BootstrapScope, intent Intent, intentDigest string) ([]byte, []byte, InstanceFacts) {
	t.Helper()
	manifestBytes, manifest := fixture.manifestBytes(t, scope, intent)
	facts := InstanceFacts{
		DeploymentID: intent.DeploymentID, Environment: intent.Environment, ClusterID: fixture.ledger.config.ClusterID,
		Cell: oci.Region(intent.Cell), OCIRegion: intent.OCIRegion, Role: intent.Role, Slot: intent.Slot,
		InstanceOCID: "ocid1.instance.oc1.sa-saopaulo-1.instance-a", CompartmentOCID: intent.CompartmentOCID,
		ImageOCID: intent.ImageOCID, CreateKey: intent.CreateKey, IntentSHA256: intentDigest,
		Profile: launchProfileForIntent(intent),
	}
	envelope, err := SignSeedReceipt(manifest, facts, fixture.now, fixture.now.Add(5*time.Minute), fixture.authority.rootPrivate)
	if err != nil {
		t.Fatalf("sign test seed receipt: %v", err)
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatalf("encode test seed receipt: %v", err)
	}
	return manifestBytes, wire, facts
}

func (fixture *ledgerFixture) headBytes(t *testing.T, scope BootstrapScope, intentBytes []byte, attempt uint64) []byte {
	t.Helper()
	intentEnvelope, err := trust.DecodeEnvelope(intentBytes)
	if err != nil {
		t.Fatalf("decode test intent envelope for HEAD schema: %v", err)
	}
	var intent Intent
	if err := decodeCanonicalPayload(intentEnvelope.Payload, &intent); err != nil {
		t.Fatalf("decode test intent payload for HEAD schema: %v", err)
	}
	schemaVersion := 1
	if intent.Mode == IntentModeManaged && intent.SchemaVersion == 2 {
		schemaVersion = 2
	}
	head := SlotHead{SchemaVersion: schemaVersion, DeploymentID: scope.DeploymentID, Cell: scope.Cell,
		Environment: fixture.environment, Role: roleController, Slot: scope.Slot, Attempt: attempt,
		Generation: attempt, IntentDigest: bodyDigest(intentBytes)}
	return fixture.sign(t, scope, domainBootstrapHead, head, fixture.now)
}

func (fixture *ledgerFixture) result(scope BootstrapScope, intent Intent, intentDigest string) Result {
	return Result{
		SchemaVersion: 1, Mode: intent.Mode, DeploymentID: scope.DeploymentID, Cell: scope.Cell, Environment: fixture.environment,
		Role: roleController, Slot: scope.Slot, Attempt: intent.Attempt, Generation: intent.Generation,
		RegionIntentGeneration: intent.RegionIntentGeneration,
		IntentDigest:           intentDigest, InstanceOCID: "ocid1.instance.oc1.sa-saopaulo-1.instance-a", ProviderRequestID: "request-a",
		ETag: "instance-etag-a", OCIRegion: intent.OCIRegion, CompartmentOCID: intent.CompartmentOCID,
		ImageOCID: intent.ImageOCID, Shape: intent.Shape, ObservedProfileDigest: intent.LaunchRequestDigest,
		CreateKey: intent.CreateKey, ObservedAt: fixture.now,
	}
}

func (fixture *ledgerFixture) retirement(scope BootstrapScope, state SlotState, disposition string) RetirementEvidence {
	return RetirementEvidence{
		SchemaVersion: 1, DeploymentID: scope.DeploymentID, Cell: scope.Cell, Environment: fixture.environment,
		Role: roleController, Slot: scope.Slot, PreviousAttempt: state.Head.Attempt,
		PreviousGeneration: state.Head.Generation, PreviousResultDigest: state.Head.ResultDigest,
		PriorInstanceOCID: state.Result.InstanceOCID, PriorCreateKey: state.Intent.CreateKey,
		Disposition: disposition, ObservedEvidenceDigest: bodyDigest([]byte("provider retirement evidence")),
		FencingAuthority: "oci-inspector", ObservedAt: fixture.now,
	}
}

func testBootstrapScope() BootstrapScope {
	return BootstrapScope{DeploymentID: "deployment-a", Cell: "GRU", Slot: "controller-a"}
}

type fakeObjectStorageClient struct {
	mu               sync.Mutex
	objects          map[string]fakeStoredObject
	clockAtCommit    map[string]time.Time
	clockAtGet       map[string]fakeClockAdvance
	getsByObject     map[string]int
	now              time.Time
	loseAckBucket    string
	putCalls         atomic.Int32
	getCalls         atomic.Int32
	invalidCondition atomic.Bool
	invalidKMSKey    atomic.Bool
	omitServerDate   atomic.Bool
	failBeforeCommit atomic.Bool
	rejectPut        error
	rejectPutBucket  string
}

type fakeClockAdvance struct {
	getNumber int
	now       time.Time
}

type fakeStoredObject struct {
	body         []byte
	etag         string
	lastModified time.Time
}

func newFakeObjectStorageClient() *fakeObjectStorageClient {
	return &fakeObjectStorageClient{
		objects: make(map[string]fakeStoredObject), clockAtCommit: make(map[string]time.Time),
		clockAtGet: make(map[string]fakeClockAdvance), getsByObject: make(map[string]int),
		now: time.Now().UTC().Truncate(time.Second),
	}
}

func (client *fakeObjectStorageClient) currentTime() time.Time {
	client.mu.Lock()
	defer client.mu.Unlock()
	return client.now
}

func (client *fakeObjectStorageClient) setNow(now time.Time) {
	client.mu.Lock()
	client.now = now.UTC()
	client.mu.Unlock()
}

func (client *fakeObjectStorageClient) setClockBeforePut(bucket, objectName string, now time.Time) {
	client.mu.Lock()
	client.clockAtCommit[requestKey(new("namespace"), new(bucket), new(objectName))] = now.UTC()
	client.mu.Unlock()
}

func (client *fakeObjectStorageClient) setClockOnGet(bucket, objectName string, after int, now time.Time) {
	client.mu.Lock()
	key := requestKey(new("namespace"), new(bucket), new(objectName))
	client.clockAtGet[key] = fakeClockAdvance{getNumber: client.getsByObject[key] + after, now: now.UTC()}
	client.mu.Unlock()
}

func (client *fakeObjectStorageClient) loseAckForBucket(bucket string) {
	client.mu.Lock()
	client.loseAckBucket = bucket
	client.mu.Unlock()
}

func (client *fakeObjectStorageClient) PutObject(_ context.Context, request objectstorage.PutObjectRequest) (objectstorage.PutObjectResponse, error) {
	client.putCalls.Add(1)
	if request.IfNoneMatch == nil && request.IfMatch == nil || request.IfNoneMatch != nil && request.IfMatch != nil ||
		request.IfNoneMatch != nil && *request.IfNoneMatch != "*" {
		client.invalidCondition.Store(true)
	}
	expectedKey := "ocid1.key.oc1.sa-saopaulo-1.ledger"
	if request.BucketName != nil && *request.BucketName == "bootstrap-head" {
		expectedKey = "ocid1.key.oc1.sa-saopaulo-1.head"
	}
	if request.OpcSseKmsKeyId == nil || *request.OpcSseKmsKeyId != expectedKey {
		client.invalidKMSKey.Store(true)
	}
	body, err := io.ReadAll(request.PutObjectBody)
	if closeErr := request.PutObjectBody.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return objectstorage.PutObjectResponse{}, err
	}
	if request.ContentLength == nil || int64(len(body)) != *request.ContentLength {
		return objectstorage.PutObjectResponse{}, errors.New("incorrect content length")
	}
	digest := sha256.Sum256(body)
	digestHeader := base64.StdEncoding.EncodeToString(digest[:])
	if request.OpcContentSha256 == nil || *request.OpcContentSha256 != digestHeader ||
		request.OpcChecksumAlgorithm != objectstorage.PutObjectOpcChecksumAlgorithmSha256 {
		return objectstorage.PutObjectResponse{}, errors.New("incorrect SHA-256 checksum")
	}
	if client.failBeforeCommit.Swap(false) {
		return objectstorage.PutObjectResponse{}, errors.New("connection reset before object commit")
	}
	if client.rejectPut != nil && (client.rejectPutBucket == "" || request.BucketName != nil && *request.BucketName == client.rejectPutBucket) {
		return objectstorage.PutObjectResponse{}, client.rejectPut
	}
	key := requestKey(request.NamespaceName, request.BucketName, request.ObjectName)
	client.mu.Lock()
	if advanceTo, ok := client.clockAtCommit[key]; ok {
		client.now = advanceTo
		delete(client.clockAtCommit, key)
	}
	previous, exists := client.objects[key]
	if request.IfNoneMatch != nil && exists || request.IfMatch != nil && (!exists || *request.IfMatch != previous.etag) {
		client.mu.Unlock()
		return objectstorage.PutObjectResponse{}, fakeObjectStorageError{status: http.StatusPreconditionFailed}
	}
	etag := `"` + hex.EncodeToString(digest[:8]) + `"`
	client.objects[key] = fakeStoredObject{
		body: bytes.Clone(body), etag: etag, lastModified: client.now.UTC().Truncate(time.Second),
	}
	loseAck := client.loseAckBucket != "" && request.BucketName != nil && *request.BucketName == client.loseAckBucket
	if loseAck {
		client.loseAckBucket = ""
	}
	client.mu.Unlock()
	if loseAck {
		return objectstorage.PutObjectResponse{}, errors.New("connection reset after object commit")
	}
	return objectstorage.PutObjectResponse{ETag: &etag, OpcRequestId: new("fake-put-request")}, nil
}

func (client *fakeObjectStorageClient) GetObject(_ context.Context, request objectstorage.GetObjectRequest) (objectstorage.GetObjectResponse, error) {
	client.getCalls.Add(1)
	key := requestKey(request.NamespaceName, request.BucketName, request.ObjectName)
	client.mu.Lock()
	client.getsByObject[key]++
	if advance, ok := client.clockAtGet[key]; ok && client.getsByObject[key] == advance.getNumber {
		client.now = advance.now
		delete(client.clockAtGet, key)
	}
	object, ok := client.objects[key]
	now := client.now
	client.mu.Unlock()
	if !ok {
		return objectstorage.GetObjectResponse{}, fakeObjectStorageError{status: http.StatusNotFound}
	}
	date := now.Format(http.TimeFormat)
	if client.omitServerDate.Load() {
		date = ""
	}
	headers := make(http.Header)
	if date != "" {
		headers.Set("Date", date)
	}
	length := int64(len(object.body))
	etag := object.etag
	lastModified := common.SDKTime{Time: object.lastModified}
	return objectstorage.GetObjectResponse{
		RawResponse: &http.Response{Header: headers}, Content: io.NopCloser(bytes.NewReader(object.body)),
		ContentLength: &length, ETag: &etag, LastModified: &lastModified, OpcRequestId: new("fake-get-request"),
	}, nil
}

func (client *fakeObjectStorageClient) objectCount() int {
	client.mu.Lock()
	defer client.mu.Unlock()
	return len(client.objects)
}

type fakeObjectStorageError struct{ status int }

func (err fakeObjectStorageError) Error() string {
	return fmt.Sprintf("fake Object Storage status %d", err.status)
}
func (err fakeObjectStorageError) GetHTTPStatusCode() int  { return err.status }
func (err fakeObjectStorageError) GetMessage() string      { return err.Error() }
func (err fakeObjectStorageError) GetCode() string         { return "FakeError" }
func (err fakeObjectStorageError) GetOpcRequestID() string { return "fake-request" }

func requestKey(namespace, bucket, objectName *string) string {
	return *namespace + "\x00" + *bucket + "\x00" + *objectName
}

func bodyDigest(body []byte) string {
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:])
}
