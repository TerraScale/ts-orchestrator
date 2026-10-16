package bootstrap

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

type managedPeerWriteCrash struct{}

type crashAfterCommittedPutClient struct {
	delegate ObjectStorageClient
	stopAt   int
	commits  int
	crashed  bool
}

func (client *crashAfterCommittedPutClient) PutObject(
	ctx context.Context,
	request objectstorage.PutObjectRequest,
) (objectstorage.PutObjectResponse, error) {
	response, err := client.delegate.PutObject(ctx, request)
	if err == nil {
		client.commits++
		if !client.crashed && client.commits == client.stopAt {
			client.crashed = true
			panic(managedPeerWriteCrash{})
		}
	}
	return response, err
}

func (client *crashAfterCommittedPutClient) GetObject(
	ctx context.Context,
	request objectstorage.GetObjectRequest,
) (objectstorage.GetObjectResponse, error) {
	return client.delegate.GetObject(ctx, request)
}

func TestManagedPeerCandidatePinStopsLaunchAndAuthorizesObservation(t *testing.T) {
	fixture := newPlanBackedManagedPeerFixture(t, "")
	facts := fixture.facts("ocid1.instance.oc1.sa-saopaulo-1.pinned-candidate")
	candidateWire := managedPeerCandidateWire(t, fixture, facts)
	candidate, _, err := fixture.ledger.decodeManagedPeerCandidate(fixture.scope, candidateWire, true)
	if err != nil {
		t.Fatalf("decode signed candidate fixture: %v", err)
	}
	initial := readAndAuthorizeManagedPeerRecovery(t, fixture, fixture.plan)
	if _, err := initial.peer.LaunchRequest(initial.recovery.AuthorizationTime()); err != nil {
		t.Fatalf("clean recovery should authorize the first launch: %v", err)
	}

	if err := fixture.ledger.RecordManagedPeerCandidate(t.Context(), fixture.scope, candidateWire,
		managedPeerProgressSigner(fixture),
		managedPeerRecoveryRefresh(fixture, fixture.plan)); err != nil {
		t.Fatalf("RecordManagedPeerCandidate(): %v", err)
	}

	pinned := readAndAuthorizeManagedPeerRecovery(t, fixture, fixture.plan)
	if pinned.recovery.Phase() != ManagedPeerRecoveryCandidateOnly {
		t.Fatalf("candidate recovery phase = %q, want candidate-only", pinned.recovery.Phase())
	}
	state := pinned.recovery.State()
	if state.Candidate == nil || *state.Candidate != candidate || state.CandidateRecord == nil ||
		!bytes.Equal(state.CandidateRecord.Bytes, candidateWire) {
		t.Fatalf("candidate pin did not preserve the exact signed candidate: %+v", state.CandidateRecord)
	}
	candidateDigest := digestBytes(candidateWire)
	if state.Head.SchemaVersion != 1 || state.Head.CandidateDigest != "" || state.Head.ResultDigest != "" {
		t.Fatalf("candidate-only HEAD = %+v, want incomplete v1 HEAD without candidate/result digest", state.Head)
	}
	progress, ok := pinned.recovery.Progress()
	if !ok || progress.Phase != ManagedPeerProgressCandidate || progress.CandidateDigest != candidateDigest ||
		progress.PendingProofKind != "" || progress.PendingProofDigest != "" || len(progress.PendingProofWire) != 0 {
		t.Fatalf("candidate progress = %+v, present=%t; want exact candidate-pinned progress without staged proof", progress, ok)
	}
	if _, err := pinned.peer.LaunchRequest(pinned.recovery.AuthorizationTime()); !errors.Is(err, ErrFounderPeerAuthorization) {
		t.Fatalf("candidate-pinned recovery authorized another launch: %v", err)
	}
	observation, err := pinned.peer.ObservationRequest(pinned.recovery.AuthorizationTime())
	if err != nil || observation.InstanceOCID != candidate.InstanceOCID {
		t.Fatalf("candidate-pinned observation = %+v, err=%v; want exact OCID %q", observation, err, candidate.InstanceOCID)
	}

	putsBeforeReplay := fixture.client.putCalls.Load()
	if err := fixture.ledger.RecordManagedPeerCandidate(t.Context(), fixture.scope, candidateWire,
		managedPeerProgressSigner(fixture),
		managedPeerRecoveryRefresh(fixture, fixture.plan)); err != nil {
		t.Fatalf("replay exact candidate pin: %v", err)
	}
	if got := fixture.client.putCalls.Load(); got != putsBeforeReplay {
		t.Fatalf("replaying exact candidate pin wrote objects: puts before=%d after=%d", putsBeforeReplay, got)
	}
}

func TestManagedPeerCandidateWriteCrashStillStopsLaunch(t *testing.T) {
	fixture := newPlanBackedManagedPeerFixture(t, "")
	facts := fixture.facts("ocid1.instance.oc1.sa-saopaulo-1.candidate-write-crash")
	candidateWire := managedPeerCandidateWire(t, fixture, facts)
	crashClient := crashManagedPeerCandidateAfterFirstPut(t, &fixture, candidateWire)
	recovery, err := fixture.ledger.ReadForManagedPeerRecovery(t.Context(), fixture.scope)
	if err != nil {
		t.Fatalf("read recovery after candidate PUT without progress CAS: %v", err)
	}
	if recovery.Phase() != ManagedPeerRecoveryCandidateOnly {
		t.Fatalf("recovery after candidate PUT = %q, want candidate-only", recovery.Phase())
	}
	state := recovery.State()
	if state.CandidateRecord == nil || !bytes.Equal(state.CandidateRecord.Bytes, candidateWire) ||
		state.ProgressRecord != nil || state.Head.CandidateDigest != "" || state.Head.ResultDigest != "" {
		t.Fatalf("candidate-write crash did not preserve candidate-only, pre-HEAD state: %+v", state)
	}
	peer, err := fixture.plan.AuthorizePeerRecovery(fixture.scope.Slot, recovery,
		fixture.selected.authority.roots, recovery.AuthorizationTime(), fixture.plan.envelope.ExpiresAt,
		fixture.selected.policy)
	if err != nil {
		t.Fatalf("authorize recovery from the candidate-only object: %v", err)
	}
	if _, err := peer.LaunchRequest(recovery.AuthorizationTime()); !errors.Is(err, ErrFounderPeerAuthorization) {
		t.Fatalf("candidate object without progress authorized another launch: %v", err)
	}
	observation, err := peer.ObservationRequest(recovery.AuthorizationTime())
	if err != nil || observation.InstanceOCID != facts.InstanceOCID {
		t.Fatalf("candidate-only recovery observation = %+v, err=%v", observation, err)
	}

	if err := fixture.ledger.RecordManagedPeerCandidate(t.Context(), fixture.scope, candidateWire,
		managedPeerProgressSigner(fixture), managedPeerRecoveryRefresh(fixture, fixture.plan)); err != nil {
		t.Fatalf("resume candidate progress CAS: %v", err)
	}
	if crashClient.commits != 2 {
		t.Fatalf("candidate resume committed %d puts, want one progress CAS and no candidate rewrite", crashClient.commits)
	}
	resumed := readAndAuthorizeManagedPeerRecovery(t, fixture, fixture.plan)
	if resumed.recovery.Phase() != ManagedPeerRecoveryCandidateOnly {
		t.Fatalf("recovery after candidate progress resume = %q, want candidate-only", resumed.recovery.Phase())
	}
}

func crashManagedPeerCandidateAfterFirstPut(
	t *testing.T,
	fixture *planBackedManagedPeerFixture,
	candidateWire []byte,
) *crashAfterCommittedPutClient {
	t.Helper()
	crashClient := &crashAfterCommittedPutClient{delegate: fixture.client, stopAt: 1}
	fixture.ledger.client = crashClient
	var recordErr error
	panicValue := captureManagedPeerPanic(func() {
		recordErr = fixture.ledger.RecordManagedPeerCandidate(t.Context(), fixture.scope, candidateWire,
			managedPeerProgressSigner(*fixture), managedPeerRecoveryRefresh(*fixture, fixture.plan))
	})
	if recordErr != nil {
		t.Fatalf("candidate write returned before simulated process loss: %v", recordErr)
	}
	if _, ok := panicValue.(managedPeerWriteCrash); !ok || !crashClient.crashed || crashClient.commits != 1 {
		t.Fatalf("candidate write panic = %T (%v), commits=%d; want crash after exact candidate PUT",
			panicValue, panicValue, crashClient.commits)
	}
	reopenManagedPeerFixtureLedger(t, fixture, crashClient)
	return crashClient
}

func managedPeerCandidateWire(t *testing.T, fixture planBackedManagedPeerFixture, facts InstanceFacts) []byte {
	t.Helper()
	candidate := ManagedPeerCandidate{
		SchemaVersion: 1, DeploymentID: fixture.scope.DeploymentID, Cell: fixture.scope.Cell,
		Environment: fixture.selected.plan.Environment, Role: roleController, Slot: fixture.scope.Slot,
		Attempt: fixture.launch.intent.Attempt, Generation: fixture.launch.intent.Generation,
		IntentDigest: fixture.launch.intentRecord.SHA256, CreateKey: fixture.launch.intent.CreateKey,
		FounderPlanSHA256: fixture.launch.intent.FounderPlanSHA256,
		PeerRowDigest:     fixture.launch.intent.PeerRowDigest,
		ManifestDigest:    fixture.row.ManifestSHA256, LaunchProfileDigest: fixture.launch.intent.LaunchRequestDigest,
		InstanceOCID: facts.InstanceOCID,
	}
	return fixture.sign(t, domainBootstrapCandidate, candidate)
}

func managedPeerProgressSigner(fixture planBackedManagedPeerFixture) ManagedPeerProgressSigner {
	return func(progress ManagedPeerProgress, issuedAt, expiresAt time.Time) ([]byte, error) {
		payload, err := trust.EncodePayload(progress)
		if err != nil {
			return nil, fmt.Errorf("encode managed-peer progress: %w", err)
		}
		envelope, err := trust.Sign(payload, trust.Scope{
			Domain: domainBootstrapProgress, DeploymentID: fixture.scope.DeploymentID,
			Cell: fixture.scope.Cell, Environment: fixture.selected.plan.Environment,
			Role: roleController, Slot: fixture.scope.Slot,
		}, issuedAt, expiresAt, fixture.selected.authority.peerPrivate)
		if err != nil {
			return nil, fmt.Errorf("sign managed-peer progress: %w", err)
		}
		wire, err := trust.EncodeEnvelope(envelope)
		if err != nil {
			return nil, fmt.Errorf("encode managed-peer progress envelope: %w", err)
		}
		return wire, nil
	}
}

func crashManagedPeerAfterCommittedPuts(
	t *testing.T,
	fixture *planBackedManagedPeerFixture,
	facts InstanceFacts,
	candidateWire []byte,
	stopAt int,
	receiptWire, resultWire, headWire []byte,
) {
	t.Helper()
	if err := fixture.ledger.RecordManagedPeerCandidate(t.Context(), fixture.scope, candidateWire,
		managedPeerProgressSigner(*fixture), managedPeerRecoveryRefresh(*fixture, fixture.plan)); err != nil {
		t.Fatalf("pin observed candidate before simulated write loss: %v", err)
	}
	crashClient := &crashAfterCommittedPutClient{delegate: fixture.client, stopAt: stopAt}
	fixture.ledger.client = crashClient
	var recordErr error
	panicValue := captureManagedPeerPanic(func() {
		_, recordErr = fixture.ledger.RecordManagedPeer(t.Context(), fixture.scope,
			fixture.manifestWire, receiptWire, facts, resultWire, headWire,
			managedPeerProgressSigner(*fixture), managedPeerRecoveryRefresh(*fixture, fixture.plan))
	})
	if recordErr != nil {
		t.Fatalf("RecordManagedPeer() before simulated loss: %v", recordErr)
	}
	if _, ok := panicValue.(managedPeerWriteCrash); !ok || !crashClient.crashed || crashClient.commits != stopAt {
		t.Fatalf("RecordManagedPeer() panic = %T (%v), committed puts=%d, want crash after %d",
			panicValue, panicValue, crashClient.commits, stopAt)
	}
	reopenManagedPeerFixtureLedger(t, fixture, crashClient)
}

func TestManagedPeerRecoveryResumesAfterEachCommittedWrite(t *testing.T) {
	for _, test := range []struct {
		name             string
		puts             int
		phase            ManagedPeerRecoveryPhase
		progressPhase    ManagedPeerProgressPhase
		progressSequence uint64
		pendingProofKind string
		pendingProofWire []byte
		manifestStored   bool
		receiptStored    bool
		resultStored     bool
	}{
		{name: "manifest", puts: 1, phase: ManagedPeerRecoveryCandidateOnly,
			progressPhase: ManagedPeerProgressCandidate, progressSequence: 1, manifestStored: true},
		{name: "receipt-stage", puts: 2, phase: ManagedPeerRecoveryProofStaged,
			progressPhase: ManagedPeerProgressReceipt, progressSequence: 2, pendingProofKind: "receipt", manifestStored: true},
		{name: "receipt", puts: 3, phase: ManagedPeerRecoveryReceiptOnly,
			progressPhase: ManagedPeerProgressReceipt, progressSequence: 2, pendingProofKind: "receipt", manifestStored: true, receiptStored: true},
		{name: "result-stage", puts: 4, phase: ManagedPeerRecoveryProofStaged,
			progressPhase: ManagedPeerProgressResult, progressSequence: 3, pendingProofKind: "result", manifestStored: true,
			receiptStored: true},
		{name: "result", puts: 5, phase: ManagedPeerRecoveryResultReady,
			progressPhase: ManagedPeerProgressResult, progressSequence: 3, pendingProofKind: "result", manifestStored: true, receiptStored: true, resultStored: true},
		{name: "head", puts: 6, phase: ManagedPeerRecoveryComplete,
			progressPhase: ManagedPeerProgressResult, progressSequence: 3, pendingProofKind: "result", manifestStored: true, receiptStored: true, resultStored: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPlanBackedManagedPeerFixture(t, "")
			facts := fixture.facts("ocid1.instance.oc1.sa-saopaulo-1.managed-recovery")
			receiptWire := fixture.receiptBytes(t, facts)
			resultWire := fixture.resultBytes(t, facts, receiptWire)
			candidateWire := managedPeerCandidateWire(t, fixture, facts)
			headWire := managedPeerCompletedHeadAt(t, fixture, resultWire, candidateWire,
				fixture.selected.now, fixture.selected.now.Add(23*time.Hour))

			initial := readAndAuthorizeManagedPeerRecovery(t, fixture, fixture.plan)
			if initial.recovery.Phase() != ManagedPeerRecoveryClean {
				t.Fatalf("initial phase = %q, want clean", initial.recovery.Phase())
			}
			if _, err := initial.peer.LaunchRequest(initial.recovery.AuthorizationTime()); err != nil {
				t.Fatalf("clean recovery did not retain launch permission: %v", err)
			}
			if err := fixture.ledger.RecordManagedPeerCandidate(t.Context(), fixture.scope, candidateWire,
				managedPeerProgressSigner(fixture), managedPeerRecoveryRefresh(fixture, fixture.plan)); err != nil {
				t.Fatalf("pin observed managed peer before recording proofs: %v", err)
			}
			if test.pendingProofKind == "receipt" {
				test.pendingProofWire = receiptWire
			} else if test.pendingProofKind == "result" {
				test.pendingProofWire = resultWire
			}
			crashClient := &crashAfterCommittedPutClient{delegate: fixture.client, stopAt: test.puts}
			fixture.ledger.client = crashClient

			var recordErr error
			panicValue := captureManagedPeerPanic(func() {
				_, recordErr = fixture.ledger.RecordManagedPeer(t.Context(), fixture.scope,
					fixture.manifestWire, receiptWire, facts, resultWire, headWire,
					managedPeerProgressSigner(fixture), managedPeerRecoveryRefresh(fixture, fixture.plan))
			})
			if recordErr != nil {
				t.Fatalf("RecordManagedPeer() returned before simulated process loss: %v", recordErr)
			}
			if _, ok := panicValue.(managedPeerWriteCrash); !ok || !crashClient.crashed {
				t.Fatalf("RecordManagedPeer() panic = %T (%v), want crash after committed put", panicValue, panicValue)
			}
			if crashClient.commits != test.puts {
				t.Fatalf("committed puts before process loss = %d, want %d", crashClient.commits, test.puts)
			}

			// Rebuild the ledger value to model a new process reading the same OCI store.
			reopenManagedPeerFixtureLedger(t, &fixture, crashClient)
			crashed := readAndAuthorizeManagedPeerRecovery(t, fixture, fixture.plan)
			if crashed.recovery.Phase() != test.phase {
				t.Fatalf("phase after committed %s write = %q, want %q", test.name, crashed.recovery.Phase(), test.phase)
			}
			assertManagedPeerRecoveryBytes(t, crashed.recovery.State(), test.phase,
				candidateWire, fixture.manifestWire, receiptWire, resultWire, headWire,
				test.progressPhase, test.progressSequence, test.pendingProofKind, test.pendingProofWire,
				test.manifestStored, test.receiptStored, test.resultStored)
			if test.receiptStored {
				assertManagedPeerProofAddressedByDigest(t, fixture.client, fixture.ledger.config.Namespace,
					fixture.ledger.config.Bucket, digestBytes(receiptWire))
			}
			if test.resultStored {
				assertManagedPeerProofAddressedByDigest(t, fixture.client, fixture.ledger.config.Namespace,
					fixture.ledger.config.Bucket, digestBytes(resultWire))
			}
			assertManagedPeerRecoveryPermissions(t, crashed.peer, crashed.recovery, facts.InstanceOCID)

			state, err := fixture.ledger.RecordManagedPeer(t.Context(), fixture.scope,
				fixture.manifestWire, receiptWire, facts, resultWire, headWire,
				managedPeerProgressSigner(fixture), managedPeerRecoveryRefresh(fixture, fixture.plan))
			if err != nil {
				t.Fatalf("resume after %s commit: %v", test.name, err)
			}
			if state.Head.ResultDigest != digestBytes(resultWire) || crashClient.commits != 6 {
				t.Fatalf("resume state/head writes = %s/%d, want %s/6", state.Head.ResultDigest,
					crashClient.commits, digestBytes(resultWire))
			}

			// Reopen again and replay a completed request. Exact bytes are idempotent
			// and must not create another immutable object or rewrite HEAD.
			reopenManagedPeerFixtureLedger(t, &fixture, crashClient)
			replayed, err := fixture.ledger.RecordManagedPeer(t.Context(), fixture.scope,
				fixture.manifestWire, receiptWire, facts, resultWire, headWire,
				managedPeerProgressSigner(fixture), managedPeerRecoveryRefresh(fixture, fixture.plan))
			if err != nil {
				t.Fatalf("replay completed request: %v", err)
			}
			if crashClient.commits != 6 || replayed.Head.ResultDigest != digestBytes(resultWire) {
				t.Fatalf("completed replay changed durable state: puts=%d state=%+v", crashClient.commits, replayed.Head)
			}
			final := readAndAuthorizeManagedPeerRecovery(t, fixture, fixture.plan)
			if final.recovery.Phase() != ManagedPeerRecoveryComplete {
				t.Fatalf("final recovery phase = %q, want complete", final.recovery.Phase())
			}
			assertManagedPeerRecoveryBytes(t, final.recovery.State(), ManagedPeerRecoveryComplete,
				candidateWire, fixture.manifestWire, receiptWire, resultWire, headWire,
				ManagedPeerProgressResult, 3, "result", resultWire, true, true, true)
		})
	}
}

func TestManagedPeerLateStagedProofIsQuarantinedAndRepairedWithFreshProofs(t *testing.T) {
	fixture := newPlanBackedManagedPeerFixture(t, "")
	facts := fixture.facts("ocid1.instance.oc1.sa-saopaulo-1.late-proof-candidate")
	lateReceiptWire := managedPeerReceiptAt(t, fixture, facts, fixture.selected.now,
		fixture.selected.now.Add(5*time.Minute))
	lateResultWire := managedPeerResultAt(t, fixture, facts, lateReceiptWire,
		fixture.selected.now, fixture.selected.now.Add(23*time.Hour))
	lateCandidateWire := managedPeerCandidateWire(t, fixture, facts)
	lateHeadWire := managedPeerCompletedHeadAt(t, fixture, lateResultWire, lateCandidateWire,
		fixture.selected.now, fixture.selected.now.Add(23*time.Hour))

	// Four commits leave the result bytes durably staged in signed progress,
	// while the content-addressed result object and completed HEAD are absent.
	crashManagedPeerAfterCommittedPuts(t, &fixture, facts, lateCandidateWire, 4,
		lateReceiptWire, lateResultWire, lateHeadWire)
	fixture.client.setNow(fixture.selected.now.Add(6 * time.Minute))
	quarantined := readAndAuthorizeManagedPeerRecovery(t, fixture, fixture.plan)
	if quarantined.recovery.Phase() != ManagedPeerRecoveryQuarantined {
		t.Fatalf("late staged result phase = %q, want quarantined", quarantined.recovery.Phase())
	}
	state := quarantined.recovery.State()
	if state.Candidate == nil || state.Candidate.InstanceOCID != facts.InstanceOCID ||
		state.CandidateRecord == nil || !bytes.Equal(state.CandidateRecord.Bytes, lateCandidateWire) ||
		state.Head.ResultDigest != "" || state.Progress == nil ||
		state.Progress.Phase != ManagedPeerProgressResult ||
		state.Progress.PendingProofDigest != digestBytes(lateResultWire) ||
		!bytes.Equal(state.Progress.PendingProofWire, lateResultWire) {
		t.Fatalf("late proof quarantine lost its pinned candidate or exact staged bytes: %+v", state)
	}
	assertManagedPeerRecoveryPermissions(t, quarantined.peer, quarantined.recovery, facts.InstanceOCID)

	objectsBeforeStaleReplay := fixture.client.objectCount()
	putsBeforeStaleReplay := fixture.client.putCalls.Load()
	if _, err := fixture.ledger.RecordManagedPeer(t.Context(), fixture.scope,
		fixture.manifestWire, lateReceiptWire, facts, lateResultWire, lateHeadWire,
		managedPeerProgressSigner(fixture), managedPeerRecoveryRefresh(fixture, fixture.plan)); !errors.Is(err, ErrManagedPeerObservationStale) && !errors.Is(err, ErrRecordAuthorization) {
		t.Fatalf("expired staged proof replay error = %v, want stale observation or authorization failure", err)
	}
	if got := fixture.client.objectCount(); got != objectsBeforeStaleReplay {
		t.Fatalf("expired staged proof replay created %d objects, want none", got-objectsBeforeStaleReplay)
	}
	if got := fixture.client.putCalls.Load(); got != putsBeforeStaleReplay {
		t.Fatalf("expired staged proof replay made %d PUT calls, want none", got-putsBeforeStaleReplay)
	}

	// The same pinned instance can be repaired only with a new observation and
	// fresh signed receipt, result, progress, and HEAD bytes.
	freshAt := fixture.selected.now.Add(6 * time.Minute)
	freshProofExpiry := fixture.selected.now.Add(23 * time.Hour)
	freshReceiptWire := managedPeerReceiptAt(t, fixture, facts, freshAt, freshAt.Add(5*time.Minute))
	freshResultWire := managedPeerResultAt(t, fixture, facts, freshReceiptWire,
		freshAt, freshProofExpiry)
	freshHeadWire := managedPeerCompletedHeadAt(t, fixture, freshResultWire, lateCandidateWire,
		freshAt, freshProofExpiry)
	fixture.client.setNow(freshAt)
	completed, err := fixture.ledger.RecordManagedPeer(t.Context(), fixture.scope,
		fixture.manifestWire, freshReceiptWire, facts, freshResultWire, freshHeadWire,
		managedPeerProgressSigner(fixture), managedPeerRecoveryRefresh(fixture, fixture.plan))
	if err != nil {
		t.Fatalf("repair quarantined candidate with fresh proofs: %v", err)
	}
	if completed.CandidateRecord == nil || !bytes.Equal(completed.CandidateRecord.Bytes, lateCandidateWire) ||
		completed.Head.CandidateDigest != digestBytes(lateCandidateWire) ||
		completed.Head.ResultDigest != digestBytes(freshResultWire) ||
		completed.ResultRecord == nil || !bytes.Equal(completed.ResultRecord.Bytes, freshResultWire) {
		t.Fatalf("fresh proof repair changed candidate identity or lost completed bindings: %+v", completed.Head)
	}
	final := readAndAuthorizeManagedPeerRecovery(t, fixture, fixture.plan)
	if final.recovery.Phase() != ManagedPeerRecoveryComplete || final.recovery.State().Progress == nil ||
		final.recovery.State().Progress.Sequence != 5 ||
		final.recovery.State().Progress.PendingProofDigest != digestBytes(freshResultWire) ||
		!bytes.Equal(final.recovery.State().Progress.PendingProofWire, freshResultWire) {
		t.Fatalf("fresh proof repair final phase/progress = %q/%+v", final.recovery.Phase(), final.recovery.State().Progress)
	}
	if _, err := final.peer.LaunchRequest(final.recovery.AuthorizationTime()); !errors.Is(err, ErrFounderPeerAuthorization) {
		t.Fatalf("fresh proof repair authorized another launch: %v", err)
	}
}

func TestManagedPeerCompletedStateSurvivesExpiredProgressAfterRestart(t *testing.T) {
	fixture := newPlanBackedManagedPeerFixture(t, "")
	facts := fixture.facts("ocid1.instance.oc1.sa-saopaulo-1.completed-proof-restart")
	candidateWire := managedPeerCandidateWire(t, fixture, facts)
	receiptWire := fixture.receiptBytes(t, facts)
	resultWire := fixture.resultBytes(t, facts, receiptWire)
	headWire := managedPeerCompletedHeadAt(t, fixture, resultWire, candidateWire,
		fixture.selected.now, fixture.selected.now.Add(23*time.Hour))
	if err := fixture.ledger.RecordManagedPeerCandidate(t.Context(), fixture.scope, candidateWire,
		managedPeerProgressSigner(fixture), managedPeerRecoveryRefresh(fixture, fixture.plan)); err != nil {
		t.Fatalf("pin candidate before completion: %v", err)
	}
	if _, err := fixture.ledger.RecordManagedPeer(t.Context(), fixture.scope,
		fixture.manifestWire, receiptWire, facts, resultWire, headWire,
		managedPeerProgressSigner(fixture), managedPeerRecoveryRefresh(fixture, fixture.plan)); err != nil {
		t.Fatalf("complete candidate before restart: %v", err)
	}

	fixture.client.setNow(fixture.selected.now.Add(6 * time.Minute))
	reopenManagedPeerFixtureLedger(t, &fixture, fixture.client)
	admitted, err := fixture.ledger.ReadSlot(t.Context(), fixture.scope)
	if err != nil {
		t.Fatalf("runtime ReadSlot() after final progress expiry: %v", err)
	}
	if admitted.quarantined || admitted.Head.ResultDigest != digestBytes(resultWire) ||
		admitted.ResultRecord == nil || !bytes.Equal(admitted.ResultRecord.Bytes, resultWire) ||
		admitted.Progress == nil || admitted.Progress.Sequence != 3 ||
		admitted.Progress.PendingProofDigest != admitted.Head.ResultDigest ||
		!bytes.Equal(admitted.Progress.PendingProofWire, resultWire) {
		t.Fatalf("runtime admission lost valid HEAD-bound terminal proof after restart: head=%+v progress=%+v quarantined=%t",
			admitted.Head, admitted.Progress, admitted.quarantined)
	}
	restarted := readAndAuthorizeManagedPeerRecovery(t, fixture, fixture.plan)
	if restarted.recovery.Phase() != ManagedPeerRecoveryComplete || restarted.recovery.State().quarantined {
		t.Fatalf("valid completed state after progress expiry = phase %q, quarantined %t; want complete and usable",
			restarted.recovery.Phase(), restarted.recovery.State().quarantined)
	}
	assertManagedPeerRecoveryBytes(t, restarted.recovery.State(), ManagedPeerRecoveryComplete,
		candidateWire, fixture.manifestWire, receiptWire, resultWire, headWire,
		ManagedPeerProgressResult, 3, "result", resultWire, true, true, true)

	putsBeforeReplay := fixture.client.putCalls.Load()
	replayed, err := fixture.ledger.RecordManagedPeer(t.Context(), fixture.scope,
		fixture.manifestWire, receiptWire, facts, resultWire, headWire,
		managedPeerProgressSigner(fixture), managedPeerRecoveryRefresh(fixture, fixture.plan))
	if err != nil {
		t.Fatalf("replay exact completed proof after restart: %v", err)
	}
	if replayed.Head.ResultDigest != digestBytes(resultWire) || fixture.client.putCalls.Load() != putsBeforeReplay {
		t.Fatalf("completed replay changed HEAD or wrote objects: head=%+v PUTs before=%d after=%d",
			replayed.Head, putsBeforeReplay, fixture.client.putCalls.Load())
	}
}

func TestManagedPeerRecoveryRefreshRejectsSupersededPlanBeforeNextWrite(t *testing.T) {
	fixture := newPlanBackedManagedPeerFixture(t, "")
	facts := fixture.facts("ocid1.instance.oc1.sa-saopaulo-1.superseded-plan")
	receiptWire := fixture.receiptBytes(t, facts)
	resultWire := fixture.resultBytes(t, facts, receiptWire)
	candidateWire := managedPeerCandidateWire(t, fixture, facts)
	headWire := managedPeerCompletedHeadAt(t, fixture, resultWire, candidateWire,
		fixture.selected.now, fixture.selected.now.Add(23*time.Hour))
	if err := fixture.ledger.RecordManagedPeerCandidate(t.Context(), fixture.scope, candidateWire,
		managedPeerProgressSigner(fixture), managedPeerRecoveryRefresh(fixture, fixture.plan)); err != nil {
		t.Fatalf("pin observed managed peer before superseding plan: %v", err)
	}

	supersedingPayload := cloneFounderPlan(fixture.selected.plan)
	supersedingPayload.LaunchDeadline = fixture.selected.now.Add(21 * time.Hour)
	supersedingWire := signFounderPlanWire(t, supersedingPayload, supersedingPayload.SeedSlot,
		fixture.selected.authority.rootPrivate, fixture.selected.now.Add(-time.Minute), fixture.selected.now.Add(23*time.Hour))
	supersedingPlan, err := VerifyFounderPlan(supersedingWire, fixture.selected.authority.roots,
		fixture.selected.anchorWire, fixture.selected.manifestWires, fixture.selected.now, fixture.selected.policy)
	if err != nil {
		t.Fatalf("verify a valid superseding plan: %v", err)
	}
	if supersedingPlan.Digest() == fixture.plan.Digest() {
		t.Fatal("superseding plan unexpectedly retained the original digest")
	}

	callbacks := 0
	refresh := func(ctx context.Context) (VerifiedFounderPeer, error) {
		callbacks++
		recovery, readErr := fixture.ledger.ReadForManagedPeerRecovery(ctx, fixture.scope)
		if readErr != nil {
			return VerifiedFounderPeer{}, readErr
		}
		selected := fixture.plan
		if callbacks > 1 {
			selected = supersedingPlan
		}
		return selected.AuthorizePeerRecovery(fixture.scope.Slot, recovery, fixture.selected.authority.roots,
			recovery.AuthorizationTime(), selected.envelope.ExpiresAt, fixture.selected.policy)
	}
	objectsBefore := fixture.client.objectCount()
	_, err = fixture.ledger.RecordManagedPeer(t.Context(), fixture.scope,
		fixture.manifestWire, receiptWire, facts, resultWire, headWire,
		managedPeerProgressSigner(fixture), refresh)
	if !errors.Is(err, ErrFounderPeerAuthorization) {
		t.Fatalf("plan supersession before receipt write = %v, want ErrFounderPeerAuthorization", err)
	}
	if callbacks != 2 {
		t.Fatalf("fresh selected-plan reads = %d, want one before manifest and one before receipt", callbacks)
	}
	if got := fixture.client.objectCount(); got != objectsBefore+1 {
		t.Fatalf("superseded plan wrote beyond its first authorized manifest: objects=%d before=%d", got, objectsBefore)
	}
	recovery, err := fixture.ledger.ReadForManagedPeerRecovery(t.Context(), fixture.scope)
	if err != nil || recovery.Phase() != ManagedPeerRecoveryCandidateOnly {
		t.Fatalf("superseded plan changed recovery state: phase=%q err=%v", recovery.Phase(), err)
	}
	state := recovery.State()
	if state.ManifestRecord == nil || !bytes.Equal(state.ManifestRecord.Bytes, fixture.manifestWire) ||
		state.PeerReceiptRecord != nil || state.ResultRecord != nil || state.Head.ResultDigest != "" {
		t.Fatalf("superseded plan left unexpected proof writes: %+v", state)
	}
}

func TestManagedPeerRecoveryRefreshRejectsReusedAuthorizationBeforeNextWrite(t *testing.T) {
	fixture := newPlanBackedManagedPeerFixture(t, "")
	facts := fixture.facts("ocid1.instance.oc1.sa-saopaulo-1.cached-recovery-read")
	receiptWire := fixture.receiptBytes(t, facts)
	resultWire := fixture.resultBytes(t, facts, receiptWire)
	candidateWire := managedPeerCandidateWire(t, fixture, facts)
	headWire := managedPeerCompletedHeadAt(t, fixture, resultWire, candidateWire,
		fixture.selected.now, fixture.selected.now.Add(23*time.Hour))
	if err := fixture.ledger.RecordManagedPeerCandidate(t.Context(), fixture.scope, candidateWire,
		managedPeerProgressSigner(fixture), managedPeerRecoveryRefresh(fixture, fixture.plan)); err != nil {
		t.Fatalf("pin observed managed peer before testing stale authorization: %v", err)
	}

	recovery, err := fixture.ledger.ReadForManagedPeerRecovery(t.Context(), fixture.scope)
	if err != nil {
		t.Fatalf("read initial recovery authorization: %v", err)
	}
	cached, err := fixture.plan.AuthorizePeerRecovery(fixture.scope.Slot, recovery,
		fixture.selected.authority.roots, recovery.AuthorizationTime(), fixture.plan.envelope.ExpiresAt,
		fixture.selected.policy)
	if err != nil {
		t.Fatalf("authorize initial recovery snapshot: %v", err)
	}
	callbacks := 0
	refresh := func(context.Context) (VerifiedFounderPeer, error) {
		callbacks++
		return cached, nil
	}
	objectsBefore := fixture.client.objectCount()
	_, err = fixture.ledger.RecordManagedPeer(t.Context(), fixture.scope,
		fixture.manifestWire, receiptWire, facts, resultWire, headWire,
		managedPeerProgressSigner(fixture), refresh)
	if !errors.Is(err, ErrRecordAuthorization) {
		t.Fatalf("reused recovery read before receipt write = %v, want ErrRecordAuthorization", err)
	}
	if callbacks != 2 {
		t.Fatalf("managed-peer refresh callbacks = %d, want one fresh read for each write", callbacks)
	}
	if got := fixture.client.objectCount(); got != objectsBefore+1 {
		t.Fatalf("reused authorization wrote beyond the first manifest: objects=%d before=%d", got, objectsBefore)
	}
	state, err := fixture.ledger.ReadForManagedPeerRecovery(t.Context(), fixture.scope)
	if err != nil || state.Phase() != ManagedPeerRecoveryCandidateOnly ||
		state.State().PeerReceiptRecord != nil {
		t.Fatalf("cached recovery token advanced beyond manifest-only: phase=%q err=%v", state.Phase(), err)
	}
}

func TestManagedPeerRecoveryClocksAndRetryBoundary(t *testing.T) {
	t.Run("authorization starts after raw OCI Date", func(t *testing.T) {
		fixture := newPlanBackedManagedPeerFixture(t, "")
		facts := fixture.facts("ocid1.instance.oc1.sa-saopaulo-1.clock-bound-peer")
		receiptWire := fixture.receiptBytes(t, facts)
		resultWire := fixture.resultBytes(t, facts, receiptWire)
		candidateWire := managedPeerCandidateWire(t, fixture, facts)
		headWire := managedPeerCompletedHeadAt(t, fixture, resultWire, candidateWire,
			fixture.selected.now, fixture.selected.now.Add(23*time.Hour))
		crashManagedPeerAfterCommittedPuts(t, &fixture, facts, candidateWire, 3, receiptWire, resultWire, headWire)
		fixture.client.setNow(fixture.selected.now.Add(time.Minute))
		recovery, err := fixture.ledger.ReadForManagedPeerRecovery(t.Context(), fixture.scope)
		if err != nil {
			t.Fatalf("read receipt-only recovery: %v", err)
		}
		if recovery.Phase() != ManagedPeerRecoveryReceiptOnly ||
			!recovery.AuthorizationTime().After(recovery.ServerDate()) {
			t.Fatalf("recovery clock = %s, OCI Date = %s, phase = %q", recovery.AuthorizationTime(),
				recovery.ServerDate(), recovery.Phase())
		}
		selectionExpiry := founderPlanWireExpiry(t, fixture.selected.planWire)
		if _, err := fixture.plan.AuthorizePeerRecovery(fixture.scope.Slot, recovery,
			fixture.selected.authority.roots, recovery.ServerDate(), recovery.AuthorizationTime(), fixture.selected.policy); !errors.Is(err, ErrFounderPlanExpired) {
			t.Fatalf("stale caller time bypassed selector expiry at conservative OCI time: %v", err)
		}
		peer, err := fixture.plan.AuthorizePeerRecovery(fixture.scope.Slot, recovery,
			fixture.selected.authority.roots, recovery.ServerDate(), selectionExpiry, fixture.selected.policy)
		if err != nil {
			t.Fatalf("authorization at conservative recovery time: %v", err)
		}
		if _, err := peer.LaunchRequest(recovery.AuthorizationTime()); !errors.Is(err, ErrFounderPeerAuthorization) {
			t.Fatalf("receipt-only launch request = %v, want ErrFounderPeerAuthorization", err)
		}
		observation, err := peer.ObservationRequest(recovery.AuthorizationTime())
		if err != nil || observation.InstanceOCID != facts.InstanceOCID {
			t.Fatalf("receipt-only observation = %+v, err=%v", observation, err)
		}
		if observation, err := peer.ObservationRequest(recovery.ServerDate()); err != nil || observation.InstanceOCID != facts.InstanceOCID {
			t.Fatalf("stale caller time was not raised to OCI authorization time: observation=%+v err=%v", observation, err)
		}
	})

	t.Run("later read consumes the remaining signed effect deadline", func(t *testing.T) {
		fixture := newPlanBackedManagedPeerFixture(t, "")
		facts := fixture.facts("ocid1.instance.oc1.sa-saopaulo-1.delayed-recovery")
		receiptWire := fixture.receiptBytes(t, facts)
		resultWire := fixture.resultBytes(t, facts, receiptWire)
		candidateWire := managedPeerCandidateWire(t, fixture, facts)
		headWire := managedPeerCompletedHeadAt(t, fixture, resultWire, candidateWire,
			fixture.selected.now, fixture.selected.now.Add(23*time.Hour))
		crashManagedPeerAfterCommittedPuts(t, &fixture, facts, candidateWire, 3, receiptWire, resultWire, headWire)
		readAt := fixture.plan.Plan().LaunchDeadline.Add(-time.Second)
		fixture.client.setNow(readAt)
		recovery, err := fixture.ledger.ReadForManagedPeerRecovery(t.Context(), fixture.scope)
		if err != nil {
			t.Fatalf("late recovery read: %v", err)
		}
		if recovery.AuthorizationTime().Before(fixture.plan.Plan().LaunchDeadline) {
			t.Fatalf("conservative recovery time %s did not reach deadline %s", recovery.AuthorizationTime(),
				fixture.plan.Plan().LaunchDeadline)
		}
		if _, err := fixture.plan.AuthorizePeerRecovery(fixture.scope.Slot, recovery,
			fixture.selected.authority.roots, recovery.AuthorizationTime(), founderPlanWireExpiry(t, fixture.selected.planWire),
			fixture.selected.policy); !errors.Is(err, ErrFounderPlanExpired) {
			t.Fatalf("authorization after delayed Date precision adjustment = %v, want ErrFounderPlanExpired", err)
		}
	})

	t.Run("selected authority expires during plan verification delay", func(t *testing.T) {
		fixture := newPlanBackedManagedPeerFixture(t, "")
		recovery, err := fixture.ledger.ReadForManagedPeerRecovery(t.Context(), fixture.scope)
		if err != nil {
			t.Fatalf("read recovery before selected-plan verification: %v", err)
		}
		selectedUntil := recovery.AuthorizationTime().Add(100 * time.Millisecond)
		time.Sleep(150 * time.Millisecond)
		if _, err := fixture.plan.AuthorizePeerRecovery(fixture.scope.Slot, recovery,
			fixture.selected.authority.roots, recovery.AuthorizationTime(), selectedUntil, fixture.selected.policy); !errors.Is(err, ErrFounderPlanExpired) {
			t.Fatalf("plan authorization after selected snapshot expiry = %v, want ErrFounderPlanExpired", err)
		}
	})

	t.Run("upper-bound clock cannot hide a stale lower-bound plan", func(t *testing.T) {
		fixture := newRetryBoundaryManagedPeerFixture(t)
		planIssuedAt := fixture.plan.envelope.IssuedAt
		fixture.client.setNow(planIssuedAt.Add(-time.Minute - 500*time.Millisecond))
		recovery, err := fixture.ledger.ReadForManagedPeerRecovery(t.Context(), fixture.scope)
		if err != nil {
			t.Fatalf("read recovery before selected-plan issue time: %v", err)
		}
		if planIssuedAt.Sub(recovery.AuthorizationTime()) > fixture.selected.policy.ClockSkew {
			t.Fatalf("upper clock %s remains outside plan clock skew from issue %s",
				recovery.AuthorizationTime(), planIssuedAt)
		}
		if _, err := VerifyFounderPlan(fixture.plan.wire, fixture.selected.authority.roots,
			fixture.selected.anchorWire, fixture.selected.manifestWires, recovery.AuthorizationTime(),
			fixture.selected.policy); err != nil {
			t.Fatalf("upper-bound verification should pass within clock skew: %v", err)
		}
		if _, err := fixture.plan.AuthorizePeerRecovery(fixture.scope.Slot, recovery,
			fixture.selected.authority.roots, recovery.AuthorizationTime(), fixture.plan.envelope.ExpiresAt,
			fixture.selected.policy); !errors.Is(err, ErrFounderPlanAuthorization) {
			t.Fatalf("stale lower-bound plan authorization = %v, want ErrFounderPlanAuthorization", err)
		}
	})

	t.Run("retry boundary is phase limited", func(t *testing.T) {
		for _, test := range []struct {
			name  string
			phase ManagedPeerRecoveryPhase
			puts  int
		}{
			{name: "clean", phase: ManagedPeerRecoveryClean},
			{name: "manifest-only", phase: ManagedPeerRecoveryManifestOnly},
			{name: "candidate-only", phase: ManagedPeerRecoveryCandidateOnly, puts: 1},
			{name: "receipt-only", phase: ManagedPeerRecoveryReceiptOnly, puts: 3},
			{name: "result-ready", phase: ManagedPeerRecoveryResultReady, puts: 5},
		} {
			t.Run(test.name, func(t *testing.T) {
				fixture := newRetryBoundaryManagedPeerFixture(t)
				facts := fixture.facts("ocid1.instance.oc1.sa-saopaulo-1.retry-boundary-peer")
				retryRead := fixture.selected.now.Add(maxRetryAge)
				var candidateWire, receiptWire, resultWire, headWire []byte
				if test.phase == ManagedPeerRecoveryManifestOnly {
					persistManagedPeerManifest(t, fixture, fixture.selected.now)
				}
				if test.phase == ManagedPeerRecoveryCandidateOnly || test.phase == ManagedPeerRecoveryReceiptOnly ||
					test.phase == ManagedPeerRecoveryResultReady {
					candidateWire = managedPeerCandidateWire(t, fixture, facts)
					if test.phase == ManagedPeerRecoveryCandidateOnly {
						fixture.client.setNow(fixture.plan.envelope.IssuedAt)
						crashManagedPeerCandidateAfterFirstPut(t, &fixture, candidateWire)
					}
				}
				if test.phase == ManagedPeerRecoveryReceiptOnly || test.phase == ManagedPeerRecoveryResultReady {
					proofTime := retryRead.Add(-time.Minute)
					receiptWire = managedPeerReceiptAt(t, fixture, facts, proofTime, proofTime.Add(5*time.Minute))
					resultWire = managedPeerResultAt(t, fixture, facts, receiptWire,
						proofTime, fixture.selected.now.Add(24*time.Hour))
					headWire = managedPeerCompletedHeadAt(t, fixture, resultWire, candidateWire,
						proofTime, fixture.selected.now.Add(24*time.Hour))
					fixture.client.setNow(proofTime)
					crashManagedPeerAfterCommittedPuts(t, &fixture, facts, candidateWire, test.puts,
						receiptWire, resultWire, headWire)
				}

				fixture.client.setNow(retryRead)
				recovery, err := fixture.ledger.ReadForManagedPeerRecovery(t.Context(), fixture.scope)
				if err != nil {
					t.Fatalf("read %s recovery at original retry boundary: %v", test.phase, err)
				}
				if recovery.Phase() != test.phase {
					t.Fatalf("phase at retry boundary = %q, want %q", recovery.Phase(), test.phase)
				}
				peer, authErr := fixture.plan.AuthorizePeerRecovery(fixture.scope.Slot, recovery,
					fixture.selected.authority.roots, recovery.AuthorizationTime(),
					founderPlanWireExpiry(t, fixture.selected.planWire), fixture.selected.policy)
				if test.phase == ManagedPeerRecoveryClean || test.phase == ManagedPeerRecoveryManifestOnly {
					if !errors.Is(authErr, ErrFounderPlanExpired) {
						t.Fatalf("%s authorization at retry boundary = %v, want ErrFounderPlanExpired", test.phase, authErr)
					}
					return
				}
				if authErr != nil {
					t.Fatalf("%s recovery authorization after retry expiry: %v", test.phase, authErr)
				}
				if _, err := peer.LaunchRequest(recovery.AuthorizationTime()); !errors.Is(err, ErrFounderPeerAuthorization) {
					t.Fatalf("%s launch request after retry expiry = %v, want ErrFounderPeerAuthorization", test.phase, err)
				}
				if test.phase == ManagedPeerRecoveryCandidateOnly || test.phase == ManagedPeerRecoveryReceiptOnly {
					observation, err := peer.ObservationRequest(recovery.AuthorizationTime())
					if err != nil || observation.InstanceOCID != facts.InstanceOCID {
						t.Fatalf("%s recovery observation after retry expiry = %+v, err=%v", test.phase, observation, err)
					}
					return
				}
				completed, err := fixture.ledger.RecordManagedPeer(t.Context(), fixture.scope,
					fixture.manifestWire, receiptWire, facts, resultWire, headWire,
					managedPeerProgressSigner(fixture), managedPeerRecoveryRefresh(fixture, fixture.plan))
				if err != nil {
					t.Fatalf("complete already persisted result after retry expiry: %v", err)
				}
				if completed.Head.ResultDigest != digestBytes(resultWire) || completed.Head.CandidateDigest != digestBytes(candidateWire) {
					t.Fatalf("result-ready recovery HEAD binding = %+v", completed.Head)
				}
			})
		}
	})
}

type authorizedManagedPeerRecovery struct {
	recovery ManagedPeerRecoveryAuthorization
	peer     VerifiedFounderPeer
}

func founderPlanWireExpiry(t *testing.T, wire []byte) time.Time {
	t.Helper()
	envelope, err := trust.DecodeEnvelope(wire)
	if err != nil {
		t.Fatalf("decode selected founder-plan envelope: %v", err)
	}
	return envelope.ExpiresAt
}

func readAndAuthorizeManagedPeerRecovery(
	t *testing.T,
	fixture planBackedManagedPeerFixture,
	plan VerifiedFounderPlan,
) authorizedManagedPeerRecovery {
	t.Helper()
	recovery, err := fixture.ledger.ReadForManagedPeerRecovery(t.Context(), fixture.scope)
	if err != nil {
		t.Fatalf("ReadForManagedPeerRecovery(): %v", err)
	}
	peer, err := plan.AuthorizePeerRecovery(fixture.scope.Slot, recovery, fixture.selected.authority.roots,
		recovery.AuthorizationTime(), plan.envelope.ExpiresAt, fixture.selected.policy)
	if err != nil {
		t.Fatalf("AuthorizePeerRecovery(%s): %v", recovery.Phase(), err)
	}
	return authorizedManagedPeerRecovery{recovery: recovery, peer: peer}
}

func managedPeerRecoveryRefresh(
	fixture planBackedManagedPeerFixture,
	plan VerifiedFounderPlan,
) ManagedPeerRecoveryRefresh {
	return func(ctx context.Context) (VerifiedFounderPeer, error) {
		recovery, err := fixture.ledger.ReadForManagedPeerRecovery(ctx, fixture.scope)
		if err != nil {
			return VerifiedFounderPeer{}, err
		}
		return plan.AuthorizePeerRecovery(fixture.scope.Slot, recovery, fixture.selected.authority.roots,
			recovery.AuthorizationTime(), plan.envelope.ExpiresAt, fixture.selected.policy)
	}
}

func assertManagedPeerRecoveryPermissions(
	t *testing.T,
	peer VerifiedFounderPeer,
	recovery ManagedPeerRecoveryAuthorization,
	instanceOCID string,
) {
	t.Helper()
	now := recovery.AuthorizationTime()
	_, launchErr := peer.LaunchRequest(now)
	if recovery.Phase() == ManagedPeerRecoveryClean || recovery.Phase() == ManagedPeerRecoveryManifestOnly {
		if launchErr != nil {
			t.Fatalf("%s LaunchRequest() = %v, want success", recovery.Phase(), launchErr)
		}
	} else if !errors.Is(launchErr, ErrFounderPeerAuthorization) {
		t.Fatalf("%s LaunchRequest() = %v, want ErrFounderPeerAuthorization", recovery.Phase(), launchErr)
	}

	observation, observationErr := peer.ObservationRequest(now)
	switch recovery.Phase() {
	case ManagedPeerRecoveryCandidateOnly, ManagedPeerRecoveryProofStaged,
		ManagedPeerRecoveryQuarantined, ManagedPeerRecoveryReceiptOnly:
		if observationErr != nil || observation.InstanceOCID != instanceOCID {
			t.Fatalf("%s ObservationRequest() = %+v, err=%v; want instance %q", recovery.Phase(),
				observation, observationErr, instanceOCID)
		}
	default:
		if !errors.Is(observationErr, ErrFounderPeerAuthorization) {
			t.Fatalf("%s ObservationRequest() = %v, want ErrFounderPeerAuthorization", recovery.Phase(), observationErr)
		}
	}
}

func assertManagedPeerRecoveryBytes(
	t *testing.T,
	state SlotState,
	phase ManagedPeerRecoveryPhase,
	candidateWire, manifestWire, receiptWire, resultWire, headWire []byte,
	progressPhase ManagedPeerProgressPhase,
	progressSequence uint64,
	pendingProofKind string,
	pendingProofWire []byte,
	manifestStored, receiptStored, resultStored bool,
) {
	t.Helper()
	candidateDigest := digestBytes(candidateWire)
	if state.Candidate == nil || state.CandidateRecord == nil ||
		!bytes.Equal(state.CandidateRecord.Bytes, candidateWire) || state.Head.SchemaVersion != 1 {
		t.Fatalf("%s phase lost the exact candidate/v1 HEAD identity: head=%+v candidate=%+v", phase, state.Head, state.Candidate)
	}
	if phase == ManagedPeerRecoveryComplete {
		if state.Head.CandidateDigest != candidateDigest {
			t.Fatalf("completed HEAD candidate digest = %s, want %s", state.Head.CandidateDigest, candidateDigest)
		}
	} else if state.Head.CandidateDigest != "" {
		t.Fatalf("unfinished %s HEAD prematurely binds candidate digest %q", phase, state.Head.CandidateDigest)
	}
	if (state.ManifestRecord != nil) != manifestStored ||
		manifestStored && !bytes.Equal(state.ManifestRecord.Bytes, manifestWire) {
		t.Fatalf("%s phase manifest presence/bytes differ from expectation: %+v", phase, state.ManifestRecord)
	}
	if (state.PeerReceiptRecord != nil) != receiptStored ||
		receiptStored && !bytes.Equal(state.PeerReceiptRecord.Bytes, receiptWire) {
		t.Fatalf("%s phase receipt presence/bytes differ from expectation: %+v", phase, state.PeerReceiptRecord)
	}
	if (state.ResultRecord != nil) != resultStored ||
		resultStored && !bytes.Equal(state.ResultRecord.Bytes, resultWire) {
		t.Fatalf("%s phase result presence/bytes differ from expectation: %+v", phase, state.ResultRecord)
	}
	if state.Progress == nil {
		t.Fatalf("%s phase has no signed progress record", phase)
	}
	progress := state.Progress
	if progress.CandidateDigest != candidateDigest || progress.Phase != progressPhase ||
		progress.Sequence != progressSequence ||
		progress.PendingProofKind != pendingProofKind ||
		!bytes.Equal(progress.PendingProofWire, pendingProofWire) ||
		(pendingProofKind == "") != (progress.PendingProofDigest == "") ||
		pendingProofKind != "" && progress.PendingProofDigest != digestBytes(pendingProofWire) {
		t.Fatalf("%s phase progress differs from exact pending proof expectation: progress=%+v", phase, progress)
	}
	if phase == ManagedPeerRecoveryComplete {
		if state.Head.ResultDigest != digestBytes(resultWire) || !bytes.Equal(state.HeadRecord.Bytes, headWire) {
			t.Fatalf("completed phase lost exact result/HEAD binding: head=%+v", state.Head)
		}
	} else if state.Head.ResultDigest != "" {
		t.Fatalf("unfinished %s phase unexpectedly has completed HEAD digest %q", phase, state.Head.ResultDigest)
	}
	if phase == ManagedPeerRecoveryProofStaged {
		if pendingProofKind == "" || len(pendingProofWire) == 0 {
			t.Fatalf("proof-staged phase lacks exact pending proof: kind=%q bytes=%d", pendingProofKind, len(pendingProofWire))
		}
	}
}

func assertManagedPeerProofAddressedByDigest(
	t *testing.T,
	client *fakeObjectStorageClient,
	namespace, bucket, digest string,
) {
	t.Helper()
	prefix := namespace + "\x00" + bucket + "\x00"
	client.mu.Lock()
	defer client.mu.Unlock()
	matches := 0
	for key := range client.objects {
		if strings.HasPrefix(key, prefix) && strings.Contains(key, digest) {
			matches++
		}
	}
	if matches != 1 {
		t.Fatalf("content-addressed proof %s has %d ledger object keys, want exactly one", digest, matches)
	}
}

func captureManagedPeerPanic(run func()) (recovered any) {
	defer func() { recovered = recover() }()
	run()
	return nil
}

func reopenManagedPeerFixtureLedger(
	t *testing.T,
	fixture *planBackedManagedPeerFixture,
	client ObjectStorageClient,
) {
	t.Helper()
	ledger, err := NewLedger(client, fixture.ledger.config)
	if err != nil {
		t.Fatalf("reopen ledger over the same object store: %v", err)
	}
	fixture.ledger = ledger
}

func newRetryBoundaryManagedPeerFixture(t *testing.T) planBackedManagedPeerFixture {
	t.Helper()
	selected := newFounderPlanFixture(t)
	validUntil := selected.now.Add(24 * time.Hour)
	for _, slot := range selected.plan.ControllerSlots {
		manifest := manifestFromWire(t, selected.manifestWires[slot], selected.authority.roots,
			selected.now, selected.policy)
		if manifest.PeerReceiptDelegation == nil {
			t.Fatalf("%s manifest has no peer receipt delegation", slot)
		}
		delegationEnvelope := *manifest.PeerReceiptDelegation
		delegationPayload, err := trust.VerifyCurrent(delegationEnvelope, delegationEnvelope.Scope,
			selected.authority.roots, selected.now, selected.policy)
		if err != nil {
			t.Fatalf("verify %s peer receipt delegation: %v", slot, err)
		}
		var delegation trust.Delegation
		if err := json.Unmarshal(delegationPayload, &delegation); err != nil {
			t.Fatalf("decode %s peer receipt delegation: %v", slot, err)
		}
		extendedDelegation, err := trust.SignDelegation(delegation, selected.now, validUntil,
			selected.authority.rootPrivate)
		if err != nil {
			t.Fatalf("extend %s peer receipt delegation: %v", slot, err)
		}
		manifest.PeerReceiptDelegation = &extendedDelegation
		manifestEnvelope, err := SignManifest(manifest, selected.now, validUntil, selected.authority.rootPrivate)
		if err != nil {
			t.Fatalf("extend %s manifest interval: %v", slot, err)
		}
		manifestWire, err := trust.EncodeEnvelope(manifestEnvelope)
		if err != nil {
			t.Fatalf("encode extended %s manifest: %v", slot, err)
		}
		manifestDigest, err := trust.Fingerprint(manifestEnvelope)
		if err != nil {
			t.Fatalf("fingerprint extended %s manifest: %v", slot, err)
		}
		selected.manifestWires[slot] = manifestWire
		if slot == selected.plan.SeedSlot {
			selected.plan.SeedManifestSHA256 = manifestDigest
		}
		if index := slices.IndexFunc(selected.plan.Peers, func(row FounderPeerRow) bool { return row.Slot == slot }); index >= 0 {
			selected.plan.Peers[index].ManifestSHA256 = manifestDigest
		}
	}
	// The intent is stored at selected.now. A plan selected an hour later has
	// its own signed 23-hour launch deadline, so tests can reach the original
	// intent's 23-hour retry boundary while the plan remains current.
	selected.plan.LaunchDeadline = selected.now.Add(23*time.Hour + 30*time.Minute)
	selected.planWire = signFounderPlanWire(t, selected.plan, selected.plan.SeedSlot,
		selected.authority.rootPrivate, selected.now.Add(time.Hour), validUntil)
	plan, err := VerifyFounderPlan(selected.planWire, selected.authority.roots, selected.anchorWire,
		selected.manifestWires, selected.now.Add(time.Hour), selected.policy)
	if err != nil {
		t.Fatalf("verify plan after its later selected-plan time: %v", err)
	}
	row := selected.plan.Peers[0]
	seedLaunch := selected.launchAuthorization(t, plan, row, "", "")

	client := newFakeObjectStorageClient()
	client.setNow(selected.now)
	anchor := selected.anchor.Anchor()
	ledgerGrant := signBootstrapLedgerGrant(t, selected.authority.rootPrivate, selected.authority.peerPublic,
		anchor.DeploymentID, anchor.Cell, anchor.Environment, anchor.ControllerSlots,
		selected.now, validUntil)
	verifiedGrant, err := trust.VerifyDelegationCurrent(ledgerGrant, selected.authority.roots,
		selected.now, selected.policy)
	if err != nil {
		t.Fatalf("verify long-window integrated ledger grant: %v", err)
	}
	config := LedgerConfig{
		DeploymentID: anchor.DeploymentID, Cell: anchor.Cell, ClusterID: anchor.ClusterID,
		InitialRegionIntentGeneration: anchor.InitialRegionIntentGeneration,
		InitialRegionIntentSHA256:     anchor.InitialRegionIntentSHA256,
		Namespace:                     anchor.StorageDomain.Namespace, Bucket: anchor.StorageDomain.LedgerBucket,
		KMSKeyID: anchor.StorageDomain.LedgerKMSKeyOCID, Prefix: anchor.StorageDomain.Prefix,
		HeadBucket: anchor.StorageDomain.HeadBucket, HeadKMSKeyID: anchor.StorageDomain.HeadKMSKeyOCID,
		Environment: anchor.Environment, ControllerSlots: append([]string(nil), anchor.ControllerSlots...),
		AnchorExpiresAt: selected.anchor.ExpiresAt(), TrustRoots: selected.authority.roots,
		Delegations: []trust.VerifiedDelegation{verifiedGrant}, TrustPolicy: selected.policy,
		VerificationNow: client.currentTime,
	}
	ledger, err := NewLedger(client, config)
	if err != nil {
		t.Fatalf("construct long-window integrated ledger: %v", err)
	}
	scope := BootstrapScope{DeploymentID: anchor.DeploymentID, Cell: string(anchor.Cell), Slot: row.Slot}
	intentWire := signManagedRecoveryWire(t, scope, anchor.Environment, domainBootstrapIntent,
		seedLaunch.intent, selected.now, validUntil, selected.authority.peerPrivate)
	head := seedLaunch.head
	head.IntentDigest = digestBytes(intentWire)
	headWire := signManagedRecoveryWire(t, scope, anchor.Environment, domainBootstrapHead,
		head, selected.now, validUntil, selected.authority.peerPrivate)
	if _, err := ledger.ReserveSlot(t.Context(), scope, intentWire, headWire); err != nil {
		t.Fatalf("reserve intent before the later plan issue time: %v", err)
	}
	launch, err := ledger.ReadForLaunch(t.Context(), scope)
	if err != nil {
		t.Fatalf("read long-window launch authorization: %v", err)
	}
	return planBackedManagedPeerFixture{
		selected: selected, plan: plan, client: client, ledger: ledger, scope: scope,
		row: cloneFounderPeerRow(row), launch: launch,
		manifestWire: bytes.Clone(selected.manifestWires[row.Slot]),
	}
}

func persistManagedPeerManifest(t *testing.T, fixture planBackedManagedPeerFixture, at time.Time) {
	t.Helper()
	fixture.client.setNow(at)
	if _, err := fixture.ledger.createOrRead(t.Context(), fixture.scope, 1, ledgerManifest, fixture.manifestWire); err != nil {
		t.Fatalf("persist manifest at %s: %v", at, err)
	}
}

func persistManagedPeerReceipt(t *testing.T, fixture planBackedManagedPeerFixture, wire []byte, at time.Time) {
	t.Helper()
	fixture.client.setNow(at)
	if _, err := fixture.ledger.createOrRead(t.Context(), fixture.scope, 1, ledgerPeerReceipt, wire); err != nil {
		t.Fatalf("persist peer receipt at %s: %v", at, err)
	}
}

func managedPeerReceiptAt(
	t *testing.T,
	fixture planBackedManagedPeerFixture,
	facts InstanceFacts,
	issuedAt, expiresAt time.Time,
) []byte {
	t.Helper()
	envelope, err := SignPeerReceipt(fixture.plan.manifests[fixture.scope.Slot], facts,
		issuedAt, expiresAt, fixture.selected.authority.peerPrivate)
	if err != nil {
		t.Fatalf("sign peer receipt for %s: %v", issuedAt, err)
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatalf("encode peer receipt for %s: %v", issuedAt, err)
	}
	return wire
}

func managedPeerResultAt(
	t *testing.T,
	fixture planBackedManagedPeerFixture,
	facts InstanceFacts,
	receiptWire []byte,
	issuedAt, expiresAt time.Time,
) []byte {
	t.Helper()
	intent := fixture.launch.intent
	result := Result{
		SchemaVersion: 1, Mode: IntentModeManaged, DeploymentID: intent.DeploymentID, Cell: intent.Cell,
		Environment: intent.Environment, Role: intent.Role, Slot: intent.Slot, Attempt: intent.Attempt,
		Generation: intent.Generation, RegionIntentGeneration: intent.RegionIntentGeneration,
		IntentDigest: fixture.launch.intentRecord.SHA256, InstanceOCID: facts.InstanceOCID,
		ProviderRequestID: "recovery-request", ETag: "recovery-etag", OCIRegion: intent.OCIRegion,
		CompartmentOCID: intent.CompartmentOCID, ImageOCID: intent.ImageOCID, Shape: intent.Shape,
		ObservedProfileDigest: intent.LaunchRequestDigest, PeerReceiptDigest: digestBytes(receiptWire),
		CreateKey: intent.CreateKey, ObservedAt: issuedAt,
	}
	return signManagedRecoveryWire(t, fixture.scope, intent.Environment, domainBootstrapResult,
		result, issuedAt, expiresAt, fixture.selected.authority.peerPrivate)
}

func managedPeerCompletedHeadAt(
	t *testing.T,
	fixture planBackedManagedPeerFixture,
	resultWire []byte,
	candidateWire []byte,
	issuedAt, expiresAt time.Time,
) []byte {
	t.Helper()
	head := fixture.launch.head
	head.SchemaVersion = 1
	head.CandidateDigest = digestBytes(candidateWire)
	head.ResultDigest = digestBytes(resultWire)
	return signManagedRecoveryWire(t, fixture.scope, fixture.launch.intent.Environment, domainBootstrapHead,
		head, issuedAt, expiresAt, fixture.selected.authority.peerPrivate)
}

func signManagedRecoveryWire(
	t *testing.T,
	scope BootstrapScope,
	environment, domain string,
	payload any,
	issuedAt, expiresAt time.Time,
	privateKey ed25519.PrivateKey,
) []byte {
	t.Helper()
	encoded, err := trust.EncodePayload(payload)
	if err != nil {
		t.Fatalf("encode %s payload: %v", domain, err)
	}
	envelope, err := trust.Sign(encoded, trust.Scope{
		Domain: domain, DeploymentID: scope.DeploymentID, Cell: scope.Cell,
		Environment: environment, Role: roleController, Slot: scope.Slot,
	}, issuedAt, expiresAt, privateKey)
	if err != nil {
		t.Fatalf("sign %s payload: %v", domain, err)
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatalf("encode %s envelope: %v", domain, err)
	}
	return wire
}
