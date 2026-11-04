package bootstrap

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
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
		{name: "receipt-stage", puts: 2, phase: ManagedPeerRecoveryProofStaged,
			progressPhase: ManagedPeerProgressReceipt, progressSequence: 2, pendingProofKind: "receipt", manifestStored: true},
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

type authorizedManagedPeerRecovery struct {
	recovery ManagedPeerRecoveryAuthorization
	peer     VerifiedFounderPeer
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
