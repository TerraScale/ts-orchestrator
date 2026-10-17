package placement

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func TestManagedUpdateR3PrepareHeldRestartReconciliation(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()

	broker, err := natscell.Start(ctx, natscell.Config{
		Cell: "gru", Instance: "managed-update-r3", Replicas: 1, Lab: true,
		Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: -1,
			StoreDir: filepath.Join(t.TempDir(), "nats")},
	})
	if err != nil {
		t.Fatalf("start embedded R3 NATS cell: %v", err)
	}
	t.Cleanup(func() { _ = broker.Close() })

	runtime, err := authority.Start(ctx, broker.JetStream(), authority.Config{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		Scope: "gru", CandidateID: "0000000000ZWGEDFHNGTFMNM86", Replicas: 1,
	})
	if err != nil {
		t.Fatalf("start R3 authority runtime: %v", err)
	}
	t.Cleanup(func() {
		closed := make(chan struct{})
		go func() {
			_ = runtime.Close()
			close(closed)
		}()
		select {
		case <-closed:
		case <-time.After(5 * time.Second):
			t.Error("close R3 authority runtime exceeded its cleanup deadline")
		}
	})
	snapshot := runtime.Current()
	if !snapshot.CanMutate() || snapshot.Epoch == 0 {
		t.Fatalf("R3 lab authority did not acquire a mutable lease: %+v", snapshot)
	}

	fixture := newManagedUpdateSeatOutcomeFixture(t)
	if fixture.controller.config.Cell != "gru" || fixture.controller.config.Region != oci.RegionGRU {
		t.Fatalf("managed update fixture is not bound to the lowercase gru cell: cell=%q region=%q",
			fixture.controller.config.Cell, fixture.controller.config.Region)
	}
	update, fakeAuthority := managedUpdateHistoryForFixture(t, &fixture, "", "")

	placementPayload, err := protocol.EncodeJSON(fixture.intent)
	if err != nil {
		t.Fatalf("encode committed placement intent: %v", err)
	}
	placementSequence, err := runtime.CommitPlacementIntent(ctx, snapshot.Epoch,
		fixture.intent.DatabaseID, fixture.intent.PartitionID, fixture.intent.OperationID(), 0, placementPayload)
	if err != nil || placementSequence == 0 {
		t.Fatalf("commit exact placement to R3: sequence=%d err=%v", placementSequence, err)
	}
	committedPlacement, err := runtime.ReadPlacementIntent(ctx, fixture.intent.DatabaseID, fixture.intent.PartitionID)
	if err != nil || committedPlacement.Sequence != placementSequence ||
		committedPlacement.SubjectKey != fixture.intent.DatabaseID+"."+fixture.intent.PartitionID {
		t.Fatalf("R3 placement identity = entry %+v err %v", committedPlacement, err)
	}

	// The fixture starts with a prepared candidate for terminal-phase unit tests.
	// Restore the canary's signed old serving predecessor before real Prepare.
	canary := fixture.canary
	preparedTarget := canary.State.ManagedRuntimeTarget
	canary.State.ManagedRuntimeTarget = ManagedRuntimeTarget{}
	canary.State.DesiredGeneration = preparedTarget.PreviousDesiredGeneration
	canary.State.Stage = StageServing
	canary.State.OperationID = memberOperationID(fixture.intent, canary.State.MemberID,
		canary.State.HostAttempt, "serving")
	canary.State.UpdatedAt = time.Now().UTC()
	fixture.canary = canary
	fixture.store.members[canary.State.MemberID] = canary

	controller := managedCanaryServingController(t, fixture, update, fakeAuthority)
	controller.fencer = runtime

	update.PlacementSequence = placementSequence
	update.AuthorityEpoch = snapshot.Epoch
	if err := update.Validate(); err != nil {
		t.Fatalf("validate R3-bound managed update request: %v", err)
	}
	prepared, signedKey := signedManagedUpdatePreparedRecord(t, update)
	if err := verifyManagedUpdatePreparedEnvelope(prepared, update, signedKey); err != nil {
		t.Fatalf("verify trusted operator Prepare signature: %v", err)
	}

	var preparedSequence uint64
	if err := awaitManagedUpdateCall(t, ctx, "PrepareManagedUpdate", func(callCtx context.Context) error {
		var prepareErr error
		preparedSequence, prepareErr = controller.PrepareManagedUpdate(callCtx, prepared)
		return prepareErr
	}); err != nil {
		t.Fatalf("PrepareManagedUpdate: %v", err)
	}
	if preparedSequence == 0 {
		t.Fatal("PrepareManagedUpdate returned an empty R3 receipt sequence")
	}
	preparedEntry, err := runtime.ReadManagedUpdate(ctx, update.DatabaseID, update.PartitionID)
	if err != nil || preparedEntry.Sequence != preparedSequence ||
		preparedEntry.OperationID != update.OperationID || preparedEntry.Epoch != snapshot.Epoch {
		t.Fatalf("R3 Prepare receipt = %+v err %v", preparedEntry, err)
	}
	var committedPrepare authority.ManagedUpdateRecord
	if err := json.Unmarshal(preparedEntry.Payload, &committedPrepare, json.RejectUnknownMembers(true)); err != nil ||
		!reflect.DeepEqual(committedPrepare, prepared) {
		t.Fatalf("R3 committed Prepare differs from the verified signed record: record=%+v err=%v", committedPrepare, err)
	}

	// Reconcile the durable Prepare into the canary seat. Tick exercises the
	// actual placement caller, including its authority guard and workload fence.
	if err := awaitManagedUpdateCall(t, ctx, "Prepared seat reconciliation", controller.Tick); err != nil {
		t.Fatalf("reconcile R3 Prepare: %v", err)
	}
	preparedSeat := fixture.store.members[canary.State.MemberID]
	if preparedSeat.State.Stage != StagePreparedDesired ||
		preparedSeat.State.ManagedRuntimeTarget.Phase != ManagedUpdateSeatPrepared ||
		preparedSeat.State.ManagedRuntimeTarget.AuthoritySequence != preparedSequence ||
		preparedSeat.State.ManagedRuntimeTarget.RequestSHA256 != prepared.SignedRequestSHA256 ||
		preparedSeat.State.ManagedRuntimeTarget.PlacementGeneration != update.PlacementGeneration ||
		preparedSeat.State.ManagedRuntimeTarget.PlacementPayloadDigest != update.PlacementPayloadDigest ||
		preparedSeat.State.ManagedRuntimeTarget.CanarySeatID != update.CanarySeatID {
		t.Fatalf("R3 Prepare did not persist the exact signed canary identity: %+v", preparedSeat.State)
	}
	preparedAt := preparedSeat.State.ManagedRuntimeTarget.PreparedAt
	if preparedAt.IsZero() || preparedAt.Location() != time.UTC {
		t.Fatalf("durable canary preparation time is not an absolute UTC deadline: %v", preparedAt)
	}

	// The read-only root path uses the same genuine R3 records and a real
	// member-state bucket, without constructing a Controller or authority writer.
	var onLeaseResponse func()
	var controlLastSequence uint64
	readJS, err := jetstream.New(broker.Conn(), jetstream.WithClientTrace(&jetstream.ClientTrace{
		ResponseReceived: func(subject string, payload []byte, _ nats.Header) {
			if onLeaseResponse == nil || subject != "$JS.API.STREAM.MSG.GET."+authority.ControlStreamName &&
				subject != "$JS.API.STREAM.INFO."+authority.ControlStreamName {
				return
			}
			var response struct {
				State struct {
					LastSequence uint64 `json:"last_seq"`
				} `json:"state"`
				Message struct {
					Subject  string `json:"subject"`
					Sequence uint64 `json:"seq"`
				} `json:"message"`
			}
			if err := json.Unmarshal(payload, &response); err != nil {
				t.Errorf("decode actual authority lease response: %v", err)
				return
			}
			if subject == "$JS.API.STREAM.INFO."+authority.ControlStreamName {
				controlLastSequence = response.State.LastSequence
				return
			}
			// currentLease retries a renewal newer than its preceding stream Info.
			if response.Message.Subject == protocol.Control(controller.config.Cell, "lease") &&
				response.Message.Sequence <= controlLastSequence {
				onLeaseResponse()
			}
		},
	}))
	if err != nil {
		t.Fatalf("trace genuine managed runtime authority: %v", err)
	}
	authorityReader, err := authority.OpenReader(ctx, readJS, controller.config.Cell)
	if err != nil {
		t.Fatalf("open read-only managed runtime authority: %v", err)
	}
	lease, err := authorityReader.AdmitCurrentLease(ctx, snapshot.DeploymentID, snapshot.CandidateID, snapshot.Epoch)
	if err != nil {
		t.Fatalf("admit actual managed runtime lease: %v", err)
	}
	intents, err := NewAuthorityIntentReader(authorityReader, controller.config.Cell, controller.config.Region)
	if err != nil {
		t.Fatalf("open actual runtime placement source: %v", err)
	}
	durableMembers, err := NewJetStreamStore(ctx, broker.JetStream(), controller.config.Cell, 1, intents)
	if err != nil {
		t.Fatalf("open genuine member state: %v", err)
	}
	memberRevision, err := durableMembers.CompareAndSwap(ctx, 0, preparedSeat.State)
	if err != nil || memberRevision == 0 {
		t.Fatalf("persist runtime target member: revision=%d err=%v", memberRevision, err)
	}
	memberPins, err := OpenMemberPinReader(ctx, broker.JetStream(), controller.config.Cell, 1)
	if err != nil {
		t.Fatalf("open exact runtime member pins: %v", err)
	}
	targetReader, err := NewManagedRuntimeTargetReader(ctx, controller.config, authorityReader, lease, memberPins)
	if err != nil {
		t.Fatalf("open readonly runtime target verifier: %v", err)
	}
	seat, exists := controller.seatForMember(fixture.intent, preparedSeat.State.Region, preparedSeat.State.MemberID)
	if !exists {
		t.Fatal("prepared runtime target seat is missing")
	}
	desired, err := controller.memberDesired(snapshot.Epoch, fixture.intent, preparedSeat.State, seat)
	if err != nil {
		t.Fatalf("derive exact prepared runtime desired: %v", err)
	}
	statuses, err := controller.hosts.ListHosts(ctx)
	if err != nil {
		t.Fatalf("read original registered runtime host: %v", err)
	}
	var registration host.Registration
	for _, status := range statuses {
		if status.Registration.Node == preparedSeat.State.HostNode {
			registration = status.Registration
		}
	}
	targetAdmission, updated, err := targetReader.Admit(ctx, desired, registration)
	if err != nil || !updated || targetAdmission == nil || targetAdmission.ArtifactPins() != (AdmittedArtifact{
		Digest: update.CandidateArtifactDigest, ManifestDigest: update.CandidateManifestDigest, SourceDigest: update.CandidateSourceDigest,
	}) {
		t.Fatalf("readonly actual runtime target pins = updated=%v admission=%v err=%v", updated, targetAdmission, err)
	}
	if targetAdmission.Guard(ctx) != nil {
		t.Fatal("unchanged genuine runtime target refused")
	}
	wrongEpoch := desired
	wrongEpoch.AuthorityEpoch++
	if _, _, err := targetReader.Admit(ctx, wrongEpoch, registration); err == nil {
		t.Fatal("readonly runtime verifier accepted another lease epoch")
	}
	original, stopOriginal := context.WithCancel(ctx)
	cancelledAdmission, _, err := targetReader.Admit(original, desired, registration)
	if err != nil {
		t.Fatalf("admit original-context runtime target: %v", err)
	}
	stopOriginal()
	if cancelledAdmission.Guard(ctx) == nil {
		t.Fatal("fresh context revived cancelled original runtime admission")
	}
	callerDeadline := time.Now().Add(time.Second)
	deadlineCaller, stopDeadline := context.WithDeadline(ctx, callerDeadline)
	defer stopDeadline()
	deadlineAdmission, _, err := targetReader.Admit(deadlineCaller, desired, registration)
	if err != nil || deadlineAdmission == nil || !deadlineAdmission.deadline.Equal(callerDeadline) {
		t.Fatalf("runtime admission did not retain its shorter caller deadline: admission=%v err=%v", deadlineAdmission, err)
	}
	<-deadlineCaller.Done()
	if deadlineAdmission.Guard(ctx) == nil {
		t.Fatal("fresh context revived expired original Admit caller")
	}
	if err := targetAdmission.Guard(ctx); err != nil {
		t.Fatalf("shorter independent caller changed the original live admission: %v", err)
	}
	for _, name := range []string{"cancel-final-guard-caller", "expire-shorter-final-guard-caller"} {
		t.Run(name, func(t *testing.T) {
			var caller context.Context
			var stopCaller context.CancelFunc
			if name == "cancel-final-guard-caller" {
				caller, stopCaller = context.WithCancel(ctx)
			} else {
				caller, stopCaller = context.WithTimeout(ctx, time.Second)
				if deadline, _ := caller.Deadline(); !deadline.Before(targetAdmission.deadline) {
					t.Fatal("Guard caller deadline did not narrow the original admission")
				}
			}
			defer stopCaller()
			delayed := &managedRuntimeGuardCaller{Context: caller, release: make(chan struct{}),
				started: make(chan struct{}), finished: make(chan struct{})}
			defer func() {
				onLeaseResponse = nil
				close(delayed.release)
				select {
				case <-delayed.started:
					select {
					case <-delayed.finished:
					case <-ctx.Done():
						t.Error("delayed caller propagation did not finish before root deadline")
					}
				default:
				}
			}()
			leaseResponses := 0
			onLeaseResponse = func() {
				leaseResponses++
				if leaseResponses != 2 {
					return
				}
				if caller.Err() != nil {
					t.Fatal("Guard caller expired before its final genuine lease response")
				}
				if name == "cancel-final-guard-caller" {
					stopCaller()
				}
				select {
				case <-delayed.started:
				case <-ctx.Done():
					t.Fatal("caller propagation did not reach its bounded scheduling barrier")
				}
			}
			guardErr := targetAdmission.Guard(delayed)
			if leaseResponses != 2 || caller.Err() == nil || guardErr == nil {
				t.Fatalf("Guard returned after final lease response with responses=%d caller=%v err=%v",
					leaseResponses, caller.Err(), guardErr)
			}
			select {
			case <-delayed.finished:
				t.Fatal("caller cancellation propagated before the synchronous return assertion")
			default:
			}
			if ctx.Err() != nil || !time.Now().Before(targetAdmission.deadline) {
				t.Fatal("final caller lifetime assertion consumed the original admission lifetime")
			}
		})
	}
	if err := targetAdmission.Guard(ctx); err != nil {
		t.Fatalf("final Guard caller expiration changed the original live admission: %v", err)
	}
	// Even identical bytes at a later real member revision replace the source.
	if _, err := durableMembers.CompareAndSwap(ctx, memberRevision, preparedSeat.State); err != nil {
		t.Fatalf("advance actual member revision: %v", err)
	}
	if targetAdmission.Guard(ctx) == nil {
		t.Fatal("runtime admission followed a replacement member revision")
	}
	targetAdmission, updated, err = targetReader.Admit(ctx, desired, registration)
	if err != nil || !updated || targetAdmission == nil {
		t.Fatalf("readmit exact current runtime revision: updated=%v err=%v", updated, err)
	}

	// Advance the controller's clock to the signed canary deadline. Inject a
	// seat CAS failure after R3 commits Held to model the crash window.
	timeoutAt := preparedAt.Add(managedUpdateCanaryProofTimeout)
	controller.now = func() time.Time { return timeoutAt }
	failedHeldCAS := false
	fixture.store.onCAS = func(next MemberState) error {
		if !failedHeldCAS && next.ManagedRuntimeTarget.Phase == ManagedUpdateSeatHeld {
			failedHeldCAS = true
			return ErrStoreConflict
		}
		return nil
	}
	heldErr := awaitManagedUpdateCall(t, ctx, "Held authority commit", controller.Tick)
	if !failedHeldCAS || !errors.Is(heldErr, ErrStoreConflict) {
		t.Fatalf("Held transition = err %v, injected CAS=%v; want R3 Held commit followed by lost seat CAS",
			heldErr, failedHeldCAS)
	}
	heldEntry, err := runtime.ReadManagedUpdate(ctx, update.DatabaseID, update.PartitionID)
	if err != nil || heldEntry.Sequence == preparedSequence || heldEntry.OperationID != update.OperationID {
		t.Fatalf("R3 Held receipt = %+v err %v", heldEntry, err)
	}
	if targetAdmission.Guard(ctx) == nil {
		t.Fatal("readonly material target admitted after genuine R3 Held before member CAS repair")
	}
	var held authority.ManagedUpdateRecord
	if err := json.Unmarshal(heldEntry.Payload, &held, json.RejectUnknownMembers(true)); err != nil ||
		held.Phase != authority.ManagedUpdateHeld || held.Outcome != "candidate-proof-timeout" ||
		!held.SameIdentity(prepared) {
		t.Fatalf("R3 Held phase did not retain the exact signed Prepare identity: record=%+v err=%v", held, err)
	}
	if current := fixture.store.members[canary.State.MemberID]; current.Revision != preparedSeat.Revision ||
		current.State.ManagedRuntimeTarget.Phase != ManagedUpdateSeatPrepared {
		t.Fatalf("injected lost CAS unexpectedly changed durable canary state: %+v", current)
	}

	// A fresh controller repairs the seat from retained R3 history. The signed
	// target pins, preparation time, placement, and untouched peer must survive.
	fixture.store.onCAS = nil
	restarted := &Controller{
		config: controller.config, store: fixture.store, fencer: runtime,
		fleet: controller.fleet, hosts: controller.hosts, desired: controller.desired,
		resolveArtifact: controller.resolveArtifact, now: controller.now,
	}
	if err := awaitManagedUpdateCall(t, ctx, "Held restart reconciliation", restarted.Tick); err != nil {
		t.Fatalf("reconcile retained R3 Held after restart: %v", err)
	}
	repaired := fixture.store.members[canary.State.MemberID]
	if repaired.State.Stage != preparedSeat.State.Stage ||
		repaired.State.ManagedRuntimeTarget.Phase != ManagedUpdateSeatHeld ||
		repaired.State.ManagedRuntimeTarget.Outcome != "candidate-proof-timeout" ||
		repaired.State.ManagedRuntimeTarget.OperationID != prepared.OperationID ||
		repaired.State.ManagedRuntimeTarget.AuthoritySequence != preparedSequence ||
		repaired.State.ManagedRuntimeTarget.RequestSHA256 != prepared.SignedRequestSHA256 ||
		repaired.State.ManagedRuntimeTarget.PlacementGeneration != update.PlacementGeneration ||
		repaired.State.ManagedRuntimeTarget.PlacementPayloadDigest != update.PlacementPayloadDigest ||
		repaired.State.ManagedRuntimeTarget.CanarySeatID != update.CanarySeatID ||
		repaired.State.ManagedRuntimeTarget.DesiredGeneration != update.CanaryDesiredGeneration ||
		repaired.State.ManagedRuntimeTarget.ArtifactDigest != update.CandidateArtifactDigest ||
		repaired.State.ManagedRuntimeTarget.ManifestDigest != update.CandidateManifestDigest ||
		repaired.State.ManagedRuntimeTarget.SourceDigest != update.CandidateSourceDigest ||
		!repaired.State.ManagedRuntimeTarget.PreparedAt.Equal(preparedAt) {
		t.Fatalf("restart did not repair exact Held seat pins: %+v", repaired.State)
	}
	if peer := fixture.store.members[fixture.peer.State.MemberID]; !reflect.DeepEqual(peer, fixture.peer) {
		t.Fatalf("managed update reconciliation changed its untouched peer: got %+v want %+v", peer, fixture.peer)
	}
	if !timeoutAt.Equal(preparedAt.Add(managedUpdateCanaryProofTimeout)) {
		t.Fatalf("test timeout clock did not reach the exact deadline: %v vs %v", timeoutAt,
			preparedAt.Add(managedUpdateCanaryProofTimeout))
	}
}

// Delay only the documented asynchronous AfterFunc callback; caller state stays real.
type managedRuntimeGuardCaller struct {
	context.Context
	release  chan struct{}
	started  chan struct{}
	finished chan struct{}
}

func (caller *managedRuntimeGuardCaller) Value(key any) any {
	// Prevent the embedded context's private cancellation state bypassing AfterFunc.
	return context.WithoutCancel(caller.Context).Value(key)
}

func (caller *managedRuntimeGuardCaller) AfterFunc(call func()) func() bool {
	return context.AfterFunc(caller.Context, func() {
		close(caller.started)
		<-caller.release
		call()
		close(caller.finished)
	})
}

func signedManagedUpdatePreparedRecord(t *testing.T, update ManagedUpdateIntent) (authority.ManagedUpdateRecord, ed25519.PublicKey) {
	t.Helper()
	requestPayload, err := protocol.EncodeJSON(update)
	if err != nil {
		t.Fatalf("encode signed managed update request: %v", err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate trusted operator signing key: %v", err)
	}
	now := time.Now().UTC()
	envelope, err := protocol.SignEnvelope(requestPayload, protocol.EnvelopeScope{
		Region: update.Cell, Kind: ManagedUpdateEnvelopeKind, Actor: "operator",
		OperationID: update.OperationID, Generation: update.CanaryDesiredGeneration, Epoch: update.AuthorityEpoch,
	}, now, now.Add(time.Minute), privateKey)
	if err != nil {
		t.Fatalf("sign managed update Prepare envelope: %v", err)
	}
	signedRequest, err := protocol.EncodeJSON(envelope)
	if err != nil {
		t.Fatalf("encode signed managed update envelope: %v", err)
	}
	requestDigest := sha256.Sum256(signedRequest)
	profileDigest, err := update.DurabilityProfile.Digest()
	if err != nil {
		t.Fatalf("digest managed update durability profile: %v", err)
	}
	prepared := authority.ManagedUpdateRecord{
		SchemaVersion: 1, Cell: update.Cell, DatabaseID: update.DatabaseID,
		PartitionID: update.PartitionID, OperationID: update.OperationID,
		Phase: authority.ManagedUpdatePrepared, SignedRequest: signedRequest,
		SignedRequestSHA256:    hex.EncodeToString(requestDigest[:]),
		PlacementGeneration:    update.PlacementGeneration,
		PlacementPayloadDigest: update.PlacementPayloadDigest,
		PlacementSequence:      update.PlacementSequence, CanarySeatID: update.CanarySeatID,
		CanaryDesiredGeneration: update.CanaryDesiredGeneration,
		OldArtifactDigest:       update.OldArtifactDigest,
		CandidateArtifactDigest: update.CandidateArtifactDigest,
		CandidateManifestDigest: update.CandidateManifestDigest,
		CandidateSourceDigest:   update.CandidateSourceDigest,
		DurabilityProfileSHA256: profileDigest,
	}
	if err := prepared.Validate(); err != nil {
		t.Fatalf("validate signed Prepare authority record: %v", err)
	}
	return prepared, publicKey
}

func verifyManagedUpdatePreparedEnvelope(record authority.ManagedUpdateRecord,
	update ManagedUpdateIntent, publicKey ed25519.PublicKey,
) error {
	var envelope protocol.Envelope
	if err := protocol.DecodeStrict(record.SignedRequest, &envelope, protocol.MaxPayloadBytes+4096); err != nil {
		return err
	}
	return protocol.VerifyEnvelope(envelope, protocol.EnvelopeScope{
		Region: update.Cell, Kind: ManagedUpdateEnvelopeKind, Actor: "operator",
		OperationID: update.OperationID, Generation: update.CanaryDesiredGeneration, Epoch: update.AuthorityEpoch,
	}, publicKey, time.Now().UTC(), protocol.VerifyPolicy{MaxLifetime: 2 * time.Minute})
}

func awaitManagedUpdateCall(t *testing.T, parent context.Context, name string,
	call func(context.Context) error,
) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- call(ctx) }()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		t.Fatalf("%s did not finish within its bounded deadline: %v", name, ctx.Err())
		return ctx.Err()
	}
}
