package app

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/delivery"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	staged "git.terrascale.tech/TerraScale/ts-orchestrator/internal/rollout"
	"github.com/nats-io/nats.go"
)

// fakeRolloutController replaces the placement controller behind the real
// cell's NATS subjects. Every Prepare passes the same signed-envelope,
// grant, independent compatibility and intent checks as controller
// admission, and must pin each seat exactly as the controller reports it;
// the canary then serves, or is held when it runs the failing candidate.
type fakeRolloutController struct {
	mu       sync.Mutex
	cell     *deployTestCellServices
	intent   placement.Intent
	sequence uint64
	seats    []*fakeRolloutSeat
	failing  string
	// failingSeat limits failing to one seat; failingToo fails anywhere.
	failingSeat string
	failingToo  string
	// restarting makes every promoted seat running it restart on each read.
	restarting string
	prepares   []placement.ManagedUpdateIntent
	rejected   []error
}

type fakeRolloutSeat struct {
	pins    placement.ManagedUpdateSeat
	update  *placementUpdateStatus
	serving bool
	pid     int
}

func TestTerraBaseUpdateRollsReleasesSeatBySeatAndRollsBackAHeldCandidate(t *testing.T) {
	cell := startDeployTestCell(t, true, true)
	ctx := t.Context()
	plan, state := writeDeployTestPlan(t, cell.root, 9465)
	runDeployTestOperator(t, ctx, cell, "terrabase-deploy", "--plan", plan, "--state", state)
	var intent placement.Intent
	var initial delivery.ArtifactRecord
	readDeployTestState(t, state, deployIntentFile, &intent)
	readDeployTestState(t, state, deployArtifactFile, &initial)
	fake := startFakeRolloutController(t, cell, intent)
	update := func(release terrabaseReleaseFiles) ([]string, error) {
		output, err := runDeployTestOperatorErr(ctx, cell, "terrabase-update", "--state", state,
			"--qualification", release.Qualification, "--binary", release.Binary, "--source-digest", release.SourceDigest,
			"--compatibility-actor", "compatibility", "--compatibility-key", cell.root+"/compatibility.key", "--wait", "30s", "--soak", "1s")
		var steps []string
		scanner := bufio.NewScanner(bytes.NewReader(output))
		for scanner.Scan() {
			var step terrabaseDeployStep
			if json.Unmarshal(scanner.Bytes(), &step) == nil {
				steps = append(steps, step.Step+":"+step.Status)
			}
		}
		return steps, err
	}

	second := writeDeployTestRelease(t, cell.root, "2")
	steps, err := update(second)
	if err != nil {
		t.Fatalf("release 2 rollout: %v (%v, rejected %v)", err, steps, fake.rejected)
	}
	if !slices.Equal(steps, []string{"artifact:admitted", "seat permanent-a:prepared", "seat permanent-a:canary-serving",
		"seat permanent-a:soaked", "seat elastic-gru:prepared", "seat elastic-gru:canary-serving", "rollout:complete"}) {
		t.Fatalf("release 2 steps = %v", steps)
	}
	r2 := fake.prepares[0].CandidateArtifactDigest
	if len(fake.prepares) != 2 || fake.prepares[0].OldArtifactDigest != initial.Digest ||
		fake.prepares[1].CanarySeatID != "elastic-gru" ||
		fake.prepares[1].Seats[1].SeatID != "permanent-a" || fake.prepares[1].Seats[1].ArtifactDigest != r2 {
		t.Fatalf("release 2 was not rolled canary then peer: %+v", fake.prepares)
	}
	if steps, err := update(second); err != nil || !slices.Equal(steps, []string{"artifact:admitted", "rollout:complete"}) ||
		len(fake.prepares) != 2 {
		t.Fatalf("rerun of a completed rollout acted again: %v %v", steps, err)
	}

	third := writeDeployTestRelease(t, cell.root, "3")
	r3, _, err := digestReleaseBinary(third.Binary)
	if err != nil {
		t.Fatal(err)
	}
	fake.failing = r3
	steps, err = update(third)
	if err == nil || !strings.Contains(err.Error(), "held on seat permanent-a") {
		t.Fatalf("a failing candidate did not stop the rollout: %v %v", steps, err)
	}
	last := fake.prepares[len(fake.prepares)-1]
	if len(fake.prepares) != 4 || last.CanarySeatID != "permanent-a" || last.OldArtifactDigest != r3 ||
		last.CandidateArtifactDigest != r2 || fake.seats[1].pins.ArtifactDigest != r2 || !fake.seats[1].serving {
		t.Fatalf("held candidate was not rolled back with its peer untouched: %+v", fake.prepares)
	}
	if fake.seats[0].pins.ArtifactDigest != r2 || !fake.seats[0].serving || len(fake.rejected) != 0 {
		t.Fatalf("rolled back seat does not serve release 2: %+v rejected %v", fake.seats[0], fake.rejected)
	}
	var knownBad staged.KnownBad
	readDeployTestState(t, state, filepath.Join(deployKnownBadDirectory, r3+".json"), &knownBad)
	if knownBad.Digest != r3 || knownBad.SeatID != "permanent-a" || !strings.Contains(knownBad.Reason, "held") {
		t.Fatalf("held candidate was not recorded known bad: %+v", knownBad)
	}
	fake.failing = ""
	if steps, err := update(third); err == nil || !strings.Contains(err.Error(), "known bad") || len(fake.prepares) != 4 {
		t.Fatalf("a known-bad candidate was retried: %v %v", steps, err)
	}

	// Compatibility evidence is derived from both releases, never assumed.
	if steps, err := update(writeDeployTestRelease(t, cell.root, "format-break-6")); err == nil ||
		!strings.Contains(err.Error(), "not compatible") || len(fake.prepares) != 4 {
		t.Fatalf("an incompatible persistent format was certified: %v %v", steps, err)
	}
	if steps, err := update(writeDeployTestRelease(t, cell.root, "no-compat-7")); err == nil ||
		!errors.Is(err, staged.ErrNoCompatibilityData) || len(fake.prepares) != 4 {
		t.Fatalf("a release without compatibility data was certified: %v %v", steps, err)
	}

	// A hold on the second seat rolls back both seats, newest first, so the
	// pair never stays mixed on the failed candidate.
	fourth := writeDeployTestRelease(t, cell.root, "4")
	r4, _, err := digestReleaseBinary(fourth.Binary)
	if err != nil {
		t.Fatal(err)
	}
	fake.failing, fake.failingSeat = r4, "elastic-gru"
	steps, err = update(fourth)
	if err == nil || !strings.Contains(err.Error(), "held on seat elastic-gru") {
		t.Fatalf("second-seat hold did not stop the rollout: %v %v", steps, err)
	}
	reverts := fake.prepares[4:]
	if len(reverts) != 4 || reverts[2].CanarySeatID != "elastic-gru" || reverts[2].CandidateArtifactDigest != r2 ||
		reverts[3].CanarySeatID != "permanent-a" || reverts[3].OldArtifactDigest != r4 || reverts[3].CandidateArtifactDigest != r2 {
		t.Fatalf("both seats were not returned to release 2: %+v", reverts)
	}
	for _, seat := range fake.seats {
		if seat.pins.ArtifactDigest != r2 || !seat.serving {
			t.Fatalf("pair left mixed after a second-seat hold: %+v", fake.seats)
		}
	}

	// A rollback that is itself held must never return the seat to the
	// known-bad candidate, on this run or any rerun.
	fifth := writeDeployTestRelease(t, cell.root, "5")
	r5, _, err := digestReleaseBinary(fifth.Binary)
	if err != nil {
		t.Fatal(err)
	}
	fake.failing, fake.failingSeat, fake.failingToo = r5, "", r2
	started := len(fake.prepares)
	steps, err = update(fifth)
	if err == nil || !strings.Contains(err.Error(), "instead of serving") {
		t.Fatalf("a held rollback was reported as rolled back: %v %v", steps, err)
	}
	before := len(fake.prepares)
	if attempt := fake.prepares[started:]; len(attempt) != 2 || attempt[0].CandidateArtifactDigest != r5 ||
		attempt[1].OldArtifactDigest != r5 || attempt[1].CandidateArtifactDigest != r2 {
		t.Fatalf("release 5 was not one canary and one rollback: %+v", attempt)
	}
	for range 2 {
		if steps, err := update(fifth); err == nil || !strings.Contains(err.Error(), "frozen") {
			t.Fatalf("rerun after a held rollback did not stay frozen: %v %v", steps, err)
		}
	}
	if len(fake.prepares) != before {
		t.Fatalf("rerun after a held rollback flipped the seat again: %+v", fake.prepares[before:])
	}
}

func TestTerraBaseUpdateSoaksTheFirstSeatAndRollsBackARestartingCandidate(t *testing.T) {
	cell := startDeployTestCell(t, true, true)
	ctx := t.Context()
	plan, state := writeDeployTestPlan(t, cell.root, 9465)
	runDeployTestOperator(t, ctx, cell, "terrabase-deploy", "--plan", plan, "--state", state)
	var intent placement.Intent
	var initial delivery.ArtifactRecord
	readDeployTestState(t, state, deployIntentFile, &intent)
	readDeployTestState(t, state, deployArtifactFile, &initial)
	fake := startFakeRolloutController(t, cell, intent)
	for _, seat := range fake.seats {
		seat.pid = 100
	}
	second := writeDeployTestRelease(t, cell.root, "2")
	r2, _, err := digestReleaseBinary(second.Binary)
	if err != nil {
		t.Fatal(err)
	}
	fake.restarting = r2
	_, err = runDeployTestOperatorErr(ctx, cell, "terrabase-update", "--state", state,
		"--qualification", second.Qualification, "--binary", second.Binary, "--source-digest", second.SourceDigest,
		"--compatibility-actor", "compatibility", "--compatibility-key", cell.root+"/compatibility.key",
		"--wait", "30s", "--soak", "30s")
	if err == nil || !strings.Contains(err.Error(), "failed its soak") {
		t.Fatalf("a restarting canary passed its soak: %v", err)
	}
	if len(fake.prepares) != 2 || fake.prepares[0].CanarySeatID != "permanent-a" ||
		fake.prepares[1].CanarySeatID != "permanent-a" || fake.prepares[1].CandidateArtifactDigest != initial.Digest {
		t.Fatalf("soak failure reached the second seat or was not rolled back: %+v", fake.prepares)
	}
	for _, seat := range fake.seats {
		if seat.pins.ArtifactDigest != initial.Digest || !seat.serving {
			t.Fatalf("pair not restored after a failed soak: %+v", fake.seats)
		}
	}
	var knownBad staged.KnownBad
	readDeployTestState(t, state, filepath.Join(deployKnownBadDirectory, r2+".json"), &knownBad)
	if !strings.Contains(knownBad.Reason, "restarted") {
		t.Fatalf("soak failure not recorded known bad: %+v", knownBad)
	}
}

func startFakeRolloutController(t *testing.T, cell *deployTestCellServices, intent placement.Intent) *fakeRolloutController {
	t.Helper()
	entry, err := cell.control.ReadPlacementIntent(t.Context(), intent.DatabaseID, intent.PartitionID)
	if err != nil {
		t.Fatal(err)
	}
	if err := cell.status.Unsubscribe(); err != nil {
		t.Fatal(err)
	}
	fake := &fakeRolloutController{cell: cell, intent: intent, sequence: entry.Sequence}
	for _, row := range intent.CanonicalRoster.Rows {
		manifest, err := intent.RuntimeManifestForSeat(placement.Seat{MemberID: row.SeatID, Region: row.Region})
		if err != nil {
			t.Fatal(err)
		}
		digest, err := manifest.Digest()
		if err != nil {
			t.Fatal(err)
		}
		fake.seats = append(fake.seats, &fakeRolloutSeat{serving: true, pins: placement.ManagedUpdateSeat{
			SeatID: row.SeatID, Region: row.Region, MemberID: row.MemberID, Incarnation: row.Incarnation,
			TLSLeafSHA256: row.TLSLeafSHA256, RuntimeManifestDigest: digest, HostNode: "host-" + row.SeatID,
			HostGeneration: 1, HostAttempt: 1, OCIInstanceID: "ocid1.instance.oc1..fake-" + row.SeatID,
			OCIOwner: deployTestOwner, OCIFleetGeneration: 1, CreateKey: "th-" + row.SeatID,
			VolumeID: "ocid1.volume.oc1..fake-" + row.SeatID, AttachmentID: "ocid1.volumeattachment.oc1..fake-" + row.SeatID,
			AttachmentETag: "etag", AttachmentDevice: "/dev/oracleoci/oraclevdb", DesiredGeneration: 1,
			ArtifactDigest: manifest.ArtifactDigest}})
	}
	fake.serve(t)
	return fake
}

func (fake *fakeRolloutController) serve(t *testing.T) {
	t.Helper()
	ctx := t.Context()
	conn := fake.cell.broker.Conn()
	status, err := serveManagedAdmissionKind(ctx, conn, deployTestCell, managedKindPlacementStatus,
		func(_ context.Context, message *nats.Msg) {
			if wire, err := fake.status(message.Data); err == nil {
				_ = message.Respond(wire)
			}
		})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = status.Unsubscribe() })
	prepare, err := conn.Subscribe(managedUpdatePrepareSubject(deployTestCell), func(message *nats.Msg) {
		response, err := fake.prepare(message.Data)
		if err != nil {
			fake.mu.Lock()
			fake.rejected = append(fake.rejected, err)
			fake.mu.Unlock()
			response = managedUpdatePrepareResponse{Error: err.Error()}
		}
		if wire, err := json.Marshal(response); err == nil {
			_ = message.Respond(wire)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = prepare.Unsubscribe() })
	if err := conn.Flush(); err != nil {
		t.Fatal(err)
	}
}

func (fake *fakeRolloutController) prepare(wire []byte) (managedUpdatePrepareResponse, error) {
	var envelope protocol.Envelope
	if err := protocol.DecodeStrict(wire, &envelope, managedUpdateRequestMaxBytes); err != nil {
		return managedUpdatePrepareResponse{}, err
	}
	var intent placement.ManagedUpdateIntent
	if err := protocol.DecodeStrict(envelope.Payload, &intent, protocol.MaxPayloadBytes); err != nil {
		return managedUpdatePrepareResponse{}, err
	}
	if err := intent.Validate(); err != nil {
		return managedUpdatePrepareResponse{}, err
	}
	grant, exists := fake.cell.policy.grants[envelope.Actor]
	trusted, known := fake.cell.policy.codec.Trusted[envelope.KeyID]
	if !exists || !grant.CanUpdateTerraBaseRuntime || !known || trusted.Actor != envelope.Actor ||
		protocol.VerifyEnvelope(envelope, protocol.EnvelopeScope{Region: deployTestCell,
			Kind: placement.ManagedUpdateEnvelopeKind, Actor: trusted.Actor, OperationID: intent.OperationID,
			Generation: intent.CanaryDesiredGeneration, Epoch: intent.AuthorityEpoch}, trusted.PublicKey, time.Now().UTC(),
			protocol.VerifyPolicy{MaxLifetime: 5 * time.Minute, ClockSkew: 30 * time.Second}) != nil {
		return managedUpdatePrepareResponse{}, errors.New("managed update signature or grant rejected")
	}
	if err := verifyManagedCompatibility(intent, envelope, fake.cell.policy); err != nil {
		return managedUpdatePrepareResponse{}, err
	}
	payload, err := protocol.EncodeJSON(fake.intent)
	if err != nil {
		return managedUpdatePrepareResponse{}, err
	}
	decoded, err := placement.DecodeCommittedIntent(payload)
	if err != nil || intent.PlacementPayloadDigest != decoded.PayloadDigest() || intent.PlacementSequence != fake.sequence ||
		intent.Environment != "canary" || intent.DurabilityProfile.Region != oci.RegionGRU {
		return managedUpdatePrepareResponse{}, errors.New("managed update does not pin the admitted placement")
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	var canary *fakeRolloutSeat
	for index, seat := range fake.seats {
		if !slices.ContainsFunc(intent.Seats, func(pin placement.ManagedUpdateSeat) bool { return pin == seat.pins }) {
			return managedUpdatePrepareResponse{}, errors.New("managed update seat pins differ from the durable seat")
		}
		if seat.pins.SeatID == intent.CanarySeatID {
			canary = fake.seats[index]
		} else if !seat.serving {
			return managedUpdatePrepareResponse{}, errors.New("peer is not serving")
		}
	}
	rollback := canary != nil && canary.update != nil && canary.update.Phase == updateHeldPhase &&
		intent.CandidateArtifactDigest == canary.update.PreviousArtifactDigest
	if canary == nil || canary.pins.ArtifactDigest != intent.OldArtifactDigest || !canary.serving && !rollback {
		return managedUpdatePrepareResponse{}, errors.New("canary is not at its signed serving predecessor")
	}
	fake.prepares = append(fake.prepares, intent)
	canary.update = &placementUpdateStatus{OperationID: intent.OperationID, ArtifactDigest: intent.CandidateArtifactDigest,
		SourceDigest: intent.CandidateSourceDigest, PreviousArtifactDigest: intent.OldArtifactDigest,
		Phase: updatePreparedPhase}
	canary.pins.ArtifactDigest, canary.pins.DesiredGeneration = intent.CandidateArtifactDigest, intent.CanaryDesiredGeneration
	canary.serving = false
	return managedUpdatePrepareResponse{DatabaseID: intent.DatabaseID, PartitionID: intent.PartitionID,
		OperationID: intent.OperationID, Phase: string(authority.ManagedUpdatePrepared), Sequence: uint64(100 + len(fake.prepares))}, nil
}

// status completes each prepared canary, then reports the seats signed with
// the controller response key.
func (fake *fakeRolloutController) status(wire []byte) ([]byte, error) {
	var envelope protocol.Envelope
	if err := protocol.DecodeStrict(wire, &envelope, maxPlacementStatusRequestBytes+4096); err != nil {
		return nil, err
	}
	var request placementStatusRequest
	if err := protocol.DecodeStrict(envelope.Payload, &request, maxPlacementStatusRequestBytes); err != nil {
		return nil, err
	}
	payload, err := protocol.EncodeJSON(fake.intent)
	if err != nil {
		return nil, err
	}
	decoded, err := placement.DecodeCommittedIntent(payload)
	if err != nil {
		return nil, err
	}
	fake.mu.Lock()
	report := placementStatusReport{Cell: deployTestCell, DatabaseID: request.DatabaseID, PartitionID: request.PartitionID,
		Nonce: request.Nonce, ObservedAt: time.Now().UTC(), AuthorityEpoch: envelope.Epoch,
		Generation: fake.intent.Generation, PayloadSHA256: decoded.PayloadDigest(), Sequence: fake.sequence, Serving: true}
	for _, seat := range fake.seats {
		if seat.update != nil && seat.update.Phase == updatePreparedPhase {
			failing := seat.update.ArtifactDigest == fake.failing &&
				(fake.failingSeat == "" || fake.failingSeat == seat.pins.SeatID) ||
				seat.update.ArtifactDigest == fake.failingToo
			if failing {
				seat.update.Phase, seat.update.Outcome = updateHeldPhase, "candidate-proof-timeout"
			} else {
				seat.update.Phase, seat.update.Outcome = string(placement.ManagedUpdateSeatCanaryServing), "canary-serving"
				seat.serving = true
			}
		}
		if seat.update != nil && seat.update.ArtifactDigest == fake.restarting &&
			seat.update.Phase == string(placement.ManagedUpdateSeatCanaryServing) {
			seat.pid++
		}
		stage := string(placement.StageServing)
		if !seat.serving {
			stage = string(placement.StageAwaitingHealthy)
		}
		pins := seat.pins
		member := placementMemberStatus{SeatID: pins.SeatID, MemberID: pins.MemberID, Stage: stage,
			ArtifactDigest: pins.ArtifactDigest, DesiredGeneration: pins.DesiredGeneration, UpdatePins: &pins}
		if seat.update != nil {
			update := *seat.update
			member.Update = &update
		}
		if seat.pid != 0 {
			member.Host = &placementHostStatus{ProcessPID: seat.pid}
		}
		report.Serving = report.Serving && seat.serving
		report.Members = append(report.Members, member)
	}
	fake.mu.Unlock()
	reportWire, err := protocol.EncodeJSON(report)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	signed, err := protocol.SignEnvelope(reportWire, protocol.EnvelopeScope{Region: deployTestCell,
		Kind: placementStatusReplyKind, Actor: "controller", OperationID: "status-" + request.Nonce,
		Generation: 1, Epoch: envelope.Epoch}, now, now.Add(time.Minute), fake.cell.controllerKey)
	if err != nil {
		return nil, err
	}
	return protocol.EncodeJSON(signed)
}
