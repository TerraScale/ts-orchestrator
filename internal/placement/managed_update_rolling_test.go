package placement

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

// rollingTestHosts keeps one desired target per node, as the host controller
// does, and lets the test publish each seat's current serving report.
type rollingTestHosts struct {
	*placementTestHosts
}

func (hosts rollingTestHosts) ApplyDesired(_ context.Context, desired host.Desired) (host.Receipt, error) {
	hosts.desiredWrites++
	hosts.desired = slices.DeleteFunc(hosts.desired, func(existing host.Desired) bool { return existing.Node == desired.Node })
	hosts.desired = append(hosts.desired, desired)
	return host.Receipt{Generation: desired.Generation, Revision: uint64(hosts.desiredWrites)}, nil
}

// fakeKnownBad is a fixed cell known-bad list.
type fakeKnownBad struct {
	bad map[string]bool
	err error
}

func (list fakeKnownBad) IsKnownBad(_ context.Context, digest string) (bool, error) {
	return list.bad[digest], list.err
}

// A release reaches both seats as two chained operations; the next release
// replaces a completed target; a candidate that never serves is held with its
// peer still serving, and a rollback operation restores the replaced artifact.
func TestManagedUpdateR3RollsReleasesAcrossSeatsAndRollsBackHeldCanary(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	broker, err := natscell.Start(ctx, natscell.Config{Cell: "gru", Instance: "managed-update-rolling", Replicas: 1,
		Lab: true, Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: -1, StoreDir: filepath.Join(t.TempDir(), "nats")}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = broker.Close() })
	runtime, err := authority.Start(ctx, broker.JetStream(), authority.Config{Scope: "gru",
		CandidateID: "0000000000D210JQZHC3BEWXCN", Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	epoch := runtime.Current().Epoch

	fixture := newManagedUpdateSeatOutcomeFixture(t)
	first, fakeAuthority := managedUpdateHistoryForFixture(t, &fixture, "", "")
	canary := fixture.canary
	target := canary.State.ManagedRuntimeTarget
	canary.State.ManagedRuntimeTarget = ManagedRuntimeTarget{}
	canary.State.DesiredGeneration = target.PreviousDesiredGeneration
	canary.State.Stage = StageServing
	canary.State.UpdatedAt = time.Now().UTC()
	fixture.canary = canary
	fixture.store.members[canary.State.MemberID] = canary
	placementPayload, err := protocol.EncodeJSON(fixture.intent)
	if err != nil {
		t.Fatal(err)
	}
	placementSequence, err := runtime.CommitPlacementIntent(ctx, epoch, fixture.intent.DatabaseID,
		fixture.intent.PartitionID, fixture.intent.OperationID(), 0, placementPayload)
	if err != nil {
		t.Fatal(err)
	}
	controller := managedCanaryServingController(t, fixture, first, fakeAuthority)
	controller.fencer = runtime
	hosts := rollingTestHosts{controller.hosts.(*placementTestHosts)}
	controller.hosts, controller.desired = hosts, hosts

	r1 := AdmittedArtifact{Digest: canary.State.RuntimeManifest.ArtifactDigest,
		ManifestDigest: strings.Repeat("6", 64), SourceDigest: canary.State.RuntimeManifest.SourceDigest}
	r2 := AdmittedArtifact{Digest: strings.Repeat("f", 64), ManifestDigest: strings.Repeat("1", 64),
		SourceDigest: strings.Repeat("2", 64)}
	r3 := AdmittedArtifact{Digest: strings.Repeat("7", 64), ManifestDigest: strings.Repeat("8", 64),
		SourceDigest: strings.Repeat("9", 64)}
	admitted := map[string]AdmittedArtifact{r1.Digest: r1, r2.Digest: r2, r3.Digest: r3}
	controller.resolveArtifact = func(_ context.Context, digest, _, _ string) (AdmittedArtifact, error) {
		artifact, exists := admitted[digest]
		if !exists {
			return AdmittedArtifact{}, errors.New("artifact is not admitted")
		}
		return artifact, nil
	}
	seat := func(id string) MemberState { return fixture.store.members[id].State }
	publishReports := func() {
		t.Helper()
		for index := range hosts.statuses {
			for _, id := range []string{canary.State.MemberID, fixture.peer.State.MemberID} {
				if state := seat(id); state.HostNode == hosts.statuses[index].Registration.Node {
					hosts.statuses[index].Reports = []host.Report{managedCanaryServingReport(t, controller,
						fixture.intent, state, hosts.statuses[index])}
				}
			}
		}
	}
	tick := func(name string) {
		t.Helper()
		if err := awaitManagedUpdateCall(t, ctx, name, controller.Tick); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	prepare := func(operation, canarySeat string, old, candidate AdmittedArtifact) {
		t.Helper()
		update := rollingManagedUpdate(t, fixture, controller, placementSequence, epoch, operation, canarySeat, old, candidate)
		record, _ := signedManagedUpdatePreparedRecord(t, update)
		if _, err := controller.PrepareManagedUpdate(ctx, record); err != nil {
			t.Fatalf("prepare %s: %v", operation, err)
		}
		tick(operation + " target")
		tick(operation + " desired")
		if state := seat(canarySeat); state.Stage != StageAwaitingHealthy ||
			state.ManagedRuntimeTarget.OperationID != operation || state.EffectiveRuntimeManifest().ArtifactDigest != candidate.Digest {
			t.Fatalf("%s did not write the candidate desired: %+v", operation, state)
		}
	}
	serve := func(operation, seatID string) {
		t.Helper()
		publishReports()
		tick(operation + " serving")
		if state := seat(seatID); state.Stage != StageServing || state.ManagedRuntimeTarget.Phase != ManagedUpdateSeatCanaryServing {
			t.Fatalf("%s did not serve: %+v", operation, state)
		}
	}

	permanent, elastic := canary.State.MemberID, fixture.peer.State.MemberID
	publishReports()
	prepare("00000000009GECCPS7VW3MTGN3", permanent, r1, r2)
	serve("00000000009GECCPS7VW3MTGN3", permanent)
	prepare("0000000000Z4T6A648T68DX06W", elastic, r1, r2)
	serve("0000000000Z4T6A648T68DX06W", elastic)
	if seat(permanent).ManagedRuntimeTarget.OperationID != "00000000009GECCPS7VW3MTGN3" {
		t.Fatal("promoting the peer changed the served canary target")
	}

	// The cell's rollout known-bad list is enforced in admission, and an
	// unreadable list refuses the update instead of admitting it.
	knownBadUpdate := rollingManagedUpdate(t, fixture, controller, placementSequence, epoch, "00000000000WTVX8ESZCTDC38P", permanent, r2, r3)
	knownBadRecord, _ := signedManagedUpdatePreparedRecord(t, knownBadUpdate)
	controller.config.KnownBad = fakeKnownBad{bad: map[string]bool{r3.Digest: true}}
	if _, err := controller.PrepareManagedUpdate(ctx, knownBadRecord); !errors.Is(err, ErrKnownBadCandidate) {
		t.Fatalf("known-bad candidate admission = %v", err)
	}
	controller.config.KnownBad = fakeKnownBad{err: errors.New("rollout store unavailable")}
	if _, err := controller.PrepareManagedUpdate(ctx, knownBadRecord); err == nil {
		t.Fatal("an unreadable known-bad list admitted the update")
	}
	controller.config.KnownBad = fakeKnownBad{bad: map[string]bool{strings.Repeat("e", 64): true}}

	prepare("0000000000JDJ1BMMVSVG25TWR", permanent, r2, r3)
	chained := seat(permanent).ManagedRuntimeTarget
	if chained.PreviousArtifactDigest != r2.Digest || chained.PreviousSourceDigest != r2.SourceDigest {
		t.Fatalf("chained target lost its predecessor: %+v", chained)
	}
	controller.now = func() time.Time { return chained.PreparedAt.Add(managedUpdateCanaryProofTimeout) }
	tick("release-3 proof timeout")
	controller.now = nil
	held := seat(permanent)
	if held.ManagedRuntimeTarget.Phase != ManagedUpdateSeatHeld || seat(elastic).Stage != StageServing ||
		seat(elastic).EffectiveRuntimeManifest().ArtifactDigest != r2.Digest {
		t.Fatalf("failed canary was not held with its peer serving: canary=%+v", held)
	}
	blocked := rollingManagedUpdate(t, fixture, controller, placementSequence, epoch, "0000000000ANHD8ZK28645M2RD", elastic, r2, r3)
	blockedRecord, _ := signedManagedUpdatePreparedRecord(t, blocked)
	if _, err := controller.PrepareManagedUpdate(ctx, blockedRecord); err == nil {
		t.Fatal("a held candidate was promoted to its peer")
	}

	prepare("0000000000CJ84K6B6KX0KC29A", permanent, r3, r2)
	serve("0000000000CJ84K6B6KX0KC29A", permanent)
	restored := seat(permanent)
	if restored.EffectiveRuntimeManifest().ArtifactDigest != r2.Digest ||
		restored.ManagedRuntimeTarget.PreviousArtifactDigest != r3.Digest {
		t.Fatalf("rollback did not restore the replaced artifact: %+v", restored.ManagedRuntimeTarget)
	}
	latest, err := runtime.ReadManagedUpdate(ctx, fixture.intent.DatabaseID, fixture.intent.PartitionID)
	if err != nil || latest.OperationID != "0000000000CJ84K6B6KX0KC29A" ||
		!strings.HasSuffix(latest.SubjectKey, string(authority.ManagedUpdateCanaryServing)) {
		t.Fatalf("latest authority outcome = %+v, %v", latest, err)
	}
	for _, id := range []string{permanent, elastic} {
		current, err := controller.managedUpdatePrepareIsCurrent(ctx, seat(id))
		if err != nil || !current {
			t.Fatalf("served target of %s is no longer current after later operations: %v", id, err)
		}
	}
	if seat(permanent).ManagedRuntimeTarget.RollbackOfHeld != true {
		t.Fatal("rollback of a held candidate was not marked")
	}

	// A rollback that is itself held must never be "rolled back" to the
	// candidate that failed first.
	r4 := AdmittedArtifact{Digest: strings.Repeat("4", 64), ManifestDigest: strings.Repeat("5", 64),
		SourceDigest: strings.Repeat("3", 64)}
	admitted[r4.Digest] = r4
	prepare("0000000000TMNRSJNWYYCT66GF", permanent, r2, r4)
	if seat(permanent).ManagedRuntimeTarget.RollbackOfHeld {
		t.Fatal("a forward update was marked as a rollback")
	}
	timeout := func(operation string) {
		t.Helper()
		target := seat(permanent).ManagedRuntimeTarget
		controller.now = func() time.Time { return target.PreparedAt.Add(managedUpdateCanaryProofTimeout) }
		tick(operation + " proof timeout")
		controller.now = nil
		if seat(permanent).ManagedRuntimeTarget.Phase != ManagedUpdateSeatHeld {
			t.Fatalf("%s was not held", operation)
		}
	}
	timeout("0000000000TMNRSJNWYYCT66GF")
	prepare("00000000004SZWDPQMXND9KS7B", permanent, r4, r2)
	timeout("00000000004SZWDPQMXND9KS7B")
	if !seat(permanent).ManagedRuntimeTarget.RollbackOfHeld {
		t.Fatal("held rollback lost its rollback mark")
	}
	flip := rollingManagedUpdate(t, fixture, controller, placementSequence, epoch, "0000000000A46ZE0FTR6XF6R8H", permanent, r2, r4)
	flipRecord, _ := signedManagedUpdatePreparedRecord(t, flip)
	if _, err := controller.PrepareManagedUpdate(ctx, flipRecord); err == nil {
		t.Fatal("a held rollback was returned to the known-bad candidate")
	}
}

// rollingManagedUpdate signs the Prepare request for one seat from the
// current durable seats, as the operator's update command builds it.
func rollingManagedUpdate(t *testing.T, fixture managedUpdateSeatOutcomeFixture, controller *Controller,
	placementSequence, epoch uint64, operation, canarySeat string, old, candidate AdmittedArtifact,
) ManagedUpdateIntent {
	t.Helper()
	base := validManagedUpdateIntent(t)
	states := []MemberState{fixture.store.members[fixture.canary.State.MemberID].State,
		fixture.store.members[fixture.peer.State.MemberID].State}
	slices.SortFunc(states, func(left, right MemberState) int { return strings.Compare(left.MemberID, right.MemberID) })
	update := ManagedUpdateIntent{SchemaVersion: ManagedUpdateSchemaVersion, Cell: controller.config.Cell,
		DatabaseID: fixture.intent.DatabaseID, PartitionID: fixture.intent.PartitionID,
		PlacementGeneration: fixture.intent.Generation, PlacementPayloadDigest: fixture.intent.PayloadDigest(),
		PlacementSequence: placementSequence, AuthorityEpoch: epoch, OperationID: operation,
		Role: controller.config.MemberRole, Environment: controller.config.Environment,
		OldArtifactDigest: old.Digest, CandidateArtifactDigest: candidate.Digest,
		CandidateManifestDigest: candidate.ManifestDigest, CandidateSourceDigest: candidate.SourceDigest,
		CanarySeatID: canarySeat,
		DurabilityProfile: ManagedUpdateDurabilityProfile{SchemaVersion: ManagedUpdateSchemaVersion,
			Region: states[0].Region, SQLSchemaBundleSHA256: states[0].RuntimeManifest.SQLSchemaBundleSHA256,
			LiveS3ConfigSHA256: states[0].RuntimeManifest.LiveS3ConfigSHA256,
			LiveS3TargetSHA256: states[0].RuntimeManifest.LiveS3TargetSHA256,
			LiveS3Credential:   states[0].RuntimeManifest.LiveS3Credential}}
	for _, state := range states {
		update.Seats = append(update.Seats, managedUpdateSeatFromState(state))
		update.DurabilityProfile.Volumes = append(update.DurabilityProfile.Volumes, ManagedUpdateVolumeProfile{
			SeatID: state.MemberID, VolumeID: state.VolumeID, FileSystemUUID: state.RuntimeManifest.FileSystemUUID,
			FileSystemType: state.RuntimeManifest.FileSystemType})
		if state.MemberID == canarySeat {
			update.CanaryDesiredGeneration = state.DesiredGeneration + 1
		}
	}
	profileDigest, err := update.DurabilityProfile.Digest()
	if err != nil {
		t.Fatal(err)
	}
	statement, err := decodeManagedCompatibility(base.CompatibilityEvidence)
	if err != nil {
		t.Fatal(err)
	}
	statement.Cell, statement.OperationID = update.Cell, update.OperationID
	statement.OldArtifactDigest, statement.CandidateArtifactDigest = update.OldArtifactDigest, update.CandidateArtifactDigest
	statement.CandidateManifestDigest, statement.DurabilityProfileSHA256 = update.CandidateManifestDigest, profileDigest
	update.CompatibilityEvidence, _ = signedManagedCompatibility(t, update, statement)
	if err := update.Validate(); err != nil {
		t.Fatalf("rolling update %s: %v", operation, err)
	}
	return update
}
