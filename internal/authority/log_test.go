package authority

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func TestTerminalMarkerWaitsForNestedWorkloadEffectAndFencesPlacement(t *testing.T) {
	js := newAuthorityTestJetStream(t)
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	runtime, err := Start(ctx, js, Config{Scope: "gru", CandidateID: "0000000000G2MMHNF41VCKD3JR", Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	epoch := runtime.Current().Epoch
	if _, err := runtime.CommitPlacementIntent(ctx, epoch, "00000000001Y9Z8VKC1VV66J6B", "0000000000Z3WK359G2W66CVT8", "0000000000H5S31NJTF5YM00K1", 0, []byte("admitted")); err != nil {
		t.Fatal(err)
	}
	intent := TerminalIntent{Cell: "gru", DatabaseID: "00000000001Y9Z8VKC1VV66J6B", PartitionID: "0000000000Z3WK359G2W66CVT8",
		Region: "GRU", Owner: "owner-a", CompartmentID: "ocid1.compartment.oc1..terminaltest",
		FleetGeneration: 1, PlacementGeneration: 1, PlacementPayloadDigest: strings.Repeat("a", 64),
		OperationID: "000000000052P5CTS9VW60Z1PQ", Nonce: entityid.New(),
		Targets:            []TerminalTarget{{SeatID: "000000000077F1R6E1XPKAC2D4", MemberID: "0000000000WM3QQGQPMW5X58P9", HostCreateKey: "0000000000R58Y74PAABAQ7X2V", DataCreateKey: "0000000000NMFV7B37QZWENX9Z"}},
		DisposableWorkload: true, AcknowledgePermanentDataLoss: true, AuthorizeForcedStop: true}
	payload, err := json.Marshal(intent, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	scope := WorkloadScope{DatabaseID: "00000000001Y9Z8VKC1VV66J6B", PartitionID: "0000000000Z3WK359G2W66CVT8"}
	effectCtx := WithActiveWorkloadEffectContext(ctx)
	releaseOuter, err := runtime.BeginActiveWorkloadEffect(effectCtx, epoch, scope)
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	started := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		close(started)
		_, err := runtime.CommitTerminalIntent(ctx, epoch, scope, intent.OperationID, payload,
			func(context.Context) error { close(entered); return nil })
		result <- err
	}()
	<-started
	select {
	case <-entered:
		t.Fatal("terminal verification entered during outer effect")
	case <-time.After(20 * time.Millisecond):
	}
	releaseNested, err := runtime.BeginActiveWorkloadEffect(effectCtx, epoch, scope)
	if err != nil {
		releaseOuter()
		t.Fatalf("nested active effect blocked by pending terminal writer: %v", err)
	}
	releaseOuter()
	select {
	case <-entered:
		t.Fatal("terminal verification entered before nested effect settled")
	default:
	}
	releaseNested()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("commit terminal marker: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("terminal marker did not complete after active effect release")
	}
	if _, err := runtime.BeginActiveWorkloadEffect(ctx, epoch, scope); !errors.Is(err, ErrFenced) {
		t.Fatalf("active effect after terminal marker = %v, want fenced", err)
	}
	if _, err := runtime.CommitPlacementIntent(ctx, epoch, "00000000001Y9Z8VKC1VV66J6B", "0000000000Z3WK359G2W66CVT8", "0000000000FY3Y7FSGAJVR07PF", 0, []byte("new")); !errors.Is(err, ErrFenced) {
		t.Fatalf("placement after terminal marker = %v, want fenced", err)
	}
	if _, err := runtime.ConfirmActivePlacementIntent(ctx, epoch, "00000000001Y9Z8VKC1VV66J6B", "0000000000Z3WK359G2W66CVT8", []byte("admitted")); !errors.Is(err, ErrFenced) {
		t.Fatalf("idempotent placement after terminal marker = %v, want fenced", err)
	}
	read, err := runtime.ReadTerminalIntent(ctx, "00000000001Y9Z8VKC1VV66J6B", "0000000000Z3WK359G2W66CVT8")
	if err != nil || !bytes.Equal(read.Payload, payload) || read.OperationID != intent.OperationID {
		t.Fatalf("read immutable terminal marker: %+v, %v", read, err)
	}
}

// A caller that binds its inputs to one epoch holds an outer effect in a
// shared effect context; a nested effect under any other epoch is fenced.
func TestNestedWorkloadEffectUnderAnotherEpochIsFenced(t *testing.T) {
	js := newAuthorityTestJetStream(t)
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	runtime, err := Start(ctx, js, Config{Scope: "gru", CandidateID: "0000000000BJN5J56B8SDAH30Y", Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	epoch := runtime.Current().Epoch
	scope := WorkloadScope{DatabaseID: "00000000001Y9Z8VKC1VV66J6B", PartitionID: "0000000000Z3WK359G2W66CVT8"}
	effectCtx := WithActiveWorkloadEffectContext(ctx)
	releaseOuter, err := runtime.BeginActiveWorkloadEffect(effectCtx, epoch, scope)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseOuter()
	if release, err := runtime.BeginActiveWorkloadEffect(effectCtx, epoch+1, scope); !errors.Is(err, ErrFenced) {
		if release != nil {
			release()
		}
		t.Fatalf("nested effect under another epoch = %v, want ErrFenced", err)
	}
	releaseNested, err := runtime.BeginActiveWorkloadEffect(effectCtx, epoch, scope)
	if err != nil {
		t.Fatalf("nested effect under the bound epoch: %v", err)
	}
	releaseNested()
}

func TestEnrollmentEffectIsDurableTerminalAdmissionHold(t *testing.T) {
	js := newAuthorityTestJetStream(t)
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	runtime, err := Start(ctx, js, Config{Scope: "gru", CandidateID: "0000000000T7KCT1BGERPKVWJZ", Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	epoch := runtime.Current().Epoch
	scope := WorkloadScope{DatabaseID: "00000000001Y9Z8VKC1VV66J6B", PartitionID: "0000000000Z3WK359G2W66CVT8"}
	effectID, instanceID := entityid.New(), "ocid1.instance.oc1..grant-effect-test"
	started, err := runtime.BeginEnrollmentEffect(ctx, epoch, scope, effectID, instanceID)
	if err != nil || started == 0 {
		t.Fatalf("start durable enrollment effect: sequence=%d error=%v", started, err)
	}
	pending, err := runtime.ListPendingEnrollmentEffects(ctx, scope)
	if err != nil || len(pending) != 1 || pending[0].EffectID != effectID ||
		pending[0].InstanceID != instanceID || pending[0].Sequence != started {
		t.Fatalf("pending enrollment effect is not visible to terminal admission: %+v, %v", pending, err)
	}
	if _, err := runtime.SettleEnrollmentEffect(ctx, epoch+1, scope, effectID, instanceID, started); err == nil {
		t.Fatal("a different epoch settled an in-flight enrollment effect")
	}
	settled, err := runtime.SettleEnrollmentEffect(ctx, epoch, scope, effectID, instanceID, started)
	if err != nil || settled <= started {
		t.Fatalf("settle exact enrollment effect: sequence=%d error=%v", settled, err)
	}
	pending, err = runtime.ListPendingEnrollmentEffects(ctx, scope)
	if err != nil || len(pending) != 0 {
		t.Fatalf("settled enrollment effect remained pending: %+v, %v", pending, err)
	}
}

type settledHistoryStream struct {
	jetstream.Stream
	info      jetstream.StreamInfo
	prefix    string
	pendingID string
}

func (stream *settledHistoryStream) Info(context.Context, ...jetstream.StreamInfoOpt) (*jetstream.StreamInfo, error) {
	info := stream.info
	return &info, nil
}

func (stream *settledHistoryStream) GetLastMsgForSubject(ctx context.Context, subject string) (*jetstream.RawStreamMsg, error) {
	effectID, ok := strings.CutPrefix(subject, stream.prefix)
	if !ok {
		return stream.Stream.GetLastMsgForSubject(ctx, subject)
	}
	phase, operationID := "settled", entityid.Derive("enrollment-settled", effectID)
	if effectID == stream.pendingID {
		phase, operationID = "pending", effectID
	}
	payload, err := enrollmentEffectBytes("ocid1.instance.oc1..history", phase)
	if err != nil {
		return nil, err
	}
	key := "00000000001Y9Z8VKC1VV66J6B.0000000000Z3WK359G2W66CVT8." + effectID
	record, err := json.Marshal(controlRecord{Version: 1, Kind: MutationEnrollmentEffect,
		Scope: "gru", SubjectKey: key, OperationID: operationID, Epoch: 1, Payload: payload})
	if err != nil {
		return nil, err
	}
	return &jetstream.RawStreamMsg{Subject: subject, Sequence: 1, Data: record}, nil
}

func TestPendingEnrollmentEffectsSurviveLargeSettledHistory(t *testing.T) {
	js := newAuthorityTestJetStream(t)
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	runtime, err := Start(ctx, js, Config{Scope: "gru", CandidateID: "0000000000BM058BHA26MBFW1K", Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	info, err := runtime.readStream.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	const prefix = "ts.control.gru.placement.enrollment.00000000001Y9Z8VKC1VV66J6B.0000000000Z3WK359G2W66CVT8."
	pendingID := entityid.Derive("effect-fixture", "4097")
	all := make(map[string]uint64, 4098)
	for index := range 4098 {
		all[prefix+entityid.Derive("effect-fixture", fmt.Sprint(index))] = 1
	}
	info.State.Subjects = all
	runtime.readStream = &settledHistoryStream{Stream: runtime.readStream, info: *info,
		prefix: prefix, pendingID: pendingID}
	pending, err := runtime.ListPendingEnrollmentEffects(ctx, WorkloadScope{DatabaseID: "00000000001Y9Z8VKC1VV66J6B", PartitionID: "0000000000Z3WK359G2W66CVT8"})
	if err != nil || len(pending) != 1 || pending[0].EffectID != pendingID {
		t.Fatalf("large settled history hid the pending enrollment effect: %+v, %v", pending, err)
	}
}

func TestPriorEpochEnrollmentEffectRequiresExactFenceProof(t *testing.T) {
	js := newAuthorityTestJetStream(t)
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	old, err := Start(ctx, js, Config{Scope: "gru", CandidateID: "0000000000CMQ0HAMXDC0MJCQK", Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	scope := WorkloadScope{DatabaseID: "00000000001Y9Z8VKC1VV66J6B", PartitionID: "0000000000Z3WK359G2W66CVT8"}
	effectID, instanceID := entityid.New(), "ocid1.instance.oc1..prior-grant-effect"
	sequence, err := old.BeginEnrollmentEffect(ctx, old.Current().Epoch, scope, effectID, instanceID)
	if err != nil {
		t.Fatal(err)
	}
	oldEpoch := old.Current().Epoch
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	current, err := Start(ctx, js, Config{Scope: "gru", CandidateID: "0000000000QQE9RSJGEQCGXJ08", Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = current.Close() })
	newEpoch := current.Current().Epoch
	if newEpoch <= oldEpoch {
		t.Fatalf("new leader epoch %d did not advance past %d", newEpoch, oldEpoch)
	}
	if _, err := current.SettleFencedEnrollmentEffect(ctx, newEpoch, scope,
		effectID, instanceID, sequence, nil); err == nil {
		t.Fatal("prior effect settled without grant fence verifier")
	}
	if _, err := current.SettleFencedEnrollmentEffect(ctx, newEpoch, scope,
		effectID, instanceID, sequence, func(context.Context) error { return errors.New("grant not disabled") }); err == nil {
		t.Fatal("prior effect settled when grant fence readback failed")
	}
	pending, err := current.ListPendingEnrollmentEffects(ctx, scope)
	if err != nil || len(pending) != 1 || pending[0].Epoch != oldEpoch {
		t.Fatalf("unknown old effect was not retained: %+v, %v", pending, err)
	}
	settled, err := current.SettleFencedEnrollmentEffect(ctx, newEpoch, scope,
		effectID, instanceID, sequence, func(context.Context) error { return nil })
	if err != nil || settled <= sequence {
		t.Fatalf("settle fenced prior effect: sequence=%d error=%v", settled, err)
	}
	pending, err = current.ListPendingEnrollmentEffects(ctx, scope)
	if err != nil || len(pending) != 0 {
		t.Fatalf("fenced prior effect remained pending: %+v, %v", pending, err)
	}
}

func TestManagedUpdateHistoryRetainsExactPrepareAcrossLeaderEpochs(t *testing.T) {
	js := newAuthorityTestJetStream(t)
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	first, err := Start(ctx, js, Config{Scope: "gru", CandidateID: "0000000000NJ1B8Y3D64AHBVBH", Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	firstClosed := false
	t.Cleanup(func() {
		if !firstClosed {
			_ = first.Close()
		}
	})
	firstEpoch := first.Current().Epoch
	record := validManagedUpdateRecord()
	preparedSequence, err := first.CommitManagedUpdate(ctx, firstEpoch, record, 0, nil)
	if err != nil || preparedSequence == 0 {
		t.Fatalf("commit signed Prepare: sequence=%d error=%v", preparedSequence, err)
	}
	replayed, err := first.CommitManagedUpdate(ctx, firstEpoch, record, 0, nil)
	if err != nil || replayed != preparedSequence {
		t.Fatalf("same Prepare retry changed its receipt: sequence=%d error=%v", replayed, err)
	}

	changed := record
	changed.SignedRequest = []byte("different signed request")
	changed.SignedRequestSHA256 = digestString(changed.SignedRequest)
	if _, err := first.CommitManagedUpdate(ctx, firstEpoch, changed, 0, nil); !errors.Is(err, ErrOperationConflict) {
		t.Fatalf("changed-body retry = %v, want operation conflict", err)
	}

	serving := record
	serving.Phase = ManagedUpdateCanaryServing
	serving.Outcome = "fresh-serving-proof"
	servingSequence, err := first.CommitManagedUpdate(ctx, firstEpoch, serving, preparedSequence, nil)
	if err != nil || servingSequence <= preparedSequence {
		t.Fatalf("commit canary result: sequence=%d error=%v", servingSequence, err)
	}
	if _, err := first.CommitManagedUpdate(ctx, firstEpoch, record, 0, nil); err != nil {
		t.Fatalf("historical Prepare receipt was not idempotent after phase advance: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	firstClosed = true

	second, err := Start(ctx, js, Config{Scope: "gru", CandidateID: "00000000002Y5BFHHZ2P4ABRTQ", Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.Close() })
	if second.Current().Epoch <= firstEpoch {
		t.Fatalf("leader epoch did not advance: first=%d second=%d", firstEpoch, second.Current().Epoch)
	}
	history, err := second.ReadManagedUpdateOperation(ctx, record.DatabaseID, record.PartitionID, record.OperationID)
	if err != nil || len(history) != 2 || history[0].Sequence != preparedSequence ||
		history[0].Epoch != firstEpoch || history[1].Sequence != servingSequence ||
		history[1].Epoch != firstEpoch || !bytes.Equal(history[0].Payload, mustManagedUpdatePayload(t, record)) {
		t.Fatalf("exact operation history was not retained after epoch change: %+v, %v", history, err)
	}
	read, err := second.ReadManagedUpdate(ctx, record.DatabaseID, record.PartitionID)
	if err != nil || read.Sequence != servingSequence || read.OperationID != record.OperationID {
		t.Fatalf("latest update result differs from immutable history: %+v, %v", read, err)
	}
	reader, err := OpenReader(ctx, js, "gru")
	if err != nil {
		t.Fatal(err)
	}
	readOnlyHistory, err := reader.ReadManagedUpdateOperation(ctx, record.DatabaseID, record.PartitionID, record.OperationID)
	if err != nil || len(readOnlyHistory) != len(history) || readOnlyHistory[0].Sequence != preparedSequence {
		t.Fatalf("read-only exact history differs: %+v, %v", readOnlyHistory, err)
	}
}

func TestManagedUpdateSuccessorFollowsOnlyATerminalOutcome(t *testing.T) {
	js := newAuthorityTestJetStream(t)
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	runtime, err := Start(ctx, js, Config{Scope: "gru", CandidateID: "0000000000S8X456Y9E7MJXSNB", Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	epoch := runtime.Current().Epoch
	first := validManagedUpdateRecord()
	prepared, err := runtime.CommitManagedUpdate(ctx, epoch, first, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	successor := first
	successor.OperationID, successor.CanarySeatID = "00000000006QPQSQ5R3B4H4MAX", "00000000000E5NVMSGX0D07DPA"
	successor.SignedRequest = []byte("peer promotion request")
	successor.SignedRequestSHA256 = digestString(successor.SignedRequest)
	if _, err := runtime.CommitManagedUpdate(ctx, epoch, successor, prepared, nil); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("successor while the first operation is prepared = %v, want invalid transition", err)
	}
	held := first
	held.Phase, held.Outcome = ManagedUpdateHeld, "candidate-proof-timeout"
	terminal, err := runtime.CommitManagedUpdate(ctx, epoch, held, prepared, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.CommitManagedUpdate(ctx, epoch, successor, prepared, nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("successor after a stale latest sequence = %v, want conflict", err)
	}
	next, err := runtime.CommitManagedUpdate(ctx, epoch, successor, terminal, nil)
	if err != nil || next <= terminal {
		t.Fatalf("successor after the held outcome: sequence=%d err=%v", next, err)
	}
	latest, err := runtime.ReadManagedUpdate(ctx, first.DatabaseID, first.PartitionID)
	if err != nil || latest.OperationID != successor.OperationID || latest.Sequence != next {
		t.Fatalf("latest operation = %+v, %v", latest, err)
	}
}

func validManagedUpdateRecord() ManagedUpdateRecord {
	request := []byte("exact canonical signed managed update request")
	return ManagedUpdateRecord{
		SchemaVersion: 1, Cell: "gru", DatabaseID: "000000000056C99ETHNC8V7NSN", PartitionID: "0000000000Z3WK359G2W66CVT8",
		OperationID: "00000000000NV7A9CE3MES6S1F", Phase: ManagedUpdatePrepared, SignedRequest: request,
		SignedRequestSHA256: digestString(request), PlacementGeneration: 1,
		PlacementPayloadDigest: strings.Repeat("a", 64), PlacementSequence: 1,
		CanarySeatID: "00000000008SEAHD1YMMYV3ARR", CanaryDesiredGeneration: 2,
		OldArtifactDigest: strings.Repeat("b", 64), CandidateArtifactDigest: strings.Repeat("c", 64),
		CandidateManifestDigest: strings.Repeat("d", 64), CandidateSourceDigest: strings.Repeat("e", 64),
		DurabilityProfileSHA256: strings.Repeat("f", 64),
	}
}

func digestString(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func mustManagedUpdatePayload(t *testing.T, record ManagedUpdateRecord) []byte {
	t.Helper()
	payload, err := json.Marshal(record, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func TestTerminalAdmissionRerunsSettlementProofAfterGlobalCASConflict(t *testing.T) {
	js := newAuthorityTestJetStream(t)
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	runtime, err := Start(ctx, js, Config{Scope: "gru", CandidateID: "00000000002ZYG3Z5ABHQBABYP", Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	scope := WorkloadScope{DatabaseID: "00000000001Y9Z8VKC1VV66J6B", PartitionID: "0000000000Z3WK359G2W66CVT8"}
	intent := TerminalIntent{Cell: "gru", DatabaseID: scope.DatabaseID, PartitionID: scope.PartitionID,
		Region: "GRU", Owner: "owner-a", CompartmentID: "ocid1.compartment.oc1..terminaltest",
		FleetGeneration: 1, PlacementGeneration: 1, PlacementPayloadDigest: strings.Repeat("a", 64),
		OperationID: "000000000035AP0Y31MVCHHG0B", Nonce: entityid.New(),
		Targets:            []TerminalTarget{{SeatID: "000000000077F1R6E1XPKAC2D4", MemberID: "0000000000WM3QQGQPMW5X58P9", HostCreateKey: "0000000000R58Y74PAABAQ7X2V", DataCreateKey: "0000000000NMFV7B37QZWENX9Z"}},
		DisposableWorkload: true, AcknowledgePermanentDataLoss: true, AuthorizeForcedStop: true}
	payload, err := json.Marshal(intent, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	_, err = runtime.CommitTerminalIntent(ctx, runtime.Current().Epoch, scope, intent.OperationID, payload,
		func(ctx context.Context) error {
			calls++
			if calls == 1 {
				// Simulate an independent leader-effect publication after the
				// first read-only proof but before the marker CAS.
				effectID := entityid.New()
				key, _ := enrollmentEffectSubjectKey(scope, effectID)
				effectPayload, _ := enrollmentEffectBytes("ocid1.instance.oc1..pending", "pending")
				record, err := json.Marshal(controlRecord{Version: 1, Kind: MutationEnrollmentEffect,
					Scope: "gru", SubjectKey: key, OperationID: effectID,
					Epoch: runtime.Current().Epoch, Payload: effectPayload})
				if err != nil {
					return err
				}
				info, err := runtime.stream.Info(ctx)
				if err != nil {
					return err
				}
				_, err = js.PublishMsg(ctx, controlMessage(mutationSubject("gru", MutationEnrollmentEffect, key),
					string(MutationEnrollmentEffect), effectID, record),
					jetstream.WithExpectLastSequence(info.State.LastSeq),
					jetstream.WithExpectLastSequenceForSubject(0, mutationSubject("gru", MutationEnrollmentEffect, key)))
				return err
			}
			pending, err := runtime.ListPendingEnrollmentEffects(ctx, scope)
			if err != nil {
				return err
			}
			if len(pending) != 0 {
				return errors.New("new enrollment effect makes first terminal proof stale")
			}
			return nil
		})
	if err == nil || calls != 2 {
		t.Fatalf("terminal CAS did not rerun proof after concurrent effect: calls=%d error=%v", calls, err)
	}
	if _, err := runtime.ReadTerminalIntent(ctx, scope.DatabaseID, scope.PartitionID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("stale proof wrote terminal marker: %v", err)
	}
}

func TestVerifyControlStreamConfigRejectsMessageEviction(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*jetstream.StreamConfig)
	}{
		{name: "max messages", mutate: func(config *jetstream.StreamConfig) { config.MaxMsgs = 100 }},
		{name: "max bytes", mutate: func(config *jetstream.StreamConfig) { config.MaxBytes = 1 << 20 }},
		{name: "max messages per subject", mutate: func(config *jetstream.StreamConfig) { config.MaxMsgsPerSubject = 10 }},
		{name: "max age", mutate: func(config *jetstream.StreamConfig) { config.MaxAge = 1 }},
		{name: "discard new per subject", mutate: func(config *jetstream.StreamConfig) { config.DiscardNewPerSubject = true }},
		{name: "rollup", mutate: func(config *jetstream.StreamConfig) { config.AllowRollup = true }},
		{name: "direct reads", mutate: func(config *jetstream.StreamConfig) { config.AllowDirect = true }},
		{name: "discard policy", mutate: func(config *jetstream.StreamConfig) { config.Discard = jetstream.DiscardNew }},
		{name: "extra wildcard subject", mutate: func(config *jetstream.StreamConfig) { config.Subjects = append(config.Subjects, "unrelated.>") }},
		{name: "duplicate control subject", mutate: func(config *jetstream.StreamConfig) { config.Subjects = append(config.Subjects, controlStreamSubject) }},
		{name: "limited consumers", mutate: func(config *jetstream.StreamConfig) { config.MaxConsumers = 1 }},
		{name: "limited message size", mutate: func(config *jetstream.StreamConfig) { config.MaxMsgSize = 128 }},
		{name: "no publish acknowledgements", mutate: func(config *jetstream.StreamConfig) { config.NoAck = true }},
		{name: "message TTL", mutate: func(config *jetstream.StreamConfig) { config.AllowMsgTTL = true }},
		{name: "subject transform", mutate: func(config *jetstream.StreamConfig) { config.SubjectTransform = &jetstream.SubjectTransformConfig{} }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := durableControlStreamConfig()
			test.mutate(&config)
			if err := verifyControlStreamConfig(config, defaultReplicas); err == nil {
				t.Fatal("verifyControlStreamConfig accepted an incompatible or unsafe config")
			}
		})
	}
}

func TestVerifyControlStreamConfigAcceptsDurableControlStream(t *testing.T) {
	if err := verifyControlStreamConfig(durableControlStreamConfig(), defaultReplicas); err != nil {
		t.Fatalf("verifyControlStreamConfig rejected the expected config: %v", err)
	}
}

func durableControlStreamConfig() jetstream.StreamConfig {
	return jetstream.StreamConfig{
		Name:              ControlStreamName,
		Subjects:          []string{controlStreamSubject},
		Retention:         jetstream.LimitsPolicy,
		MaxConsumers:      -1,
		MaxMsgs:           -1,
		MaxBytes:          -1,
		MaxMsgsPerSubject: -1,
		Storage:           jetstream.FileStorage,
		Replicas:          defaultReplicas,
		DenyDelete:        true,
		DenyPurge:         true,
		Metadata:          map[string]string{"terrascale-contract": "authority-log-v1"},
	}
}

func TestAuthorityDiagnosticsAreSafeAndRateLimited(t *testing.T) {
	queue := make(chan authorityDiagnostic, 1)
	queue <- authorityDiagnostic{}
	var dropped atomic.Uint64
	started := time.Now()
	if enqueueAuthorityDiagnostic(queue, &dropped, authorityDiagnostic{}) {
		t.Fatal("full diagnostic queue unexpectedly accepted another event")
	}
	if time.Since(started) > 100*time.Millisecond || dropped.Load() != 1 {
		t.Fatalf("full queue enqueue blocked or failed to count its drop: elapsed=%s dropped=%d", time.Since(started), dropped.Load())
	}

	var output bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&output, nil))
	runtime := &Runtime{
		config: Config{Scope: "gru"}, logger: logger, diagTimes: make(map[string]time.Time),
	}
	runtime.publishSnapshot(Snapshot{Scope: "gru", CandidateID: "0000000000C66H81REBS854264", OwnerID: "0000000000DXKPTGJCKZVQAP63", Reason: "not-observed"})
	runtime.logSnapshotTransition()
	runtime.publishSnapshot(Snapshot{Scope: "gru", CandidateID: "0000000000C66H81REBS854264", OwnerID: "0000000000DXKPTGJCKZVQAP63", Leader: true, Ready: true, Epoch: 1, Reason: "leader"})
	runtime.logSnapshotTransition()
	runtime.publishSnapshot(Snapshot{Scope: "gru", CandidateID: "0000000000C66H81REBS854264", OwnerID: "0000000000DXKPTGJCKZVQAP63", Leader: true, Ready: true, Epoch: 1, Revision: 8, Reason: "leader"})
	runtime.logSnapshotTransition()

	apiErr := &jetstream.APIError{Code: 503, ErrorCode: 10164, Description: "private-server-description"}
	failure := stageFailure("lease_publish", fmt.Errorf("%w: %w", ErrOutcomeUnknown, apiErr))
	runtime.recordFailure(failure)
	runtime.recordFailure(failure)
	if err := flushAuthorityDiagnostics(t.Context()); err != nil {
		t.Fatalf("flush diagnostic test events: %v", err)
	}

	logs := output.String()
	if !strings.Contains(logs, "stage=lease_publish") || !strings.Contains(logs, "error_class=outcome_unknown") ||
		!strings.Contains(logs, "cause_class=jetstream_api") || !strings.Contains(logs, "jetstream_error_code=10164") {
		t.Fatalf("diagnostic log omitted the operation stage or error class: %s", logs)
	}
	if strings.Count(logs, "authority operation failed") != 1 {
		t.Fatalf("repeated errors were not rate-limited: %s", logs)
	}
	if strings.Count(logs, "authority state transition") != 2 {
		t.Fatalf("state transitions were emitted per renewal instead of per state change: %s", logs)
	}
	for _, secret := range []string{"0000000000DXKPTGJCKZVQAP63", "private-server-description", "0000000000C66H81REBS854264", "lease_publish"} {
		if strings.Contains(logs, secret) && secret != "lease_publish" {
			t.Fatalf("diagnostic log exposed %q: %s", secret, logs)
		}
	}
}

func TestPlacementIntentIdentityIncludesPartitionAndIgnoresLeaseHistory(t *testing.T) {
	srv, err := server.NewServer(&server.Options{
		Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: filepath.Join(t.TempDir(), "jetstream"),
	})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS did not start")
	}
	t.Cleanup(func() { srv.Shutdown(); srv.WaitForShutdown() })

	conn, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	runtime, err := Start(ctx, js, Config{
		Scope: "gru", CandidateID: "0000000000C66H81REBS854264", LeaseDuration: time.Second,
		RenewInterval: 10 * time.Millisecond, Replicas: 1,
	})
	if err != nil {
		t.Fatalf("start authority runtime: %v", err)
	}
	observedStream, err := js.Stream(ctx, ControlStreamName)
	if err != nil {
		t.Fatalf("open independent stream observer: %v", err)
	}
	t.Cleanup(func() {
		if err := runtime.Close(); err != nil {
			t.Errorf("close authority runtime: %v", err)
		}
	})
	epoch := runtime.Current().Epoch
	if epoch == 0 || !runtime.Current().CanMutate() {
		t.Fatalf("runtime did not acquire authority: %+v", runtime.Current())
	}
	if _, err := runtime.CommitHostMutation(ctx, epoch, MutationRegistration, "gru.node-a", "0000000000JDBT2PAM9H86A22N", 0, []byte("host")); err != nil {
		t.Fatalf("commit host registration for concurrent reads: %v", err)
	}
	materialSequence, err := runtime.CommitMaterialReceipt(ctx, epoch, "00000000001Y9Z8VKC1VV66J6B", "0000000000Z3WK359G2W66CVT8", "00000000004RQWCSF109ZZXXMW", 0, []byte("signed-receipt"))
	if err != nil {
		t.Fatalf("commit initial material receipt: %v", err)
	}
	materialEntry, err := runtime.ReadMaterialReceipt(ctx, "00000000001Y9Z8VKC1VV66J6B", "0000000000Z3WK359G2W66CVT8")
	if err != nil || materialEntry.Kind != MutationMaterialReceipt || materialEntry.Sequence != materialSequence ||
		string(materialEntry.Payload) != "signed-receipt" {
		t.Fatalf("read committed material receipt: %+v, %v", materialEntry, err)
	}
	if _, err := runtime.CommitMaterialReceipt(ctx, epoch, "00000000001Y9Z8VKC1VV66J6B", "0000000000Z3WK359G2W66CVT8", "0000000000W794HACRSCP7P4TY", 0, []byte("foreign")); !errors.Is(err, ErrConflict) {
		t.Fatalf("second material receipt did not respect R3 CAS: %v", err)
	}

	firstSequence, err := runtime.CommitPlacementIntent(ctx, epoch, "00000000001Y9Z8VKC1VV66J6B", "0000000000Z3WK359G2W66CVT8", "0000000000SR9J18DPZWQ44CD1", 0, []byte("first"))
	if err != nil {
		t.Fatalf("commit first partition: %v", err)
	}
	secondSequence, err := runtime.CommitPlacementIntent(ctx, epoch, "00000000001Y9Z8VKC1VV66J6B", "00000000001WFHC56Q8NB0X6T8", "0000000000ECMERPYM7GPJH1JM", 0, []byte("second"))
	if err != nil {
		t.Fatalf("commit second partition of the same database: %v", err)
	}
	if secondSequence <= firstSequence {
		t.Fatalf("second partition sequence %d did not follow first %d", secondSequence, firstSequence)
	}
	if _, err := runtime.CommitPlacementIntent(ctx, epoch, "00000000001Y9Z8VKC1VV66J6B", "0000000000Z3WK359G2W66CVT8", "0000000000VF5V91DK3SK85HVR", 0, []byte("stale")); err != ErrConflict {
		t.Fatalf("stale same-partition write returned %v, want ErrConflict", err)
	}

	updatedSequence, err := runtime.CommitPlacementIntent(ctx, epoch, "00000000001Y9Z8VKC1VV66J6B", "0000000000Z3WK359G2W66CVT8", "0000000000VF5V91DK3SK85HVR", firstSequence, []byte("updated"))
	if err != nil {
		t.Fatalf("commit same-partition update at current sequence: %v", err)
	}
	if updatedSequence <= firstSequence {
		t.Fatalf("updated partition sequence %d did not follow first %d", updatedSequence, firstSequence)
	}
	updated, err := runtime.ReadPlacementIntent(ctx, "00000000001Y9Z8VKC1VV66J6B", "0000000000Z3WK359G2W66CVT8")
	if err != nil || updated.SubjectKey != "00000000001Y9Z8VKC1VV66J6B.0000000000Z3WK359G2W66CVT8" || updated.Sequence != updatedSequence || string(updated.Payload) != "updated" {
		t.Fatalf("read updated partition: entry=%+v err=%v", updated, err)
	}
	independent, err := runtime.ReadPlacementIntent(ctx, "00000000001Y9Z8VKC1VV66J6B", "00000000001WFHC56Q8NB0X6T8")
	if err != nil || independent.SubjectKey != "00000000001Y9Z8VKC1VV66J6B.00000000001WFHC56Q8NB0X6T8" || independent.Sequence != secondSequence || string(independent.Payload) != "second" {
		t.Fatalf("read independent partition: entry=%+v err=%v", independent, err)
	}
	reader, err := OpenReader(ctx, js, "gru")
	if err != nil {
		t.Fatalf("open shared reader: %v", err)
	}
	info, err := observedStream.Info(ctx)
	if err != nil || info.Config.AllowDirect {
		t.Fatalf("control stream direct-read setting = %v, error = %v; want disabled", info.Config.AllowDirect, err)
	}
	observed, err := Observe(ctx, js, "gru")
	if err != nil || observed.Epoch != epoch {
		t.Fatalf("observe current lease through leader-backed read: snapshot=%+v err=%v", observed, err)
	}

	var readers sync.WaitGroup
	readErrors := make(chan error, 4)
	for range 4 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for range 8 {
				if entry, err := runtime.ReadHostMutation(ctx, MutationRegistration, "gru.node-a"); err != nil || entry.Sequence == 0 {
					readErrors <- errors.Join(err, errors.New("runtime host mutation read returned no committed record"))
					return
				}
				if entry, err := runtime.ReadPlacementIntent(ctx, "00000000001Y9Z8VKC1VV66J6B", "0000000000Z3WK359G2W66CVT8"); err != nil || entry.Sequence == 0 {
					readErrors <- errors.Join(err, errors.New("runtime placement read returned no committed record"))
					return
				}
				if _, err := runtime.ListPlacementIntents(ctx); err != nil {
					readErrors <- fmt.Errorf("runtime placement list: %w", err)
					return
				}
				if entry, err := reader.ReadHostMutation(ctx, MutationRegistration, "gru.node-a"); err != nil || entry.Sequence == 0 {
					readErrors <- errors.Join(err, errors.New("reader host mutation read returned no committed record"))
					return
				}
				if entry, err := reader.ReadPlacementIntent(ctx, "00000000001Y9Z8VKC1VV66J6B", "00000000001WFHC56Q8NB0X6T8"); err != nil || entry.Sequence == 0 {
					readErrors <- errors.Join(err, errors.New("reader placement read returned no committed record"))
					return
				}
				if _, err := reader.ListPlacementIntents(ctx); err != nil {
					readErrors <- fmt.Errorf("reader placement list: %w", err)
					return
				}
			}
		}()
	}
	readers.Wait()
	close(readErrors)
	for err := range readErrors {
		t.Errorf("concurrent authority read: %v", err)
	}

	deadline := time.Now().Add(time.Second)
	for {
		info, err := observedStream.Info(ctx)
		if err != nil {
			t.Fatalf("read authority stream state: %v", err)
		}
		if info.State.Msgs >= 25 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("lease renewals did not produce enough history: %d messages", info.State.Msgs)
		}
		time.Sleep(5 * time.Millisecond)
	}

	intents, err := runtime.ListPlacementIntents(ctx)
	if err != nil {
		t.Fatalf("list current placement intents after lease renewals: %v", err)
	}
	if len(intents) != 2 || intents[1].SubjectKey != "00000000001Y9Z8VKC1VV66J6B.0000000000Z3WK359G2W66CVT8" || intents[0].SubjectKey != "00000000001Y9Z8VKC1VV66J6B.00000000001WFHC56Q8NB0X6T8" {
		t.Fatalf("listed placement identities = %+v, want both distinct partitions", intents)
	}
}
