package authority

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestTerminalMarkerWaitsForNestedWorkloadEffectAndFencesPlacement(t *testing.T) {
	js := newAuthorityTestJetStream(t)
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	runtime, err := Start(ctx, js, Config{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Scope: "gru", CandidateID: "0000000000G2MMHNF41VCKD3JR", Replicas: 1})
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
		OperationID: "000000000052P5CTS9VW60Z1PQ", Nonce: "0123456789abcdef0123456789abcdef",
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
