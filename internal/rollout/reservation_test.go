package rollout

import (
	"context"
	"errors"
	"maps"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go/jetstream"
)

func TestReservationRefusesUnpublishedStageWithoutChargingAnotherDigest(t *testing.T) {
	store, _ := testStore(t)
	ctx := t.Context()
	state := CellState{SchemaVersion: SchemaVersion, Cell: "gru", Attempts: map[string]int{otherBad: 2}}
	if err := store.writeCell(ctx, 7, state, 0); err != nil {
		t.Fatal(err)
	}
	spec := testSpec(testStageID(1))
	if _, _, err := store.Begin(ctx, spec, testStart); !errors.Is(err, ErrNoRelease) {
		t.Fatalf("unpublished stage admitted: %v", err)
	}
	if _, err := store.PublishRelease(ctx, 7, Release{Digest: otherBad, Actor: "ci", CreatedAt: testStart}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Begin(ctx, spec, testStart); !errors.Is(err, ErrConflict) {
		t.Fatalf("later generation changed the stage target: %v", err)
	}
	if err := store.RecoverReservation(ctx, 7); err != nil {
		t.Fatal(err)
	}
	after, _, err := store.Cell(ctx)
	if err != nil || after.ActiveRolloutID != "" || !maps.Equal(after.Attempts, state.Attempts) {
		t.Fatalf("unbound admission/refund changed historical counts: %+v, %v", after, err)
	}
}

type pausedReservationKV struct {
	jetstream.KeyValue
	recordID string
	entered  chan struct{}
	resume   chan struct{}
}

func (kv pausedReservationKV) Update(ctx context.Context, key string, value []byte, revision uint64) (uint64, error) {
	if key == cellKey {
		close(kv.entered)
		select {
		case <-kv.resume:
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	return kv.KeyValue.Update(ctx, key, value, revision)
}

func (kv pausedReservationKV) Create(ctx context.Context, key string, value []byte, opts ...jetstream.KVCreateOpt) (uint64, error) {
	if key == kv.recordID {
		return 0, errors.New("injected record creation failure")
	}
	return kv.KeyValue.Create(ctx, key, value, opts...)
}

func TestPublicationPreservesProofAcrossAdmissionAndRecordFailure(t *testing.T) {
	for _, domain := range []string{ControllerReleaseDomain, HostReleaseDomain} {
		t.Run(domain, func(t *testing.T) {
			store, _ := testStore(t)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			first, err := store.PublishRelease(ctx, 7, Release{Digest: toDigest, Actor: "ci", CreatedAt: testStart})
			if err != nil {
				t.Fatal(err)
			}
			for generation := 2; generation <= ReleaseHistory; generation++ {
				digest := fromDigest
				if generation%2 == 0 {
					digest = otherBad
				}
				if _, err := store.PublishRelease(ctx, 7, Release{Digest: digest, Actor: "ci", CreatedAt: testStart}); err != nil {
					t.Fatal(err)
				}
			}
			if err := store.writeCell(ctx, 7, CellState{SchemaVersion: SchemaVersion, Cell: "gru"}, 0); err != nil {
				t.Fatal(err)
			}
			id := entityid.Derive(domain, ReleaseRolloutID(first.Generation))
			originalKV := store.kv
			entered, resume := make(chan struct{}), make(chan struct{})
			store.kv = pausedReservationKV{KeyValue: originalKV, recordID: id, entered: entered, resume: resume}
			spec := testSpec(id)
			if domain == HostReleaseDomain {
				spec.Kind = KindHost
			}
			admitted := make(chan error, 1)
			go func() { _, _, err := store.Begin(ctx, spec, testStart); admitted <- err }()
			select {
			case <-entered:
			case <-ctx.Done():
				close(resume)
				t.Fatal(ctx.Err())
			}
			started, published := make(chan struct{}), make(chan error, 1)
			go func() {
				close(started)
				_, err := store.PublishRelease(ctx, 7, Release{Digest: fromDigest, Actor: "ci", CreatedAt: testStart})
				published <- err
			}()
			<-started
			select {
			case err := <-published:
				close(resume)
				<-admitted
				t.Fatalf("publication passed an unfinished admission: %v", err)
			case <-time.After(100 * time.Millisecond):
			}
			close(resume)
			if err := <-admitted; err == nil {
				t.Fatal("record failure was not injected")
			}
			if err := <-published; err != nil {
				t.Fatal(err)
			}
			store.kv = originalKV
			if _, err := store.ReleaseGeneration(ctx, first.Generation); err != nil {
				t.Fatalf("active reservation proof pruned: %v", err)
			}
			if err := store.RecoverReservation(ctx, 7); err != nil {
				t.Fatal(err)
			}
			if cell, _, err := store.Cell(ctx); err != nil || cell.ActiveRolloutID != "" || cell.Attempts[toDigest] != 0 {
				t.Fatalf("record-free reservation lost its refund proof: %+v, %v", cell, err)
			}
		})
	}
}

func TestAdmissionRefusesRetainedGenerationAheadOfPublishedDesired(t *testing.T) {
	store, _ := testStore(t)
	ctx := t.Context()
	if _, err := store.PublishRelease(ctx, 7, Release{Digest: toDigest, Actor: "ci", CreatedAt: testStart}); err != nil {
		t.Fatal(err)
	}
	future := Release{ID: generationKey("gru", 2), Generation: 2, Digest: otherBad, Actor: "ci", CreatedAt: testStart}
	if err := store.retain(ctx, 7, future); err != nil {
		t.Fatal(err)
	}
	spec := testSpec(testStageID(2))
	spec.ToDigest = otherBad
	if _, _, err := store.Begin(ctx, spec, testStart); !errors.Is(err, ErrNoRelease) {
		t.Fatalf("unpublished retained generation admitted: %v", err)
	}
	if cell, _, err := store.Cell(ctx); err != nil || cell.ActiveRolloutID != "" || len(cell.Attempts) != 0 {
		t.Fatalf("refused future generation charged a reservation: %+v, %v", cell, err)
	}
}

func TestExistingFullRecordResumesWithoutRetainedGeneration(t *testing.T) {
	store, _ := testStore(t)
	ctx := t.Context()
	spec := testSpec(entityid.Derive("persisted", "full record without generation"))
	record, err := New(spec, testStart)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := protocol.EncodeJSON(record)
	if err != nil {
		t.Fatal(err)
	}
	revision, err := store.kv.Create(ctx, spec.RolloutID, wire)
	if err != nil {
		t.Fatal(err)
	}
	state := CellState{SchemaVersion: SchemaVersion, Cell: "gru", ActiveRolloutID: spec.RolloutID, Attempts: map[string]int{toDigest: 1}}
	if err := store.writeCell(ctx, 7, state, 0); err != nil {
		t.Fatal(err)
	}
	resumed, resumedRevision, err := store.Begin(ctx, spec, testStart.Add(time.Minute))
	if err != nil || resumedRevision != revision || !resumed.StartedAt.Equal(record.StartedAt) {
		t.Fatalf("full record lost its identity/clock without history: %+v, %v", resumed, err)
	}
	if cell, _, err := store.Cell(ctx); err != nil || !maps.Equal(cell.Attempts, state.Attempts) {
		t.Fatalf("continuation changed the reservation count: %+v, %v", cell, err)
	}
}

type pausedPruneCellKV struct {
	jetstream.KeyValue
	armed   bool
	entered chan struct{}
	resume  chan struct{}
}

func (kv *pausedPruneCellKV) Update(ctx context.Context, key string, value []byte, revision uint64) (uint64, error) {
	result, err := kv.KeyValue.Update(ctx, key, value, revision)
	if key == desiredKey && err == nil {
		kv.armed = true
	}
	return result, err
}
func (kv *pausedPruneCellKV) Get(ctx context.Context, key string) (jetstream.KeyValueEntry, error) {
	entry, err := kv.KeyValue.Get(ctx, key)
	if key == cellKey && kv.armed {
		kv.armed = false
		close(kv.entered)
		select {
		case <-kv.resume:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return entry, err
}

func TestStalePublisherPreservesSuccessorReservationProof(t *testing.T) {
	store, fence := testStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if _, err := store.PublishRelease(ctx, 7, Release{Digest: toDigest, Actor: "ci", CreatedAt: testStart}); err != nil {
		t.Fatal(err)
	}
	for generation := 2; generation <= ReleaseHistory; generation++ {
		digest := fromDigest
		if generation%2 == 0 {
			digest = otherBad
		}
		if _, err := store.PublishRelease(ctx, 7, Release{Digest: digest, Actor: "ci", CreatedAt: testStart}); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.writeCell(ctx, 7, CellState{SchemaVersion: SchemaVersion, Cell: "gru"}, 0); err != nil {
		t.Fatal(err)
	}
	original := store.kv
	paused := &pausedPruneCellKV{KeyValue: original, entered: make(chan struct{}), resume: make(chan struct{})}
	store.kv = paused
	published := make(chan error, 1)
	go func() {
		_, err := store.PublishRelease(ctx, 7, Release{Digest: fromDigest, Actor: "ci", CreatedAt: testStart})
		published <- err
	}()
	select {
	case <-paused.entered:
	case <-ctx.Done():
		close(paused.resume)
		t.Fatal(ctx.Err())
	}
	fence.epoch.Store(8)
	id := testStageID(1)
	failure := errors.New("successor record Create failure")
	successor := &Store{kv: recordCreateFailureKV{KeyValue: original, key: id, err: failure}, fencer: fence, cell: "gru"}
	spec := testSpec(id)
	spec.AuthorityEpoch = 8
	if _, _, err := successor.Begin(ctx, spec, testStart); !errors.Is(err, failure) {
		close(paused.resume)
		<-published
		t.Fatalf("successor admission did not fail at actual Create: %v", err)
	}
	close(paused.resume)
	if err := <-published; err != nil {
		t.Fatal(err)
	}
	successor.kv = original
	if _, err := successor.ReleaseGeneration(ctx, 1); err != nil {
		t.Errorf("stale publisher deleted successor's generation proof: %v", err)
	}
	if err := successor.RecoverReservation(ctx, 8); err != nil {
		t.Fatal(err)
	}
	if state, _, err := successor.Cell(ctx); err != nil || state.ActiveRolloutID != "" || state.Attempts[toDigest] != 0 {
		t.Errorf("successor lost the refundable reservation: %+v %v", state, err)
	}
}
