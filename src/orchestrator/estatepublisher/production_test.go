package estatepublisher

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/estate"
)

type fakeClient struct {
	mu      sync.Mutex
	puts    []fakePut
	deletes []fakeDelete
	list    []DocumentRef
	fail    error
}

type fakePut struct {
	id   string
	body string
	opts WriteOptions
}

type fakeDelete struct {
	id   string
	opts WriteOptions
}

func (f *fakeClient) PutDocument(_ context.Context, _ string, id string, body json.RawMessage, options WriteOptions) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return f.fail
	}
	f.puts = append(f.puts, fakePut{id: id, body: string(body), opts: options})
	return nil
}

func (f *fakeClient) ListDocuments(context.Context, string) ([]DocumentRef, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]DocumentRef(nil), f.list...), nil
}

func (f *fakeClient) DeleteDocument(_ context.Context, _ string, id string, options WriteOptions) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deletes = append(f.deletes, fakeDelete{id: id, opts: options})
	return nil
}

func testSnapshot(value any) func(context.Context) (estate.Snapshot, error) {
	return func(context.Context) (estate.Snapshot, error) {
		return estate.Snapshot{Regions: value, Hosts: value, Databases: value, Rollouts: value, SLO: value, Reconcile: value}, nil
	}
}

func TestProductionPublisherPublishesAllFamiliesAndOnlyChanges(t *testing.T) {
	client := &fakeClient{}
	var generation uint64 = 7
	snapshot := map[string]any{"state": "healthy"}
	publisher, err := New(Config{
		Client: client, Snapshot: testSnapshot(snapshot), Generation: generation,
		RetryMaxAttempts: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := publisher.Publish(context.Background())
	if err != nil || first.Writes != 6 || first.Generation != generation {
		t.Fatalf("first result = %+v, err=%v", first, err)
	}
	second, err := publisher.Publish(context.Background())
	if err != nil || second.Writes != 0 {
		t.Fatalf("unchanged result = %+v, err=%v", second, err)
	}
	snapshot["state"] = "degraded"
	third, err := publisher.Publish(context.Background())
	if err != nil || third.Writes != 6 {
		t.Fatalf("changed result = %+v, err=%v", third, err)
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if len(client.puts) != 12 {
		t.Fatalf("puts = %d, want 12", len(client.puts))
	}
	seen := map[string]bool{}
	for _, put := range client.puts[:6] {
		seen[put.id] = true
		if put.opts.Generation != generation || put.opts.IdempotencyKey == "" {
			t.Fatalf("write options = %+v", put.opts)
		}
	}
	for _, id := range DocumentIDs {
		if !seen[id] {
			t.Fatalf("family %q was not published", id)
		}
	}
}

func TestProductionPublisherFencesBeforeMutationAndExposesFailure(t *testing.T) {
	client := &fakeClient{}
	var generation uint64 = 2
	publisher, err := New(Config{
		Client: client, Snapshot: testSnapshot(map[string]any{"x": 1}),
		Authority: AuthorityFunc{
			GenerationFunc: func(context.Context) (uint64, error) { return generation, nil },
			FenceFunc: func(context.Context, uint64) error {
				if generation != 2 {
					return ErrFenced
				}
				return nil
			},
		}, RetryMaxAttempts: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Publish(context.Background()); err != nil {
		t.Fatal(err)
	}
	generation = 3
	if _, err := publisher.Publish(context.Background()); !errors.Is(err, ErrFenced) {
		t.Fatalf("error = %v, want fenced", err)
	}
	if publisher.Status().FailureCount != 1 || !publisher.Status().Fenced {
		t.Fatalf("status = %+v", publisher.Status())
	}
	if publisher.LastError() == nil {
		t.Fatal("failed pass is not visible")
	}
}

func TestProductionPublisherGenerationIsPartOfRevision(t *testing.T) {
	client := &fakeClient{}
	var generation uint64 = 1
	publisher, err := New(Config{
		Client: client, Snapshot: testSnapshot(map[string]any{"same": true}),
		Authority: AuthorityFunc{
			GenerationFunc: func(context.Context) (uint64, error) { return generation, nil },
		}, RetryMaxAttempts: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Publish(context.Background()); err != nil {
		t.Fatal(err)
	}
	generation = 2
	if result, err := publisher.Publish(context.Background()); err != nil || result.Writes != 6 {
		t.Fatalf("new-generation result = %+v, err=%v", result, err)
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.puts[0].opts.IdempotencyKey == client.puts[6].opts.IdempotencyKey {
		t.Fatal("different generations reused an idempotency key")
	}
}

func TestProductionPublisherRemovesUnknownEstateDocuments(t *testing.T) {
	client := &fakeClient{list: []DocumentRef{{ID: "regions"}, {ID: "retired-family"}}}
	publisher, err := New(Config{Client: client, Snapshot: testSnapshot(nil), Generation: 1, RetryMaxAttempts: 1})
	if err != nil {
		t.Fatal(err)
	}
	result, err := publisher.Publish(context.Background())
	if err != nil || result.Deletes != 1 {
		t.Fatalf("result = %+v, err=%v", result, err)
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if len(client.deletes) != 1 || client.deletes[0].id != "retired-family" {
		t.Fatalf("deletes = %+v", client.deletes)
	}
	if client.deletes[0].opts.Generation != 1 || client.deletes[0].opts.IdempotencyKey == "" {
		t.Fatalf("delete options = %+v", client.deletes[0].opts)
	}
}

func TestProductionPublisherRedactsAndBoundsPayload(t *testing.T) {
	client := &fakeClient{}
	publisher, err := New(Config{
		Client:     client,
		Snapshot:   testSnapshot(map[string]any{"APIKey": "do-not-publish", "healthy": true}),
		Generation: 1, RetryMaxAttempts: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Publish(context.Background()); err != nil {
		t.Fatal(err)
	}
	client.mu.Lock()
	for _, put := range client.puts {
		if strings.Contains(put.body, "do-not-publish") {
			t.Fatalf("secret leaked in %s", put.body)
		}
	}
	client.mu.Unlock()
	bounded, err := New(Config{Client: &fakeClient{}, Snapshot: testSnapshot(map[string]any{"large": "value"}), Generation: 1, MaxDocumentBytes: 4, RetryMaxAttempts: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bounded.Publish(context.Background()); !errors.Is(err, ErrPayloadBounds) {
		t.Fatalf("bounded error = %v, want payload bounds", err)
	}
}

func TestProductionPublisherSerializesConcurrentPassesAndStartNotifications(t *testing.T) {
	client := &fakeClient{}
	publisher, err := New(Config{Client: client, Snapshot: testSnapshot(map[string]any{"x": 1}), Generation: 1, Interval: time.Hour, RetryMaxAttempts: 1})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = publisher.Publish(context.Background())
		}()
	}
	wg.Wait()
	client.mu.Lock()
	puts := len(client.puts)
	client.mu.Unlock()
	if puts != 6 {
		t.Fatalf("concurrent puts = %d, want 6", puts)
	}
	ready := make(chan struct{}, 1)
	publisher.onSuccess = func(PublishResult) {
		select {
		case ready <- struct{}{}:
		default:
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := publisher.Start(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("initial start pass did not complete")
	}
	publisher.NotifyChange()
	cancel()
	if err := publisher.Close(); err != nil {
		t.Fatal(err)
	}
}
