package estatepublisher

import (
	"context"
	"errors"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/estate"
)

func TestProductionPublisherRejectsUnboundedLabelsBeforeMutation(t *testing.T) {
	client := &fakeClient{}
	publisher, err := NewProductionPublisher(Config{
		Client: client,
		Snapshot: func(context.Context) (estate.Snapshot, error) {
			value := map[string]any{"labels": map[string]string{"tenant_id": "customer-1"}}
			return estate.Snapshot{Regions: value, Hosts: value, Databases: value, Rollouts: value, SLO: value, Reconcile: value}, nil
		},
		Generation:       1,
		RetryMaxAttempts: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Publish(t.Context()); !errors.Is(err, ErrLabelPolicy) {
		t.Fatalf("publish error = %v, want label policy failure", err)
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if len(client.puts) != 0 {
		t.Fatalf("unsafe label document reached the client: %d puts", len(client.puts))
	}
}

func TestProductionPublisherAcceptsClosedLabels(t *testing.T) {
	client := &fakeClient{}
	value := map[string]any{"labels": map[string]string{"region": "gru", "subsystem": "orchestrator"}}
	publisher, err := NewProductionPublisher(Config{
		Client: client, Snapshot: testSnapshot(value), Generation: 1, RetryMaxAttempts: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := publisher.Publish(t.Context())
	if err != nil || result.Writes != len(DocumentIDs) {
		t.Fatalf("publish result = %+v, err = %v", result, err)
	}
}
