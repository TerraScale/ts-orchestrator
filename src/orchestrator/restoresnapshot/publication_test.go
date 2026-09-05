package restoresnapshot

import (
	"context"
	"encoding/json"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/provider"
)

func TestUploadCurrentTermPreservesArchiveEpoch(t *testing.T) {
	store, backend, state, epoch := fixture(t)
	*epoch = 19
	key := "jetstream/control/run.epoch-7.snapshot"
	body := []byte("archive captured in term seven")
	ctx := context.Background()
	if err := store.Put(ctx, "gru", "snapshots", key, body); err == nil {
		t.Fatal("old archive term authorized new upload")
	}
	if err := store.PutAtEpoch(ctx, "gru", "snapshots", key, body, 19); err != nil {
		t.Fatal(err)
	}
	foundIntent := false
	for _, raw := range state.values {
		var record provider.ProviderMutationRecord
		if json.Unmarshal(raw, &record) == nil && record.Intent.Action == "object.put" {
			foundIntent = true
			if record.Intent.Epoch.Value != 19 {
				t.Fatal("journal recorded archived authority")
			}
		}
	}
	if !foundIntent {
		t.Fatal("no durable upload mutation")
	}
	*epoch = 20
	if err := store.PutAtEpoch(ctx, "gru", "snapshots", key, body, 20); err != nil || backend.puts != 1 {
		t.Fatalf("immutable retry rewrote object: %v", err)
	}
	if err := store.PutAtEpoch(ctx, "sfo", "snapshots", key, body, 19); err == nil {
		t.Fatal("stale current term authorized destination upload")
	}
	if err := store.PutAtEpoch(ctx, "sfo", "snapshots", key, body, 20); err != nil {
		t.Fatal(err)
	}
}
func TestImmutablePublicationReceiptScope(t *testing.T) {
	store, backend, _, epoch := fixture(t)
	key := "jetstream/control/publication.receipt.json"
	body := []byte(`{"signed":"receipt"}`)
	if err := store.PutPublicationReceipt(context.Background(), "gru", "snapshots", key, body, *epoch); err != nil {
		t.Fatal(err)
	}
	if err := store.PutPublicationReceipt(context.Background(), "gru", "snapshots", key, body, *epoch); err != nil || backend.puts != 1 {
		t.Fatal("receipt retry changed object")
	}
	if err := store.PutPublicationReceipt(context.Background(), "gru", "snapshots", key, []byte("changed"), *epoch); err == nil {
		t.Fatal("receipt replacement accepted")
	}
	got, found, err := store.GetPublicationReceipt(context.Background(), "gru", "snapshots", key)
	if err != nil || !found || string(got) != string(body) {
		t.Fatal("receipt readback failed")
	}
	if _, _, err := store.GetSnapshot(context.Background(), "gru", "snapshots", key); err == nil {
		t.Fatal("receipt became snapshot")
	}
	for _, bad := range []string{"jetstream/control/arbitrary.receipt.json", "jetstream/control/run.epoch-7.snapshot", "jetstream/control/other/publication.receipt.json"} {
		if err := store.PutPublicationReceipt(context.Background(), "gru", "snapshots", bad, body, *epoch); err == nil {
			t.Fatal("receipt scope widened")
		}
	}
}

func TestRetrySettlesJournalAfterAcceptedUploadLostCompletion(t *testing.T) {
	store, backend, state, epoch := fixture(t)
	backend.afterPut = func() { state.mu.Lock(); state.fail = true; state.mu.Unlock() }
	body := []byte("archive")
	key := "jetstream/control/archive.epoch-7.snapshot"
	if err := store.PutAtEpoch(context.Background(), "gru", "snapshots", key, body, 7); err == nil {
		t.Fatal("lost journal completion reported success")
	}
	if backend.puts != 1 {
		t.Fatal("upload did not reach provider")
	}
	state.mu.Lock()
	state.fail = false
	state.mu.Unlock()
	backend.afterPut = nil
	*epoch = 19
	if err := store.PutAtEpoch(context.Background(), "gru", "snapshots", key, body, 19); err != nil {
		t.Fatal(err)
	}
	if backend.puts != 1 {
		t.Fatal("retry rewrote immutable snapshot")
	}
	settled := false
	for _, raw := range state.values {
		var record provider.ProviderMutationRecord
		if json.Unmarshal(raw, &record) == nil && record.Intent.Action == "object.put" {
			settled = true
			if record.State != provider.MutationSucceeded || record.Intent.Epoch.Value != 19 {
				t.Fatalf("unsettled journal %+v", record)
			}
		}
	}
	if !settled {
		t.Fatal("journal disappeared")
	}
}
