package oci

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/nats-io/nats.go/jetstream"
)

func TestRegionIntentUsesFixedProductMapping(t *testing.T) {
	valid := []byte(`{"schemaVersion":1,"generation":8,"bootstrapRegion":"GRU","regions":[{"cell":"GRU","ociRegion":"sa-saopaulo-1"},{"cell":"SFO","ociRegion":"us-sanjose-1"}]}`)
	intent, err := ParseRegionIntent(valid)
	if err != nil {
		t.Fatal(err)
	}
	config, _ := testRegionConfig()
	config.Generation = intent.Generation
	if err := config.Validate(intent); err != nil {
		t.Fatalf("valid GRU config rejected: %v", err)
	}
	wrongRegion := []byte(`{"schemaVersion":1,"generation":8,"bootstrapRegion":"GRU","regions":[{"cell":"GRU","ociRegion":"us-sanjose-1"}]}`)
	if _, err := ParseRegionIntent(wrongRegion); err == nil {
		t.Fatal("unsupported product-to-OCI mapping was accepted")
	}
	unknownField := []byte(`{"schemaVersion":1,"generation":8,"bootstrapRegion":"GRU","regions":[{"cell":"GRU","ociRegion":"sa-saopaulo-1"}],"endpoint":"https://elsewhere"}`)
	if _, err := ParseRegionIntent(unknownField); err == nil {
		t.Fatal("unknown region-intent field was accepted")
	}
}

func TestJournalRepairsOwnershipProjectionAfterPartialFailure(t *testing.T) {
	ctx := t.Context()
	kv := testJournalBucket(t)
	failing := &failOwnershipCreateKV{KeyValue: kv, failOnce: true}
	journal, err := NewKVJournal(failing)
	if err != nil {
		t.Fatal(err)
	}
	intent := testLaunchIntent("node-create-journal-1")
	if err := journal.RecordIntent(ctx, intent); err != nil {
		t.Fatal(err)
	}
	result := OperationResult{Intent: intent, ResourceID: "ocid1.instance.journal-a", ETag: "e1"}
	if err := journal.RecordResult(ctx, result); err == nil {
		t.Fatal("injected ownership projection failure was not surfaced")
	}
	identity := ResourceIdentity{
		ID: result.ResourceID, Region: intent.Region, Generation: intent.Generation,
		Owner: intent.Owner, CreateKey: intent.CreateKey,
	}
	owned, err := journal.IsOwnedInstance(ctx, identity)
	if err != nil || !owned {
		t.Fatalf("confirmed operation did not repair ownership on read: owned=%v err=%v", owned, err)
	}
	if err := journal.RecordResult(ctx, result); err != nil {
		t.Fatalf("idempotent result retry did not repair ownership: %v", err)
	}
}

func TestJournalDistinguishesFreshIntentFromUnknownProviderOutcome(t *testing.T) {
	ctx := t.Context()
	journal, err := NewKVJournal(testJournalBucket(t))
	if err != nil {
		t.Fatal(err)
	}
	intent := OperationIntent{
		Action: actionVolumeCreate, Key: "data-volume-unknown", Region: RegionGRU,
		Generation: 7, Owner: "orchestrator", CreateKey: "data-volume-unknown",
		AvailabilityDomain: "sa-saopaulo-1-AD-1", SizeGB: 50, CreatedAt: time.Now().UTC(),
	}
	if err := journal.RecordIntent(ctx, intent); err != nil {
		t.Fatal(err)
	}
	if _, found, err := journal.GetResult(ctx, intent); err != nil || found {
		t.Fatalf("fresh intent was misclassified as a provider attempt: found=%v err=%v", found, err)
	}
	unknown := OperationResult{Intent: intent, Unknown: true}
	if err := journal.RecordResult(ctx, unknown); err != nil {
		t.Fatal(err)
	}
	result, found, err := journal.GetResult(ctx, intent)
	if err != nil || !found || !result.Unknown {
		t.Fatalf("unknown provider result was not durably distinguished: found=%v result=%+v err=%v", found, result, err)
	}
	confirmed := OperationResult{Intent: intent, ResourceID: "ocid1.volume.journal-confirmed"}
	if err := journal.RecordResult(ctx, confirmed); err != nil {
		t.Fatalf("confirmed retry-token result was not accepted: %v", err)
	}
	identity := ResourceIdentity{
		ID: confirmed.ResourceID, Region: intent.Region, Generation: intent.Generation,
		Owner: intent.Owner, CreateKey: intent.CreateKey,
		AvailabilityDomain: intent.AvailabilityDomain, SizeGB: intent.SizeGB,
	}
	if owned, err := journal.IsOwnedVolume(ctx, identity); err != nil || !owned {
		t.Fatalf("confirmed volume identity was not durably owned: owned=%v err=%v", owned, err)
	}
	identity.SizeGB++
	if owned, err := journal.IsOwnedVolume(ctx, identity); err != nil || owned {
		t.Fatalf("journal ownership accepted a mismatched volume size: owned=%v err=%v", owned, err)
	}
}

func TestJournalConcurrentConflictingResultsHaveOneImmutableWinner(t *testing.T) {
	ctx := t.Context()
	kv := testJournalBucket(t)
	journal, err := NewKVJournal(kv)
	if err != nil {
		t.Fatal(err)
	}
	intent := testLaunchIntent("node-create-journal-race")
	if err := journal.RecordIntent(ctx, intent); err != nil {
		t.Fatal(err)
	}
	key := operationKey(intent)
	barrier := &barrierGetKV{KeyValue: kv, operationKey: key, release: make(chan struct{})}
	journal.kv = barrier
	results := []OperationResult{
		{Intent: intent, ResourceID: "ocid1.instance.winner-a", ETag: "ea"},
		{Intent: intent, ResourceID: "ocid1.instance.winner-b", ETag: "eb"},
	}
	errs := make(chan error, len(results))
	var callers sync.WaitGroup
	for _, result := range results {
		callers.Go(func() { errs <- journal.RecordResult(ctx, result) })
	}
	callers.Wait()
	close(errs)
	accepted, rejected := 0, 0
	for err := range errs {
		if err == nil {
			accepted++
		} else {
			rejected++
		}
	}
	if accepted != 1 || rejected != 1 {
		t.Fatalf("conflicting operation results did not have one winner: accepted=%d rejected=%d", accepted, rejected)
	}

	entry, err := kv.Get(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := decodeJournalEntry(entry.Value())
	if err != nil {
		t.Fatal(err)
	}
	if stored.Result.ResourceID == "" || stored.Result.Unknown {
		t.Fatalf("accepted operation result is incomplete: %+v", stored.Result)
	}
	for _, result := range results {
		identity := ResourceIdentity{
			ID: result.ResourceID, Region: intent.Region, Generation: intent.Generation,
			Owner: intent.Owner, CreateKey: intent.CreateKey,
		}
		owned, err := journal.IsOwnedInstance(ctx, identity)
		if err != nil {
			t.Fatal(err)
		}
		if owned != (result.ResourceID == stored.Result.ResourceID) {
			t.Fatalf("resource projection disagrees with immutable winner %q for candidate %q: owned=%v", stored.Result.ResourceID, result.ResourceID, owned)
		}
	}
}

func testLaunchIntent(createKey string) OperationIntent {
	return OperationIntent{
		Action: actionLaunch, Key: createKey, Region: RegionGRU, Generation: 7,
		Owner: "orchestrator", CreateKey: createKey, FaultDomain: "FAULT-DOMAIN-1",
		CreatedAt: time.Now().UTC(),
	}
}

func testJournalBucket(t *testing.T) jetstream.KeyValue {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	runtime, err := natscell.Start(ctx, natscell.Config{
		Cell: "lab", Instance: "oci-journal-test", Replicas: 1, Lab: true,
		Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: -1, StoreDir: filepath.Join(t.TempDir(), "jetstream")},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	journal, err := OpenJournal(ctx, runtime.JetStream(), 1)
	if err != nil {
		t.Fatal(err)
	}
	return journal.kv
}

type failOwnershipCreateKV struct {
	jetstream.KeyValue
	failOnce bool
}

func (kv *failOwnershipCreateKV) Create(ctx context.Context, key string, value []byte, opts ...jetstream.KVCreateOpt) (uint64, error) {
	if kv.failOnce && strings.HasPrefix(key, "instance.") {
		kv.failOnce = false
		return 0, errors.New("injected projection failure")
	}
	return kv.KeyValue.Create(ctx, key, value, opts...)
}

type barrierGetKV struct {
	jetstream.KeyValue
	operationKey string
	release      chan struct{}
	arrived      atomic.Int32
}

func (kv *barrierGetKV) Get(ctx context.Context, key string) (jetstream.KeyValueEntry, error) {
	entry, err := kv.KeyValue.Get(ctx, key)
	if err != nil || key != kv.operationKey {
		return entry, err
	}
	if kv.arrived.Add(1) == 2 {
		close(kv.release)
	}
	<-kv.release
	return entry, nil
}
