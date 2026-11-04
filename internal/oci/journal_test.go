package oci

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

func TestJournalBootBindingSurvivesReopenAndRejectsRebinding(t *testing.T) {
	kv := testJournalBucket(t)
	if (JournalReader{}).Valid() || (JournalReader{journal: &KVJournal{}}).Valid() ||
		!(JournalReader{journal: &KVJournal{kv: kv}}).Valid() {
		t.Fatal("root fleet binding requires an existing durable journal")
	}
	journal, err := NewKVJournal(kv)
	if err != nil {
		t.Fatal(err)
	}
	config, _ := testRegionConfig()
	binding := BootBinding{InstanceID: "ocid1.instance.boot-binding", BootVolumeID: "ocid1.bootvolume.boot-binding",
		Region: config.Region, Generation: config.Generation, Owner: config.Owner, CreateKey: "00000000009R9M51DSAZK1GRKK",
		CompartmentID: config.CompartmentID, AvailabilityDomain: config.AvailabilityDomain,
		ImageID: config.ImageID, SizeGB: int64(config.BootVolumeGB), VPUsPerGB: int64(config.BootVolumeVPUsPerGB)}
	if err := journal.RecordBootBinding(t.Context(), binding); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewKVJournal(kv)
	if err != nil {
		t.Fatal(err)
	}
	got, found, err := reopened.GetBootBinding(t.Context(), binding.InstanceID)
	if err != nil || !found || got != binding {
		t.Fatalf("reopened journal lost exact boot binding: %+v found=%v err=%v", got, found, err)
	}
	if err := reopened.RecordBootBinding(t.Context(), binding); err != nil {
		t.Fatalf("idempotent binding failed: %v", err)
	}
	rebound := binding
	rebound.BootVolumeID = "ocid1.bootvolume.foreign"
	if err := reopened.RecordBootBinding(t.Context(), rebound); err == nil {
		t.Fatal("journal allowed boot volume rebinding")
	}
}

func testLaunchIntent(createKey string) OperationIntent {
	config, _ := testRegionConfig()
	request := testEnsureRequest(createKey)
	descriptor, err := (&fleet{config: config}).hostBootDescriptor(request, config.ImageID)
	if err != nil {
		panic(err)
	}
	wire, err := descriptor.CanonicalBytes()
	if err != nil {
		panic(err)
	}
	digest, err := descriptor.Digest()
	if err != nil {
		panic(err)
	}
	return OperationIntent{
		Action: actionLaunch, Key: createKey, Region: RegionGRU, Generation: 7,
		Owner: "orchestrator", CreateKey: createKey, PrivateIP: "10.251.0.21", FaultDomain: "FAULT-DOMAIN-1",
		Shape: "VM.Standard.E5.Flex", WholeOCPUs: 1, MemoryInGBs: 6,
		PlacementProfileDigest: strings.Repeat("a", 64), PlacementGeneration: 3,
		ImageID: config.ImageID, BootDescriptor: string(wire), BootDescriptorSHA256: digest,
		CreatedAt: time.Now().UTC(),
	}
}

func testJournalBucket(t *testing.T) jetstream.KeyValue {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	runtime, err := startAuthenticatedJournal(ctx, authenticatedJournalConfig(t, "oci-journal-test"))
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
