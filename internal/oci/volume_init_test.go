package oci

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

type volumeInitTestFencer struct {
	snapshot authority.Snapshot
}

func (f volumeInitTestFencer) Current() authority.Snapshot { return f.snapshot }

func (f volumeInitTestFencer) Guard(ctx context.Context, epoch uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !f.snapshot.CanMutate() || f.snapshot.Epoch != epoch {
		return authority.ErrFenced
	}
	return nil
}

func (f volumeInitTestFencer) BeginActiveWorkloadEffect(ctx context.Context, epoch uint64,
	scope authority.WorkloadScope,
) (func(), error) {
	if scope.DatabaseID == "" || scope.PartitionID == "" {
		return nil, authority.ErrFenced
	}
	if err := f.Guard(ctx, epoch); err != nil {
		return nil, err
	}
	return func() {}, nil
}

func newVolumeInitFixture(t *testing.T) (*fleet, *fakeProvider, *KVJournal, VolumeInitializationPins, string) {
	t.Helper()
	config, regionIntent := testRegionConfig()
	provider := newFakeProvider(config)
	journal, err := NewKVJournal(testJournalBucket(t))
	if err != nil {
		t.Fatal(err)
	}
	api, err := newTestFleet(config, regionIntent, provider, journal,
		volumeInitTestFencer{snapshot: writableSnapshot()}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	fleet := api.(*fleet)
	host, err := fleet.EnsureHost(t.Context(), testEnsureRequest(entityid.Derive("test-operation", "volume-init-host")))
	if err != nil {
		t.Fatal(err)
	}
	instance := provider.instances[host.ID]
	instance.LifecycleState = "RUNNING"
	provider.instances[host.ID] = instance
	volume, err := fleet.CreateRetainedVolume(t.Context(), VolumeCreateRequest{
		Name: "gru-1-db-1-data", DatabaseID: "0000000000JJVVW9EMWY1PE1VX", PartitionID: "0000000000HE4W7FRNR204Q6TQ", CreateKey: "00000000005XQ4CBN4YC3ETEXN", SizeGB: 50,
	})
	if err != nil {
		t.Fatal(err)
	}
	cloudVolume := provider.volumes[volume.ID]
	cloudVolume.LifecycleState = "AVAILABLE"
	provider.volumes[volume.ID] = cloudVolume
	attachment, err := fleet.AttachRetainedVolume(t.Context(), VolumeAttachRequest{
		DatabaseID: "0000000000JJVVW9EMWY1PE1VX", PartitionID: "0000000000HE4W7FRNR204Q6TQ", VolumeID: volume.ID,
		InstanceID: host.ID, IdempotencyKey: entityid.Derive("test-attach", "volume-init-first-attach"),
	})
	if err != nil {
		t.Fatal(err)
	}
	pins := VolumeInitializationPins{
		DatabaseID: "0000000000JJVVW9EMWY1PE1VX", PartitionID: "0000000000HE4W7FRNR204Q6TQ", InstanceID: host.ID,
		HostCreateKey: host.CreateKey, VolumeID: volume.ID, AttachmentID: attachment.ID,
		AttachmentETag: attachment.ETag, Device: attachment.Device,
		FileSystemUUID: "12345678-1234-1234-1234-123456789abc", FileSystemType: "ext4",
	}
	return fleet, provider, journal, pins, host.BootDescriptorSHA256
}

func TestVolumeFormatPermitJournalOneWinnerAndImmutableBinding(t *testing.T) {
	kv := testJournalBucket(t)
	first, err := NewKVJournal(kv)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewKVJournal(kv)
	if err != nil {
		t.Fatal(err)
	}
	config, _ := testRegionConfig()
	record := VolumeFormatPermitRecord{
		Region: config.Region, Generation: config.Generation, Owner: config.Owner,
		DatabaseID: "0000000000JJVVW9EMWY1PE1VX", PartitionID: "0000000000HE4W7FRNR204Q6TQ",
		InstanceID: "ocid1.instance.format-owner", HostCreateKey: "0000000000DWTH9DFW5RRMYGPH",
		VolumeID: "ocid1.volume.format-once", AttachmentID: "ocid1.volumeattachment.format-once",
		AttachmentETag: "attachment-etag", Device: "/dev/oracleoci/oraclevdb",
		FileSystemUUID: "12345678-1234-1234-1234-123456789abc", FileSystemType: "ext4",
		BootDescriptorSHA256: strings.Repeat("a", 64),
	}
	type result struct {
		allowed bool
		err     error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	var calls sync.WaitGroup
	for _, journal := range []*KVJournal{first, second} {
		calls.Go(func() {
			<-start
			allowed, err := journal.ClaimVolumeFormatPermit(t.Context(), record)
			results <- result{allowed, err}
		})
	}
	close(start)
	calls.Wait()
	close(results)
	winners := 0
	for claim := range results {
		if claim.err != nil {
			t.Fatalf("exact concurrent claim failed: %v", claim.err)
		}
		if claim.allowed {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("two controller claims produced %d first-format winners", winners)
	}
	reopened, err := NewKVJournal(kv)
	if err != nil {
		t.Fatal(err)
	}
	if allowed, err := reopened.ClaimVolumeFormatPermit(t.Context(), record); err != nil || allowed {
		t.Fatalf("reopened controller reissued format permission: allowed=%v err=%v", allowed, err)
	}
	changed := record
	changed.InstanceID = "ocid1.instance.foreign"
	if allowed, err := reopened.ClaimVolumeFormatPermit(t.Context(), changed); err == nil || allowed {
		t.Fatalf("permit record accepted another host: allowed=%v err=%v", allowed, err)
	}
	if operations, err := reopened.ListOperations(t.Context()); err != nil || len(operations) != 0 {
		t.Fatalf("format record appeared as a pending OCI operation: operations=%d err=%v", len(operations), err)
	}
}
