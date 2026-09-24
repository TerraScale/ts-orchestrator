package oci

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
)

func TestEnsureHostRecoversLostLaunchResponse(t *testing.T) {
	ctx := t.Context()
	config, intent := testRegionConfig()
	provider := newFakeProvider(config)
	provider.launchErrorAfterCreate = errors.New("response dropped")
	journal := newFakeJournal()
	fencer := &fakeFencer{snapshot: writableSnapshot()}
	fleet, err := NewFleet(config, intent, provider, journal, fencer, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	want, err := fleet.EnsureHost(ctx, EnsureRequest{CreateKey: "node-create-01", FaultDomain: "FAULT-DOMAIN-1"})
	if err != nil {
		t.Fatalf("EnsureHost after lost response: %v", err)
	}
	if provider.launches != 1 || want.ID == "" || want.Node == "" || want.State != "PROVISIONING" {
		t.Fatalf("unexpected recovered host: launches=%d host=%+v", provider.launches, want)
	}

	again, err := fleet.EnsureHost(ctx, EnsureRequest{CreateKey: "node-create-01", FaultDomain: "FAULT-DOMAIN-1"})
	if err != nil {
		t.Fatalf("idempotent EnsureHost: %v", err)
	}
	if provider.launches != 1 || again.ID != want.ID || again.Node != want.Node {
		t.Fatalf("retry created or changed host: launches=%d first=%+v retry=%+v", provider.launches, want, again)
	}
}

func TestStaleLeaderCannotLaunch(t *testing.T) {
	ctx := t.Context()
	config, intent := testRegionConfig()
	provider := newFakeProvider(config)
	journal := newFakeJournal()
	fencer := &fakeFencer{snapshot: writableSnapshot(), guardErr: authority.ErrFenced}
	fleet, err := NewFleet(config, intent, provider, journal, fencer, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = fleet.EnsureHost(ctx, EnsureRequest{CreateKey: "node-create-02", FaultDomain: "FAULT-DOMAIN-1"})
	if !errors.Is(err, authority.ErrFenced) {
		t.Fatalf("expected stale leader fence, got %v", err)
	}
	if provider.launches != 0 || len(journal.intents) != 0 {
		t.Fatalf("fenced candidate mutated state: launches=%d intents=%d", provider.launches, len(journal.intents))
	}
}

func TestEnsureHostRefusesForeignResourceWithSameCreateKey(t *testing.T) {
	ctx := t.Context()
	config, intent := testRegionConfig()
	provider := newFakeProvider(config)
	foreign := CloudInstance{
		ID: "ocid1.instance.foreign", CompartmentID: config.CompartmentID,
		AvailabilityDomain: config.AvailabilityDomain, FaultDomain: "FAULT-DOMAIN-1",
		LifecycleState: "RUNNING", ETag: "e1",
		FreeformTags: map[string]string{
			tagManagedBy: managedByValue, tagOwner: "another-owner", tagRegion: string(config.Region),
			tagGeneration: fmt.Sprint(config.Generation), tagResource: resourceMemberHost,
			tagCreateKey: "shared-create-key", tagHostNode: "host-foreign",
		},
	}
	provider.instances[foreign.ID] = foreign
	fleet, err := NewFleet(config, intent, provider, newFakeJournal(), &fakeFencer{snapshot: writableSnapshot()}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = fleet.EnsureHost(ctx, EnsureRequest{CreateKey: "shared-create-key", FaultDomain: "FAULT-DOMAIN-1"})
	if !errors.Is(err, ErrForeignResource) {
		t.Fatalf("expected ownership refusal, got %v", err)
	}
	if provider.launches != 0 {
		t.Fatalf("foreign collision was followed by a launch (%d)", provider.launches)
	}
}

func TestEnsureHostDoesNotAdoptMatchingTagsWithoutJournalProof(t *testing.T) {
	ctx := t.Context()
	config, intent := testRegionConfig()
	provider := newFakeProvider(config)
	createKey := "node-seeded-unowned"
	provider.instances["ocid1.instance.seeded"] = CloudInstance{
		ID: "ocid1.instance.seeded", CompartmentID: config.CompartmentID,
		AvailabilityDomain: config.AvailabilityDomain, FaultDomain: "FAULT-DOMAIN-1",
		LifecycleState: "RUNNING", ETag: "seed-etag", FreeformTags: hostTags(config, createKey),
	}
	journal := newFakeJournal()
	fleet, err := NewFleet(config, intent, provider, journal, &fakeFencer{snapshot: writableSnapshot()}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = fleet.EnsureHost(ctx, EnsureRequest{CreateKey: createKey, FaultDomain: "FAULT-DOMAIN-1"})
	if !errors.Is(err, ErrForeignResource) {
		t.Fatalf("unowned matching-tag instance was adopted instead of refused: %v", err)
	}
	if len(journal.instances) != 0 || provider.launches != 0 {
		t.Fatalf("matching tags triggered a launch or established ownership: launches=%d ownership=%+v", provider.launches, journal.instances)
	}
}

func TestCreateRetainedVolumeRecoversLostResponseAndIsIdempotent(t *testing.T) {
	ctx := t.Context()
	config, intent := testRegionConfig()
	provider := newFakeProvider(config)
	provider.volumeCreateErrorAfterCreate = errors.New("response dropped")
	journal := newFakeJournal()
	fleet, err := NewFleet(config, intent, provider, journal, &fakeFencer{snapshot: writableSnapshot()}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	request := VolumeCreateRequest{CreateKey: "data-volume-create-01", SizeGB: 50}
	created, err := fleet.CreateRetainedVolume(ctx, request)
	if err != nil {
		t.Fatalf("CreateRetainedVolume after lost response: %v", err)
	}
	if created.ID == "" || created.Region != config.Region || created.Generation != config.Generation ||
		created.Owner != config.Owner || created.AvailabilityDomain != config.AvailabilityDomain || created.SizeGB != request.SizeGB {
		t.Fatalf("recovered volume has incomplete identity: %+v", created)
	}
	if provider.volumeCreates != 1 || provider.volumeCreateCalls != 2 {
		t.Fatalf("lost response was not safely replayed: creates=%d calls=%d", provider.volumeCreates, provider.volumeCreateCalls)
	}
	identity := ResourceIdentity{
		ID: created.ID, Region: created.Region, Generation: created.Generation,
		Owner: created.Owner, CreateKey: created.CreateKey,
		AvailabilityDomain: created.AvailabilityDomain, SizeGB: created.SizeGB,
	}
	if owned, err := journal.IsOwnedVolume(ctx, identity); err != nil || !owned {
		t.Fatalf("confirmed volume is not journal-owned: owned=%v err=%v", owned, err)
	}

	retried, err := fleet.CreateRetainedVolume(ctx, request)
	if err != nil || retried.ID != created.ID || provider.volumeCreates != 1 || provider.volumeCreateCalls != 2 {
		t.Fatalf("same create key did not remain idempotent: first=%+v retry=%+v creates=%d calls=%d err=%v",
			created, retried, provider.volumeCreates, provider.volumeCreateCalls, err)
	}
}

func TestCreateRetainedVolumeRejectsForeignScopeAndDuplicateCreateKeys(t *testing.T) {
	ctx := t.Context()
	config, intent := testRegionConfig()
	provider := newFakeProvider(config)
	provider.volumes["ocid1.volume.foreign"] = CloudVolume{
		ID: "ocid1.volume.foreign", CompartmentID: config.CompartmentID,
		AvailabilityDomain: config.AvailabilityDomain, SizeGB: 50, LifecycleState: "AVAILABLE",
		FreeformTags: map[string]string{
			tagManagedBy: managedByValue, tagOwner: "another-owner", tagRegion: string(config.Region),
			tagGeneration: fmt.Sprint(config.Generation), tagResource: resourceMemberData,
			tagCreateKey: "data-volume-foreign", tagVolumeSize: "50",
		},
	}
	fleet, err := NewFleet(config, intent, provider, newFakeJournal(), &fakeFencer{snapshot: writableSnapshot()}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fleet.CreateRetainedVolume(ctx, VolumeCreateRequest{CreateKey: "data-volume-foreign", SizeGB: 50}); !errors.Is(err, ErrForeignResource) {
		t.Fatalf("foreign tagged volume was not refused: %v", err)
	}
	if provider.volumeCreates != 0 {
		t.Fatalf("foreign tagged volume triggered an OCI create: %d", provider.volumeCreates)
	}

	config, intent = testRegionConfig()
	provider = newFakeProvider(config)
	key := "data-volume-seeded-unowned"
	provider.volumes["ocid1.volume.seeded"] = CloudVolume{
		ID: "ocid1.volume.seeded", CompartmentID: config.CompartmentID,
		AvailabilityDomain: config.AvailabilityDomain, SizeGB: 50, LifecycleState: "AVAILABLE",
		FreeformTags: volumeTags(config, VolumeCreateRequest{CreateKey: key, SizeGB: 50}),
	}
	fleet, err = NewFleet(config, intent, provider, newFakeJournal(), &fakeFencer{snapshot: writableSnapshot()}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fleet.CreateRetainedVolume(ctx, VolumeCreateRequest{CreateKey: key, SizeGB: 50}); !errors.Is(err, ErrRetainedVolumeUnknown) {
		t.Fatalf("unowned matching-tag volume was adopted instead of refused: %v", err)
	}
	if provider.volumeCreates != 0 {
		t.Fatalf("unowned matching-tag volume triggered a create: %d", provider.volumeCreates)
	}

	config, intent = testRegionConfig()
	provider = newFakeProvider(config)
	journal := newFakeJournal()
	fleet, err = NewFleet(config, intent, provider, journal, &fakeFencer{snapshot: writableSnapshot()}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	created, err := fleet.CreateRetainedVolume(ctx, VolumeCreateRequest{CreateKey: "data-volume-duplicate", SizeGB: 64})
	if err != nil {
		t.Fatal(err)
	}
	duplicate := provider.volumes[created.ID]
	duplicate.ID = "ocid1.volume.duplicate"
	provider.volumes[duplicate.ID] = duplicate
	if _, err := fleet.CreateRetainedVolume(ctx, VolumeCreateRequest{CreateKey: "data-volume-duplicate", SizeGB: 64}); !errors.Is(err, ErrDuplicateCreateKey) {
		t.Fatalf("duplicate create key selected an arbitrary volume: %v", err)
	}
}

func TestCreateRetainedVolumePinsProfileBeforeMutation(t *testing.T) {
	ctx := t.Context()
	config, intent := testRegionConfig()
	provider := newFakeProvider(config)
	fleet, err := NewFleet(config, intent, provider, newFakeJournal(), &fakeFencer{snapshot: writableSnapshot()}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, request := range []VolumeCreateRequest{
		{CreateKey: "too-small", SizeGB: 49},
		{CreateKey: "wrong-ad", SizeGB: 50, AvailabilityDomain: "another-AD"},
	} {
		if _, err := fleet.CreateRetainedVolume(ctx, request); err == nil {
			t.Fatalf("invalid volume profile was accepted: %+v", request)
		}
	}
	if provider.volumeCreates != 0 {
		t.Fatalf("invalid profile reached OCI: %d creates", provider.volumeCreates)
	}
}

func TestCreateRetainedVolumeDoesNotReplayAfterAuthorityIsFenced(t *testing.T) {
	ctx := t.Context()
	config, intent := testRegionConfig()
	provider := newFakeProvider(config)
	provider.volumeCreateErrorAfterCreate = errors.New("response dropped")
	fencer := &fakeFencer{snapshot: writableSnapshot()}
	provider.afterVolumeCreate = func() { fencer.guardErr = authority.ErrFenced }
	journal := newFakeJournal()
	fleet, err := NewFleet(config, intent, provider, journal, fencer, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = fleet.CreateRetainedVolume(ctx, VolumeCreateRequest{CreateKey: "data-volume-fenced-retry", SizeGB: 50})
	if !errors.Is(err, authority.ErrFenced) || !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("lost response was replayed after authority fencing: %v", err)
	}
	if provider.volumeCreateCalls != 1 || len(journal.volumes) != 0 {
		t.Fatalf("fenced retry mutated or confirmed ownership: calls=%d owned=%+v", provider.volumeCreateCalls, journal.volumes)
	}
}

func TestCreateRetainedVolumeKeepsUnconfirmedOutcomeUnowned(t *testing.T) {
	ctx := t.Context()
	config, intent := testRegionConfig()
	provider := newFakeProvider(config)
	provider.volumeCreateErrorAfterCreate = errors.New("first response dropped")
	provider.volumeRetryReplayError = errors.New("retry response dropped")
	journal := newFakeJournal()
	fleet, err := NewFleet(config, intent, provider, journal, &fakeFencer{snapshot: writableSnapshot()}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	request := VolumeCreateRequest{CreateKey: "data-volume-unconfirmed", SizeGB: 50}
	if _, err := fleet.CreateRetainedVolume(ctx, request); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("ambiguous provider outcome was not held: %v", err)
	}
	intentRecord := OperationIntent{
		Action: actionVolumeCreate, Key: request.CreateKey, Region: config.Region,
		Generation: config.Generation, Owner: config.Owner, CreateKey: request.CreateKey,
		AvailabilityDomain: config.AvailabilityDomain, SizeGB: request.SizeGB, CreatedAt: time.Now().UTC(),
	}
	result, found, err := journal.GetResult(ctx, intentRecord)
	if err != nil || !found || !result.Unknown || len(journal.volumes) != 0 {
		t.Fatalf("ambiguous volume was incorrectly confirmed: found=%v result=%+v owned=%+v err=%v",
			found, result, journal.volumes, err)
	}
	var ambiguousVolumeID string
	for id, volume := range provider.volumes {
		if volume.FreeformTags[tagCreateKey] == request.CreateKey {
			ambiguousVolumeID = id
		}
	}
	if ambiguousVolumeID == "" {
		t.Fatal("test provider did not retain the ambiguous volume")
	}

	host, err := fleet.EnsureHost(ctx, EnsureRequest{CreateKey: "node-unconfirmed-volume", FaultDomain: "FAULT-DOMAIN-1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fleet.AttachRetainedVolume(ctx, VolumeAttachRequest{
		VolumeID: ambiguousVolumeID, InstanceID: host.ID, IdempotencyKey: "attach-unconfirmed-volume",
	}); !errors.Is(err, ErrRetainedVolumeUnknown) {
		t.Fatalf("unconfirmed retained volume was attachable: %v", err)
	}
}

func TestTerminateRequiresNoAttachedVolumeAndVerifiedWriterStop(t *testing.T) {
	ctx := t.Context()
	config, intent := testRegionConfig()
	provider := newFakeProvider(config)
	journal := newFakeJournal()
	fencer := &fakeFencer{snapshot: writableSnapshot()}
	writerStop := &fakeWriterStop{}
	fleet, err := NewFleet(config, intent, provider, journal, fencer, nil, writerStop)
	if err != nil {
		t.Fatal(err)
	}
	host, err := fleet.EnsureHost(ctx, EnsureRequest{CreateKey: "node-create-03", FaultDomain: "FAULT-DOMAIN-1"})
	if err != nil {
		t.Fatal(err)
	}
	provider.attachments["attachment-1"] = CloudAttachment{
		ID: "attachment-1", VolumeID: "volume-1", InstanceID: host.ID,
		LifecycleState: "ATTACHED", ETag: "a1",
	}

	err = fleet.Terminate(ctx, host.ID, host.ETag, WriterStopEvidence("verified"))
	if err == nil || !strings.Contains(err.Error(), "detach and retain") {
		t.Fatalf("termination with attached retained volume should be held, got %v", err)
	}
	if provider.terminations != 0 || writerStop.instanceChecks != 0 {
		t.Fatalf("unsafe termination path ran: terminations=%d writerChecks=%d", provider.terminations, writerStop.instanceChecks)
	}

	delete(provider.attachments, "attachment-1")
	writerStop.instanceErr = ErrWriterStopUnverified
	err = fleet.Terminate(ctx, host.ID, host.ETag, WriterStopEvidence("invalid"))
	if !errors.Is(err, ErrWriterStopUnverified) {
		t.Fatalf("termination without proof should fail closed, got %v", err)
	}
	if provider.terminations != 0 {
		t.Fatalf("invalid proof still terminated the host: %d", provider.terminations)
	}
}

func TestRetainedVolumeAttachRequiresDurableOwnership(t *testing.T) {
	ctx := t.Context()
	config, intent := testRegionConfig()
	provider := newFakeProvider(config)
	journal := newFakeJournal()
	fleet, err := NewFleet(config, intent, provider, journal, &fakeFencer{snapshot: writableSnapshot()}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	host, err := fleet.EnsureHost(ctx, EnsureRequest{CreateKey: "node-create-04", FaultDomain: "FAULT-DOMAIN-1"})
	if err != nil {
		t.Fatal(err)
	}
	volumeKey := "data-volume-01"
	provider.volumes["ocid1.volume.retained"] = CloudVolume{
		ID: "ocid1.volume.retained", CompartmentID: config.CompartmentID,
		AvailabilityDomain: config.AvailabilityDomain, SizeGB: 50, LifecycleState: "AVAILABLE", FreeformTags: map[string]string{
			tagManagedBy: managedByValue, tagOwner: config.Owner, tagRegion: string(config.Region),
			tagGeneration: fmt.Sprint(config.Generation), tagResource: resourceMemberData, tagCreateKey: volumeKey,
			tagVolumeSize: "50",
		},
	}

	_, err = fleet.AttachRetainedVolume(ctx, VolumeAttachRequest{
		VolumeID: "ocid1.volume.retained", InstanceID: host.ID, IdempotencyKey: "attach-volume-01",
	})
	if !errors.Is(err, ErrRetainedVolumeUnknown) {
		t.Fatalf("untagged/unjournaled volume must not be adopted, got %v", err)
	}
	if provider.attachCalls != 0 {
		t.Fatalf("unowned volume was attached: %d", provider.attachCalls)
	}
}

func TestObserveReturnsOnlyDurablyOwnedInstancesAndTerminalState(t *testing.T) {
	ctx := t.Context()
	config, intent := testRegionConfig()
	provider := newFakeProvider(config)
	journal := newFakeJournal()
	fleet, err := NewFleet(config, intent, provider, journal, &fakeFencer{snapshot: writableSnapshot()}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	host, err := fleet.EnsureHost(ctx, EnsureRequest{CreateKey: "node-create-05", FaultDomain: "FAULT-DOMAIN-1"})
	if err != nil {
		t.Fatal(err)
	}
	current := provider.instances[host.ID]
	current.LifecycleState = "TERMINATED"
	provider.instances[host.ID] = current

	observed, err := fleet.Observe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(observed) != 1 || observed[0].State != "TERMINATED" || observed[0].Node != host.Node {
		t.Fatalf("terminal owned host was not preserved as an observation: %+v", observed)
	}
}

func TestObserveSkipsUnverifiedIdentitiesWithoutBlockingOwnedInstances(t *testing.T) {
	ctx := t.Context()
	config, intent := testRegionConfig()
	provider := newFakeProvider(config)
	journal := newFakeJournal()
	fleet, err := NewFleet(config, intent, provider, journal, &fakeFencer{snapshot: writableSnapshot()}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	owned, err := fleet.EnsureHost(ctx, EnsureRequest{CreateKey: "node-owned-observation", FaultDomain: "FAULT-DOMAIN-1"})
	if err != nil {
		t.Fatal(err)
	}
	foreignConfig := config
	foreignConfig.Generation--
	provider.instances["ocid1.instance.old-generation"] = CloudInstance{
		ID: "ocid1.instance.old-generation", CompartmentID: config.CompartmentID,
		AvailabilityDomain: config.AvailabilityDomain, FaultDomain: "FAULT-DOMAIN-1",
		LifecycleState: "RUNNING", ETag: "old-etag", FreeformTags: hostTags(foreignConfig, "node-old-generation"),
	}
	provider.instances["ocid1.instance.tag-only"] = CloudInstance{
		ID: "ocid1.instance.tag-only", CompartmentID: config.CompartmentID,
		AvailabilityDomain: config.AvailabilityDomain, FaultDomain: "FAULT-DOMAIN-1",
		LifecycleState: "RUNNING", ETag: "tag-only-etag", FreeformTags: hostTags(config, "node-tag-only"),
	}

	observed, err := fleet.Observe(ctx)
	if err != nil {
		t.Fatalf("unverified instance blocked owned fleet observation: %v", err)
	}
	if len(observed) != 1 || observed[0].ID != owned.ID || len(journal.instances) != 1 || provider.launches != 1 {
		t.Fatalf("observation returned or mutated an unverified host: observed=%+v owned=%+v launches=%d",
			observed, journal.instances, provider.launches)
	}
}

func TestObserveAllowsEnsureHostToRecoverDurableUnknownLaunch(t *testing.T) {
	ctx := t.Context()
	config, intent := testRegionConfig()
	provider := newFakeProvider(config)
	journal := newFakeJournal()
	fleet, err := NewFleet(config, intent, provider, journal, &fakeFencer{snapshot: writableSnapshot()}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	createKey := "node-durable-unknown"
	operation := OperationIntent{
		Action: actionLaunch, Key: createKey, Region: config.Region, Generation: config.Generation,
		Owner: config.Owner, CreateKey: createKey, FaultDomain: "FAULT-DOMAIN-1", CreatedAt: time.Now().UTC(),
	}
	if err := journal.RecordIntent(ctx, operation); err != nil {
		t.Fatal(err)
	}
	if err := journal.RecordResult(ctx, OperationResult{Intent: operation, Unknown: true}); err != nil {
		t.Fatal(err)
	}
	instanceID := "ocid1.instance.unknown-launch"
	provider.instances[instanceID] = CloudInstance{
		ID: instanceID, CompartmentID: config.CompartmentID, AvailabilityDomain: config.AvailabilityDomain,
		FaultDomain: "FAULT-DOMAIN-1", LifecycleState: "PROVISIONING", ETag: "unknown-etag",
		FreeformTags: hostTags(config, createKey),
	}
	provider.launchRetryTokens[retryToken(strings.Join([]string{
		config.Owner, string(config.Region), fmt.Sprint(config.Generation), createKey,
	}, ":"))] = instanceID

	observed, err := fleet.Observe(ctx)
	if err != nil || len(observed) != 0 {
		t.Fatalf("unconfirmed launch should be withheld without blocking Observe: observed=%+v err=%v", observed, err)
	}
	recovered, err := fleet.EnsureHost(ctx, EnsureRequest{CreateKey: createKey, FaultDomain: "FAULT-DOMAIN-1"})
	if err != nil || recovered.ID != instanceID {
		t.Fatalf("durable unknown launch was not recovered through retry-token proof: recovered=%+v err=%v", recovered, err)
	}
	observed, err = fleet.Observe(ctx)
	if err != nil || len(observed) != 1 || observed[0].ID != instanceID {
		t.Fatalf("confirmed launch was not returned as an owned observation: observed=%+v err=%v", observed, err)
	}
}

func testRegionConfig() (RegionConfig, RegionIntent) {
	intent := RegionIntent{
		SchemaVersion: 1, Generation: 7, BootstrapRegion: RegionGRU,
		Regions: []RegionMapping{{Cell: RegionGRU, OCIRegion: "sa-saopaulo-1"}},
	}
	return RegionConfig{
		Region: RegionGRU, Generation: intent.Generation,
		Endpoint:                "https://iaas.sa-saopaulo-1.oraclecloud.com",
		CompartmentID:           "ocid1.compartment.oc1..aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		AvailabilityDomain:      "sa-saopaulo-1-AD-1",
		FaultDomains:            []string{"FAULT-DOMAIN-1", "FAULT-DOMAIN-2"},
		SubnetID:                "ocid1.subnet.oc1.sa-saopaulo-1.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		NetworkSecurityGroupIDs: []string{"ocid1.networksecuritygroup.oc1.sa-saopaulo-1.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		ImageID:                 "ocid1.image.oc1.sa-saopaulo-1.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Shape:                   "VM.Standard.E5.Flex", Owner: "orchestrator",
	}, intent
}

func writableSnapshot() authority.Snapshot {
	return authority.Snapshot{
		CandidateID: "candidate-1", Leader: true, Ready: true, Epoch: 4, Revision: 9,
		ExpiresAt: time.Now().Add(time.Minute), ObservedAt: time.Now(),
	}
}

type fakeFencer struct {
	snapshot authority.Snapshot
	guardErr error
	guards   int
}

func (f *fakeFencer) Current() authority.Snapshot { return f.snapshot }
func (f *fakeFencer) Guard(context.Context, uint64) error {
	f.guards++
	return f.guardErr
}

type fakeJournal struct {
	intents   map[string]OperationIntent
	results   map[string]OperationResult
	instances map[string]ResourceIdentity
	volumes   map[string]ResourceIdentity
}

func newFakeJournal() *fakeJournal {
	return &fakeJournal{
		intents: make(map[string]OperationIntent), results: make(map[string]OperationResult),
		instances: make(map[string]ResourceIdentity),
		volumes:   make(map[string]ResourceIdentity),
	}
}

func (j *fakeJournal) RecordIntent(_ context.Context, intent OperationIntent) error {
	key := operationKey(intent)
	if current, exists := j.intents[key]; exists && !sameIntent(current, intent) {
		return errors.New("operation key conflict")
	}
	j.intents[key] = intent
	return nil
}

func (j *fakeJournal) RecordResult(_ context.Context, result OperationResult) error {
	key := operationKey(result.Intent)
	if _, ok := j.intents[key]; !ok {
		return errors.New("missing intent")
	}
	j.results[key] = result
	if result.Unknown || result.ResourceID == "" {
		return nil
	}
	identity := ResourceIdentity{
		ID: result.ResourceID, Region: result.Intent.Region, Generation: result.Intent.Generation,
		Owner: result.Intent.Owner, CreateKey: result.Intent.CreateKey,
	}
	switch result.Intent.Action {
	case actionLaunch:
		j.instances[identity.ID] = identity
	case actionVolumeCreate:
		identity.AvailabilityDomain = result.Intent.AvailabilityDomain
		identity.SizeGB = result.Intent.SizeGB
		j.volumes[identity.ID] = identity
	}
	return nil
}

func (j *fakeJournal) GetResult(_ context.Context, intent OperationIntent) (OperationResult, bool, error) {
	result, ok := j.results[operationKey(intent)]
	return result, ok, nil
}

func (j *fakeJournal) IsOwnedInstance(_ context.Context, identity ResourceIdentity) (bool, error) {
	return j.instances[identity.ID] == identity, nil
}

func (j *fakeJournal) IsOwnedVolume(_ context.Context, identity ResourceIdentity) (bool, error) {
	return j.volumes[identity.ID] == identity, nil
}

type fakeWriterStop struct {
	volumeErr      error
	instanceErr    error
	volumeChecks   int
	instanceChecks int
}

func (v *fakeWriterStop) VerifyVolumeWriterStopped(context.Context, Region, string, string, WriterStopEvidence) error {
	v.volumeChecks++
	return v.volumeErr
}
func (v *fakeWriterStop) VerifyInstanceWritersStopped(context.Context, Region, string, WriterStopEvidence) error {
	v.instanceChecks++
	return v.instanceErr
}

type fakeProvider struct {
	config                       RegionConfig
	instances                    map[string]CloudInstance
	launchRetryTokens            map[string]string
	volumes                      map[string]CloudVolume
	volumeRetryTokens            map[string]string
	attachments                  map[string]CloudAttachment
	launches                     int
	launchCalls                  int
	launchErrorAfterCreate       error
	volumeCreates                int
	volumeCreateCalls            int
	volumeCreateErrorAfterCreate error
	volumeRetryReplayError       error
	afterVolumeCreate            func()
	attachCalls                  int
	terminations                 int
}

func newFakeProvider(config RegionConfig) *fakeProvider {
	return &fakeProvider{
		config: config, instances: make(map[string]CloudInstance), launchRetryTokens: make(map[string]string),
		volumes: make(map[string]CloudVolume), volumeRetryTokens: make(map[string]string),
		attachments: make(map[string]CloudAttachment),
	}
}

func (p *fakeProvider) ListInstances(_ context.Context, compartmentID string) ([]CloudInstance, error) {
	if compartmentID != p.config.CompartmentID {
		return nil, ErrForeignResource
	}
	instances := make([]CloudInstance, 0, len(p.instances))
	for _, instance := range p.instances {
		instances = append(instances, cloneCloudInstance(instance))
	}
	return instances, nil
}

func (p *fakeProvider) GetInstance(_ context.Context, id string) (CloudInstance, error) {
	instance, ok := p.instances[id]
	if !ok {
		return CloudInstance{}, fakeNotFound{}
	}
	return cloneCloudInstance(instance), nil
}

func (p *fakeProvider) LaunchInstance(_ context.Context, request LaunchRequest) (CloudInstance, error) {
	p.launchCalls++
	if id, exists := p.launchRetryTokens[request.RetryToken]; exists {
		return cloneCloudInstance(p.instances[id]), nil
	}
	p.launches++
	id := fmt.Sprintf("ocid1.instance.new-%d", p.launches)
	instance := CloudInstance{
		ID: id, CompartmentID: p.config.CompartmentID, AvailabilityDomain: p.config.AvailabilityDomain,
		FaultDomain: request.FaultDomain, LifecycleState: "PROVISIONING", ETag: "e1",
		FreeformTags: cloneStringMap(request.FreeformTags),
	}
	p.instances[id] = instance
	p.launchRetryTokens[request.RetryToken] = id
	launchErr := p.launchErrorAfterCreate
	p.launchErrorAfterCreate = nil
	return cloneCloudInstance(instance), launchErr
}

func (p *fakeProvider) UpdateInstanceTags(_ context.Context, id, etag string, tags map[string]string) (CloudInstance, error) {
	instance, ok := p.instances[id]
	if !ok {
		return CloudInstance{}, fakeNotFound{}
	}
	if instance.ETag != etag {
		return CloudInstance{}, ErrStaleETag
	}
	instance.FreeformTags = cloneStringMap(tags)
	instance.ETag = etag + "-next"
	p.instances[id] = instance
	return cloneCloudInstance(instance), nil
}

func (p *fakeProvider) TerminateInstance(_ context.Context, id, etag string) error {
	instance, ok := p.instances[id]
	if !ok {
		return fakeNotFound{}
	}
	if instance.ETag != etag {
		return ErrStaleETag
	}
	instance.LifecycleState = "TERMINATING"
	instance.ETag = etag + "-term"
	p.instances[id] = instance
	p.terminations++
	return nil
}

func (p *fakeProvider) ListVolumeAttachments(_ context.Context, compartmentID, instanceID string) ([]CloudAttachment, error) {
	if compartmentID != p.config.CompartmentID {
		return nil, ErrForeignResource
	}
	var attachments []CloudAttachment
	for _, attachment := range p.attachments {
		if instanceID == "" || attachment.InstanceID == instanceID {
			attachments = append(attachments, attachment)
		}
	}
	return attachments, nil
}

func (p *fakeProvider) GetVolumeAttachment(_ context.Context, id string) (CloudAttachment, error) {
	attachment, ok := p.attachments[id]
	if !ok {
		return CloudAttachment{}, fakeNotFound{}
	}
	return attachment, nil
}

func (p *fakeProvider) AttachVolume(_ context.Context, request VolumeAttachRequest) (CloudAttachment, error) {
	p.attachCalls++
	attachment := CloudAttachment{
		ID: fmt.Sprintf("attachment-%d", p.attachCalls), VolumeID: request.VolumeID,
		InstanceID: request.InstanceID, LifecycleState: "ATTACHED", ETag: "a1",
	}
	p.attachments[attachment.ID] = attachment
	return attachment, nil
}

func (p *fakeProvider) DetachVolume(_ context.Context, id, etag string) error {
	attachment, ok := p.attachments[id]
	if !ok {
		return fakeNotFound{}
	}
	if attachment.ETag != etag {
		return ErrStaleETag
	}
	delete(p.attachments, id)
	return nil
}

func (p *fakeProvider) GetVolume(_ context.Context, id string) (CloudVolume, error) {
	volume, ok := p.volumes[id]
	if !ok {
		return CloudVolume{}, fakeNotFound{}
	}
	volume.FreeformTags = cloneStringMap(volume.FreeformTags)
	return volume, nil
}

func (p *fakeProvider) ListVolumes(_ context.Context, compartmentID, availabilityDomain string) ([]CloudVolume, error) {
	if compartmentID != p.config.CompartmentID || availabilityDomain != p.config.AvailabilityDomain {
		return nil, ErrForeignResource
	}
	var volumes []CloudVolume
	for _, volume := range p.volumes {
		if volume.AvailabilityDomain == availabilityDomain {
			volume.FreeformTags = cloneStringMap(volume.FreeformTags)
			volumes = append(volumes, volume)
		}
	}
	return volumes, nil
}

func (p *fakeProvider) CreateVolume(_ context.Context, request VolumeCreateRequest, tags map[string]string, retry string) (CloudVolume, error) {
	p.volumeCreateCalls++
	if id, exists := p.volumeRetryTokens[retry]; exists {
		return p.volumes[id], p.volumeRetryReplayError
	}
	p.volumeCreates++
	id := fmt.Sprintf("ocid1.volume.created-%d", p.volumeCreates)
	volume := CloudVolume{
		ID: id, CompartmentID: p.config.CompartmentID, AvailabilityDomain: request.AvailabilityDomain,
		SizeGB: request.SizeGB, LifecycleState: "PROVISIONING", FreeformTags: cloneStringMap(tags),
	}
	p.volumes[id] = volume
	p.volumeRetryTokens[retry] = id
	createErr := p.volumeCreateErrorAfterCreate
	p.volumeCreateErrorAfterCreate = nil
	if p.afterVolumeCreate != nil {
		p.afterVolumeCreate()
	}
	volume.FreeformTags = cloneStringMap(volume.FreeformTags)
	return volume, createErr
}

func cloneCloudInstance(instance CloudInstance) CloudInstance {
	instance.FreeformTags = maps.Clone(instance.FreeformTags)
	return instance
}

type fakeNotFound struct{}

func (fakeNotFound) Error() string          { return "not found" }
func (fakeNotFound) GetHTTPStatusCode() int { return 404 }
