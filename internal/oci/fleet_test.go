package oci

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/hostboot"
)

func TestEnsureHostRecoversLostLaunchResponse(t *testing.T) {
	ctx := t.Context()
	config, intent := testRegionConfig()
	provider := newFakeProvider(config)
	provider.launchErrorAfterCreate = errors.New("response dropped")
	journal := newFakeJournal()
	fencer := &fakeFencer{snapshot: writableSnapshot()}
	fleet, err := newTestFleet(config, intent, provider, journal, fencer, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	want, err := fleet.EnsureHost(ctx, testEnsureRequest(entityid.Derive("test-operation", "node-create-01")))
	if err != nil {
		t.Fatalf("EnsureHost after lost response: %v", err)
	}
	if provider.launches != 1 || want.ID == "" || want.Node == "" || want.State != "PROVISIONING" {
		t.Fatalf("unexpected recovered host: launches=%d host=%+v", provider.launches, want)
	}
	request := testEnsureRequest(entityid.Derive("test-operation", "node-create-01"))
	if want.Shape != request.Shape || want.WholeOCPUs != request.WholeOCPUs || want.MemoryInGBs != request.MemoryInGBs ||
		want.PlacementProfileDigest != request.PlacementProfileDigest || want.PlacementGeneration != request.PlacementGeneration {
		t.Fatalf("EnsureHost did not return the verified immutable placement profile: host=%+v request=%+v", want, request)
	}
	if len(provider.launchRequests) != 2 || !sameLaunchProfile(provider.launchRequests[0], provider.launchRequests[1]) ||
		provider.launchRequests[0].RetryToken != provider.launchRequests[1].RetryToken {
		t.Fatalf("lost-response replay changed the signed tuple or retry token: requests=%+v", provider.launchRequests)
	}

	again, err := fleet.EnsureHost(ctx, testEnsureRequest(entityid.Derive("test-operation", "node-create-01")))
	if err != nil {
		t.Fatalf("idempotent EnsureHost: %v", err)
	}
	if provider.launches != 1 || again.ID != want.ID || again.Node != want.Node {
		t.Fatalf("retry created or changed host: launches=%d first=%+v retry=%+v", provider.launches, want, again)
	}
}

// A release re-signs the fleet under a new owner and generation, and the
// replacement host gets a new create key and node. The fleet launches the
// caller's static name unchanged and keeps the release identity in the tags;
// placement's side is TestPlacementLaunchNameIsStableAcrossReleases.
type allowListImageVerifier struct {
	fakeImageVerifier
	allowed []string
	launch  string
	// version is the cell spec version; chosen runs after a launch image is
	// chosen, to change the spec before the provider launch.
	version string
	chosen  func()
	// held counts launches inside the cell spec fence.
	held int
}

func (v *allowListImageVerifier) HostImages() ([]string, string) { return v.allowed, v.launch }

func (v *allowListImageVerifier) QualifiedLaunchImage(ctx context.Context, region Region, pin string) (string, string, error) {
	image := pin
	if v.launch != "" && slices.Contains(v.allowed, v.launch) {
		image = v.launch
	}
	version := v.version
	err := v.VerifyImageQualified(ctx, region, image)
	if v.chosen != nil {
		v.chosen()
	}
	return image, version, err
}

func (v *allowListImageVerifier) AdmitLaunch(ctx context.Context, region Region, imageID, version string) (func(), error) {
	if version != "" && version != v.version {
		return nil, errors.New("cell spec changed")
	}
	if err := v.VerifyImageQualified(ctx, region, imageID); err != nil {
		return nil, err
	}
	v.held++
	return func() { v.held-- }, nil
}

// revokingVerifier qualifies the launch image when the fleet chooses it and
// refuses it afterwards, as when the cell spec revokes it before the launch.
func TestStaleLeaderCannotLaunch(t *testing.T) {
	ctx := t.Context()
	config, intent := testRegionConfig()
	provider := newFakeProvider(config)
	journal := newFakeJournal()
	fencer := &fakeFencer{snapshot: writableSnapshot(), guardErr: authority.ErrFenced}
	fleet, err := newTestFleet(config, intent, provider, journal, fencer, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = fleet.EnsureHost(ctx, testEnsureRequest(entityid.Derive("test-operation", "node-create-02")))
	if !errors.Is(err, authority.ErrFenced) {
		t.Fatalf("expected stale leader fence, got %v", err)
	}
	if provider.launches != 0 || len(journal.intents) != 0 {
		t.Fatalf("fenced candidate mutated state: launches=%d intents=%d", provider.launches, len(journal.intents))
	}
}

func TestTerminateRequiresNoAttachedVolumeAndVerifiedWriterStop(t *testing.T) {
	ctx := t.Context()
	config, intent := testRegionConfig()
	provider := newFakeProvider(config)
	journal := newFakeJournal()
	fencer := &fakeFencer{snapshot: writableSnapshot()}
	writerStop := &fakeWriterStop{}
	fleet, err := newTestFleet(config, intent, provider, journal, fencer, nil, writerStop)
	if err != nil {
		t.Fatal(err)
	}
	host, err := fleet.EnsureHost(ctx, testEnsureRequest(entityid.Derive("test-operation", "node-create-03")))
	if err != nil {
		t.Fatal(err)
	}
	provider.attachments["attachment-1"] = CloudAttachment{
		ID: "attachment-1", VolumeID: "volume-1", InstanceID: host.ID,
		LifecycleState: "ATTACHED", ETag: "a1", Device: "/dev/oracleoci/oraclevdb",
		IsReadOnly: boolPointer(false), IsShareable: boolPointer(false), IsPvEncryptionInTransitEnabled: boolPointer(true),
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

func testRegionConfig() (RegionConfig, RegionIntent) {
	intent := RegionIntent{
		SchemaVersion: 1, Generation: 7, BootstrapRegion: RegionGRU,
		Regions: []RegionMapping{{Cell: RegionGRU, OCIRegion: "sa-saopaulo-1"}},
	}
	return RegionConfig{
		Region: RegionGRU, Generation: intent.Generation,
		Endpoint:                "https://iaas.sa-saopaulo-1.oraclecloud.com",
		CompartmentID:           "ocid1.compartment.oc1..aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ImageCompartmentID:      "ocid1.compartment.oc1..bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		AvailabilityDomain:      "sa-saopaulo-1-AD-1",
		FaultDomains:            []string{"FAULT-DOMAIN-1", "FAULT-DOMAIN-2"},
		SubnetID:                "ocid1.subnet.oc1.sa-saopaulo-1.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		NetworkSecurityGroupIDs: []string{"ocid1.networksecuritygroup.oc1.sa-saopaulo-1.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		ImageID:                 "ocid1.image.oc1.sa-saopaulo-1.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		BootVolumeGB:            50,
		BootVolumeVPUsPerGB:     10,
		DataVolumeVPUsPerGB:     10,
		MaxDataVolumeGB:         32768,
		Shape:                   "VM.Standard.E5.Flex", Owner: "orchestrator",
	}, intent
}

func testEnsureRequest(createKey string) EnsureRequest {
	return EnsureRequest{
		Name: "gru-1-db-1", CreateKey: createKey, PrivateIP: "10.251.0.21", FaultDomain: "FAULT-DOMAIN-1", Shape: "VM.Standard.E5.Flex",
		WholeOCPUs: 1, MemoryInGBs: 6, PlacementProfileDigest: strings.Repeat("a", 64), PlacementGeneration: 3,
		BootPins: HostBootPins{
			DatabaseID: "0000000000JJVVW9EMWY1PE1VX", PartitionID: "0000000000HE4W7FRNR204Q6TQ", SeatID: "0000000000M4R4NE7RJXQ9M8NM",
			HostAttempt: 1, IntentPayloadDigest: strings.Repeat("b", 64),
			CanonicalRosterDigest: strings.Repeat("c", 64), RuntimeManifestDigest: strings.Repeat("d", 64),
		},
	}
}

func sameLaunchProfile(a, b LaunchRequest) bool {
	return a.CreateKey == b.CreateKey && a.Node == b.Node && a.PrivateIP == b.PrivateIP && a.FaultDomain == b.FaultDomain &&
		a.Shape == b.Shape && a.WholeOCPUs == b.WholeOCPUs && a.MemoryInGBs == b.MemoryInGBs &&
		a.PlacementProfileDigest == b.PlacementProfileDigest && a.PlacementGeneration == b.PlacementGeneration &&
		a.ImageID == b.ImageID && a.BootDescriptor == b.BootDescriptor &&
		maps.Equal(a.FreeformTags, b.FreeformTags)
}

func writableSnapshot() authority.Snapshot {
	return authority.Snapshot{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		CandidateID: "00000000008VQHCQFMKQSH41D6", Leader: true, Ready: true, Epoch: 4, Revision: 9,
		ExpiresAt: time.Now().Add(time.Minute), ObservedAt: time.Now(),
	}
}

type fakeFencer struct {
	snapshot      authority.Snapshot
	guardErr      error
	guards        int
	onGuard       func()
	terminalEntry authority.LogEntry
}

func (f *fakeFencer) Current() authority.Snapshot { return f.snapshot }
func (f *fakeFencer) ReadTerminalIntent(context.Context, string, string) (authority.LogEntry, error) {
	if f.terminalEntry.Sequence == 0 {
		return authority.LogEntry{}, authority.ErrNotFound
	}
	return f.terminalEntry, nil
}
func (f *fakeFencer) BeginActiveWorkloadEffect(ctx context.Context, epoch uint64, scope authority.WorkloadScope) (func(), error) {
	if scope.DatabaseID == "" || scope.PartitionID == "" {
		return nil, errors.New("missing test workload scope")
	}
	if err := f.Guard(ctx, epoch); err != nil {
		return nil, err
	}
	return func() {}, nil
}
func (f *fakeFencer) Guard(context.Context, uint64) error {
	f.guards++
	if f.onGuard != nil {
		f.onGuard()
	}
	return f.guardErr
}

type fakeJournal struct {
	terminations map[string]RegionConfig
	intents      map[string]OperationIntent
	results      map[string]OperationResult
	instances    map[string]ResourceIdentity
	volumes      map[string]ResourceIdentity
	attachments  map[string]AttachmentIdentity
	bootBindings map[string]BootBinding
}

func newFakeJournal() *fakeJournal {
	return &fakeJournal{
		terminations: make(map[string]RegionConfig),
		intents:      make(map[string]OperationIntent), results: make(map[string]OperationResult),
		instances: make(map[string]ResourceIdentity),
		volumes:   make(map[string]ResourceIdentity), attachments: make(map[string]AttachmentIdentity),
		bootBindings: make(map[string]BootBinding),
	}
}

func (j *fakeJournal) RecordVolumeTermination(_ context.Context, config RegionConfig, id string) error {
	j.terminations[id] = config
	return nil
}

func (j *fakeJournal) RecordBootBinding(_ context.Context, binding BootBinding) error {
	if existing, ok := j.bootBindings[binding.InstanceID]; ok && existing != binding {
		return errors.New("boot binding conflict")
	}
	j.bootBindings[binding.InstanceID] = binding
	return nil
}

func (j *fakeJournal) GetBootBinding(_ context.Context, instanceID string) (BootBinding, bool, error) {
	binding, ok := j.bootBindings[instanceID]
	return binding, ok, nil
}

func (j *fakeJournal) ListOperations(context.Context) ([]OperationRecord, error) {
	items := make([]OperationRecord, 0, len(j.intents))
	for key, intent := range j.intents {
		items = append(items, OperationRecord{Intent: intent, Result: j.results[key]})
	}
	return items, nil
}

func (j *fakeJournal) RecordIntent(_ context.Context, intent OperationIntent) error {
	key := operationKey(intent)
	if current, exists := j.intents[key]; exists {
		if !sameIntent(current, intent) {
			return errors.New("operation key conflict")
		}
		return nil
	}
	j.intents[key] = intent
	return nil
}

func (j *fakeJournal) RecordResult(_ context.Context, result OperationResult) error {
	key := operationKey(result.Intent)
	intent, ok := j.intents[key]
	if !ok {
		return errors.New("missing intent")
	}
	result.Intent = intent
	if result.RecordedAt.IsZero() {
		result.RecordedAt = time.Now().UTC()
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
	case actionVolumeAttach:
		identity := attachmentIdentityFromResult(result)
		j.attachments[identity.ID] = identity
	case actionVolumeResize:
		identity.ID = result.Intent.VolumeID
		identity.AvailabilityDomain = result.Intent.AvailabilityDomain
		previous := identity
		previous.SizeGB = result.Intent.PreviousSizeGB
		identity.SizeGB = result.Intent.SizeGB
		if current := j.volumes[identity.ID]; current != previous && current != identity {
			return errors.New("resize predecessor ownership mismatch")
		}
		j.volumes[identity.ID] = identity
	}
	return nil
}

func (j *fakeJournal) GetResult(_ context.Context, intent OperationIntent) (OperationResult, bool, error) {
	key := operationKey(intent)
	storedIntent, exists := j.intents[key]
	if !exists {
		return OperationResult{}, false, nil
	}
	result, found := j.results[key]
	if !found {
		result.Intent = storedIntent
		return result, false, nil
	}
	result.Intent = storedIntent
	return result, true, nil
}

func (j *fakeJournal) GetOperation(_ context.Context, scope OperationScope) (OperationIntent, bool, error) {
	intent := OperationIntent{
		Action: scope.Action, Key: scope.Key, Region: scope.Region,
		Generation: scope.Generation, Owner: scope.Owner,
	}
	stored, exists := j.intents[operationKey(intent)]
	if !exists {
		return OperationIntent{}, false, nil
	}
	if stored.Action != scope.Action || stored.Key != scope.Key || stored.Region != scope.Region ||
		stored.Generation != scope.Generation || stored.Owner != scope.Owner {
		return OperationIntent{}, false, errors.New("operation scope conflict")
	}
	return stored, true, nil
}

func (j *fakeJournal) IsOwnedInstance(_ context.Context, identity ResourceIdentity) (bool, error) {
	return j.instances[identity.ID] == identity, nil
}

func (j *fakeJournal) IsOwnedVolume(_ context.Context, identity ResourceIdentity) (bool, error) {
	return j.volumes[identity.ID] == identity, nil
}

func (j *fakeJournal) IsOwnedAttachment(_ context.Context, identity AttachmentIdentity) (bool, error) {
	return j.attachments[identity.ID] == identity, nil
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

type fakeImageVerifier struct {
	err    error
	images []string
	// refuse fails only this image.
	refuse string
}

func (v *fakeImageVerifier) VerifyImageQualified(_ context.Context, _ Region, imageID string) error {
	v.images = append(v.images, imageID)
	if imageID == v.refuse {
		return errors.New("image refused")
	}
	return v.err
}

func newTestFleet(
	config RegionConfig,
	intent RegionIntent,
	provider Provider,
	journal Journal,
	fencer authority.Fencer,
	drainRequester DrainRequester,
	writerStop WriterStopVerifier,
) (Fleet, error) {
	return NewFleetWithImageVerifier(config, intent, provider, journal, fencer, drainRequester, writerStop, &fakeImageVerifier{})
}

// Keep the SDK GetInstance adapter in this regression path. A boot mismatch
// must be withheld as one foreign host without hiding an unrelated OCI error.
type observeSDKSigner struct{}

func (observeSDKSigner) Sign(*http.Request) error { return nil }

func newAttachTestState(t *testing.T) (RegionConfig, *fakeProvider, *fakeJournal, Fleet, Instance, RetainedVolume) {
	t.Helper()
	ctx := t.Context()
	config, regionIntent := testRegionConfig()
	provider := newFakeProvider(config)
	journal := newFakeJournal()
	fleet, err := newTestFleet(config, regionIntent, provider, journal, &fakeFencer{snapshot: writableSnapshot()}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	host, err := fleet.EnsureHost(ctx, testEnsureRequest(entityid.Derive("test-operation", "attach-test-host")))
	if err != nil {
		t.Fatal(err)
	}
	volume, err := fleet.CreateRetainedVolume(ctx, VolumeCreateRequest{Name: "gru-1-db-1-data", DatabaseID: "0000000000JJVVW9EMWY1PE1VX", PartitionID: "0000000000HE4W7FRNR204Q6TQ", CreateKey: "0000000000SXHAFTXWBNBVG4JP", SizeGB: 50})
	if err != nil {
		t.Fatal(err)
	}
	return config, provider, journal, fleet, host, volume
}

type fakeProvider struct {
	config                       RegionConfig
	instances                    map[string]CloudInstance
	launchRetryTokens            map[string]string
	launchRequests               []LaunchRequest
	launchObservationMutation    func(*CloudInstance)
	launchErrorBeforeCreate      error
	devices                      map[string][]CloudDevice
	volumes                      map[string]CloudVolume
	bootVolumes                  map[string]CloudBootVolume
	volumeRetryTokens            map[string]string
	attachments                  map[string]CloudAttachment
	attachRetryTokens            map[string]string
	attachmentListErr            error
	afterAttach                  func(*fakeProvider, string)
	launches                     int
	launchCalls                  int
	launchErrorAfterCreate       error
	volumeCreates                int
	volumeCreateCalls            int
	volumeCreateErrorAfterCreate error
	volumeRetryReplayError       error
	afterVolumeCreate            func()
	attachCalls                  int
	deviceListCalls              int
	attachErrorAfterCreate       error
	attachReplayError            error
	terminations                 int
	backupPolicies               []CloudBackupPolicy
	backupPolicyRetryTokens      map[string]string
	backupPolicyAssignments      map[string]string
	backupPolicyCreates          int
	volumeCreateRequests         []VolumeCreateRequest
	volumeBackups                []CloudVolumeBackup
}

func newFakeProvider(config RegionConfig) *fakeProvider {
	return &fakeProvider{
		config: config, instances: make(map[string]CloudInstance), launchRetryTokens: make(map[string]string),
		devices: make(map[string][]CloudDevice),
		volumes: make(map[string]CloudVolume), volumeRetryTokens: make(map[string]string),
		bootVolumes: make(map[string]CloudBootVolume),
		attachments: make(map[string]CloudAttachment), attachRetryTokens: make(map[string]string),
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
	p.launchRequests = append(p.launchRequests, request)
	if p.launchErrorBeforeCreate != nil {
		return CloudInstance{}, p.launchErrorBeforeCreate
	}
	if id, exists := p.launchRetryTokens[request.RetryToken]; exists {
		return cloneCloudInstance(p.instances[id]), nil
	}
	p.launches++
	id := fmt.Sprintf("ocid1.instance.new-%d", p.launches)
	instance := CloudInstance{
		ID: id, PrivateIP: request.PrivateIP, CompartmentID: p.config.CompartmentID, AvailabilityDomain: p.config.AvailabilityDomain,
		FaultDomain: request.FaultDomain, Shape: request.Shape, Ocpus: new(float32(request.WholeOCPUs)),
		MemoryInGBs: new(float32(request.MemoryInGBs)), LifecycleState: "PROVISIONING", ETag: "e1", ImageID: request.ImageID,
		ConsistentVolumeNamingEnabled: new(true),
		Metadata:                      map[string]string{hostboot.MetadataKey: request.BootDescriptor, "terrascale_host_node": request.Node},
		FreeformTags:                  cloneStringMap(request.FreeformTags),
	}
	if p.launchObservationMutation != nil {
		p.launchObservationMutation(&instance)
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

func (p *fakeProvider) TerminateTerminalInstance(ctx context.Context, id, etag string) error {
	return p.TerminateInstance(ctx, id, etag)
}

func (p *fakeProvider) GetAttachedBootVolume(_ context.Context, instanceID string) (CloudBootVolume, error) {
	instance, ok := p.instances[instanceID]
	if !ok {
		return CloudBootVolume{}, fakeNotFound{}
	}
	id := "ocid1.bootvolume." + strings.TrimPrefix(instanceID, "ocid1.instance.")
	if boot, ok := p.bootVolumes[id]; ok {
		return boot, nil
	}
	boot := CloudBootVolume{ID: id, CompartmentID: p.config.CompartmentID,
		AvailabilityDomain: p.config.AvailabilityDomain, ImageID: instance.ImageID,
		SizeGB: int64(p.config.BootVolumeGB), VPUsPerGB: int64(p.config.BootVolumeVPUsPerGB),
		LifecycleState: "AVAILABLE", ETag: "boot-etag"}
	p.bootVolumes[id] = boot
	return boot, nil
}

func (p *fakeProvider) GetBootVolume(_ context.Context, id string) (CloudBootVolume, error) {
	boot, ok := p.bootVolumes[id]
	if !ok {
		return CloudBootVolume{}, fakeNotFound{}
	}
	return boot, nil
}

func (p *fakeProvider) ListBootVolumeAttachments(_ context.Context, id string) ([]CloudBootAttachment, error) {
	for instanceID, instance := range p.instances {
		if id == "ocid1.bootvolume."+strings.TrimPrefix(instanceID, "ocid1.instance.") {
			if instance.LifecycleState == "TERMINATED" {
				return nil, nil
			}
			return []CloudBootAttachment{{InstanceID: instanceID, BootVolumeID: id, LifecycleState: "ATTACHED"}}, nil
		}
	}
	return nil, nil
}

func (p *fakeProvider) DeleteBootVolume(_ context.Context, id, etag string) error {
	boot, ok := p.bootVolumes[id]
	if !ok {
		return fakeNotFound{}
	}
	if boot.ETag != etag {
		return ErrStaleETag
	}
	delete(p.bootVolumes, id)
	return nil
}

func (p *fakeProvider) DeleteVolume(_ context.Context, id, etag string) error {
	volume, ok := p.volumes[id]
	if !ok {
		return fakeNotFound{}
	}
	if volume.ETag != etag {
		return ErrStaleETag
	}
	delete(p.volumes, id)
	return nil
}

func (p *fakeProvider) ListVolumeAttachments(_ context.Context, compartmentID, instanceID string) ([]CloudAttachment, error) {
	if compartmentID != p.config.CompartmentID {
		return nil, ErrForeignResource
	}
	if p.attachmentListErr != nil {
		err := p.attachmentListErr
		p.attachmentListErr = nil
		return nil, err
	}
	var attachments []CloudAttachment
	for _, attachment := range p.attachments {
		if instanceID == "" || attachment.InstanceID == instanceID {
			attachments = append(attachments, attachment)
		}
	}
	return attachments, nil
}

func (p *fakeProvider) ListInstanceDevices(_ context.Context, instanceID string) ([]CloudDevice, error) {
	p.deviceListCalls++
	devices, exists := p.devices[instanceID]
	if exists {
		return cloneCloudDevices(devices), nil
	}
	available := true
	return []CloudDevice{
		{Name: "/dev/oracleoci/oraclevdb", IsAvailable: &available},
		{Name: "/dev/oracleoci/oraclevdc", IsAvailable: &available},
	}, nil
}

func (p *fakeProvider) GetVolumeAttachment(_ context.Context, id string) (CloudAttachment, error) {
	attachment, ok := p.attachments[id]
	if !ok {
		return CloudAttachment{}, fakeNotFound{}
	}
	return attachment, nil
}

func (p *fakeProvider) AttachVolume(_ context.Context, request CloudVolumeAttachRequest) (CloudAttachment, error) {
	if id, exists := p.attachRetryTokens[request.RetryToken]; exists {
		return p.attachments[id], p.attachReplayError
	}
	p.attachCalls++
	readOnly, shareable, encryption := request.IsReadOnly, request.IsShareable, request.IsPvEncryptionInTransitEnabled
	attachment := CloudAttachment{
		ID: fmt.Sprintf("attachment-%d", p.attachCalls), VolumeID: request.VolumeID,
		InstanceID: request.InstanceID, LifecycleState: "ATTACHED", ETag: "a1", Device: request.Device,
		IsReadOnly: &readOnly, IsShareable: &shareable, IsPvEncryptionInTransitEnabled: &encryption,
	}
	// Like OCI, the response describes the attachment while it is ATTACHING,
	// under an ETag that changes once it settles.
	response := attachment
	response.LifecycleState, response.ETag = "ATTACHING", "a0"
	p.attachments[attachment.ID] = attachment
	p.attachRetryTokens[request.RetryToken] = attachment.ID
	if p.afterAttach != nil {
		p.afterAttach(p, attachment.ID)
		p.afterAttach = nil
	}
	attachErr := p.attachErrorAfterCreate
	p.attachErrorAfterCreate = nil
	return response, attachErr
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
	p.volumeCreateRequests = append(p.volumeCreateRequests, request)
	id := fmt.Sprintf("ocid1.volume.created-%d", p.volumeCreates)
	volume := CloudVolume{
		ID: id, CompartmentID: p.config.CompartmentID, AvailabilityDomain: request.AvailabilityDomain,
		SizeGB: request.SizeGB, VPUsPerGB: int64(p.config.DataVolumeVPUsPerGB),
		LifecycleState: "PROVISIONING", ETag: "volume-etag", FreeformTags: cloneStringMap(tags),
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
	instance.Metadata = maps.Clone(instance.Metadata)
	if instance.Ocpus != nil {
		instance.Ocpus = new(*instance.Ocpus)
	}
	if instance.MemoryInGBs != nil {
		instance.MemoryInGBs = new(*instance.MemoryInGBs)
	}
	if instance.ConsistentVolumeNamingEnabled != nil {
		instance.ConsistentVolumeNamingEnabled = boolPointer(*instance.ConsistentVolumeNamingEnabled)
	}
	return instance
}

func cloneCloudDevices(devices []CloudDevice) []CloudDevice {
	cloned := make([]CloudDevice, len(devices))
	for index, device := range devices {
		cloned[index].Name = device.Name
		if device.IsAvailable != nil {
			cloned[index].IsAvailable = boolPointer(*device.IsAvailable)
		}
	}
	return cloned
}

func boolPointer(value bool) *bool { return &value }

type fakeNotFound struct{}

func (fakeNotFound) Error() string          { return "not found" }
func (fakeNotFound) GetHTTPStatusCode() int { return 404 }
