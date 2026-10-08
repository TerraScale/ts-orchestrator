package app

import (
	"context"
	"errors"
	"maps"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostboot"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

// The ordered placement log is represented by placementAdmissionTestControl;
// placement state and OCI operation ownership use real JetStream KV buckets.
func TestSignedPlacementSizingReachesProviderThroughController(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	broker, err := natscell.Start(ctx, natscell.Config{
		Cell: "gru", Instance: "placement-sizing", Replicas: 1, Lab: true,
		Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: -1, StoreDir: filepath.Join(t.TempDir(), "nats")},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = broker.Close() })

	policy, privateKey := newPlacementAdmissionPolicy(t)
	control := newPlacementAdmissionControl()
	intent := testManagedPlacementIntent()
	wire := signedPlacementEnvelope(t, intent, privateKey, protocol.EncodeJSON)
	receipt, err := verifyAndApplyPlacement(ctx, wire, "gru", policy, control)
	if err != nil || receipt.Sequence != 1 {
		t.Fatalf("signed placement admission: receipt=%+v err=%v", receipt, err)
	}
	reader := admittedPlacementReader{cell: "gru", store: control}
	committed, err := reader.ListPlacementIntents(ctx, "gru")
	if err != nil || len(committed) != 1 || committed[0].PayloadDigest() == "" {
		t.Fatalf("admitted ordered-log readback: intents=%+v err=%v", committed, err)
	}
	profile, err := committed[0].ManagedHostProfile(oci.RegionGRU)
	if err != nil {
		t.Fatal(err)
	}
	profileDigest, err := committed[0].ProfileDigest(oci.RegionGRU)
	if err != nil {
		t.Fatal(err)
	}
	rosterDigest, err := committed[0].CanonicalRosterDigest()
	if err != nil {
		t.Fatal(err)
	}
	rosterRow, err := committed[0].RosterRowForSeat(placement.Seat{
		MemberID: "000000000082AXF7GZQT1D126Y", Region: oci.RegionGRU, FailureDomain: "FAULT-DOMAIN-1", Kind: placement.MemberPermanent,
	})
	if err != nil {
		t.Fatal(err)
	}
	store, err := placement.NewJetStreamStore(ctx, broker.JetStream(), "gru", 1, reader)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := oci.OpenJournal(ctx, broker.JetStream(), 1)
	if err != nil {
		t.Fatal(err)
	}
	regionIntent := oci.RegionIntent{
		SchemaVersion: 1, Generation: 1, BootstrapRegion: oci.RegionGRU,
		Regions: []oci.RegionMapping{{Cell: oci.RegionGRU, OCIRegion: "sa-saopaulo-1"}},
	}
	regionConfig := oci.RegionConfig{
		Region: oci.RegionGRU, Generation: 1, Endpoint: "https://iaas.sa-saopaulo-1.oraclecloud.com",
		CompartmentID: "ocid1.compartment.oc1..owned", ImageCompartmentID: "ocid1.compartment.oc1..image", AvailabilityDomain: "AD-1",
		FaultDomains: []string{"FAULT-DOMAIN-1", "FAULT-DOMAIN-2"},
		SubnetID:     "ocid1.subnet.oc1..owned", ImageID: "ocid1.image.oc1..owned",
		NetworkSecurityGroupIDs: []string{"ocid1.networksecuritygroup.oc1..owned"},
		BootVolumeGB:            50, BootVolumeVPUsPerGB: 10, DataVolumeVPUsPerGB: 10, MaxDataVolumeGB: 50,
		Shape: profile.Compute.Shape, Owner: "regional-owner",
	}
	provider := &placementSizingProvider{config: regionConfig}
	fencer := placementSizingFencer{control: control}
	fleet, err := oci.NewFleetWithImageVerifier(regionConfig, regionIntent, provider, journal, fencer, nil, nil, acceptingImageVerifier{})
	if err != nil {
		t.Fatal(err)
	}
	controller, err := placement.StartController(ctx, placement.Config{
		Cell: "gru", Region: oci.RegionGRU, FaultDomains: regionConfig.FaultDomains,
		ManagedOwner: regionConfig.Owner, FleetGeneration: regionConfig.Generation,
		ImageID:     regionConfig.ImageID,
		Environment: "production", MemberRole: "terrabase",
		Resources: placement.Resources{CPU: 1, MemoryBytes: 1 << 30, DiskBytes: 32 << 30},
	}, store, fencer, fleet, placementSizingHosts{}, placementSizingHosts{}, testPlacementAdmittedArtifact(intent))
	if err != nil {
		t.Fatal(err)
	}

	if err := controller.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	members, err := store.ListMembers(ctx, intent.DatabaseID, intent.PartitionID)
	if err != nil || len(members) != 1 {
		t.Fatalf("first tick did not CAS one prepared seat: members=%+v err=%v", members, err)
	}
	prepared := members[0]
	if prepared.Revision == 0 || prepared.State.Stage != placement.StagePreparedHost ||
		prepared.State.CanonicalRosterRow != rosterRow ||
		prepared.State.CanonicalRosterDigest != rosterDigest ||
		prepared.State.AuthorityReference != committed[0].CanonicalRoster.Authority ||
		prepared.State.IntentPayloadDigest != committed[0].PayloadDigest() ||
		prepared.State.ManagedHostProfile != profile || prepared.State.ManagedHostProfileDigest != profileDigest ||
		prepared.State.IntentGeneration != intent.Generation || len(provider.launches) != 0 {
		t.Fatalf("signed profile was not durably pinned before provider launch: member=%+v launches=%+v", prepared, provider.launches)
	}
	pinned, err := store.ReadMember(ctx, intent.DatabaseID, intent.PartitionID, rosterRow.SeatID)
	if err != nil || pinned.Revision != prepared.Revision || pinned.State.CanonicalRosterRow != rosterRow ||
		pinned.State.CanonicalRosterDigest != rosterDigest || pinned.State.AuthorityReference != committed[0].CanonicalRoster.Authority {
		t.Fatalf("exact JetStream member read lost the signed roster pin: member=%+v err=%v", pinned, err)
	}

	if err := controller.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if len(provider.launches) != 1 {
		t.Fatalf("provider launches = %d, want one", len(provider.launches))
	}
	launch := provider.launches[0]
	if want := map[string]string{permanentSeatID(oci.RegionGRU): "gru-1-db-1", elasticSeatID(oci.RegionGRU): "gru-1-db-2"}[rosterRow.SeatID]; launch.DisplayName != want {
		t.Fatalf("placement launched seat %s as %q, want its static name %q", rosterRow.SeatID, launch.DisplayName, want)
	}
	descriptor, err := hostboot.Parse([]byte(launch.BootDescriptor))
	if err != nil {
		t.Fatalf("provider did not receive canonical public boot descriptor: %v", err)
	}
	descriptorDigest, err := descriptor.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if descriptor.Cell != "gru" || descriptor.Region != "GRU" || descriptor.Node != launch.Node ||
		descriptor.Owner != regionConfig.Owner || descriptor.FleetGeneration != regionConfig.Generation ||
		descriptor.CreateKey != prepared.State.CreateKey || descriptor.ImageID != regionConfig.ImageID ||
		descriptor.DatabaseID != prepared.State.DatabaseID || descriptor.PartitionID != prepared.State.PartitionID ||
		descriptor.SeatID != prepared.State.MemberID || descriptor.HostAttempt != prepared.State.HostAttempt ||
		descriptor.IntentGeneration != prepared.State.IntentGeneration ||
		descriptor.IntentPayloadDigest != prepared.State.IntentPayloadDigest ||
		descriptor.CanonicalRosterDigest != prepared.State.CanonicalRosterDigest ||
		descriptor.ManagedHostProfileDigest != prepared.State.ManagedHostProfileDigest ||
		descriptor.RuntimeManifestDigest != prepared.State.RuntimeManifestDigest ||
		launch.ImageID != regionConfig.ImageID {
		t.Fatalf("provider launch descriptor differs from prepared member and pinned OCI image: %+v", descriptor)
	}
	storedLaunch, found, err := journal.GetOperation(ctx, oci.OperationScope{
		Action: "launch", Key: prepared.State.CreateKey, Region: regionConfig.Region,
		Generation: regionConfig.Generation, Owner: regionConfig.Owner,
	})
	if err != nil || !found || storedLaunch.BootDescriptor != launch.BootDescriptor ||
		storedLaunch.BootDescriptorSHA256 != descriptorDigest || storedLaunch.ImageID != regionConfig.ImageID {
		t.Fatalf("OCI journal did not persist exact launch descriptor/image: found=%v intent=%+v err=%v", found, storedLaunch, err)
	}
	if launch.CreateKey != prepared.State.CreateKey || launch.FaultDomain != prepared.State.FailureDomain ||
		launch.Shape != profile.Compute.Shape || launch.WholeOCPUs != profile.Compute.WholeOCPUs ||
		launch.MemoryInGBs != profile.Compute.MemoryInGBs || launch.PlacementProfileDigest != profileDigest ||
		launch.PlacementGeneration != intent.Generation || regionConfig.Generation != 1 || intent.Generation != 7 ||
		launch.FreeformTags["terrascale-placement-profile-digest"] != profileDigest ||
		launch.FreeformTags["terrascale-placement-generation"] != "7" ||
		launch.FreeformTags["terrascale-generation"] != "1" {
		t.Fatalf("provider launch changed signed sizing or conflated fleet and placement generations: %+v", launch)
	}
	members, err = store.ListMembers(ctx, intent.DatabaseID, intent.PartitionID)
	if err != nil || len(members) != 1 || members[0].Revision <= prepared.Revision ||
		members[0].State.Stage != placement.StageAwaitingHost ||
		members[0].State.InstanceID != provider.instance.ID ||
		members[0].State.HostNode != launch.Node || members[0].State.InstanceETag != provider.instance.ETag {
		t.Fatalf("verified OCI identity was not CAS-bound after launch: members=%+v err=%v", members, err)
	}
	observed, err := fleet.Observe(ctx)
	if err != nil || len(observed) != 1 || observed[0].PlacementProfileDigest != profileDigest ||
		observed[0].PlacementGeneration != intent.Generation || observed[0].Generation != regionConfig.Generation ||
		observed[0].ImageID != regionConfig.ImageID || observed[0].BootDescriptorSHA256 != descriptorDigest {
		t.Fatalf("real OCI fleet did not reobserve its journal-bound profile: observed=%+v err=%v", observed, err)
	}
	restarted, err := oci.NewFleetWithImageVerifier(regionConfig, regionIntent, provider, journal, fencer, nil, nil, acceptingImageVerifier{})
	if err != nil {
		t.Fatal(err)
	}
	retry, err := restarted.EnsureHost(ctx, oci.EnsureRequest{
		Name: launch.DisplayName, CreateKey: prepared.State.CreateKey, PrivateIP: launch.PrivateIP, FaultDomain: prepared.State.FailureDomain,
		Shape: profile.Compute.Shape, WholeOCPUs: profile.Compute.WholeOCPUs,
		MemoryInGBs: profile.Compute.MemoryInGBs, PlacementProfileDigest: profileDigest,
		PlacementGeneration: prepared.State.IntentGeneration,
		BootPins: oci.HostBootPins{
			DatabaseID: prepared.State.DatabaseID, PartitionID: prepared.State.PartitionID,
			SeatID: prepared.State.MemberID, HostAttempt: prepared.State.HostAttempt,
			IntentPayloadDigest:   prepared.State.IntentPayloadDigest,
			CanonicalRosterDigest: prepared.State.CanonicalRosterDigest,
			RuntimeManifestDigest: prepared.State.RuntimeManifestDigest,
		},
	})
	if err != nil || retry.ID != provider.instance.ID || retry.BootDescriptorSHA256 != descriptorDigest || len(provider.launches) != 1 {
		t.Fatalf("restart did not reuse exact journal-bound host: retry=%+v launches=%d err=%v", retry, len(provider.launches), err)
	}
	drifted := storedLaunch
	drifted.ImageID = "ocid1.image.oc1..different"
	if err := journal.RecordIntent(ctx, drifted); err == nil {
		t.Fatal("journal accepted image drift for the original launch key")
	}
	provider.instance.Metadata[hostboot.MetadataKey] = "{}"
	if driftedHosts, err := restarted.Observe(ctx); err != nil || len(driftedHosts) != 0 {
		t.Fatalf("metadata-drifted host was observed: hosts=%+v err=%v", driftedHosts, err)
	}
	provider.instance.Metadata[hostboot.MetadataKey] = launch.BootDescriptor
	provider.instance.ImageID = "ocid1.image.oc1..different"
	if driftedHosts, err := restarted.Observe(ctx); err != nil || len(driftedHosts) != 0 {
		t.Fatalf("image-drifted host was observed: hosts=%+v err=%v", driftedHosts, err)
	}
}

type placementSizingFencer struct {
	control *placementAdmissionTestControl
}

func (f placementSizingFencer) Current() authority.Snapshot { return f.control.Current() }

func (f placementSizingFencer) Guard(ctx context.Context, epoch uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !f.Current().CanMutate() || f.Current().Epoch != epoch {
		return authority.ErrFenced
	}
	return nil
}

func (f placementSizingFencer) ReadManagedUpdate(ctx context.Context, databaseID, partitionID string) (authority.LogEntry, error) {
	return f.control.ReadManagedUpdate(ctx, databaseID, partitionID)
}

func (f placementSizingFencer) ReadManagedUpdateOperation(
	ctx context.Context, databaseID, partitionID, operationID string,
) ([]authority.LogEntry, error) {
	return f.control.ReadManagedUpdateOperation(ctx, databaseID, partitionID, operationID)
}

func (f placementSizingFencer) ListManagedUpdates(ctx context.Context, databaseID, partitionID string) ([]authority.LogEntry, error) {
	return f.control.ListManagedUpdates(ctx, databaseID, partitionID)
}

func (f placementSizingFencer) BeginActiveWorkloadEffect(ctx context.Context, epoch uint64,
	scope authority.WorkloadScope,
) (func(), error) {
	if scope.DatabaseID == "" || scope.PartitionID == "" {
		return nil, authority.ErrFenced
	}
	if err := f.Guard(ctx, epoch); err != nil {
		return nil, err
	}
	if _, err := f.control.ReadTerminalIntent(ctx, scope.DatabaseID, scope.PartitionID); err == nil {
		return nil, authority.ErrFenced
	} else if !errors.Is(err, authority.ErrNotFound) {
		return nil, err
	}
	return func() {}, nil
}

type placementSizingHosts struct{}

func (placementSizingHosts) ListHosts(context.Context) ([]host.HostStatus, error) { return nil, nil }

func (placementSizingHosts) ListDesired(context.Context, string) ([]host.Desired, error) {
	return nil, nil
}

func (placementSizingHosts) ApplyDesired(context.Context, host.Desired) (host.Receipt, error) {
	return host.Receipt{}, errors.New("sizing fixture must not apply desired state")
}

type placementSizingProvider struct {
	oci.Provider
	config         oci.RegionConfig
	instance       oci.CloudInstance
	bootInstanceID string
	bootVolume     oci.CloudBootVolume
	launches       []oci.LaunchRequest
}

func (p *placementSizingProvider) ListInstances(_ context.Context, compartmentID string) ([]oci.CloudInstance, error) {
	if compartmentID != p.config.CompartmentID {
		return nil, oci.ErrForeignResource
	}
	if p.instance.ID == "" {
		return nil, nil
	}
	instance := p.instance
	instance.FreeformTags = maps.Clone(instance.FreeformTags)
	instance.Metadata = maps.Clone(instance.Metadata)
	return []oci.CloudInstance{instance}, nil
}

func (p *placementSizingProvider) GetInstance(_ context.Context, instanceID string) (oci.CloudInstance, error) {
	if p.instance.ID != instanceID || instanceID == "" {
		return oci.CloudInstance{}, errors.New("unknown fake OCI instance")
	}
	instance := p.instance
	instance.FreeformTags = maps.Clone(instance.FreeformTags)
	instance.Metadata = maps.Clone(instance.Metadata)
	return instance, nil
}

func (p *placementSizingProvider) LaunchInstance(_ context.Context, request oci.LaunchRequest) (oci.CloudInstance, error) {
	if p.instance.ID != "" {
		return oci.CloudInstance{}, errors.New("unexpected second fake OCI launch")
	}
	request.FreeformTags = maps.Clone(request.FreeformTags)
	p.launches = append(p.launches, request)
	p.instance = oci.CloudInstance{
		ID: "ocid1.instance.oc1..placement-sized", CompartmentID: p.config.CompartmentID,
		PrivateIP:          request.PrivateIP,
		AvailabilityDomain: p.config.AvailabilityDomain, FaultDomain: request.FaultDomain,
		Shape: request.Shape, Ocpus: new(float32(request.WholeOCPUs)),
		MemoryInGBs: new(float32(request.MemoryInGBs)), LifecycleState: "PROVISIONING", ETag: "etag-1",
		ImageID: p.config.ImageID, ConsistentVolumeNamingEnabled: new(true),
		Metadata:     map[string]string{hostboot.MetadataKey: request.BootDescriptor, "terrascale_host_node": request.Node},
		FreeformTags: maps.Clone(request.FreeformTags),
	}
	if err := p.bindBootVolume(p.instance.ID); err != nil {
		return oci.CloudInstance{}, err
	}
	return p.instance, nil
}

func (p *placementSizingProvider) bindBootVolume(instanceID string) error {
	if instanceID == "" || p.instance.ID != instanceID || len(p.launches) != 1 {
		return errors.New("fake OCI boot volume requires its one launched instance")
	}
	suffix, ok := strings.CutPrefix(instanceID, "ocid1.instance.")
	if !ok || suffix == "" {
		return errors.New("fake OCI instance has no valid boot-volume identity")
	}
	p.bootInstanceID = instanceID
	p.bootVolume = oci.CloudBootVolume{
		ID: "ocid1.bootvolume." + suffix, CompartmentID: p.config.CompartmentID,
		AvailabilityDomain: p.config.AvailabilityDomain, ImageID: p.config.ImageID,
		SizeGB: int64(p.config.BootVolumeGB), VPUsPerGB: int64(p.config.BootVolumeVPUsPerGB),
		LifecycleState: "AVAILABLE", ETag: "boot-etag-1",
	}
	return nil
}

func (p *placementSizingProvider) GetAttachedBootVolume(_ context.Context, instanceID string) (oci.CloudBootVolume, error) {
	if instanceID == "" || p.instance.ID != instanceID || p.bootInstanceID != instanceID ||
		p.bootVolume.ID == "" {
		return oci.CloudBootVolume{}, errors.New("unknown fake OCI boot attachment")
	}
	return p.bootVolume, nil
}

func (p *placementSizingProvider) ListVolumeAttachments(_ context.Context, compartmentID, instanceID string) ([]oci.CloudAttachment, error) {
	if compartmentID != p.config.CompartmentID || instanceID != p.instance.ID {
		return nil, oci.ErrForeignResource
	}
	return nil, nil
}

var _ authority.Fencer = placementSizingFencer{}
var _ placement.HostView = placementSizingHosts{}
var _ oci.Provider = (*placementSizingProvider)(nil)

// A release re-signs the region config under a new owner and fleet
// generation. Placement launches the same seat under the same static name
// each time; the release identity moves to the instance tags.
func TestPlacementLaunchNameIsStableAcrossReleases(t *testing.T) {
	var launches []oci.LaunchRequest
	for i, owner := range []string{"ts-preview-gru-20260929-r4", "ts-preview-gru-20261004-r5"} {
		launches = append(launches, launchPermanentSeat(t, owner, uint64(i+1)))
	}
	before, after := launches[0], launches[1]
	if before.DisplayName != "gru-1-db-1" || after.DisplayName != before.DisplayName || before.Node == after.Node ||
		before.FreeformTags["terrascale-owner"] != "ts-preview-gru-20260929-r4" ||
		after.FreeformTags["terrascale-owner"] != "ts-preview-gru-20261004-r5" {
		t.Fatalf("release changed the launched name or lost its tagged identity: before=%+v after=%+v", before, after)
	}
}

// launchPermanentSeat runs a fresh controller for one release until it
// launches the permanent GRU seat and returns that launch.
func launchPermanentSeat(t *testing.T, owner string, generation uint64) oci.LaunchRequest {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	broker, err := natscell.Start(ctx, natscell.Config{
		Cell: "gru", Instance: "placement-release", Replicas: 1, Lab: true,
		Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: -1, StoreDir: filepath.Join(t.TempDir(), "nats")},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer broker.Close()
	policy, privateKey := newPlacementAdmissionPolicy(t)
	control := newPlacementAdmissionControl()
	intent := testManagedPlacementIntent()
	if _, err := verifyAndApplyPlacement(ctx, signedPlacementEnvelope(t, intent, privateKey, protocol.EncodeJSON), "gru", policy, control); err != nil {
		t.Fatal(err)
	}
	reader := admittedPlacementReader{cell: "gru", store: control}
	committed, err := reader.ListPlacementIntents(ctx, "gru")
	if err != nil || len(committed) != 1 {
		t.Fatalf("admitted intents=%+v err=%v", committed, err)
	}
	profile, err := committed[0].ManagedHostProfile(oci.RegionGRU)
	if err != nil {
		t.Fatal(err)
	}
	store, err := placement.NewJetStreamStore(ctx, broker.JetStream(), "gru", 1, reader)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := oci.OpenJournal(ctx, broker.JetStream(), 1)
	if err != nil {
		t.Fatal(err)
	}
	regionIntent := oci.RegionIntent{
		SchemaVersion: 1, Generation: generation, BootstrapRegion: oci.RegionGRU,
		Regions: []oci.RegionMapping{{Cell: oci.RegionGRU, OCIRegion: "sa-saopaulo-1"}},
	}
	regionConfig := oci.RegionConfig{
		Region: oci.RegionGRU, Generation: generation, Endpoint: "https://iaas.sa-saopaulo-1.oraclecloud.com",
		CompartmentID: "ocid1.compartment.oc1..owned", ImageCompartmentID: "ocid1.compartment.oc1..image", AvailabilityDomain: "AD-1",
		FaultDomains: []string{"FAULT-DOMAIN-1", "FAULT-DOMAIN-2"},
		SubnetID:     "ocid1.subnet.oc1..owned", ImageID: "ocid1.image.oc1..owned",
		NetworkSecurityGroupIDs: []string{"ocid1.networksecuritygroup.oc1..owned"},
		BootVolumeGB:            50, BootVolumeVPUsPerGB: 10, DataVolumeVPUsPerGB: 10, MaxDataVolumeGB: 50,
		Shape: profile.Compute.Shape, Owner: owner,
	}
	provider := &placementSizingProvider{config: regionConfig}
	fencer := placementSizingFencer{control: control}
	fleet, err := oci.NewFleetWithImageVerifier(regionConfig, regionIntent, provider, journal, fencer, nil, nil, acceptingImageVerifier{})
	if err != nil {
		t.Fatal(err)
	}
	controller, err := placement.StartController(ctx, placement.Config{
		Cell: "gru", Region: oci.RegionGRU, FaultDomains: regionConfig.FaultDomains,
		ManagedOwner: owner, FleetGeneration: generation, ImageID: regionConfig.ImageID,
		Environment: "production", MemberRole: "terrabase",
		Resources: placement.Resources{CPU: 1, MemoryBytes: 1 << 30, DiskBytes: 32 << 30},
	}, store, fencer, fleet, placementSizingHosts{}, placementSizingHosts{}, testPlacementAdmittedArtifact(intent))
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := controller.Tick(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if len(provider.launches) != 1 {
		t.Fatalf("provider launches = %d, want one", len(provider.launches))
	}
	return provider.launches[0]
}
