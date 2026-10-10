package app

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostboot"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostenroll"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

func TestOperatorTerminalTeardownThroughSignedRuntimeAndGrantReadback(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	root := t.TempDir()

	controllerNKey, controllerSeed := testNKey(t)
	operatorNKey, operatorSeed := testNKey(t)
	broker, err := natscell.Start(ctx, natscell.Config{
		Cell: "gru", Instance: "terminal-integration", Replicas: 1, Lab: true,
		NKeySeedFile: controllerSeed,
		Embedded: &natscell.Embedded{
			Host: "127.0.0.1", Port: -1, StoreDir: filepath.Join(root, "nats"),
			Users: []natscell.NKeyGrant{
				{PublicKey: controllerNKey, Role: "controller"},
				{PublicKey: operatorNKey, Role: "operator"},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = broker.Close() })
	if err := broker.WaitForCluster(ctx, 1); err != nil {
		t.Fatal(err)
	}
	control, err := authority.Start(ctx, broker.JetStream(), authority.Config{
		Scope: "gru", CandidateID: "0000000000S9GTF4XKZB00HRAT", Replicas: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = control.Close() })
	if !control.Current().CanMutate() {
		t.Fatal("regional authority did not acquire a mutable lease")
	}

	operatorPublic, _ := testEd25519(t, root, "operator.key")
	grant := TrustedSignerConfig{
		Actor: "ops", PublicKey: base64.StdEncoding.EncodeToString(operatorPublic),
		Roles: []string{"terrabase"}, Environments: []string{"production"},
		CanPlaceTerraBase: true, CanTeardownTerraBase: true,
	}
	policy, err := buildSignerPolicy(Config{
		NATS:       natscell.Config{Cell: "gru"},
		Controller: ControllerConfig{TrustedSigners: []TrustedSignerConfig{grant}},
	})
	if err != nil {
		t.Fatal(err)
	}
	operatorConfig := testJSONFile(t, root, "operator.json", Config{Version: ConfigVersion,
		NATS: natscell.Config{Cell: "gru", Instance: "terminal-operator", Replicas: 1, Lab: true,
			URL: broker.URL(), NKeySeedFile: operatorSeed},
		Controller: ControllerConfig{TrustedSigners: []TrustedSignerConfig{grant}},
		Operator:   OperatorConfig{Actor: "ops", SigningKeyFile: filepath.Join(root, "operator.key")},
	})

	placementSub, err := servePlacementAdmission(ctx, broker.Conn(), "gru", policy, control)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = placementSub.Unsubscribe() })
	intent := testManagedPlacementIntentForRegions(oci.RegionGRU)
	placementPath := testJSONFile(t, root, "placement.json", intent)
	var placementOutput bytes.Buffer
	if err := Run(ctx, []string{"operator", "placement-apply", "--config", operatorConfig,
		"--intent", placementPath}, &placementOutput); err != nil {
		t.Fatalf("signed placement admission through restricted operator NKey: %v", err)
	}
	placementEntry, err := control.ReadPlacementIntent(ctx, intent.DatabaseID, intent.PartitionID)
	if err != nil {
		t.Fatalf("read committed placement for OCI fixture setup: %v", err)
	}
	intent, err = placement.DecodeCommittedIntent(placementEntry.Payload)
	if err != nil {
		t.Fatalf("decode committed placement for OCI fixture setup: %v", err)
	}

	reader, err := placement.NewAuthorityIntentReader(control, "gru", oci.RegionGRU)
	if err != nil {
		t.Fatal(err)
	}
	members, err := placement.NewJetStreamStore(ctx, broker.JetStream(), "gru", 1, reader)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := oci.OpenJournal(ctx, broker.JetStream(), 1)
	if err != nil {
		t.Fatal(err)
	}
	region := terminalIntegrationRegion()
	regionIntent := oci.RegionIntent{SchemaVersion: 1, Generation: region.Generation,
		BootstrapRegion: oci.RegionGRU,
		Regions:         []oci.RegionMapping{{Cell: oci.RegionGRU, OCIRegion: "sa-saopaulo-1"}},
	}
	provider := newTerminalIntegrationProvider(region)
	fleet, err := oci.NewFleetWithImageVerifier(region, regionIntent, provider, journal, control,
		nil, nil, terminalIntegrationImageVerifier{})
	if err != nil {
		t.Fatal(err)
	}
	terminalExecutor, ok := fleet.(oci.TerminalExecutor)
	if !ok {
		t.Fatal("region-bound OCI fleet does not expose terminal execution")
	}
	seats, err := placement.DesiredSeats(intent, map[oci.Region][]string{
		oci.RegionGRU: region.FaultDomains,
	})
	if err != nil {
		t.Fatal(err)
	}
	seededTargets, err := placement.TerminalTargetsForRegion(intent, oci.RegionGRU, region.FaultDomains, nil)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := intent.ManagedHostProfile(oci.RegionGRU)
	if err != nil {
		t.Fatal(err)
	}
	profileDigest, err := profile.ProfileDigest()
	if err != nil {
		t.Fatal(err)
	}
	rosterDigest, err := intent.CanonicalRosterDigest()
	if err != nil {
		t.Fatal(err)
	}
	grants, err := hostenroll.OpenGrantStore(ctx, broker.JetStream(), 1)
	if err != nil {
		t.Fatal(err)
	}
	hostNKey, _ := testNKey(t)
	identityPublic, identityPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(identityPrivate)
	var grantInstances []string
	for index, seat := range seats {
		target := seededTargets[index]
		row, err := intent.RosterRowForSeat(seat)
		if err != nil {
			t.Fatal(err)
		}
		manifest, err := intent.RuntimeManifestForSeat(seat)
		if err != nil {
			t.Fatal(err)
		}
		manifestDigest, err := manifest.Digest()
		if err != nil {
			t.Fatal(err)
		}
		privateIP := fmt.Sprintf("10.251.0.%d", index+21)
		name := fmt.Sprintf("gru-1-db-%d", index+1)
		host, err := fleet.EnsureHost(ctx, oci.EnsureRequest{
			Name: name, CreateKey: target.HostCreateKey, PrivateIP: privateIP, FaultDomain: seat.FailureDomain,
			Shape: profile.Compute.Shape, WholeOCPUs: profile.Compute.WholeOCPUs,
			MemoryInGBs:            profile.Compute.MemoryInGBs,
			PlacementProfileDigest: profileDigest, PlacementGeneration: intent.Generation,
			BootPins: oci.HostBootPins{
				DatabaseID: intent.DatabaseID, PartitionID: intent.PartitionID, SeatID: seat.MemberID,
				HostAttempt: 1, IntentPayloadDigest: intent.PayloadDigest(),
				CanonicalRosterDigest: rosterDigest, RuntimeManifestDigest: manifestDigest,
			},
		})
		if err != nil {
			t.Fatalf("create exact fake OCI host for %s: %v", seat.MemberID, err)
		}
		volume, err := fleet.CreateRetainedVolume(ctx, oci.VolumeCreateRequest{
			Name: name + "-data", DatabaseID: intent.DatabaseID, PartitionID: intent.PartitionID,
			MemberID: seat.MemberID, CreateKey: target.DataCreateKey, SizeGB: 50,
		})
		if err != nil {
			t.Fatalf("create exact fake OCI volume for %s: %v", seat.MemberID, err)
		}
		state := placement.MemberState{
			SchemaVersion: 5, DatabaseID: intent.DatabaseID, PartitionID: intent.PartitionID,
			MemberID: seat.MemberID, Region: seat.Region, FailureDomain: seat.FailureDomain,
			Kind: seat.Kind, Stage: placement.StageAwaitingHost, CreateKey: target.HostCreateKey,
			HostNode: host.Node, InstanceID: host.ID, VolumeID: volume.ID, HostAttempt: 1,
			IntentGeneration: intent.Generation, IntentPayloadDigest: intent.PayloadDigest(),
			ManagedHostProfile: profile, ManagedHostProfileDigest: profileDigest,
			CanonicalRosterRow: row, CanonicalRosterDigest: rosterDigest,
			AuthorityReference: intent.CanonicalRoster.Authority,
			RuntimeManifest:    manifest, RuntimeManifestDigest: manifestDigest,
			HostGeneration: 1, OperationID: entityid.Derive("test-operation", fmt.Sprintf("terminal-member-%d", index+1)), UpdatedAt: time.Now().UTC(),
		}
		if err := state.Validate(); err != nil {
			t.Fatalf("exact durable placement member %s: %v", seat.MemberID, err)
		}
		if _, err := members.CompareAndSwap(ctx, 0, state); err != nil {
			t.Fatalf("persist exact durable placement member %s: %v", seat.MemberID, err)
		}
		cloud, err := provider.GetInstance(ctx, host.ID)
		if err != nil {
			t.Fatal(err)
		}
		descriptor, err := hostboot.Parse([]byte(cloud.Metadata[hostboot.MetadataKey]))
		if err != nil {
			t.Fatal(err)
		}
		requestWire := terminalIntegrationGrantRequest(t, descriptor, host.ID, hostNKey, identityPublic, identityPrivate)
		descriptorDigest, err := descriptor.Digest()
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := grants.Claim(ctx, hostenroll.Grant{
			SchemaVersion: 1, InstanceID: host.ID, CreateKey: target.HostCreateKey,
			DescriptorSHA256: descriptorDigest, Request: requestWire,
		}); err != nil {
			t.Fatalf("persist exact real JetStream enrollment grant for %s: %v", seat.MemberID, err)
		}
		grantInstances = append(grantInstances, host.ID)
	}

	enrollment := &managedHostEnrollment{
		cell: "gru", region: oci.RegionGRU, owner: region.Owner, generation: region.Generation,
		environment: "production", fleet: fleet, intents: control, members: members,
		grants: grants, fencer: control,
	}
	terminalSub, err := serveTerminalAdmission(ctx, broker.Conn(), "gru", policy, control, region,
		members, terminalExecutor, enrollment.fenceTerminalGrants, enrollment.verifyTerminalGrantFence,
		enrollment.verifyTerminalGrants)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = terminalSub.Unsubscribe() })
	if err := broker.Conn().FlushTimeout(2 * time.Second); err != nil {
		t.Fatal(err)
	}

	var planOutput bytes.Buffer
	if err := Run(ctx, []string{"operator", "terminal-plan", "--config", operatorConfig,
		"--database-id", intent.DatabaseID, "--partition-id", intent.PartitionID,
		"--operation-id", entityid.Derive("test", "terminal-cleanup-a")}, &planOutput); err != nil {
		t.Fatalf("signed terminal plan through restricted operator NKey: %v", err)
	}
	var reviewed authority.TerminalIntent
	if err := json.Unmarshal(planOutput.Bytes(), &reviewed); err != nil {
		t.Fatalf("decode read-only terminal plan: %v", err)
	}
	if reviewed.DisposableWorkload || reviewed.AcknowledgePermanentDataLoss || reviewed.AuthorizeForcedStop ||
		len(reviewed.Targets) != 2 || reviewed.Targets[0].InstanceID == "" || reviewed.Targets[1].InstanceID == "" {
		t.Fatalf("terminal plan omitted exact resources or enabled consent: %+v", reviewed)
	}
	reviewed.DisposableWorkload = true
	reviewed.AcknowledgePermanentDataLoss = true
	reviewed.AuthorizeForcedStop = true
	applyPath := testJSONFile(t, root, "reviewed-terminal-plan.json", reviewed)
	var applyOutput bytes.Buffer
	if err := Run(ctx, []string{"operator", "terminal-apply", "--config", operatorConfig,
		"--intent", applyPath}, &applyOutput); err != nil {
		t.Fatalf("signed exact terminal apply through restricted operator NKey: %v", err)
	}
	var receipt terminalReply
	if err := json.Unmarshal(applyOutput.Bytes(), &receipt); err != nil || receipt.MarkerSequence == 0 || receipt.Intent == nil {
		t.Fatalf("terminal apply receipt: %+v, %v", receipt, err)
	}
	for _, instanceID := range grantInstances {
		grant, revision, err := grants.Read(ctx, instanceID)
		if err != nil || revision == 0 || !grant.Disabled {
			t.Fatalf("apply did not durably disable exact enrollment grant %s: grant=%+v revision=%d err=%v",
				instanceID, grant, revision, err)
		}
	}

	// The accepted marker is durable before the first OCI mutation. Status must
	// remain noncomplete while exact instances and their two volumes per host remain.
	var heldStatusOutput bytes.Buffer
	if err := Run(ctx, []string{"operator", "terminal-status", "--config", operatorConfig,
		"--database-id", intent.DatabaseID, "--partition-id", intent.PartitionID}, &heldStatusOutput); err != nil {
		t.Fatalf("signed terminal status before reconcile: %v", err)
	}
	var held terminalReply
	if err := json.Unmarshal(heldStatusOutput.Bytes(), &held); err != nil || held.Status == nil || held.Status.Phase == oci.TerminalPhaseComplete {
		t.Fatalf("terminal status completed before OCI teardown: %+v, %v", held, err)
	}

	terminalRuntime := &managedTerminalRuntime{
		control: control, placements: members, executor: terminalExecutor, enrollment: enrollment, requireEnrollment: true,
	}
	if err := terminalRuntime.reconcile(ctx); err != nil {
		t.Fatalf("production managed terminal runtime reconcile: %v", err)
	}
	if provider.terminated != 2 || provider.deletedBootVolumes != 2 || provider.deletedDataVolumes != 2 {
		t.Fatalf("exact fake OCI resources were not torn down: terminations=%d bootDeletes=%d dataDeletes=%d",
			provider.terminated, provider.deletedBootVolumes, provider.deletedDataVolumes)
	}
	for _, instanceID := range grantInstances {
		grant, revision, err := grants.Read(ctx, instanceID)
		if err != nil || revision == 0 || !grant.Disabled {
			t.Fatalf("post-teardown exact grant readback failed for %s: grant=%+v revision=%d err=%v",
				instanceID, grant, revision, err)
		}
	}

	// An unreadable grant is a held status even after OCI reports all six exact
	// resources deleted. Restore the stored value and verify the real readback path.
	grantKV, err := broker.JetStream().KeyValue(ctx, hostenroll.GrantBucket)
	if err != nil {
		t.Fatal(err)
	}
	key := terminalIntegrationGrantKey(grantInstances[0])
	grantValue, grantRevision, err := grants.Read(ctx, grantInstances[0])
	if err != nil {
		t.Fatal(err)
	}
	corruptRevision, err := grantKV.Update(ctx, key, []byte("{"), grantRevision)
	if err != nil {
		t.Fatalf("inject unreadable grant readback: %v", err)
	}
	var unreadableStatusOutput bytes.Buffer
	if err := Run(ctx, []string{"operator", "terminal-status", "--config", operatorConfig,
		"--database-id", intent.DatabaseID, "--partition-id", intent.PartitionID}, &unreadableStatusOutput); err != nil {
		t.Fatalf("signed terminal status with unreadable grant: %v", err)
	}
	var unreadable terminalReply
	if err := json.Unmarshal(unreadableStatusOutput.Bytes(), &unreadable); err != nil || unreadable.Status == nil ||
		unreadable.Status.Phase != oci.TerminalPhaseHeld || len(unreadable.Status.Pending) == 0 {
		t.Fatalf("status did not hold on unreadable terminal grant readback: %+v, %v", unreadable, err)
	}
	restored, err := json.Marshal(grantValue)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := grantKV.Update(ctx, key, restored, corruptRevision); err != nil {
		t.Fatalf("restore exact disabled grant value: %v", err)
	}
	var finalStatusOutput bytes.Buffer
	if err := Run(ctx, []string{"operator", "terminal-status", "--config", operatorConfig,
		"--database-id", intent.DatabaseID, "--partition-id", intent.PartitionID}, &finalStatusOutput); err != nil {
		t.Fatalf("signed terminal status after exact grant readback: %v", err)
	}
	var final terminalReply
	if err := json.Unmarshal(finalStatusOutput.Bytes(), &final); err != nil || final.Status == nil ||
		final.Status.Phase != oci.TerminalPhaseComplete || final.MarkerSequence != receipt.MarkerSequence {
		t.Fatalf("terminal status did not confirm exact teardown and grant readback: %+v, %v", final, err)
	}
}

func terminalIntegrationRegion() oci.RegionConfig {
	return oci.RegionConfig{
		Region: oci.RegionGRU, Generation: 1,
		Endpoint:                "https://iaas.sa-saopaulo-1.oraclecloud.com",
		CompartmentID:           "ocid1.compartment.oc1.sa-saopaulo-1.terminaltest",
		ImageCompartmentID:      "ocid1.compartment.oc1.sa-saopaulo-1.terminaltest-image",
		AvailabilityDomain:      "sa-saopaulo-1-AD-1",
		FaultDomains:            []string{"FAULT-DOMAIN-1", "FAULT-DOMAIN-2"},
		SubnetID:                "ocid1.subnet.oc1.sa-saopaulo-1.terminaltest",
		NetworkSecurityGroupIDs: []string{"ocid1.networksecuritygroup.oc1.sa-saopaulo-1.terminaltest"},
		ImageID:                 "ocid1.image.oc1.sa-saopaulo-1.terminaltest", BootVolumeGB: 50,
		BootVolumeVPUsPerGB: 10, DataVolumeVPUsPerGB: 10, MaxDataVolumeGB: 50,
		Shape: "VM.Standard.E4.Flex", Owner: "terminal-owner",
	}
}

type terminalIntegrationImageVerifier struct{}

func (terminalIntegrationImageVerifier) VerifyImageQualified(context.Context, oci.Region, string) error {
	return nil
}

type terminalIntegrationProvider struct {
	oci.Provider
	config             oci.RegionConfig
	instances          map[string]oci.CloudInstance
	boots              map[string]oci.CloudBootVolume
	bootForInstance    map[string]string
	volumes            map[string]oci.CloudVolume
	next               int
	terminated         int
	deletedBootVolumes int
	deletedDataVolumes int
}

func newTerminalIntegrationProvider(config oci.RegionConfig) *terminalIntegrationProvider {
	return &terminalIntegrationProvider{config: config, instances: make(map[string]oci.CloudInstance),
		boots: make(map[string]oci.CloudBootVolume), bootForInstance: make(map[string]string),
		volumes: make(map[string]oci.CloudVolume)}
}

func (provider *terminalIntegrationProvider) ListInstances(_ context.Context, compartment string) ([]oci.CloudInstance, error) {
	if compartment != provider.config.CompartmentID {
		return nil, oci.ErrForeignResource
	}
	instances := make([]oci.CloudInstance, 0, len(provider.instances))
	for _, instance := range provider.instances {
		instances = append(instances, instance)
	}
	return instances, nil
}

func (provider *terminalIntegrationProvider) GetInstance(_ context.Context, id string) (oci.CloudInstance, error) {
	instance, ok := provider.instances[id]
	if !ok {
		return oci.CloudInstance{}, terminalIntegrationNotFound{}
	}
	return instance, nil
}

func (provider *terminalIntegrationProvider) LaunchInstance(_ context.Context, request oci.LaunchRequest) (oci.CloudInstance, error) {
	provider.next++
	id := fmt.Sprintf("ocid1.instance.oc1.sa-saopaulo-1.terminaltest-%d", provider.next)
	bootID := fmt.Sprintf("ocid1.bootvolume.oc1.sa-saopaulo-1.terminaltest-%d", provider.next)
	instance := oci.CloudInstance{
		ID: id, PrivateIP: request.PrivateIP, CompartmentID: provider.config.CompartmentID,
		AvailabilityDomain: provider.config.AvailabilityDomain, FaultDomain: request.FaultDomain,
		Shape: request.Shape, Ocpus: new(float32(request.WholeOCPUs)),
		MemoryInGBs: new(float32(request.MemoryInGBs)), LifecycleState: "PROVISIONING",
		ETag: "terminal-instance-etag", ImageID: provider.config.ImageID,
		ConsistentVolumeNamingEnabled: new(true),
		Metadata:                      map[string]string{hostboot.MetadataKey: request.BootDescriptor, "terrascale_host_node": request.Node},
		FreeformTags:                  request.FreeformTags,
	}
	provider.instances[id] = instance
	provider.bootForInstance[id] = bootID
	provider.boots[bootID] = oci.CloudBootVolume{
		ID: bootID, CompartmentID: provider.config.CompartmentID,
		AvailabilityDomain: provider.config.AvailabilityDomain, ImageID: provider.config.ImageID,
		SizeGB: int64(provider.config.BootVolumeGB), VPUsPerGB: int64(provider.config.BootVolumeVPUsPerGB),
		LifecycleState: "AVAILABLE", ETag: "terminal-boot-etag",
	}
	return instance, nil
}

func (provider *terminalIntegrationProvider) GetAttachedBootVolume(_ context.Context, instanceID string) (oci.CloudBootVolume, error) {
	bootID := provider.bootForInstance[instanceID]
	boot, ok := provider.boots[bootID]
	if !ok {
		return oci.CloudBootVolume{}, terminalIntegrationNotFound{}
	}
	return boot, nil
}

func (provider *terminalIntegrationProvider) GetBootVolume(_ context.Context, id string) (oci.CloudBootVolume, error) {
	boot, ok := provider.boots[id]
	if !ok {
		return oci.CloudBootVolume{}, terminalIntegrationNotFound{}
	}
	return boot, nil
}

func (*terminalIntegrationProvider) ListBootVolumeAttachments(context.Context, string) ([]oci.CloudBootAttachment, error) {
	return nil, nil
}

func (provider *terminalIntegrationProvider) TerminateTerminalInstance(_ context.Context, id, etag string) error {
	instance, ok := provider.instances[id]
	if !ok {
		return terminalIntegrationNotFound{}
	}
	if instance.ETag != etag {
		return errors.New("terminal integration instance ETag changed")
	}
	instance.LifecycleState = "TERMINATED"
	provider.instances[id] = instance
	provider.terminated++
	return nil
}

func (*terminalIntegrationProvider) ListVolumeAttachments(context.Context, string, string) ([]oci.CloudAttachment, error) {
	return nil, nil
}

func (provider *terminalIntegrationProvider) ListVolumes(_ context.Context, compartment, domain string) ([]oci.CloudVolume, error) {
	if compartment != provider.config.CompartmentID || domain != provider.config.AvailabilityDomain {
		return nil, oci.ErrForeignResource
	}
	volumes := make([]oci.CloudVolume, 0, len(provider.volumes))
	for _, volume := range provider.volumes {
		volumes = append(volumes, volume)
	}
	return volumes, nil
}

func (provider *terminalIntegrationProvider) CreateVolume(_ context.Context, request oci.VolumeCreateRequest,
	tags map[string]string, _ string,
) (oci.CloudVolume, error) {
	provider.next++
	volume := oci.CloudVolume{
		ID:            fmt.Sprintf("ocid1.volume.oc1.sa-saopaulo-1.terminaltest-%d", provider.next),
		CompartmentID: provider.config.CompartmentID, AvailabilityDomain: provider.config.AvailabilityDomain,
		SizeGB: request.SizeGB, VPUsPerGB: int64(provider.config.DataVolumeVPUsPerGB),
		LifecycleState: "AVAILABLE", ETag: "terminal-volume-etag", FreeformTags: tags,
	}
	provider.volumes[volume.ID] = volume
	return volume, nil
}

func (provider *terminalIntegrationProvider) GetVolume(_ context.Context, id string) (oci.CloudVolume, error) {
	volume, ok := provider.volumes[id]
	if !ok {
		return oci.CloudVolume{}, terminalIntegrationNotFound{}
	}
	return volume, nil
}

func (provider *terminalIntegrationProvider) DeleteBootVolume(_ context.Context, id, etag string) error {
	boot, ok := provider.boots[id]
	if !ok {
		return terminalIntegrationNotFound{}
	}
	if boot.ETag != etag {
		return errors.New("terminal integration boot volume ETag changed")
	}
	delete(provider.boots, id)
	provider.deletedBootVolumes++
	return nil
}

func (provider *terminalIntegrationProvider) DeleteVolume(_ context.Context, id, etag string) error {
	volume, ok := provider.volumes[id]
	if !ok {
		return terminalIntegrationNotFound{}
	}
	if volume.ETag != etag {
		return errors.New("terminal integration data volume ETag changed")
	}
	delete(provider.volumes, id)
	provider.deletedDataVolumes++
	return nil
}

type terminalIntegrationNotFound struct{}

func (terminalIntegrationNotFound) Error() string          { return "terminal integration resource not found" }
func (terminalIntegrationNotFound) GetHTTPStatusCode() int { return 404 }

func terminalIntegrationGrantRequest(t *testing.T, descriptor hostboot.Descriptor, instanceID, hostNKey string,
	identityPublic ed25519.PublicKey, identityPrivate ed25519.PrivateKey,
) []byte {
	t.Helper()
	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, csrKey)
	if err != nil {
		t.Fatal(err)
	}
	descriptorWire, err := descriptor.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	request := hostenroll.Request{
		SchemaVersion: 1, Operation: "enroll", InstanceID: instanceID,
		Descriptor: string(descriptorWire), IdentityPublicKey: base64.StdEncoding.EncodeToString(identityPublic),
		NATSUserPublicKey: hostNKey,
		CSRPEM:            string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})),
		Nonce:             base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)), IssuedAt: time.Now().UTC(),
	}
	if err := request.Sign(identityPrivate); err != nil {
		t.Fatal(err)
	}
	wire, err := protocol.EncodeJSON(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, parsed, err := hostenroll.ParseRequest(wire, time.Now().UTC().Add(time.Second)); err != nil || parsed != descriptor {
		t.Fatalf("validate exact synthetic host enrollment request: descriptor=%+v err=%v", parsed, err)
	}
	return wire
}

func terminalIntegrationGrantKey(instanceID string) string {
	return entityid.Derive("host-enrollment", instanceID)
}

var _ oci.Provider = (*terminalIntegrationProvider)(nil)
var _ oci.ImageQualificationVerifier = terminalIntegrationImageVerifier{}
