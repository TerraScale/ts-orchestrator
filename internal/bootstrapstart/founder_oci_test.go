package bootstrapstart

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"github.com/oracle/oci-go-sdk/v65/core"
)

const (
	founderTestInstanceID = "ocid1.instance.oc1.sa-saopaulo-1.peer"
	founderTestVNICID     = "ocid1.vnic.oc1.sa-saopaulo-1.peer"
	founderTestBootID     = "ocid1.bootvolume.oc1.sa-saopaulo-1.peer"
)

func founderOCIRequestFixture(t *testing.T) bootstrap.FounderPeerLaunchRequest {
	t.Helper()
	fixture := newFounderSelectionFixture(t)
	manifestWire := fixture.manifests["controller-b"]
	return bootstrap.FounderPeerLaunchRequest{
		DeploymentID: "deployment-a", Cell: oci.RegionGRU, Environment: "production",
		Slot: "controller-b", ManifestWire: manifestWire, ManifestSHA256: digestWire(manifestWire),
		RetryToken: "fixed-original-token",
		Row: bootstrap.FounderPeerRow{
			Slot: "controller-b", ImageOCID: "ocid1.image.oc1.sa-saopaulo-1.image",
			ImageCompartmentOCID: "ocid1.compartment.oc1..images",
			CompartmentOCID:      "ocid1.compartment.oc1..peers",
			AvailabilityDomain:   "SA-SAOPAULO-1-AD-1", FaultDomain: "FAULT-DOMAIN-2",
			SubnetOCID: "ocid1.subnet.oc1.sa-saopaulo-1.peers",
			NetworkSecurityGroupOCIDs: []string{
				"ocid1.networksecuritygroup.oc1.sa-saopaulo-1.a",
				"ocid1.networksecuritygroup.oc1.sa-saopaulo-1.b",
			},
			Shape: "VM.Standard.E5.Flex", WholeOCPUs: 2, MemoryInGB: 12,
			BootVolumeGB: 50, BootVolumeTier: bootstrap.FounderBootVolumeTierBalanced,
			PrivateIP: "10.44.0.12",
		},
	}
}

func TestFounderOCIObservationOnlyAttemptCannotLaunchOrChangeCandidate(t *testing.T) {
	request := founderOCIRequestFixture(t)
	attempt := FounderOCIAttempt{request: request, deadline: time.Now().UTC().Add(time.Hour),
		observationOnly: true, candidateID: founderTestInstanceID, valid: true}
	adapter := &FounderOCI{region: oci.RegionGRU}
	if _, err := adapter.Launch(t.Context(), attempt, nil); !errors.Is(err, ErrFounderOCI) {
		t.Fatalf("observation-only attempt reached launch path: %v", err)
	}
	if _, err := adapter.Observe(t.Context(), attempt, nil,
		"ocid1.instance.oc1.sa-saopaulo-1.other"); !errors.Is(err, ErrFounderOCI) {
		t.Fatalf("observation-only attempt changed exact candidate: %v", err)
	}
}

type lostResponseCompute struct {
	requests []core.LaunchInstanceRequest
}

func (fake *lostResponseCompute) LaunchInstance(_ context.Context, request core.LaunchInstanceRequest) (core.LaunchInstanceResponse, error) {
	fake.requests = append(fake.requests, request)
	if len(fake.requests) == 1 {
		return core.LaunchInstanceResponse{}, errors.New("response lost after OCI accepted request")
	}
	return core.LaunchInstanceResponse{Instance: core.Instance{
		Id: new(founderTestInstanceID), CompartmentId: request.CompartmentId,
		ImageId: new("ocid1.image.oc1.sa-saopaulo-1.image"),
	}}, nil
}

func TestFounderOCIProjectionUsesPinnedFlexNetworkImageAndBootTier(t *testing.T) {
	request := founderOCIRequestFixture(t)
	sdk, err := founderLaunchSDKRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	row := request.Row
	if value(sdk.AvailabilityDomain) != row.AvailabilityDomain || value(sdk.CompartmentId) != row.CompartmentOCID ||
		value(sdk.FaultDomain) != row.FaultDomain || value(sdk.Shape) != row.Shape ||
		value(sdk.OpcRetryToken) != request.RetryToken || value(sdk.DisplayName) != request.Slot {
		t.Fatalf("launch request omitted signed placement, shape, or retry token: %+v", sdk)
	}
	if sdk.RequestMetadata.RetryPolicy == nil || sdk.RequestMetadata.RetryPolicy.MaximumNumberAttempts != 1 ||
		sdk.ShapeConfig == nil || sdk.ShapeConfig.Ocpus == nil || *sdk.ShapeConfig.Ocpus != 2 ||
		sdk.ShapeConfig.MemoryInGBs == nil || *sdk.ShapeConfig.MemoryInGBs != 12 {
		t.Fatal("launch request changed exact Flex dimensions or enabled SDK retries")
	}
	source, ok := sdk.SourceDetails.(core.InstanceSourceViaImageDetails)
	if !ok || value(source.ImageId) != row.ImageOCID || source.BootVolumeSizeInGBs == nil ||
		*source.BootVolumeSizeInGBs != 50 || source.BootVolumeVpusPerGB == nil || *source.BootVolumeVpusPerGB != 10 {
		t.Fatalf("source details = %#v", sdk.SourceDetails)
	}
	if sdk.CreateVnicDetails == nil || value(sdk.CreateVnicDetails.SubnetId) != row.SubnetOCID ||
		value(sdk.CreateVnicDetails.PrivateIp) != row.PrivateIP || sdk.CreateVnicDetails.AssignPublicIp == nil ||
		*sdk.CreateVnicDetails.AssignPublicIp || !slices.Equal(sdk.CreateVnicDetails.NsgIds, row.NetworkSecurityGroupOCIDs) {
		t.Fatalf("VNIC details = %#v", sdk.CreateVnicDetails)
	}
	descriptor, err := ParseDescriptor([]byte(sdk.Metadata["terrascale-bootstrap"]))
	if err != nil || descriptor != (Descriptor{SchemaVersion: 1, Slot: request.Slot}) {
		t.Fatalf("slot metadata = %q, descriptor=%+v, err=%v", sdk.Metadata["terrascale-bootstrap"], descriptor, err)
	}
	if len(sdk.FreeformTags) != 0 {
		t.Fatal("mutable tags were used as launch identity")
	}
}

func TestFounderOCILostResponseRetryKeepsOriginalTokenAndOneSDKAttempt(t *testing.T) {
	request := founderOCIRequestFixture(t)
	fake := new(lostResponseCompute)
	for range 2 {
		sdk, err := founderLaunchSDKRequest(request)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = fake.LaunchInstance(t.Context(), sdk)
	}
	if len(fake.requests) != 2 || value(fake.requests[0].OpcRetryToken) != request.RetryToken ||
		value(fake.requests[1].OpcRetryToken) != request.RetryToken ||
		!reflect.DeepEqual(fake.requests[0].LaunchInstanceDetails, fake.requests[1].LaunchInstanceDetails) {
		t.Fatal("lost-response replay changed the original token or request")
	}
	for _, sdk := range fake.requests {
		if sdk.RequestMetadata.RetryPolicy == nil || sdk.RequestMetadata.RetryPolicy.MaximumNumberAttempts != 1 {
			t.Fatal("SDK could retry without a new authority read")
		}
	}
	bad := request
	bad.Row.BootVolumeTier = "higher-performance"
	if _, err := founderLaunchSDKRequest(bad); !errors.Is(err, ErrFounderOCI) {
		t.Fatalf("unsupported boot tier = %v", err)
	}
	bad = request
	bad.Row.WholeOCPUs = 1<<24 + 1
	if _, err := founderLaunchSDKRequest(bad); !errors.Is(err, ErrFounderOCI) {
		t.Fatalf("inexact float32 OCPU count = %v", err)
	}
}

func TestFounderOCIBootVolumeLaunchSizeBounds(t *testing.T) {
	for _, test := range []struct {
		gigabytes uint32
		valid     bool
	}{
		{49, false},
		{50, true},
		{32768, true},
		{32769, false},
	} {
		request := founderOCIRequestFixture(t)
		request.Row.BootVolumeGB = test.gigabytes
		sdk, err := founderLaunchSDKRequest(request)
		if test.valid {
			if err != nil {
				t.Fatalf("boot volume %d GB was rejected: %v", test.gigabytes, err)
			}
			source := sdk.SourceDetails.(core.InstanceSourceViaImageDetails)
			if source.BootVolumeSizeInGBs == nil || *source.BootVolumeSizeInGBs != int64(test.gigabytes) {
				t.Fatalf("boot volume %d GB projected as %#v", test.gigabytes, source.BootVolumeSizeInGBs)
			}
		} else if !errors.Is(err, ErrFounderOCI) {
			t.Fatalf("boot volume %d GB was accepted: %v", test.gigabytes, err)
		}
	}
}

func TestFounderOCIAttemptRejectsChangedAuthorityTokenAndDeadline(t *testing.T) {
	request := founderOCIRequestFixture(t)
	request.FounderPlanSHA256 = "plan-A"
	request.IntentSHA256 = "original-intent"
	now := time.Date(2026, time.September, 26, 7, 0, 0, 0, time.UTC)
	deadline := now.Add(23 * time.Hour)
	attempt := FounderOCIAttempt{request: request, deadline: deadline, valid: true}
	if !sameFounderAttempt(attempt, request, deadline, now) {
		t.Fatal("same original attempt was rejected")
	}
	changed := request
	changed.FounderPlanSHA256 = "plan-B"
	if sameFounderAttempt(attempt, changed, deadline, now) {
		t.Fatal("a superseding selected plan authorized a retry of the old attempt")
	}
	changed = request
	changed.RetryToken = "new-token"
	if sameFounderAttempt(attempt, changed, deadline, now) {
		t.Fatal("a changed retry token was accepted")
	}
	changed = request
	changed.IntentSHA256 = "replacement-intent"
	if sameFounderAttempt(attempt, changed, deadline, now) {
		t.Fatal("a changed intent was accepted")
	}
	if sameFounderAttempt(attempt, request, deadline.Add(time.Second), now) ||
		sameFounderAttempt(attempt, request, deadline, deadline) ||
		sameFounderAttempt(attempt, request, deadline, now.In(time.FixedZone("other", 0))) {
		t.Fatal("an extended or expired effect deadline was accepted")
	}
}

func TestFounderOCIObservationRejectsEveryPinnedMismatch(t *testing.T) {
	request := founderOCIRequestFixture(t)
	row := request.Row
	descriptor := `{"schemaVersion":1,"slot":"controller-b"}`
	instance := core.Instance{
		Id: new(founderTestInstanceID), CompartmentId: new(row.CompartmentOCID), ImageId: new(row.ImageOCID),
		AvailabilityDomain: new(row.AvailabilityDomain), FaultDomain: new(row.FaultDomain), Shape: new(row.Shape),
		LifecycleState: core.InstanceLifecycleStateRunning, Metadata: map[string]string{"terrascale-bootstrap": descriptor},
		ShapeConfig: &core.InstanceShapeConfig{Ocpus: new(float32(2)), MemoryInGBs: new(float32(12))},
	}
	image := core.Image{Id: new(row.ImageOCID), CompartmentId: new(row.ImageCompartmentOCID),
		LifecycleState: core.ImageLifecycleStateAvailable}
	vnic := core.Vnic{
		Id: new(founderTestVNICID), CompartmentId: new("ocid1.compartment.oc1..network"),
		AvailabilityDomain: new(row.AvailabilityDomain), SubnetId: new(row.SubnetOCID),
		PrivateIp: new(row.PrivateIP), IsPrimary: new(true), LifecycleState: core.VnicLifecycleStateAvailable,
		NsgIds: slices.Clone(row.NetworkSecurityGroupOCIDs),
	}
	volume := core.BootVolume{
		Id: new(founderTestBootID), CompartmentId: new(row.CompartmentOCID),
		AvailabilityDomain: new(row.AvailabilityDomain), ImageId: new(row.ImageOCID),
		SizeInGBs: new(int64(50)), VpusPerGB: new(int64(10)), LifecycleState: core.BootVolumeLifecycleStateAvailable,
	}
	if !founderInstanceMatches(instance, founderTestInstanceID, row, descriptor) ||
		!founderImageMatches(image, row) || !founderVNICMatches(vnic, founderTestVNICID, row) ||
		!founderBootVolumeMatches(volume, founderTestBootID, row) ||
		!founderObservationImageProven(instance, volume, row) {
		t.Fatal("baseline exact OCI observations were rejected")
	}
	tests := []struct {
		name  string
		match func() bool
	}{
		{"wrong instance OCID", func() bool { return founderInstanceMatches(instance, founderTestInstanceID+"foreign", row, descriptor) }},
		{"wrong instance compartment", func() bool {
			changed := instance
			changed.CompartmentId = new("foreign")
			return founderInstanceMatches(changed, founderTestInstanceID, row, descriptor)
		}},
		{"wrong instance image", func() bool {
			changed := instance
			changed.ImageId = new("foreign")
			return founderInstanceMatches(changed, founderTestInstanceID, row, descriptor)
		}},
		{"wrong fault domain", func() bool {
			changed := instance
			changed.FaultDomain = new("FAULT-DOMAIN-1")
			return founderInstanceMatches(changed, founderTestInstanceID, row, descriptor)
		}},
		{"wrong Flex memory", func() bool {
			changed := instance
			changed.ShapeConfig = &core.InstanceShapeConfig{Ocpus: new(float32(2)), MemoryInGBs: new(float32(8))}
			return founderInstanceMatches(changed, founderTestInstanceID, row, descriptor)
		}},
		{"wrong slot metadata", func() bool {
			changed := instance
			changed.Metadata = map[string]string{"terrascale-bootstrap": "foreign"}
			return founderInstanceMatches(changed, founderTestInstanceID, row, descriptor)
		}},
		{"wrong image compartment", func() bool {
			changed := image
			changed.CompartmentId = new("foreign")
			return founderImageMatches(changed, row)
		}},
		{"wrong image state", func() bool {
			changed := image
			changed.LifecycleState = core.ImageLifecycleStateDeleted
			return founderImageMatches(changed, row)
		}},
		{"wrong primary private IP", func() bool {
			changed := vnic
			changed.PrivateIp = new("10.44.0.13")
			return founderVNICMatches(changed, founderTestVNICID, row)
		}},
		{"wrong subnet", func() bool {
			changed := vnic
			changed.SubnetId = new("foreign")
			return founderVNICMatches(changed, founderTestVNICID, row)
		}},
		{"wrong NSGs", func() bool {
			changed := vnic
			changed.NsgIds = []string{"foreign"}
			return founderVNICMatches(changed, founderTestVNICID, row)
		}},
		{"public IP", func() bool {
			changed := vnic
			changed.PublicIp = new("203.0.113.2")
			return founderVNICMatches(changed, founderTestVNICID, row)
		}},
		{"not primary", func() bool {
			changed := vnic
			changed.IsPrimary = new(false)
			return founderVNICMatches(changed, founderTestVNICID, row)
		}},
		{"wrong boot size", func() bool {
			changed := volume
			changed.SizeInGBs = new(int64(100))
			return founderBootVolumeMatches(changed, founderTestBootID, row)
		}},
		{"wrong boot tier", func() bool {
			changed := volume
			changed.VpusPerGB = new(int64(20))
			return founderBootVolumeMatches(changed, founderTestBootID, row)
		}},
		{"missing boot image", func() bool {
			changed := volume
			changed.ImageId = nil
			return founderBootVolumeMatches(changed, founderTestBootID, row)
		}},
		{"wrong boot source", func() bool {
			changed := volume
			changed.ImageId = new("foreign")
			return founderBootVolumeMatches(changed, founderTestBootID, row)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.match() {
				t.Fatal("mismatched OCI observation was accepted")
			}
		})
	}
}

func TestFounderVNICRequiresSubnetNetworkOwnership(t *testing.T) {
	row := founderOCIRequestFixture(t).Row
	vnic := core.Vnic{
		Id: new(founderTestVNICID), CompartmentId: new("ocid1.compartment.oc1..network"),
		AvailabilityDomain: new(row.AvailabilityDomain), SubnetId: new(row.SubnetOCID),
		PrivateIp: new(row.PrivateIP), IsPrimary: new(true), LifecycleState: core.VnicLifecycleStateAvailable,
		NsgIds: slices.Clone(row.NetworkSecurityGroupOCIDs),
	}
	subnet := core.Subnet{Id: new(row.SubnetOCID), CompartmentId: new("ocid1.compartment.oc1..network"),
		VcnId: new("ocid1.vcn.oc1.sa-saopaulo-1.founder"), LifecycleState: core.SubnetLifecycleStateAvailable}
	if !founderVNICMatches(vnic, founderTestVNICID, row) ||
		!vnicSubnetMatches(vnic, subnet, founderTestInstanceID) {
		t.Fatal("valid founder VNIC in network compartment rejected")
	}
	subnet.CompartmentId = new(row.CompartmentOCID)
	if vnicSubnetMatches(vnic, subnet, founderTestInstanceID) {
		t.Fatal("founder VNIC accepted subnet in control compartment")
	}
}

func TestFounderOCIUsesModernImageSourceAndRequiresPositiveProvenance(t *testing.T) {
	row := founderOCIRequestFixture(t).Row
	instance := core.Instance{Id: new(founderTestInstanceID), CompartmentId: new(row.CompartmentOCID)}
	if !founderLaunchCandidateMatches(instance, row) {
		t.Fatal("launch response without deprecated image ID lost its exact candidate OCID")
	}
	volume := core.BootVolume{ImageId: new(row.ImageOCID)}
	if !founderObservationImageProven(instance, volume, row) {
		t.Fatal("attached boot volume did not establish exact image provenance")
	}
	volume.ImageId = nil
	if founderObservationImageProven(instance, volume, row) {
		t.Fatal("missing attached-volume image was treated as positive provenance")
	}
	instance.SourceDetails = core.InstanceSourceViaImageDetails{ImageId: new(row.ImageOCID)}
	if founderObservationImageProven(instance, volume, row) {
		t.Fatal("historical launch source concealed missing current-volume provenance")
	}
	volume.ImageId = new(row.ImageOCID)
	if !founderObservationImageProven(instance, volume, row) {
		t.Fatal("matching modern source and current-volume image were rejected")
	}
	instance.ImageId = new(row.ImageOCID)
	instance.SourceDetails = core.InstanceSourceViaImageDetails{ImageId: new("foreign")}
	if founderLaunchCandidateMatches(instance, row) || founderObservationImageProven(instance, volume, row) {
		t.Fatal("conflicting legacy and modern image IDs were accepted")
	}
	instance.ImageId = nil
	instance.SourceDetails = core.InstanceSourceViaBootVolumeDetails{}
	if founderLaunchCandidateMatches(instance, row) || founderObservationImageProven(instance, volume, row) {
		t.Fatal("boot-volume launch source was accepted for a signed image launch")
	}
	instance.SourceDetails = nil
	volume.ImageId = new("foreign")
	if founderObservationImageProven(instance, volume, row) {
		t.Fatal("replacement boot-volume image was accepted")
	}
}
