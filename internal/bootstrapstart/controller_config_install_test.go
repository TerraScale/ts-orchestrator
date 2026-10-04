package bootstrapstart

import (
	"bytes"
	"errors"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostboot"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

func TestVerifyControllerConfigInstallBindsSignedEnvelopeAndOCIInstance(t *testing.T) {
	fixture := newAdmissionFlowFixture(t)
	gate := fixture.gate
	wire := gate.Ledgers.(*countingLedgerOpener).state.ManifestRecord.Bytes
	baked := BakedInputs{Roots: gate.Roots, AnchorWire: gate.AnchorWire,
		Identity: BakedIdentity{SchemaVersion: 1, DeploymentID: gate.Expected.DeploymentID,
			Environment: gate.Expected.Environment, Cell: gate.Expected.Cell}}
	manifest, observed, err := VerifyControllerConfigInstall(t.Context(), baked, wire,
		gate.Descriptor, gate.Instances, *fixture.now)
	if err != nil || manifest.Slot != "controller-b" || observed.InstanceOCID == "" {
		t.Fatalf("valid signed controller install proof rejected: manifest=%+v observed=%+v err=%v", manifest, observed, err)
	}
	tampered := bytes.Clone(wire)
	tampered[len(tampered)/2] ^= 1
	tests := []struct {
		name       string
		wire       []byte
		descriptor DescriptorSource
		observer   InstanceObserver
	}{
		{name: "tampered envelope", wire: tampered, descriptor: gate.Descriptor, observer: gate.Instances},
		{name: "wrong slot", wire: wire, descriptor: fixedDescriptor{slot: "wrong-slot", instance: observed.InstanceOCID}, observer: gate.Instances},
		{name: "wrong instance", wire: wire, descriptor: fixedDescriptor{slot: "controller-b", instance: "ocid1.instance.oc1.sa-saopaulo-1.wrong"}, observer: gate.Instances},
		{name: "wrong image", wire: wire, descriptor: gate.Descriptor, observer: fakeInstanceObserver{func() InstanceObservation {
			changed := observed
			changed.ImageOCID = "ocid1.image.oc1.sa-saopaulo-1.wrong"
			return changed
		}()}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := VerifyControllerConfigInstall(t.Context(), baked, tc.wire,
				tc.descriptor, tc.observer, *fixture.now); err == nil {
				t.Fatal("untrusted controller install input was accepted")
			}
		})
	}
}

func TestFounderLaunchMetadataReachesControllerConfigInstall(t *testing.T) {
	fixture := newAdmissionFlowFixture(t)
	gate := fixture.gate
	wire := gate.Ledgers.(*countingLedgerOpener).state.ManifestRecord.Bytes
	envelope, err := trust.DecodeEnvelope(wire)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := bootstrap.ManifestPayload(envelope.Payload)
	if err != nil {
		t.Fatal(err)
	}
	profile := manifest.Profiles[0]
	instanceID, err := gate.Descriptor.FetchInstanceID(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	observed, err := gate.Instances.ObserveInstance(t.Context(), instanceID)
	if err != nil {
		t.Fatal(err)
	}
	request := bootstrap.FounderPeerLaunchRequest{
		DeploymentID: manifest.DeploymentID, Cell: manifest.Cell, Environment: manifest.Environment,
		Slot: manifest.Slot, ManifestWire: wire, ManifestSHA256: digestWire(wire), RetryToken: "fixed-test-token",
		Row: bootstrap.FounderPeerRow{Slot: manifest.Slot, ImageOCID: manifest.ImageOCID,
			CompartmentOCID: profile.CompartmentOCID, AvailabilityDomain: profile.AvailabilityDomain,
			FaultDomain: profile.FaultDomain, SubnetOCID: profile.SubnetOCID,
			NetworkSecurityGroupOCIDs: profile.NetworkSecurityGroupOCIDs, Shape: profile.Shape,
			PrivateIP: observed.PrimaryPrivateIP, WholeOCPUs: 1, MemoryInGB: 6,
			BootVolumeGB: 50, BootVolumeTier: bootstrap.FounderBootVolumeTierBalanced},
	}
	material := LaunchMaterial{Identity: []byte(`{"identity":1}`), Anchor: gate.AnchorWire,
		HostEnrollment: []byte(`{"bundle":1}`), OperatorSSHKey: []byte(testOperatorSSHKey)}
	sdk, err := founderLaunchSDKRequest(request, material)
	if err != nil {
		t.Fatal(err)
	}
	if sdk.Metadata[AnchorMetadataKey] != string(gate.AnchorWire) ||
		sdk.Metadata[IdentityMetadataKey] != string(material.Identity) ||
		sdk.Metadata[hostboot.EnrollmentMetadataKey] != string(material.HostEnrollment) ||
		sdk.Metadata[OperatorSSHKeyMetadataKey] != testOperatorSSHKey {
		t.Fatal("OCI launch did not carry the controller launch material")
	}
	if _, err := founderLaunchSDKRequest(request, LaunchMaterial{}); !errors.Is(err, ErrFounderOCI) {
		t.Fatalf("founder launched a peer without launch material: %v", err)
	}
	metadataWire := []byte(sdk.Metadata["terrascale-controller-manifest-v1"])
	if !bytes.Equal(metadataWire, wire) {
		t.Fatal("OCI launch did not carry the exact signed manifest envelope")
	}
	desc, err := ParseDescriptor([]byte(sdk.Metadata["terrascale-bootstrap"]))
	if err != nil {
		t.Fatal(err)
	}
	baked := BakedInputs{Roots: gate.Roots, AnchorWire: gate.AnchorWire,
		Identity: BakedIdentity{SchemaVersion: 1, DeploymentID: gate.Expected.DeploymentID,
			Environment: gate.Expected.Environment, Cell: gate.Expected.Cell}}
	installed, _, err := VerifyControllerConfigInstall(t.Context(), baked, metadataWire,
		fixedDescriptor{slot: desc.Slot, instance: instanceID}, gate.Instances, *fixture.now)
	if err != nil || installed.ControllerConfigSHA256 != manifest.ControllerConfigSHA256 {
		t.Fatalf("guest rejected the launched signed config: manifest=%+v err=%v", installed, err)
	}
}
