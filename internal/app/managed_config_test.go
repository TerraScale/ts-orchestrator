package app

import (
	"context"
	"strings"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
)

func TestManagedControllerConfigRejectsGenericMemberRole(t *testing.T) {
	intent := oci.RegionIntent{SchemaVersion: 1, Generation: 7, BootstrapRegion: oci.RegionGRU,
		Regions: []oci.RegionMapping{{Cell: oci.RegionGRU, OCIRegion: "sa-saopaulo-1"}}}
	region := oci.RegionConfig{Region: oci.RegionGRU, Generation: 7, Endpoint: "https://iaas.sa-saopaulo-1.oraclecloud.com",
		CompartmentID: "ocid1.compartment.oc1..owned", ImageCompartmentID: "ocid1.compartment.oc1..image", AvailabilityDomain: "AD-1",
		FaultDomains: []string{"FAULT-DOMAIN-1", "FAULT-DOMAIN-2"}, SubnetID: "ocid1.subnet.oc1..owned",
		NetworkSecurityGroupIDs: []string{"ocid1.networksecuritygroup.oc1..owned"},
		BootVolumeGB:            50, BootVolumeVPUsPerGB: 10, DataVolumeVPUsPerGB: 10, MaxDataVolumeGB: 50,
		ImageID: "ocid1.image.oc1..owned", Shape: "VM.Standard.A1.Flex", Owner: "regional-owner"}
	settings := managedPlacementSettings{Environment: "test", MemberRole: "terrabase",
		Resources: placement.Resources{CPU: 1, MemoryBytes: 1 << 20, DiskBytes: 1 << 20}}
	managed := &managedControllerConfig{intent: intent, region: region, placement: settings}
	if err := managed.validateWorkloads(map[string]WorkloadProfile{"terrabase": {Resources: settings.Resources}}); err == nil || !strings.Contains(err.Error(), "overlaps") {
		t.Fatalf("overlapping generic profile accepted: %v", err)
	}
	if err := managed.validateWorkloads(nil); err != nil {
		t.Fatal(err)
	}
	controller, err := placement.StartController(t.Context(), managed.placementConfig("gru", nil, nil),
		struct{ placement.Store }{}, struct{ authority.Fencer }{}, regionOnlyFleet{region: managed.region.Region},
		struct{ placement.HostView }{}, struct{ placement.DesiredWriter }{},
		func(context.Context, string, string, string) (placement.AdmittedArtifact, error) {
			return placement.AdmittedArtifact{}, nil
		})
	if err != nil || controller == nil {
		t.Fatalf("managed placement constructor rejected validated config: %v", err)
	}
}

func TestManagedControllerConfigRequiresSignedAdmissionInLab(t *testing.T) {
	root := t.TempDir()
	cfg := Config{NATS: natscell.Config{Cell: "gru", Lab: true}, Controller: ControllerConfig{
		OciRegionIntentFile: testJSONFile(t, root, "intent.json", map[string]any{}),
		OciRegionConfig:     testJSONFile(t, root, "region.json", map[string]any{}),
		PlacementConfig:     testJSONFile(t, root, "placement.json", map[string]any{}),
	}}
	if _, err := loadManagedControllerConfig(cfg); err == nil || strings.Contains(err.Error(), "OCI region intent") {
		t.Fatalf("lab selected unsigned sidecar loading: %v", err)
	}
}

func TestManagedPlacementRejectsRetiredSwitches(t *testing.T) {
	for _, key := range []string{"auto_grow_volumes", "reattach_on_host_loss"} {
		for _, value := range []string{"true", "false"} {
			if _, err := parseManagedPlacementSettings([]byte(`{"` + key + `":` + value + `}`)); err == nil {
				t.Fatalf("retired switch accepted: %s=%s", key, value)
			}
		}
	}
}

type regionOnlyFleet struct {
	oci.Fleet
	region oci.Region
}

func TestPlacementFileRejectsRemovedControls(t *testing.T) {
	for _, wire := range []string{
		`{"auto_grow_volumes":false}`, `{"auto_grow_volumes":true}`,
		`{"reattach_on_host_loss":false}`, `{"reattach_on_host_loss":true}`,
		`{"tick_millis":0}`, `{"tick_millis":5000}`,
	} {
		if _, err := parseManagedPlacementSettings([]byte(wire)); err == nil {
			t.Errorf("retired setting accepted: %s", wire)
		}
	}
}

func (fleet regionOnlyFleet) Region() oci.Region { return fleet.region }
