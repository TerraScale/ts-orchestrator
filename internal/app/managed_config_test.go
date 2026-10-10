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
	root := t.TempDir()
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
	cfg := Config{NATS: natscell.Config{Cell: "gru"}, Controller: ControllerConfig{
		OciRegionIntentFile: testJSONFile(t, root, "intent.json", intent),
		OciRegionConfig:     testJSONFile(t, root, "region.json", region),
		PlacementConfig:     testJSONFile(t, root, "placement.json", settings),
		Workloads:           map[string]WorkloadProfile{"terrabase": {Resources: settings.Resources}},
	}}
	if _, err := loadManagedControllerConfig(cfg); err == nil || !strings.Contains(err.Error(), "overlaps") {
		t.Fatalf("overlapping generic profile accepted: %v", err)
	}
	cfg.Controller.Workloads = nil
	managed, err := loadManagedControllerConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	controller, err := placement.StartController(t.Context(), managed.placementConfig(cfg.NATS.Cell, nil, nil),
		struct{ placement.Store }{}, struct{ authority.Fencer }{}, regionOnlyFleet{region: managed.region.Region},
		struct{ placement.HostView }{}, struct{ placement.DesiredWriter }{},
		func(context.Context, string, string, string) (placement.AdmittedArtifact, error) {
			return placement.AdmittedArtifact{}, nil
		})
	if err != nil || controller == nil {
		t.Fatalf("managed placement constructor rejected validated config: %v", err)
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
