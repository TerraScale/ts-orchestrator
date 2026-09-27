package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostenroll"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

func TestHostEnrollmentPublicBundleUsesExactCanaryMaterialAndImagePaths(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	config := bootstrapmaterial.Config{Environment: "canary", Region: "sa-saopaulo-1", Cell: "gru",
		DeploymentID: "ts-preview-gru-20260926", ClusterID: "ts-preview-gru-20260926",
		SubnetCIDR: "10.251.0.0/25", ValidityHours: 48,
		Slots: []bootstrapmaterial.Slot{{Name: "controller-a", PrivateIP: "10.251.0.11"},
			{Name: "controller-b", PrivateIP: "10.251.0.12"}, {Name: "controller-c", PrivateIP: "10.251.0.13"}}}
	directory := filepath.Join(t.TempDir(), "material")
	record, err := bootstrapmaterial.Generate(directory, config, now)
	if err != nil {
		t.Fatal(err)
	}
	caWire, err := os.ReadFile(filepath.Join(directory, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := hostEnrollmentPublicFromRecord(record, caWire, now)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := protocol.EncodeJSON(bundle)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := hostenroll.ParsePublicBundle(wire)
	if err != nil || !reflect.DeepEqual(parsed, bundle) {
		t.Fatalf("image bundle does not round-trip through the guest parser: %v", err)
	}
	if bundle.WorkloadUID != 2000 || bundle.WorkloadGID != 2000 ||
		bundle.InstallRoot != "/var/lib/terrascale-orchestrator-host/install" ||
		bundle.StateRoot != "/var/lib/terrascale-orchestrator-host/state" ||
		bundle.ManagedRuntimeRoot != "/srv/ts-managed" ||
		bundle.ControllerResponsePublicKey != record.Public.ControllerResponsePublicKey ||
		bundle.CellAccountNKey != record.Public.CellAccountNKey || bundle.CAPEM != string(caWire) {
		t.Fatal("image bundle differs from reviewed source or fixed host image paths")
	}
	if _, err := hostEnrollmentPublicFromRecord(record, []byte("different CA"), now); err == nil {
		t.Fatal("unreviewed regional CA accepted")
	}
	changed := record
	changed.Config.Slots = append([]bootstrapmaterial.Slot(nil), record.Config.Slots...)
	changed.Config.Slots[0].PrivateIP = "10.251.0.14"
	if _, err := hostEnrollmentPublicFromRecord(changed, caWire, now); err == nil {
		t.Fatal("changed controller address accepted")
	}
	if _, err := hostEnrollmentPublicFromRecord(record, caWire, now.Add(25*time.Hour)); err == nil {
		t.Fatal("image bundle emitted with less than 24 hours of material validity")
	}
}
