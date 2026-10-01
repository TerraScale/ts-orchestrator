package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostenroll"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

func TestHostEnrollmentPublicBundleUsesRegionalMaterialAndImagePaths(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	cases := []struct {
		cell, region, environment, subnet string
		ips                               [3]string
		validityHours                     int
	}{
		{"gru", "sa-saopaulo-1", "canary", "10.251.0.0/25", [3]string{"10.251.0.11", "10.251.0.12", "10.251.0.13"}, 48},
		{"sfo", "us-sanjose-1", "production", "10.52.8.0/24", [3]string{"10.52.8.101", "10.52.8.102", "10.52.8.103"}, 24},
		{"fra", "eu-frankfurt-1", "canary", "172.20.16.0/24", [3]string{"172.20.16.41", "172.20.16.42", "172.20.16.43"}, 720},
	}
	for _, test := range cases {
		t.Run(test.cell, func(t *testing.T) {
			config := bootstrapmaterial.Config{
				Environment: test.environment, Region: test.region, Cell: test.cell,
				DeploymentID: "ts-preview-" + test.cell, ClusterID: "ts-preview-" + test.cell,
				SubnetCIDR: test.subnet, ValidityHours: test.validityHours,
			}
			for index, ip := range test.ips {
				config.Slots = append(config.Slots, bootstrapmaterial.Slot{
					Name: fmt.Sprintf("controller-%c", 'a'+index), PrivateIP: ip,
				})
			}
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
			if bundle.Cell != test.cell || bundle.Region != strings.ToUpper(test.cell) ||
				bundle.Environment != test.environment || bundle.WorkloadUID != 2000 || bundle.WorkloadGID != 2000 ||
				bundle.InstallRoot != "/var/lib/terrascale-orchestrator-host/install" ||
				bundle.StateRoot != "/var/lib/terrascale-orchestrator-host/state" ||
				bundle.ManagedRuntimeRoot != "/srv/ts-managed" ||
				bundle.ControllerResponsePublicKey != record.Public.ControllerResponsePublicKey ||
				bundle.CellAccountNKey != record.Public.CellAccountNKey || bundle.CAPEM != string(caWire) {
				t.Fatal("image bundle differs from reviewed source or fixed host image paths")
			}
			for index, ip := range test.ips {
				if bundle.ControllerEndpoints[index] != ip+":8443" ||
					bundle.NATSURLs[index] != "tls://"+ip+":4222" {
					t.Fatalf("controller %d endpoints differ from reviewed slot", index)
				}
			}
			seed, err := os.ReadFile(filepath.Join(directory, "issuer-operator.seed"))
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(wire, seed) || bytes.Contains(wire, []byte("issuer-operator.seed")) {
				t.Fatal("public bundle exposes private material")
			}
			if test.cell == "gru" {
				testHostEnrollmentPublicFailures(t, record, caWire, now)
			}
		})
	}
}

func testHostEnrollmentPublicFailures(t *testing.T, record bootstrapmaterial.Record, caWire []byte, now time.Time) {
	t.Helper()
	if _, err := hostEnrollmentPublicFromRecord(record, []byte("different CA"), now); err == nil {
		t.Fatal("unreviewed regional CA accepted")
	}
	changed := record
	changed.Files = append([]bootstrapmaterial.File(nil), record.Files...)
	for index := range changed.Files {
		if changed.Files[index].Name == "ca.pem" {
			changed.Files[index].SHA256 = strings.Repeat("0", 64)
		}
	}
	if _, err := hostEnrollmentPublicFromRecord(changed, caWire, now); err == nil {
		t.Fatal("unreviewed regional CA digest accepted")
	}
	invalidConfigs := []struct {
		name   string
		change func(*bootstrapmaterial.Config)
	}{
		{"cell region mismatch", func(config *bootstrapmaterial.Config) { config.Region = "us-sanjose-1" }},
		{"unsupported cell", func(config *bootstrapmaterial.Config) { config.Cell = "unknown" }},
		{"missing slot", func(config *bootstrapmaterial.Config) { config.Slots = config.Slots[:2] }},
		{"wrong slot order", func(config *bootstrapmaterial.Config) {
			config.Slots[0], config.Slots[1] = config.Slots[1], config.Slots[0]
		}},
		{"duplicate slot IP", func(config *bootstrapmaterial.Config) { config.Slots[1].PrivateIP = config.Slots[0].PrivateIP }},
		{"out of subnet IP", func(config *bootstrapmaterial.Config) { config.Slots[1].PrivateIP = "10.252.0.12" }},
		{"invalid validity", func(config *bootstrapmaterial.Config) { config.ValidityHours = 721 }},
	}
	for _, test := range invalidConfigs {
		t.Run(test.name, func(t *testing.T) {
			changed := record
			changed.Config.Slots = append([]bootstrapmaterial.Slot(nil), record.Config.Slots...)
			test.change(&changed.Config)
			if _, err := hostEnrollmentPublicFromRecord(changed, caWire, now); err == nil {
				t.Fatal("invalid regional material accepted")
			}
		})
	}
	changed = record
	changed.ExpiresAt = changed.ExpiresAt.Add(time.Hour)
	if _, err := hostEnrollmentPublicFromRecord(changed, caWire, now); err == nil {
		t.Fatal("material lifetime differs from reviewed validity")
	}
	if _, err := hostEnrollmentPublicFromRecord(record, caWire, now.Add(25*time.Hour)); err == nil {
		t.Fatal("image bundle emitted with less than 24 hours of material validity")
	}
	if _, err := hostEnrollmentPublicFromRecord(record, caWire, now.Add(24*time.Hour)); err != nil {
		t.Fatalf("image bundle rejected with exactly 24 hours remaining: %v", err)
	}
	changed = record
	changed.Config.Slots = append([]bootstrapmaterial.Slot(nil), record.Config.Slots...)
	changed.Config.Slots[0].PrivateIP = "10.251.0.14"
	bundle, err := hostEnrollmentPublicFromRecord(changed, caWire, now)
	if err != nil || bundle.ControllerEndpoints[0] != "10.251.0.14:8443" {
		t.Fatalf("valid reviewed controller slot did not determine endpoint: %v", err)
	}
}
