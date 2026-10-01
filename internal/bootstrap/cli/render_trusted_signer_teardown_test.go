package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/app"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

func TestRenderedConfigsPreserveTerraBaseTeardownGrant(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	material := bootstrapmaterial.Config{
		Environment: "canary", Cell: "gru", Region: "sa-saopaulo-1",
		DeploymentID: "teardown-render-test", ClusterID: "teardown-render-test",
		SubnetCIDR: "10.251.0.0/24", ValidityHours: 48,
		Slots: []bootstrapmaterial.Slot{
			{Name: "controller-a", PrivateIP: "10.251.0.10"},
			{Name: "controller-b", PrivateIP: "10.251.0.11"},
			{Name: "controller-c", PrivateIP: "10.251.0.12"},
		},
	}
	record, err := bootstrapmaterial.Generate(filepath.Join(t.TempDir(), "material"), material, now)
	if err != nil {
		t.Fatal(err)
	}
	manifest := bootstrap.Manifest{
		DeploymentID: material.DeploymentID, ClusterID: material.ClusterID,
		Environment: material.Environment, Cell: oci.RegionGRU, OCIRegion: material.Region,
		Slot:            material.Slots[0].Name,
		ControllerSlots: []string{material.Slots[0].Name, material.Slots[1].Name, material.Slots[2].Name},
	}

	for _, test := range []struct {
		name     string
		teardown bool
	}{
		{name: "default denied"},
		{name: "explicitly granted", teardown: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			grant := app.TrustedSignerConfig{
				Actor: "ops", PublicKey: record.Public.ControllerResponsePublicKey,
				Roles: []string{"terrabase"}, Environments: []string{"canary"},
				CanTeardownTerraBase: test.teardown,
			}
			if err := app.ValidateTrustedSignerGrant(grant); err != nil {
				t.Fatalf("reviewed signer grant is invalid: %v", err)
			}
			grantWire, err := protocol.EncodeJSON(grant)
			if err != nil {
				t.Fatal(err)
			}
			var reviewed app.TrustedSignerConfig
			if err := protocol.DecodeStrict(grantWire, &reviewed, 4<<10); err != nil {
				t.Fatal(err)
			}
			for _, renderer := range []struct {
				name   string
				render func() (app.Config, error)
			}{
				{name: "render-controller-config", render: func() (app.Config, error) {
					return controllerConfigFromRecord(manifest, record, reviewed, now.Add(time.Minute))
				}},
				{name: "render-operator-config", render: func() (app.Config, error) {
					return operatorConfigFromRecord(record, reviewed, now.Add(time.Minute))
				}},
			} {
				t.Run(renderer.name, func(t *testing.T) {
					cfg, err := renderer.render()
					if err != nil {
						t.Fatal(err)
					}
					wire, err := protocol.EncodeJSON(cfg)
					if err != nil {
						t.Fatal(err)
					}
					field := []byte(`"can_teardown_terrabase":true`)
					if bytes.Contains(wire, field) != test.teardown {
						t.Fatalf("rendered teardown field differs from explicit grant: %s", wire)
					}
					path := filepath.Join(t.TempDir(), "config.json")
					if err := os.WriteFile(path, wire, 0o600); err != nil {
						t.Fatal(err)
					}
					loaded, err := app.LoadConfig(path)
					if err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(loaded.Controller.TrustedSigners, []app.TrustedSignerConfig{grant}) {
						t.Fatalf("rendered trusted signer differs from reviewed grant: got %+v", loaded.Controller.TrustedSigners)
					}
				})
			}
		})
	}
}
