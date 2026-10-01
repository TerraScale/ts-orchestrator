package cli

import (
	"path/filepath"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/app"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
)

func TestOperatorConfigUsesRegionalMaterialCell(t *testing.T) {
	for _, test := range []struct{ cell, region string }{
		{"sfo", "us-sanjose-1"}, {"fra", "eu-frankfurt-1"},
	} {
		t.Run(test.cell, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Second)
			cfg := bootstrapmaterial.Config{Environment: "production", Cell: test.cell,
				Region: test.region, DeploymentID: "alpha-20260927", ClusterID: "alpha-" + test.cell,
				SubnetCIDR: "10.251.0.0/24", ValidityHours: 48,
				Slots: []bootstrapmaterial.Slot{{Name: "controller-a", PrivateIP: "10.251.0.10"},
					{Name: "controller-b", PrivateIP: "10.251.0.11"},
					{Name: "controller-c", PrivateIP: "10.251.0.12"}}}
			record, err := bootstrapmaterial.Generate(filepath.Join(t.TempDir(), "material"), cfg, now)
			if err != nil {
				t.Fatal(err)
			}
			grant := app.TrustedSignerConfig{Actor: "ops", PublicKey: record.Public.ControllerResponsePublicKey,
				Roles: []string{"terrabase"}, Environments: []string{"production"}}
			operator, err := operatorConfigFromRecord(record, grant, now.Add(time.Minute))
			if err != nil || operator.NATS.Cell != test.cell {
				t.Fatalf("regional operator config rejected: cell=%s err=%v", operator.NATS.Cell, err)
			}
			record.Config.Region = "sa-saopaulo-1"
			if _, err := operatorConfigFromRecord(record, grant, now.Add(time.Minute)); err == nil {
				t.Fatal("operator config accepted cell with a different OCI region")
			}
		})
	}
}
