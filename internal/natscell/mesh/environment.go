package mesh

import (
	"context"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/fleet"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/nats-io/nats.go"
)

type Environment struct {
	Founder     string
	Regions     []string
	Rollout     []string
	VaultRegion string
	Vault       vaultsecret.Target
}

func EnvironmentOf(region string) Environment {
	staging := fleet.Embedded().Staging
	if region == staging.Label {
		return Environment{Founder: staging.Label, Regions: []string{staging.Label}, Rollout: []string{staging.Label}, VaultRegion: staging.OCIRegion,
			Vault: vaultsecret.Target{CompartmentID: staging.CompartmentID, VaultID: staging.VaultID, KeyID: staging.KeyID}}
	}
	return Environment{Founder: strings.ToLower(catalog.Bootstrap), Regions: founded(), Rollout: catalog.RolloutOrder(), VaultRegion: vaultRegion, Vault: SharedVault}
}

func (d Environment) Secret(purpose string) string {
	return d.Founder + "-1-" + purpose
}

func (d Environment) GHCRPullToken(ctx context.Context) (string, error) {
	return vaultsecret.ReadGHCRPullToken(ctx, d.Vault.VaultID, d.Secret("ghcr-pull-token"))
}

func connRegion(conn *nats.Conn) string {
	return serverRegion(conn.ConnectedServerName())
}

func ConnRegions(conn *nats.Conn) []string {
	return Regions(connRegion(conn))
}

func Regions(region string) []string {
	return EnvironmentOf(region).Regions
}

func founded() []string {
	names := []string{}
	for _, entry := range catalog.Founded() {
		names = append(names, entry.Name())
	}
	return names
}
