package mesh

import (
	"context"
	"strings"

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
	return Environment{Founder: strings.ToLower(catalog.Bootstrap), Regions: founded(), Rollout: catalog.RolloutOrder(), VaultRegion: vaultRegion, Vault: SharedVault}
}

func (d Environment) Secret(purpose string) string {
	return d.Founder + "-1-" + purpose
}

func (d Environment) GHCRPullToken(ctx context.Context) (string, error) {
	return vaultsecret.ReadGHCRPullToken(ctx, d.Vault.VaultID, d.Secret("ghcr-pull-token"))
}

func ConnRegion(conn *nats.Conn) string {
	return serverRegion(conn.ConnectedServerName())
}

func ConnRegions(conn *nats.Conn) []string {
	return Regions(ConnRegion(conn))
}

func StoreReplicas(region string) int {
	return min(3, len(Regions(region)))
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
