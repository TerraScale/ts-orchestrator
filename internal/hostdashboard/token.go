package hostdashboard

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	ocivault "github.com/oracle/oci-go-sdk/v65/vault"
)

// SecretName is region's dashboard token in gru-vault, the cell spec's
// <cell>-<n>-orch-dashboard-token of the region's first cell.
func SecretName(region string) string {
	return vaultsecret.Name(region+"-1", cellspec.DashboardRole+"-"+cellspec.DashboardKey)
}

// readToken reads region's dashboard token with the instance principal. The
// first host to find none creates a random one; OCI keeps secret names unique,
// so concurrent creators settle on one. The value is never logged.
func readToken(ctx context.Context, region string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	factory, err := ociclient.InstancePrincipalContext(ctx, mesh.SharedVaultRegion)
	if err != nil {
		return "", err
	}
	bundles, err := vaultsecret.SecretsClient(factory)
	if err != nil {
		return "", err
	}
	name := SecretName(region)
	value, err := vaultsecret.Read(ctx, bundles, mesh.SharedVault.VaultID, name)
	if err == nil || !vaultsecret.Absent(err) {
		return value, err
	}
	management, err := ocivault.NewVaultsClientWithConfigurationProvider(factory.Provider())
	if err != nil {
		return "", err
	}
	management.SetRegion(factory.Region())
	factory.Configure(&management.BaseClient, ociclient.ServiceVault)
	stored, err := vaultsecret.Ensure(ctx, &management, mesh.SharedVault, name, "ts-orch operator dashboard token of "+region,
		func(context.Context) (string, error) {
			token := make([]byte, 32)
			_, err := rand.Read(token)
			return hex.EncodeToString(token), err
		})
	if err != nil {
		return "", err
	}
	return vaultsecret.ReadBack(ctx, bundles, mesh.SharedVault.VaultID, name, stored.Created || stored.Provisioning)
}
