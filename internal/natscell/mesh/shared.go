package mesh

import (
	"context"

	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

// The in-region join (internal/regionjoin) keeps its material in the same
// gru-vault as the mesh secret and names it by the same region token.
const SharedVaultRegion = vaultRegion

// SharedVault is where the gru-vault creates secrets.
var SharedVault = vaultsecret.Target{CompartmentID: compartmentID, VaultID: vaultID, KeyID: vaultKeyID}

// OwnRegion is this OCI instance's region token, from IMDS.
func OwnRegion(ctx context.Context) (string, error) { return ownRegion(ctx) }

const (
	ClusterPort   = 6222
	netBirdDomain = "nb.ts.internal"
)

// Cluster places this host's mesh server in the mesh NATS cluster.
type Cluster struct {
	// Routes returns the route URLs to dial (the founder's, for a worker).
	Routes func(ctx context.Context, region string) ([]string, error)
	// Worker is a SwarmKit worker: it has no control socket, so it answers
	// no ping, state or apply and the region answers once, from its founder.
	Worker bool
}
