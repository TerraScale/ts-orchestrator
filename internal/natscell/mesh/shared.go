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

// ClusterPort joins a region's mesh servers into one NATS cluster; the host
// NSG admits it inside the VCN only.
const ClusterPort = 6222

// Cluster places this host's mesh server in its region's NATS cluster.
type Cluster struct {
	// Address is this host's private VCN IP; "" runs no cluster listener.
	Address string
	// Routes returns the route URLs to dial (the founder's, for a worker).
	Routes func(ctx context.Context, region string) ([]string, error)
	// Worker is a SwarmKit worker: it has no control socket, so it answers
	// no ping, state or apply and the region answers once, from its founder.
	Worker bool
}
