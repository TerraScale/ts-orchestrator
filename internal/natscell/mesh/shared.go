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

// OwnRegion is this OCI instance's ordered region token, from IMDS.
func OwnRegion(ctx context.Context) (string, error) { return ownRegion(ctx) }
