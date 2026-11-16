package bootstrapstart

import (
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// TrustInputs is independently verified image genesis and its adopted lineage.
// Durable rollback floors belong to the installer/adoption journal.
type TrustInputs struct {
	ChainIdentity trust.ChainIdentity
	Genesis       trust.Keyring
	Chain         trust.RootChain
	Roots         trust.VerifiedRoots
}
