package managedmaterial

import (
	"crypto/ed25519"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
)

// PreparationService owns the only transition from a create-only KMS object
// to an R3-committed, controller-signed initial material receipt. The caller
// must first authenticate an operator-signed preparation request, including
// the explicit member IPs in spec, against its regional operator grant.
type PreparationService struct {
	Cell                 string
	Repository           *Repository
	Receipts             authority.MaterialReceiptStore
	Fencer               authority.Fencer
	ControllerKey        ed25519.PrivateKey
	RecipientSigner      ed25519.PublicKey
	AllowedSubnetCIDR    string
	NativeValidator      NativeMaterialValidator
	NativeVerifierSHA256 string
}
