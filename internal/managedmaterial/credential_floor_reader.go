package managedmaterial

import (
	"crypto/ed25519"
	"net/netip"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
)

// CredentialFloorReader authenticates existing material without mutation keys.
type CredentialFloorReader struct {
	repository *Repository
	mutations  *authority.Reader
	controller ed25519.PublicKey
	subnet     netip.Prefix
}
