package bootstrapmaterial

import (
	"github.com/TerraScale/ts-orchestrator/internal/roleidentity"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

// roleScope is the cell account's role signer scope for the key the
// controllers derive from the host NATS issuer.
func roleScope(hostIssuer nkeys.KeyPair) (*jwt.UserScope, error) {
	signer, err := roleidentity.Signer(hostIssuer)
	if err != nil {
		return nil, err
	}
	public, err := signer.PublicKey()
	signer.Wipe()
	if err != nil {
		return nil, err
	}
	return roleidentity.Scope(public), nil
}
