package bootstrapmaterial

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"

	"github.com/TerraScale/ts-orchestrator/internal/roleidentity"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

// RoleClaim adds the role signer (TS-651) to current, the cell account claim
// the region's brokers hold, and signs it again with the regional operator
// key. The signer is derived from the material's host NATS issuer seed, as
// the controllers derive it; everything else in the claim is kept.
// operator broker-claim-apply installs the result. Material generated since
// TS-663 already carries the signer; this is for cells founded before.
func RoleClaim(materialDirectory, current string) (string, string, error) {
	material, err := Load(materialDirectory)
	if err != nil {
		return "", "", err
	}
	claim, err := jwt.DecodeAccountClaims(current)
	if err != nil || claim.Subject != material.Public.CellAccountNKey || claim.Issuer != material.Public.OperatorNKey {
		return "", "", errors.New("the current claim is not this material's cell account signed by its operator")
	}
	host, scoped := claim.SigningKeys.GetScope(material.Public.HostNATSIssuerNKey)
	if hostScope, ok := host.(*jwt.UserScope); !scoped || !ok ||
		!reflect.DeepEqual(hostScope, expectedHostScope(material.Config.Cell, material.Public.HostNATSIssuerNKey)) {
		return "", "", errors.New("the current claim lacks the material's host signer")
	}
	key := func(name, public string) (nkeys.KeyPair, error) {
		seed, err := readOwnedFile(filepath.Join(materialDirectory, name), 4096)
		if err != nil {
			return nil, ErrMaterial
		}
		pair, err := nkeys.FromSeed(bytes.TrimSpace(seed))
		clear(seed)
		if err != nil {
			return nil, ErrMaterial
		}
		if got, err := pair.PublicKey(); err != nil || got != public {
			pair.Wipe()
			return nil, ErrMaterial
		}
		return pair, nil
	}
	operator, err := key("issuer-operator.seed", material.Public.OperatorNKey)
	if err != nil {
		return "", "", err
	}
	defer operator.Wipe()
	hostIssuer, err := key("host-nats-issuer.seed", material.Public.HostNATSIssuerNKey)
	if err != nil {
		return "", "", err
	}
	scope, err := roleScope(hostIssuer)
	hostIssuer.Wipe()
	if err != nil {
		return "", "", err
	}
	issued := claim.IssuedAt
	claim.SigningKeys.AddScopedSigner(scope)
	raw, err := claim.Encode(operator)
	if err != nil {
		return "", "", fmt.Errorf("sign the cell account claim: %w", err)
	}
	// Encode stamps the time; brokers take only a strictly newer claim.
	if claim.IssuedAt <= issued {
		return "", "", errors.New("the current claim was issued this second; run again")
	}
	return raw, scope.Key, nil
}

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
