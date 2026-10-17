//go:build fixturetest

package bootstrap

import (
	"time"

	"github.com/oracle/oci-go-sdk/v65/secrets"
)

// NewVaultFromSDKFixture retains the exact production SDK adapter and Vault
// authorization/materialization path; it does not qualify instance principals.
func NewVaultFromSDKFixture(client *secrets.SecretsClient) (*Vault, error) {
	if client == nil {
		return nil, ErrMaterialization
	}
	return &Vault{reader: ociSecretBundleReader{client: *client}, now: time.Now}, nil
}
