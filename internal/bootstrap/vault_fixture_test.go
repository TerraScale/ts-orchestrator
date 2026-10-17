//go:build fixturetest

package bootstrap

import (
	"errors"
	"testing"
)

func TestVaultSDKFixtureRejectsMissingClient(t *testing.T) {
	vault, err := NewVaultFromSDKFixture(nil)
	if vault != nil || !errors.Is(err, ErrMaterialization) {
		t.Fatalf("missing SDK client returned Vault %v, error %v", vault, err)
	}
}
