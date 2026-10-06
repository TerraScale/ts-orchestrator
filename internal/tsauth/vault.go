package tsauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/vaultsecret"
)

// VaultClient is the part of the OCI Vault management API that stores secrets.
type VaultClient = vaultsecret.VaultClient

// BundleClient reads secret contents.
type BundleClient = vaultsecret.BundleClient

// Target is the cell's Vault: the control compartment, the Vault created in
// phase 1 and its master key. The controllers may read secret bundles there.
type Target = vaultsecret.Target

// SecretName is the Vault secret holding key for cell, for example
// gru-1-ts-auth-master-key.
func SecretName(cell, key string) string { return vaultsecret.Name(cell, key) }

// Stored is one secret of the Vault; it never carries the value.
type Stored struct {
	Key string `json:"key"`
	vaultsecret.Stored
}

// Ensure stores the value of key in the Vault unless a secret of its name
// exists. value runs only when the secret is absent, so an existing secret is
// never regenerated, replaced or rotated.
func Ensure(ctx context.Context, client VaultClient, target Target, cell, key string, value func(context.Context) (string, error)) (Stored, error) {
	stored, err := vaultsecret.Ensure(ctx, client, target, SecretName(cell, key), key+" of cell "+cell+"; created once by ts-orch.",
		func(ctx context.Context) (string, error) {
			secret, err := value(ctx)
			if err == nil {
				err = validSecret(key, secret)
			}
			return secret, err
		})
	return Stored{Key: key, Stored: stored}, err
}

// Generate returns 32 random bytes in base64, the form of the Generated secrets.
func Generate(context.Context) (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

// readSecret reads and checks the current version of one secret.
func readSecret(ctx context.Context, client BundleClient, vaultID, cell, key string) (string, error) {
	return readBack(ctx, client, vaultID, cell, key, false)
}

// readBack reads and checks a secret that may have been created a moment ago.
func readBack(ctx context.Context, client BundleClient, vaultID, cell, key string, created bool) (string, error) {
	name := SecretName(cell, key)
	value, err := vaultsecret.ReadBack(ctx, client, vaultID, name, created)
	if err != nil {
		return "", err
	}
	if err := validSecret(key, value); err != nil {
		return "", errors.Join(fmt.Errorf("Vault secret %s", name), err)
	}
	return value, nil
}
