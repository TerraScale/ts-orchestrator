package vaultsecret

import "context"

// LookupMetadata reads exact-name metadata without creating or changing a secret.
func LookupMetadata(ctx context.Context, client VaultClient, target Target, name string) (Stored, error) {
	stored := Stored{Secret: name}
	if err := safeEnv(); err != nil {
		return stored, err
	}
	var err error
	stored.ID, stored.Provisioning, err = lookup(ctx, client, target, name)
	return stored, err
}
