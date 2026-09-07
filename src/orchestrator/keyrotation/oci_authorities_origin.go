package keyrotation

import (
	"context"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

// OCIOriginProofVault owns a separate OCI secret namespace. It cannot fetch or
// retire capability secrets, even when both roles use the same OCI vault.
type OCIOriginProofVault struct{ *ociHMACVault }
type OCIOriginProofVaultConfig ociHMACVaultConfig

func NewOCIOriginProofVault(c OCIOriginProofVaultConfig) (*OCIOriginProofVault, error) {
	v, err := newOCIHMACVault(ociHMACVaultConfig(c), "ts-origin-proof")
	if err != nil {
		return nil, err
	}
	return &OCIOriginProofVault{v}, nil
}
func (v *OCIOriginProofVault) Generate(ctx context.Context, r security.OriginProofRequest) (security.OriginProofMaterial, error) {
	m, err := v.generate(ctx, ociHMACRequest(r))
	return originMaterial(m), err
}
func (v *OCIOriginProofVault) Fetch(ctx context.Context, reference string) (security.OriginProofMaterial, error) {
	m, err := v.fetch(ctx, reference)
	return originMaterial(m), err
}
func (v *OCIOriginProofVault) Retire(ctx context.Context, reference, operation string) error {
	return v.retire(ctx, reference, operation)
}
func originMaterial(m ociHMACMaterial) security.OriginProofMaterial {
	return security.OriginProofMaterial{ID: m.ID, Reference: m.Reference, Version: m.Version, Bucket: m.Bucket, NotBefore: m.NotBefore, ExpiresAt: m.ExpiresAt, Secret: m.Key}
}
