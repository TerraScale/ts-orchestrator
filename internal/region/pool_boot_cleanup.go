package region

import (
	"errors"
	"time"
)

// PoolBootCleanupAuthority pins a new original boot DELETE after positive
// instance termination. It cannot renew an already reserved deletion wire.
type PoolBootCleanupAuthority struct {
	Lifecycle    PoolLifecycleBinding `json:"lifecycle"`
	DrainSHA256  string               `json:"drainSha256"`
	AuthorizedAt time.Time            `json:"authorizedAt"`
	ExpiresAt    time.Time            `json:"expiresAt"`
}

func (p PoolBootCleanupAuthority) validate(child PoolChildRecord, updated time.Time) error {
	b := p.Lifecycle
	if child.InstanceTerminal == nil || child.DeleteBoot == nil || child.DrainSource == nil ||
		b.InstallationID == "" || b.Cell == "" || b.CompartmentID == "" || b.Role == "" || b.Architecture == "" || b.Shape == "" ||
		b.BirthOperationID != child.OperationID || b.InstanceID != child.InstanceID || b.BootVolumeID != child.BootVolumeID ||
		b.BootAttachmentID != child.BootAttachmentID || b.PoolID != child.PoolID || b.ConfigurationID != child.ConfigurationID || b.RecipeSHA256 != child.RecipeSHA256 ||
		!validFoundationDigest(b.ProfileSHA256) || !validFoundationDigest(b.CurrentProfileSHA256) || !validFoundationDigest(b.PoolBirthSHA256) ||
		!validFoundationDigest(b.ConfigurationSHA256) || !validFoundationDigest(b.BirthSHA256) || !validFoundationDigest(b.GrantSHA256) || b.Generation == 0 ||
		!validFoundationDigest(p.DrainSHA256) || p.DrainSHA256 != child.DrainAuthoritySHA256 || p.DrainSHA256 != child.DrainSource.ReceiptSHA256 ||
		p.AuthorizedAt.IsZero() || p.AuthorizedAt.Before(child.InstanceTerminal.TerminalObservedAt) || p.AuthorizedAt.After(updated) ||
		!p.ExpiresAt.After(p.AuthorizedAt) || p.ExpiresAt.After(p.AuthorizedAt.Add(2*time.Minute)) ||
		child.DeleteBoot.FirstAttemptAt.Before(p.AuthorizedAt) || !child.DeleteBoot.ExpiresAt.Equal(p.ExpiresAt) {
		return errors.New("boot cleanup lost its first original bounded current authority, historical drain or positive instance termination")
	}
	return nil
}
