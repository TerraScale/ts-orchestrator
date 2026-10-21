package release

import (
	"fmt"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// VerifiedFreshRoleBaseline authorizes an empty-history admission; consumers
// must independently authenticate absence and keep its source current through CAS.
type VerifiedFreshRoleBaseline struct {
	role, environment, cell, migrationSHA256 string
	issuedAt, expiresAt, verifiedAt          time.Time
}

func VerifyFreshRoleBaselineCurrent(envelope trust.Envelope, roots trust.Keyring, role, environment, cell string, now time.Time) (VerifiedFreshRoleBaseline, error) {
	migration, err := VerifySequenceMigrationCurrent(envelope, roots, role, environment, now)
	if err != nil {
		return VerifiedFreshRoleBaseline{}, err
	}
	if migration.Schema != SequenceFreshRoleSchema || !slices.Contains(migration.FreshCells, cell) {
		return VerifiedFreshRoleBaseline{}, fmt.Errorf("%w: fresh role baseline scope", ErrInvalidReceipt)
	}
	fingerprint, err := trust.Fingerprint(envelope)
	if err != nil {
		return VerifiedFreshRoleBaseline{}, err
	}
	return VerifiedFreshRoleBaseline{role: role, environment: environment, cell: cell, migrationSHA256: fingerprint,
		issuedAt: envelope.IssuedAt, expiresAt: envelope.ExpiresAt, verifiedAt: now}, nil
}

func (baseline VerifiedFreshRoleBaseline) ExpiresAt() time.Time { return baseline.expiresAt }

// ValidFor preserves the original deadline; the operation context must also be
// capped at ExpiresAt before reading history or creating the durable floor.
func (baseline VerifiedFreshRoleBaseline) ValidFor(role, environment, cell, migrationSHA256 string, now time.Time) error {
	if baseline.verifiedAt.IsZero() || baseline.role != role || baseline.environment != environment || baseline.cell != cell || baseline.migrationSHA256 != migrationSHA256 || now.Before(baseline.verifiedAt) || now.Before(baseline.issuedAt) || !now.Before(baseline.expiresAt) {
		return fmt.Errorf("%w: fresh role baseline scope or deadline", ErrInvalidReceipt)
	}
	return nil
}
