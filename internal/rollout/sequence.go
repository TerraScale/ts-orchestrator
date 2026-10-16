package rollout

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// PublishSequencedRelease admits ordering and independent qualification at the
// durable publication boundary, including callers that bypass regional OCI.
func (s *Store) PublishSequencedRelease(ctx context.Context, epoch uint64, admitted Release, roots trust.Keyring, cell, environment string) (Release, error) {
	if !strings.EqualFold(cell, s.cell) || admitted.RollbackOf != 0 || admitted.ReleaseSequence == 0 {
		return Release{}, fmt.Errorf("%w: sequenced release target", ErrInvalid)
	}
	envelope, err := trust.DecodeEnvelope(admitted.Receipt)
	if err != nil {
		return Release{}, err
	}
	architecture, ok := strings.CutPrefix(envelope.Scope.Slot, "linux-")
	if !ok {
		return Release{}, trust.ErrScopeMismatch
	}
	binary, err := release.VerifyQualifiedBinaryUpdateCurrent(admitted.Receipt, admitted.Delegation, roots, release.UpdateExpectation{Cell: strings.ToUpper(s.cell), Environment: environment, Architecture: architecture}, time.Now().UTC())
	if err != nil {
		return Release{}, err
	}
	migrationEnvelope, err := trust.DecodeEnvelope(admitted.SequenceMigration)
	if err != nil {
		return Release{}, err
	}
	migration, err := release.VerifySequenceMigrationHistorical(migrationEnvelope, roots, "orchestrator", environment)
	if err != nil {
		return Release{}, err
	}
	fingerprint, err := trust.Fingerprint(migrationEnvelope)
	if err != nil {
		return Release{}, err
	}
	var receipt release.BinaryUpdateReceipt
	if err := protocol.DecodeStrict(envelope.Payload, &receipt, trust.MaxPayloadBytes); err != nil {
		return Release{}, err
	}
	if envelope.KeyID != migration.SignerKeyID || admitted.ReleaseSequence <= migration.SequenceFloor || admitted.SequenceMigrationSHA256 != fingerprint || receipt.SequenceMigrationSHA256 != fingerprint || receipt.ReleaseSequence != admitted.ReleaseSequence || receipt.Lineage.QualificationRunNum != admitted.RunNumber || binary.Receipt().SHA256 != admitted.Digest || binary.Receipt().SourceRevision != admitted.SourceRevision || !envelope.IssuedAt.Equal(admitted.CreatedAt) {
		return Release{}, fmt.Errorf("%w: signed release ordering identity", ErrInvalid)
	}
	return s.publishRelease(ctx, epoch, admitted, false)
}

// seedReleaseOrdering upgrades every surviving historical floor once. The
// signed records stay in Desired even after bounded rollback history is purged.
func (s *Store) seedReleaseOrdering(ctx context.Context, desired Desired) (Desired, error) {
	if desired.OrderingFloor.Generation > 0 || desired.LegacyFloor.Generation > 0 && desired.LegacyIssuanceFloor.Generation > 0 || desired.Generation() == 0 {
		return desired, nil
	}
	retained, err := s.retainedReleases(ctx, desired)
	if err != nil {
		return Desired{}, err
	}
	for _, historical := range retained {
		if historical.ReleaseSequence > 0 {
			return Desired{}, fmt.Errorf("%w: sequenced history has no durable floor", ErrInvalid)
		}
		if desired.LegacyFloor.Generation == 0 || historical.RunNumber > desired.LegacyFloor.RunNumber {
			desired.LegacyFloor = historical
		}
		if desired.LegacyIssuanceFloor.Generation == 0 || historical.CreatedAt.After(desired.LegacyIssuanceFloor.CreatedAt) {
			desired.LegacyIssuanceFloor = historical
		}
	}
	return desired, nil
}

func advanceReleaseOrdering(desired *Desired, next Release, cell string) error {
	floor := desired.OrderingFloor
	if floor.ReleaseSequence > 0 {
		if next.SequenceMigrationSHA256 != floor.SequenceMigrationSHA256 {
			return fmt.Errorf("%w: release ordering migration cannot change", ErrInvalid)
		}
		if next.ReleaseSequence < floor.ReleaseSequence {
			return fmt.Errorf("%w: signer sequence %d is below retained floor %d", ErrInvalid, next.ReleaseSequence, floor.ReleaseSequence)
		}
		if next.ReleaseSequence == floor.ReleaseSequence {
			same, err := sameSequencedContent(floor, next)
			if err != nil {
				return err
			}
			if !same {
				return fmt.Errorf("%w: signer sequence already names another release", ErrInvalid)
			}
			if desired.Release.Digest != next.Digest || desired.Release.RollbackOf != 0 {
				return fmt.Errorf("%w: retained sequence cannot restart a rolled-back release", ErrInvalid)
			}
			return nil
		}
	}
	if next.ReleaseSequence > 0 {
		envelope, err := trust.DecodeEnvelope(next.SequenceMigration)
		if err != nil {
			return err
		}
		var migration release.SequenceMigration
		if err := protocol.DecodeStrict(envelope.Payload, &migration, trust.MaxPayloadBytes); err != nil {
			return err
		}
		if !migration.AdmitsLegacyFloor(strings.ToUpper(cell), desired.LegacyFloor.RunNumber, desired.LegacyIssuanceFloor.CreatedAt) {
			return fmt.Errorf("%w: migration omits retained legacy run floor %d", ErrInvalid, desired.LegacyFloor.RunNumber)
		}
		desired.OrderingFloor = next
	} else {
		if next.RunNumber < desired.LegacyFloor.RunNumber {
			return fmt.Errorf("%w: CI run is below retained legacy floor", ErrInvalid)
		}
		if next.CreatedAt.Before(desired.LegacyIssuanceFloor.CreatedAt) {
			return fmt.Errorf("%w: issuance is below retained legacy floor", ErrInvalid)
		}
		if next.RunNumber > 0 && next.RunNumber == desired.LegacyFloor.RunNumber && (next.Digest != desired.LegacyFloor.Digest || next.SourceRevision != desired.LegacyFloor.SourceRevision) {
			return fmt.Errorf("%w: CI run already names another release", ErrInvalid)
		}
		if desired.LegacyFloor.Generation == 0 || next.RunNumber > desired.LegacyFloor.RunNumber {
			desired.LegacyFloor = next
		}
		if desired.LegacyIssuanceFloor.Generation == 0 || next.CreatedAt.After(desired.LegacyIssuanceFloor.CreatedAt) {
			desired.LegacyIssuanceFloor = next
		}
	}
	return nil
}

func newerReleaseOrder(previous, next Release) bool {
	if previous.ReleaseSequence > 0 || next.ReleaseSequence > 0 {
		return next.ReleaseSequence > previous.ReleaseSequence
	}
	return next.RunNumber > previous.RunNumber
}

func sameSequencedContent(previous, next Release) (bool, error) {
	if previous.Digest != next.Digest || previous.SourceRevision != next.SourceRevision || previous.RunNumber != next.RunNumber || previous.SequenceMigrationSHA256 != next.SequenceMigrationSHA256 {
		return false, nil
	}
	left, err := trust.DecodeEnvelope(previous.Receipt)
	if err != nil {
		return false, err
	}
	right, err := trust.DecodeEnvelope(next.Receipt)
	if err != nil {
		return false, err
	}
	var oldReceipt, newReceipt release.BinaryUpdateReceipt
	if err := protocol.DecodeStrict(left.Payload, &oldReceipt, trust.MaxPayloadBytes); err != nil {
		return false, err
	}
	if err := protocol.DecodeStrict(right.Payload, &newReceipt, trust.MaxPayloadBytes); err != nil {
		return false, err
	}
	return oldReceipt.Binary == newReceipt.Binary && oldReceipt.Lineage == newReceipt.Lineage, nil
}
