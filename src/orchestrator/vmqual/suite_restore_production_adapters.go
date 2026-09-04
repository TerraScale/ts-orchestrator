package vmqual

import (
	"context"
	"errors"

	"terrascale.tech/orchestrator/src/orchestrator/delivery"
	"terrascale.tech/orchestrator/src/orchestrator/restoredrill"
)

// VerifyMirror supplies the provider-backed HEAD required by the production
// restore composition after each Region copy.
func (s *localControlSnapshots) VerifyMirror(ctx context.Context, snapshot restoredrill.ControlStateSnapshot, region string) error {
	identity, found, err := s.objects.head(ctx, region, operationsControlBucket, snapshot.ObjectKey)
	if err != nil {
		return err
	}
	if !found || identity.Size != snapshot.Size || !delivery.SameDigest(identity.Digest, snapshot.Checksum) {
		return errors.New("vmqual: mirrored control snapshot identity does not match")
	}
	return nil
}

var _ restoredrill.VerifiedSnapshotMirror = (*localControlSnapshots)(nil)
