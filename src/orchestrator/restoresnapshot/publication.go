package restoresnapshot

import (
	"context"
	"errors"

	"terrascale.tech/orchestrator/src/orchestrator/delivery"
)

// PutAtEpoch preserves the archived snapshot's epoch and key while authorizing
// new provider mutations under the current live upload authority. This permits
// an explicitly signed retry after the source has elected a new global term.
func (s *Store) PutAtEpoch(ctx context.Context, region, bucket, key string, body []byte, uploadEpoch uint64) error {
	if uploadEpoch == 0 {
		return errors.New("snapshot: current upload epoch required")
	}
	return s.putObject(ctx, region, bucket, key, body, uploadEpoch, false)
}

// PutPublicationReceipt persists the exact signed source receipt immutably. Its
// sole admitted key is <configured prefix>/publication.receipt.json. The caller
// verifies and binds the signature before invoking this transport operation.
func (s *Store) PutPublicationReceipt(ctx context.Context, region, bucket, key string, body []byte, uploadEpoch uint64) error {
	if uploadEpoch == 0 || len(body) > 1<<20 {
		return errors.New("snapshot: invalid publication receipt binding")
	}
	return s.putObject(ctx, region, bucket, key, body, uploadEpoch, true)
}
func (s *Store) GetPublicationReceipt(ctx context.Context, region, bucket, key string) ([]byte, bool, error) {
	return s.getObject(ctx, region, bucket, key, true)
}
func (s *Store) HeadPublicationReceipt(ctx context.Context, region, bucket, key string) (delivery.ObjectIdentity, bool, error) {
	return s.headObject(ctx, region, bucket, key, true)
}
