package region

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
)

// PrepareRootPublication pins the actual stream incarnation before the original
// finite Create. A later readback cannot bless a replacement stream.
func (proof VerifiedBrokerCreation) PrepareRootPublication(ctx context.Context, runtime *natscell.Runtime) error {
	return proof.prepareControlPublication(ctx, runtime, controlRootsBucket, controlRootsKey)
}

// PrepareSpecPublication pins the original spec stream before its first write.
// The genuine creation proof is required; an ordinary later writer cannot fill
// a missing stream-origin premise from discovered current state.
func (proof VerifiedBrokerCreation) PrepareSpecPublication(ctx context.Context, runtime *natscell.Runtime) error {
	return proof.prepareControlPublication(ctx, runtime, controlSpecBucket, controlSpecKey)
}

func (proof VerifiedBrokerCreation) prepareControlPublication(ctx context.Context, runtime *natscell.Runtime, bucket, key string) error {
	operation, finish, err := proof.BoundContext(ctx)
	if err != nil {
		return err
	}
	defer finish()
	if err := proof.RevalidateRuntime(operation, runtime); err != nil {
		return err
	}
	record, etag, resolver, purposeExpiry, err := proof.publicationSource(operation)
	if err != nil {
		return err
	}
	operation, cancel := context.WithDeadline(operation, purposeExpiry)
	defer cancel()
	actual, err := observeControlSource(operation, runtime, bucket, key)
	if err != nil {
		return err
	}
	floor := *record.RuntimeLineage.TrustFloor
	held := floor.RootStreamCreated
	if bucket == controlSpecBucket {
		held = floor.SpecStreamCreated
	}
	if !held.IsZero() {
		if !held.Equal(actual.created) {
			return errors.New("original control stream has been replaced")
		}
		return proof.RevalidateRuntime(operation, runtime)
	}
	if actual.created.Before(proof.genesis.StartedAt) {
		return errors.New("unreserved control stream predates its actual original broker")
	}
	if actual.revision != 0 {
		return errors.New("unreserved control stream already contains public source")
	}
	if bucket == controlRootsBucket {
		floor.RootStreamCreated = actual.created
	} else {
		floor.SpecStreamCreated = actual.created
	}
	return proof.commitPublication(operation, runtime, resolver, record, etag, floor, bucket, key, actual)
}

// AdoptRootPublication checkpoints only the exact initial root chain on the
// already reserved stream. It does not initialize or adopt a successor chain.
func (proof VerifiedBrokerCreation) AdoptRootPublication(ctx context.Context, runtime *natscell.Runtime) error {
	operation, finish, err := proof.BoundContext(ctx)
	if err != nil {
		return err
	}
	defer finish()
	if err := proof.RevalidateRuntime(operation, runtime); err != nil {
		return err
	}
	expected, err := proof.InitialRootChain(operation)
	if err != nil {
		return err
	}
	record, etag, resolver, purposeExpiry, err := proof.publicationSource(operation)
	if err != nil {
		return err
	}
	operation, cancel := context.WithDeadline(operation, purposeExpiry)
	defer cancel()
	actual, err := observeControlSource(operation, runtime, controlRootsBucket, controlRootsKey)
	if err != nil {
		return err
	}
	floor := *record.RuntimeLineage.TrustFloor
	if floor.RootStreamCreated.IsZero() || !floor.RootStreamCreated.Equal(actual.created) || actual.revision == 0 ||
		!bytes.Equal(actual.wire, expected) || floor.RootChainSHA256 != brokerSourceDigest(actual.wire) {
		return errors.New("initial root publication differs from its original stream and exact authenticated chain")
	}
	if floor.RootRevision != 0 {
		if floor.RootRevision != actual.revision {
			return errors.New("initial root publication revision changed after adoption")
		}
		return proof.RevalidateRuntime(operation, runtime)
	}
	floor.RootRevision = actual.revision
	return proof.commitPublication(operation, runtime, resolver, record, etag, floor, controlRootsBucket, controlRootsKey, actual)
}

func (proof VerifiedBrokerCreation) publicationSource(ctx context.Context) (FoundationRecord, string, FoundationResolver, time.Time, error) {
	record, etag, err := proof.permit.current(ctx, &proof.genesis)
	if err != nil {
		return FoundationRecord{}, "", FoundationResolver{}, time.Time{}, err
	}
	resolver, err := discoverCurrentFoundation(ctx, proof.permit.home.objects, proof.permit.home.tenancyID, proof.permit.home.currentGenesis)
	if err != nil {
		return FoundationRecord{}, "", FoundationResolver{}, time.Time{}, err
	}
	expires, err := regionalControlPurposeExpiry(ctx, resolver, record.Cell)
	if err != nil {
		return FoundationRecord{}, "", FoundationResolver{}, time.Time{}, err
	}
	return record, etag, resolver, expires, nil
}

func (proof VerifiedBrokerCreation) commitPublication(ctx context.Context, runtime *natscell.Runtime, resolver FoundationResolver, record FoundationRecord, etag string, floor RuntimeTrustFloor, bucket, key string, expected controlSource) error {
	before := *record.RuntimeLineage.TrustFloor
	guard := func(ctx context.Context) error {
		if err := proof.RevalidateRuntime(ctx, runtime); err != nil {
			return err
		}
		current, held, _, _, err := proof.publicationSource(ctx)
		if err != nil {
			return err
		}
		if held != etag || *current.RuntimeLineage.TrustFloor != before {
			return ErrFoundationConflict
		}
		actual, err := observeControlSource(ctx, runtime, bucket, key)
		if err != nil {
			return err
		}
		if !actual.same(expected) {
			return errors.New("original control publication changed before protected checkpoint")
		}
		if err := proof.RevalidateRuntime(ctx, runtime); err != nil {
			return err
		}
		return ociclient.LimitAdmission(ctx, proof.ExpiresAt())
	}
	if err := guard(ctx); err != nil {
		return err
	}
	now := time.Now().UTC()
	lineage := *record.RuntimeLineage
	floor.UpdatedAt = now
	lineage.TrustFloor = new(floor)
	record.RuntimeLineage, record.UpdatedAt = &lineage, now
	writeCtx := ociclient.WithAuthority(ctx, guard)
	writeCtx = ociclient.WithAdmission(writeCtx, func(ctx context.Context) (func(), error) {
		if err := guard(ctx); err != nil {
			return nil, err
		}
		return func() {}, nil
	})
	if _, err := resolver.Store.CompareAndSwap(writeCtx, record, etag); err != nil {
		return err
	}
	saved, _, err := resolver.Store.Load(ctx, record.Cell)
	if err != nil {
		return err
	}
	if saved.RuntimeLineage == nil || saved.RuntimeLineage.TrustFloor == nil || *saved.RuntimeLineage.TrustFloor != floor {
		return errors.New("original control publication checkpoint was not retained exactly")
	}
	actual, err := observeControlSource(ctx, runtime, bucket, key)
	if err != nil {
		return err
	}
	if !actual.same(expected) {
		return errors.New("original control publication changed after protected checkpoint")
	}
	return proof.RevalidateRuntime(ctx, runtime)
}
