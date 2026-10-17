package ociresource

import (
	"context"
	"errors"
	"fmt"

	"github.com/nats-io/nats.go/jetstream"
)

// RejectLegacyDesired never imports unsigned bodies, tokens or tombstones.
// Their original mutation authority cannot be recovered from ordinary KV.
func RejectLegacyDesired(ctx context.Context, js jetstream.JetStream, cell string) error {
	if err := (Key{Region: cell, Kind: "x", Name: "x"}).Validate(); err != nil {
		return err
	}
	kv, err := js.KeyValue(ctx, desiredBucket)
	if errors.Is(err, jetstream.ErrBucketNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	lister, err := kv.ListKeysFiltered(ctx, cell+".*.*")
	if errors.Is(err, jetstream.ErrNoKeysFound) {
		return nil
	}
	if err != nil {
		return err
	}
	defer lister.Stop()
	for range lister.Keys() {
		return fmt.Errorf("legacy OCI desired migration remains open for %s: unsigned operation history cannot authorize root effects", cell)
	}
	return ctx.Err()
}
