package placement

import (
	"context"
	"errors"

	"github.com/nats-io/nats.go/jetstream"
)

// ListingReader exposes admitted placement and retained seats without writes.
type ListingReader interface {
	ListIntents(context.Context) ([]Intent, error)
	ListMembers(context.Context, string, string) ([]VersionedMemberState, error)
}

type listingReader struct{ store *jetStreamStore }

// OpenReadStore opens existing state with the same durability checks as exact
// member reads. It never creates a bucket or changes its configuration.
func OpenReadStore(ctx context.Context, js jetstream.JetStream, cell string, replicas int, intents AdmittedIntentReader) (ListingReader, error) {
	if !validToken(cell) || js == nil || intents == nil || replicas < 1 || replicas > 5 {
		return nil, errors.New("placement listing requires cell, JetStream, admitted intents and valid replica count")
	}
	kv, err := js.KeyValue(ctx, stateBucketName)
	if err != nil {
		return nil, err
	}
	status, err := kv.Status(ctx)
	if err != nil {
		return nil, err
	}
	config := status.Config()
	if kv.Bucket() != stateBucketName || status.Bucket() != stateBucketName || config.Bucket != stateBucketName ||
		config.Replicas != replicas || config.Storage != jetstream.FileStorage || config.TTL != 0 || config.History < 2 ||
		config.MaxValueSize <= 0 || config.MaxValueSize > maxStateBytes {
		return nil, errors.New("existing placement member state has incompatible identity or durability limits")
	}
	return listingReader{&jetStreamStore{cell: cell, state: kv, intents: intents}}, nil
}

func (reader listingReader) ListIntents(ctx context.Context) ([]Intent, error) {
	return reader.store.ListIntents(ctx)
}

func (reader listingReader) ListMembers(ctx context.Context, database, partition string) ([]VersionedMemberState, error) {
	return reader.store.ListMembers(ctx, database, partition)
}
