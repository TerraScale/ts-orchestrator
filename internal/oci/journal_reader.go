package oci

import (
	"context"
	"errors"
	"fmt"

	"github.com/nats-io/nats.go/jetstream"
)

// JournalReader is an opaque handle to existing durable ownership records.
type JournalReader struct{ journal *KVJournal }

// OpenJournalReader never creates a bucket or repairs ownership projections.
func OpenJournalReader(ctx context.Context, js jetstream.JetStream, replicas int) (JournalReader, error) {
	if js == nil || replicas < 1 || replicas > 5 {
		return JournalReader{}, errors.New("OCI journal reader requires JetStream and one to five replicas")
	}
	kv, err := js.KeyValue(ctx, journalBucket)
	if err != nil {
		return JournalReader{}, fmt.Errorf("open existing OCI journal bucket: %w", err)
	}
	status, err := kv.Status(ctx)
	if err != nil {
		return JournalReader{}, fmt.Errorf("inspect OCI journal bucket: %w", err)
	}
	config := status.Config()
	if kv.Bucket() != journalBucket || status.Bucket() != journalBucket || config.Bucket != journalBucket ||
		config.Replicas != replicas || config.Storage != jetstream.FileStorage || config.TTL != 0 || config.History < 2 || config.MaxValueSize > journalMaxValueSize {
		return JournalReader{}, errors.New("existing OCI journal bucket has incompatible identity or durability limits")
	}
	return JournalReader{journal: &KVJournal{kv: kv}}, nil
}
