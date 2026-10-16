// Package kvsnapshot keeps a copy of the regional configuration KV buckets in
// OCI Object Storage so that a rebuilt controller set, which starts with an
// empty JetStream store, recovers them automatically.
//
// Each bucket has one object, kv-snapshot/v1/<cell>/<bucket>.json, holding the
// latest value of every key. The authority leader rewrites it whenever the
// bucket's stream changes, with an ETag compare-and-swap; the Object Storage
// bucket's versioning keeps the history. Values are stored and restored byte
// for byte, so a signed value (the cell spec, for example) keeps its
// signature and is verified by its owner as before.
package kvsnapshot

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go/jetstream"
)

// Buckets are the KV buckets whose latest values survive the loss of every
// controller. They hold configuration (the cell spec, the root chain,
// enrollment grants, rollouts and known-bad releases, desired OCI resources,
// apps and machines, managed volumes) rather than state
// bound to the authority control log, which a rebuilt cell starts afresh.
var Buckets = []string{"TS_SERVICE_SET", "TS_TRUST_ROOTS", "TS_HOST_ENROLLMENT", "TS_ROLLOUTS", "TS_OCI_DESIRED", "TS_APPS", "TS_MACHINES", "TS_VOLUMES"}

const (
	documentVersion  = 1
	snapshotPrefix   = "kv-snapshot/v1"
	snapshotInterval = 30 * time.Second
	maxDocumentBytes = 64 << 20
)

var (
	namespacePattern = regexp.MustCompile(`^[a-z0-9]{1,64}$`)
	kvBucketPattern  = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	kvKeyPattern     = regexp.MustCompile(`^[-/_=.a-zA-Z0-9]+$`)
)

func objectName(cell, bucket string) string {
	return snapshotPrefix + "/" + cell + "/" + bucket + ".json"
}

// Document is one bucket's snapshot. StreamCreated identifies the JetStream
// stream the values were read from: a rebuilt cell's stream is created later,
// so its snapshots supersede the old cell's, and within one stream Sequence
// only grows.
type Document struct {
	Version       int          `json:"version"`
	Cell          string       `json:"cell"`
	Bucket        string       `json:"bucket"`
	StreamCreated time.Time    `json:"stream_created"`
	Sequence      uint64       `json:"sequence"`
	TakenAt       time.Time    `json:"taken_at"`
	Config        BucketConfig `json:"config"`
	Entries       []Entry      `json:"entries"`
}

// BucketConfig is the part of the bucket's configuration a restore recreates
// until the bucket's owner opens it. Replicas follow the restoring cell. It
// carries no TTL or byte limit: an owner that keeps an existing bucket must
// not inherit one that expires or blocks its values.
type BucketConfig struct {
	Description  string `json:"description,omitempty"`
	History      uint8  `json:"history"`
	MaxValueSize int32  `json:"max_value_size"`
	Compression  bool   `json:"compression,omitzero"`
}

// Entry is one key's latest value.
type Entry struct {
	Key   string `json:"key"`
	Value []byte `json:"value"`
}

func (config BucketConfig) keyValueConfig(bucket string, replicas int) jetstream.KeyValueConfig {
	return jetstream.KeyValueConfig{Bucket: bucket, Description: config.Description, History: config.History,
		MaxValueSize: config.MaxValueSize, Compression: config.Compression, Storage: jetstream.FileStorage,
		Replicas: replicas}
}

func encodeDocument(document Document) ([]byte, error) {
	data, err := protocol.EncodeJSON(document)
	if err != nil {
		return nil, err
	}
	if len(data) > maxDocumentBytes {
		return nil, fmt.Errorf("kv snapshot of %s exceeds %d bytes", document.Bucket, maxDocumentBytes)
	}
	return data, nil
}

// decodeDocument accepts only a well-formed snapshot of exactly this cell's
// bucket: sorted unique valid keys whose values fit the recorded limit.
func decodeDocument(data []byte, cell, bucket string) (Document, error) {
	var document Document
	if err := protocol.DecodeStrict(data, &document, maxDocumentBytes); err != nil {
		return Document{}, fmt.Errorf("decode kv snapshot of %s: %w", bucket, err)
	}
	config := document.Config
	if document.Version != documentVersion || document.Cell != cell || document.Bucket != bucket ||
		document.StreamCreated.IsZero() || document.Sequence == 0 || document.TakenAt.IsZero() ||
		config.History < 1 || config.History > 64 || config.MaxValueSize == 0 || config.MaxValueSize < -1 {
		return Document{}, fmt.Errorf("kv snapshot of %s is not a valid snapshot of cell %s", bucket, cell)
	}
	for index, entry := range document.Entries {
		if !validKey(entry.Key) || index > 0 && document.Entries[index-1].Key >= entry.Key ||
			config.MaxValueSize > 0 && len(entry.Value) > int(config.MaxValueSize) {
			return Document{}, fmt.Errorf("kv snapshot of %s has an invalid, unsorted or oversized entry", bucket)
		}
	}
	return document, nil
}

func validKey(key string) bool {
	return kvKeyPattern.MatchString(key) && !strings.HasPrefix(key, ".") && !strings.HasSuffix(key, ".")
}

func validBuckets(buckets []string) error {
	for index, bucket := range buckets {
		if !kvBucketPattern.MatchString(bucket) || bucket == planBucket || slices.Contains(buckets[:index], bucket) {
			return fmt.Errorf("kv snapshot bucket %q is invalid or repeated", bucket)
		}
	}
	return nil
}
