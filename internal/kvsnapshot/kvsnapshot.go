// Package kvsnapshot keeps a copy of the regional configuration KV buckets in
// OCI Object Storage so that a rebuilt controller set, which starts with an
// empty JetStream store, recovers them automatically.
//
// Each bucket has one object, <prefix>/<cell>/<bucket>.json, holding the
// latest value of every key. The authority leader rewrites it whenever the
// bucket's stream changes, with an ETag compare-and-swap; the Object Storage
// bucket's versioning keeps the history. Values are stored and restored byte
// for byte, so a signed value (the cell spec, for example) keeps its
// signature and is verified by its owner as before.
package kvsnapshot

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go/jetstream"
)

// Buckets are the KV buckets whose latest values survive the loss of every
// controller. They hold configuration (the cell spec, the root chain,
// enrollment grants, rollouts and known-bad releases, desired OCI resources)
// rather than state
// bound to the authority control log, which a rebuilt cell starts afresh.
var Buckets = []string{"TS_SERVICE_SET", "TS_TRUST_ROOTS", "TS_HOST_ENROLLMENT", "TS_ROLLOUTS", "TS_OCI_DESIRED"}

const (
	documentVersion  = 1
	defaultPrefix    = "kv-snapshot/v1"
	defaultInterval  = 30 * time.Second
	maxDocumentBytes = 64 << 20
)

var (
	namespacePattern = regexp.MustCompile(`^[a-z0-9]{1,64}$`)
	bucketPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$`)
	segmentPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	kvBucketPattern  = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	kvKeyPattern     = regexp.MustCompile(`^[-/_=.a-zA-Z0-9]+$`)
)

// Config is the controller's kv_snapshot setting. It is off by default; the
// controller dynamic group needs object read, create and overwrite on
// <prefix>/* in Bucket before it is enabled.
type Config struct {
	Enabled bool `json:"enabled,omitzero"`
	// Region is the OCI region identifier of Bucket, e.g. sa-saopaulo-1.
	Region    string `json:"region,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Bucket    string `json:"bucket,omitempty"`
	// KMSKeyID, when set, encrypts every snapshot with this key instead of
	// the bucket's default key.
	KMSKeyID string `json:"kms_key_id,omitempty"`
	// Prefix defaults to kv-snapshot/v1.
	Prefix string `json:"prefix,omitempty"`
	// IntervalSeconds is how often the leader looks for changed buckets
	// (default 30, 5 to 3600). Only a changed bucket is uploaded.
	IntervalSeconds int `json:"interval_seconds,omitzero"`
}

// Validate bounds an enabled config.
func (config Config) Validate() error {
	if !config.Enabled {
		return nil
	}
	if !catalog.IsOCIRegion(config.Region) || !namespacePattern.MatchString(config.Namespace) ||
		!bucketPattern.MatchString(config.Bucket) ||
		config.KMSKeyID != "" && !strings.HasPrefix(config.KMSKeyID, "ocid1.key.") ||
		config.IntervalSeconds != 0 && (config.IntervalSeconds < 5 || config.IntervalSeconds > 3600) {
		return errors.New("kv_snapshot needs an OCI region, namespace and bucket, an optional KMS key OCID and an interval of 5 to 3600 seconds")
	}
	if config.Prefix != "" {
		for segment := range strings.SplitSeq(config.Prefix, "/") {
			if !segmentPattern.MatchString(segment) {
				return errors.New("kv_snapshot prefix is not canonical")
			}
		}
	}
	return nil
}

// Interval is the leader's change check period.
func (config Config) Interval() time.Duration {
	if config.IntervalSeconds == 0 {
		return defaultInterval
	}
	return time.Duration(config.IntervalSeconds) * time.Second
}

func (config Config) objectName(cell, bucket string) string {
	prefix := config.Prefix
	if prefix == "" {
		prefix = defaultPrefix
	}
	return prefix + "/" + cell + "/" + bucket + ".json"
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
