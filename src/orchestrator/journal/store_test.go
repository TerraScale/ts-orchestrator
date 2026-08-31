package journal

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
)

func operationJournalConfiguration() jetstream.KeyValueConfig {
	return jetstream.KeyValueConfig{
		Bucket: "ORCH_OPERATIONS", Description: "operations", History: 2,
		MaxValueSize: 16 * 1024, MaxBytes: 256 * 1024 * 1024, Replicas: 3,
	}
}

func proofJournalConfiguration() jetstream.KeyValueConfig {
	return jetstream.KeyValueConfig{
		Bucket: "ORCH_OPERATION_PROOFS", Description: "proofs", History: 1,
		TTL: 5 * time.Minute, MaxValueSize: 256, MaxBytes: 8 * 1024 * 1024, Replicas: 3,
	}
}

func serverMetadata() map[string]string {
	return map[string]string{
		"_nats.level": "1", "_nats.req.level": "0", "_nats.ver": "2.14.6",
	}
}

func TestExactR3JournalConfigurations(t *testing.T) {
	for _, test := range []struct {
		name          string
		configuration jetstream.KeyValueConfig
	}{
		{"operations", operationJournalConfiguration()},
		{"proof-consumptions", proofJournalConfiguration()},
	} {
		t.Run(test.name, func(t *testing.T) {
			actual := NatsOperationJournalStore.CanonicalStream(test.configuration)
			if err := NatsOperationJournalStore.ValidateConfiguration(actual, test.configuration); err != nil {
				t.Fatalf("exact configuration rejected: %v", err)
			}
		})
	}
}

func TestJournalConfigurationRejectsForbiddenMutations(t *testing.T) {
	mutations := []struct {
		name   string
		mutate func(*jetstream.KeyValueConfig)
	}{
		{"bucket", func(c *jetstream.KeyValueConfig) { c.Bucket = "OTHER" }},
		{"history", func(c *jetstream.KeyValueConfig) { c.History++ }},
		{"ttl", func(c *jetstream.KeyValueConfig) { c.TTL = time.Second }},
		{"max-value-size", func(c *jetstream.KeyValueConfig) { c.MaxValueSize++ }},
		{"max-bytes", func(c *jetstream.KeyValueConfig) { c.MaxBytes++ }},
		{"replicas", func(c *jetstream.KeyValueConfig) { c.Replicas = 1 }},
		{"memory-storage", func(c *jetstream.KeyValueConfig) { c.Storage = jetstream.MemoryStorage }},
		{"placement", func(c *jetstream.KeyValueConfig) { c.Placement = &jetstream.Placement{Cluster: "other"} }},
		{"republish", func(c *jetstream.KeyValueConfig) {
			c.RePublish = &jetstream.RePublish{Source: ">", Destination: "copy"}
		}},
		{"mirror", func(c *jetstream.KeyValueConfig) { c.Mirror = &jetstream.StreamSource{Name: "source"} }},
		{"sources", func(c *jetstream.KeyValueConfig) { c.Sources = []*jetstream.StreamSource{{Name: "source"}} }},
		{"compression", func(c *jetstream.KeyValueConfig) { c.Compression = true }},
		{"limit-marker-ttl", func(c *jetstream.KeyValueConfig) { c.LimitMarkerTTL = time.Minute }},
		{"metadata", func(c *jetstream.KeyValueConfig) { c.Metadata = map[string]string{"owner": "test"} }},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			configuration := operationJournalConfiguration()
			test.mutate(&configuration)
			err := NatsOperationJournalStore.ValidateConfiguration(
				NatsOperationJournalStore.CanonicalStream(configuration), configuration)
			assertArgument(t, err, "configuration")
		})
	}
}

func TestExactStreamRejectsPreviouslyUncheckedFields(t *testing.T) {
	expected := NatsOperationJournalStore.CanonicalStream(operationJournalConfiguration())
	mutations := []struct {
		name   string
		mutate func(*jetstream.StreamConfig)
	}{
		{"first-sequence", func(c *jetstream.StreamConfig) { c.FirstSeq = 42 }},
		{"consumer-inactive-threshold", func(c *jetstream.StreamConfig) { c.ConsumerLimits.InactiveThreshold = time.Minute }},
		{"consumer-max-ack-pending", func(c *jetstream.StreamConfig) { c.ConsumerLimits.MaxAckPending = 1 }},
		{"template", func(c *jetstream.StreamConfig) { c.Template = "legacy" }},
		{"persist-mode", func(c *jetstream.StreamConfig) { c.PersistMode = jetstream.AsyncPersistMode }},
		{"batch-publish", func(c *jetstream.StreamConfig) { c.AllowBatchPublish = true }},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			actual := expected
			test.mutate(&actual)
			if err := NatsOperationJournalStore.ValidateExactStreamConfiguration(actual, expected); err == nil {
				t.Fatal("forbidden stream mutation was accepted")
			}
		})
	}
}

func TestExactStreamAcceptsOnlyKnownValidServerMetadata(t *testing.T) {
	expected := NatsOperationJournalStore.CanonicalStream(operationJournalConfiguration())
	valid := []map[string]string{nil, {}, serverMetadata()}
	for index, metadata := range valid {
		actual := expected
		actual.Metadata = metadata
		if err := NatsOperationJournalStore.ValidateExactStreamConfiguration(actual, expected); err != nil {
			t.Fatalf("valid metadata case %d rejected: %v", index, err)
		}
	}

	invalid := []map[string]string{
		{"_nats.level": "1", "_nats.req.level": "0", "_nats.ver": "2.14.6", "_nats.extra": "1"},
		{"_nats.level": "+1", "_nats.req.level": "0", "_nats.ver": "2.14.6"},
		{"_nats.level": "1", "_nats.req.level": "-0", "_nats.ver": "2.14.6"},
		{"_nats.level": "1", "_nats.req.level": "0", "_nats.ver": "2..14"},
		{"owner": "test"},
	}
	for index, metadata := range invalid {
		actual := expected
		actual.Metadata = metadata
		if err := NatsOperationJournalStore.ValidateExactStreamConfiguration(actual, expected); err == nil {
			t.Fatalf("invalid metadata case %d was accepted", index)
		}
	}
	expected.Metadata = serverMetadata()
	if err := NatsOperationJournalStore.ValidateExactStreamConfiguration(expected, expected); err == nil {
		t.Fatal("nonempty expected metadata was ignored")
	}
}

func TestTopologyKeyValueAndObjectStoreDrift(t *testing.T) {
	kv := jetstream.KeyValueConfig{
		Bucket: "GLOBAL_CELLS", Description: "cells", History: 16,
		TTL: 30 * 24 * time.Hour, MaxValueSize: 64 * 1024,
		MaxBytes: 64 * 1024 * 1024, Replicas: 3,
	}
	kvActual := NatsOperationJournalStore.CanonicalKeyValueStream(kv)
	kvActual.Metadata = serverMetadata()
	if err := NatsOperationJournalStore.ValidatePlainTopologyKeyValueConfiguration(kvActual, kv); err != nil {
		t.Fatalf("global KV configuration rejected: %v", err)
	}
	kvActual.MaxAge++
	if err := NatsOperationJournalStore.ValidatePlainTopologyKeyValueConfiguration(kvActual, kv); err == nil {
		t.Fatal("KV MaxAge drift was accepted")
	}

	object := jetstream.ObjectStoreConfig{
		Bucket: "CI_RUNNER_BUNDLES", Description: "runner bundles",
		TTL: 30 * 24 * time.Hour, MaxBytes: 64 * 1024 * 1024, Replicas: 3,
	}
	objectActual := canonicalObjectStoreStream(object)
	objectActual.Metadata = serverMetadata()
	if err := NatsOperationJournalStore.ValidateExactObjectConfiguration(objectActual, object); err != nil {
		t.Fatalf("TTL object-store configuration rejected: %v", err)
	}
	objectActual.MaxAge = 0
	if err := NatsOperationJournalStore.ValidateExactObjectConfiguration(objectActual, object); err == nil {
		t.Fatal("object-store TTL drift was accepted")
	}
}

func TestValidateBatchPublishResponse(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{"omitted", `{"config":{}}`, false},
		{"modern-false", `{"config":{"allow_batched":false}}`, false},
		{"legacy-false", `{"config":{"allow_batch_publish":false}}`, false},
		{"both-false", `{"config":{"allow_batched":false,"allow_batch_publish":false}}`, false},
		{"modern-true", `{"config":{"allow_batched":true}}`, true},
		{"legacy-true", `{"config":{"allow_batch_publish":true}}`, true},
		{"conflicting-aliases", `{"config":{"allow_batched":false,"allow_batch_publish":true}}`, true},
		{"null", `{"config":{"allow_batched":null}}`, true},
		{"string", `{"config":{"allow_batched":"false"}}`, true},
		{"null-config", `{"config":null}`, true},
		{"missing-config", `{}`, true},
		{"error-response", `{"error":{"code":500},"config":{}}`, true},
		{"malformed", `{`, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := NatsOperationJournalStore.ValidateBatchPublish([]byte(test.body))
			if (err != nil) != test.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

func TestPublicBoundariesReturnTypedArguments(t *testing.T) {
	configuration := operationJournalConfiguration()
	var typedNilContext *nilBoundaryContext
	var typedNilJetStream *nilBoundaryJetStream
	var typedNilKeyValueJetStream *nilBoundaryJetStream
	var typedNilKeyValue *nilBoundaryKeyValue
	tests := []struct {
		name  string
		param string
		call  func() error
	}{
		{"provision-context", "ctx", func() error {
			_, err := NatsOperationJournalStore.ProvisionAsync(nil, nil, nil, nil, configuration)
			return err
		}},
		{"provision-client", "client", func() error {
			_, err := NatsOperationJournalStore.ProvisionAsync(context.Background(), nil, nil, nil, configuration)
			return err
		}},
		{"provision-typed-nil-context", "ctx", func() error {
			_, err := NatsOperationJournalStore.ProvisionAsync(
				typedNilContext, nil, nil, nil, configuration)
			return err
		}},
		{"provision-jetstream", "js", func() error {
			_, err := NatsOperationJournalStore.ProvisionAsync(context.Background(), &nats.Conn{}, nil, nil, configuration)
			return err
		}},
		{"provision-typed-nil-jetstream", "js", func() error {
			_, err := NatsOperationJournalStore.ProvisionAsync(
				context.Background(), &nats.Conn{}, typedNilJetStream, nil, configuration)
			return err
		}},
		{"provision-typed-nil-key-value", "keyValue", func() error {
			_, err := NatsOperationJournalStore.ProvisionAsync(
				context.Background(), &nats.Conn{}, &nilBoundaryJetStream{},
				typedNilKeyValueJetStream, configuration)
			return err
		}},
		{"open-context", "ctx", func() error {
			_, err := NatsOperationJournalStore.OpenAsync(nil, nil, configuration, nil)
			return err
		}},
		{"open-jetstream", "keyValue", func() error {
			_, err := NatsOperationJournalStore.OpenAsync(context.Background(), nil, configuration, &nats.Conn{})
			return err
		}},
		{"open-typed-nil-key-value", "keyValue", func() error {
			_, err := NatsOperationJournalStore.OpenAsync(
				context.Background(), typedNilKeyValueJetStream, configuration, &nats.Conn{})
			return err
		}},
		{"open-client", "client", func() error {
			_, err := NatsOperationJournalStore.OpenAsync(
				context.Background(), &nilBoundaryJetStream{}, configuration, nil)
			return err
		}},
		{"validate-context", "ctx", func() error {
			return NatsOperationJournalStore.ValidateAsync(nil, nil, nil, configuration)
		}},
		{"validate-jetstream", "keyValue", func() error {
			return NatsOperationJournalStore.ValidateAsync(context.Background(), nil, nil, configuration)
		}},
		{"validate-typed-nil-key-value", "keyValue", func() error {
			return NatsOperationJournalStore.ValidateAsync(
				context.Background(), typedNilKeyValueJetStream, nil, configuration)
		}},
		{"validate-typed-nil-store", "store", func() error {
			return NatsOperationJournalStore.ValidateAsync(
				context.Background(), &nilBoundaryJetStream{}, typedNilKeyValue, configuration)
		}},
		{"invalid-journal-configuration", "configuration", func() error {
			return NatsOperationJournalStore.ValidateConfiguration(jetstream.StreamConfig{}, jetstream.KeyValueConfig{})
		}},
		{"invalid-kv-configuration", "configuration", func() error {
			return NatsOperationJournalStore.ValidatePlainTopologyKeyValueConfiguration(
				jetstream.StreamConfig{}, jetstream.KeyValueConfig{})
		}},
		{"invalid-object-configuration", "configuration", func() error {
			return NatsOperationJournalStore.ValidateExactObjectConfiguration(
				jetstream.StreamConfig{}, jetstream.ObjectStoreConfig{})
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) { assertArgument(t, test.call(), test.param) })
	}
}

func TestClosedTopologyConfigurationBoundaries(t *testing.T) {
	kvMutations := []struct {
		name   string
		mutate func(*jetstream.KeyValueConfig)
	}{
		{"bucket-syntax", func(c *jetstream.KeyValueConfig) { c.Bucket = "bad.bucket" }},
		{"history", func(c *jetstream.KeyValueConfig) { c.History = 65 }},
		{"negative-ttl", func(c *jetstream.KeyValueConfig) { c.TTL = -1 }},
		{"max-value-size", func(c *jetstream.KeyValueConfig) { c.MaxValueSize = -2 }},
		{"negative-max-bytes", func(c *jetstream.KeyValueConfig) { c.MaxBytes = -1 }},
		{"negative-replicas", func(c *jetstream.KeyValueConfig) { c.Replicas = -1 }},
		{"too-many-replicas", func(c *jetstream.KeyValueConfig) { c.Replicas = 6 }},
		{"storage", func(c *jetstream.KeyValueConfig) { c.Storage = jetstream.StorageType(99) }},
		{"negative-marker-ttl", func(c *jetstream.KeyValueConfig) { c.LimitMarkerTTL = -1 }},
	}
	for _, test := range kvMutations {
		t.Run("kv-"+test.name, func(t *testing.T) {
			configuration := jetstream.KeyValueConfig{Bucket: "VALID", Replicas: 1}
			test.mutate(&configuration)
			assertArgument(t, NatsOperationJournalStore.ValidatePlainTopologyKeyValueConfiguration(
				jetstream.StreamConfig{}, configuration), "configuration")
		})
	}

	objectMutations := []struct {
		name   string
		mutate func(*jetstream.ObjectStoreConfig)
	}{
		{"bucket-syntax", func(c *jetstream.ObjectStoreConfig) { c.Bucket = "bad.bucket" }},
		{"negative-ttl", func(c *jetstream.ObjectStoreConfig) { c.TTL = -1 }},
		{"negative-max-bytes", func(c *jetstream.ObjectStoreConfig) { c.MaxBytes = -1 }},
		{"negative-replicas", func(c *jetstream.ObjectStoreConfig) { c.Replicas = -1 }},
		{"too-many-replicas", func(c *jetstream.ObjectStoreConfig) { c.Replicas = 6 }},
		{"storage", func(c *jetstream.ObjectStoreConfig) { c.Storage = jetstream.StorageType(99) }},
	}
	for _, test := range objectMutations {
		t.Run("object-"+test.name, func(t *testing.T) {
			configuration := jetstream.ObjectStoreConfig{Bucket: "VALID", Replicas: 1}
			test.mutate(&configuration)
			assertArgument(t, NatsOperationJournalStore.ValidateExactObjectConfiguration(
				jetstream.StreamConfig{}, configuration), "configuration")
		})
	}
}

type nilBoundaryContext struct{ context.Context }
type nilBoundaryJetStream struct{ jetstream.JetStream }
type nilBoundaryKeyValue struct{ jetstream.KeyValue }

func assertArgument(t *testing.T, err error, param string) {
	t.Helper()
	var argument *errs.Argument
	if !errors.As(err, &argument) || argument.Param != param {
		t.Fatalf("error = %#v, want *errs.Argument for %s", err, param)
	}
}
