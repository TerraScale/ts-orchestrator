// Port of src/TerraScale.Orchestrator/Messaging/NatsOperationJournalStore.cs.
package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// NatsOperationJournalStore mirrors the C# static class: infrastructure
// provisions this bucket; controller identities only open and validate it.
var NatsOperationJournalStore natsOperationJournalStore

type natsOperationJournalStore struct{}

// ProvisionAsync mirrors the C# ProvisionAsync.
func (natsOperationJournalStore) ProvisionAsync(
	ctx context.Context,
	client *nats.Conn,
	js jetstream.JetStream,
	keyValue jetstream.JetStream,
	configuration jetstream.KeyValueConfig,
) (jetstream.KeyValue, error) {
	if ctx == nil {
		return nil, errors.New("(Parameter 'ctx')")
	}
	if client == nil {
		return nil, errors.New("(Parameter 'client')")
	}
	if js == nil {
		return nil, errors.New("(Parameter 'js')")
	}
	if keyValue == nil {
		return nil, errors.New("(Parameter 'keyValue')")
	}
	if err := natsOperationJournalValidateExpected(configuration); err != nil {
		return nil, err
	}

	if _, err := js.CreateOrUpdateStream(ctx, natsOperationJournalCanonicalStream(configuration)); err != nil {
		return nil, err
	}

	if err := natsOperationJournalSetBatchPublishDisabled(ctx, client, configuration); err != nil {
		return nil, err
	}

	store, err := keyValue.KeyValue(ctx, configuration.Bucket)
	if err != nil {
		return nil, err
	}

	if err := natsOperationJournalValidate(ctx, keyValue, store, configuration, nil); err != nil {
		return nil, err
	}

	return store, nil
}

// OpenAsync mirrors the C# OpenAsync.
func (natsOperationJournalStore) OpenAsync(
	ctx context.Context,
	keyValue jetstream.JetStream,
	configuration jetstream.KeyValueConfig,
	client *nats.Conn,
) (jetstream.KeyValue, error) {
	if ctx == nil {
		return nil, errors.New("(Parameter 'ctx')")
	}
	if keyValue == nil {
		return nil, errors.New("(Parameter 'keyValue')")
	}
	if err := natsOperationJournalValidateExpected(configuration); err != nil {
		return nil, err
	}

	store, err := keyValue.KeyValue(ctx, configuration.Bucket)
	if err != nil {
		return nil, err
	}

	if err := natsOperationJournalValidate(ctx, keyValue, store, configuration, client); err != nil {
		return nil, err
	}

	return store, nil
}

// ValidateAsync mirrors the C# public ValidateAsync. The Go nats.go client
// exposes the backing stream through the JetStream context, so the store is
// accompanied by the context it was opened from.
func (natsOperationJournalStore) ValidateAsync(
	ctx context.Context,
	keyValue jetstream.JetStream,
	store jetstream.KeyValue,
	configuration jetstream.KeyValueConfig,
) error {
	if ctx == nil {
		return errors.New("(Parameter 'ctx')")
	}
	if keyValue == nil || store == nil {
		return errors.New("(Parameter 'store')")
	}
	return natsOperationJournalValidate(ctx, keyValue, store, configuration, nil)
}

func natsOperationJournalValidate(
	ctx context.Context,
	keyValue jetstream.JetStream,
	store jetstream.KeyValue,
	configuration jetstream.KeyValueConfig,
	client *nats.Conn,
) error {
	if err := natsOperationJournalValidateExpected(configuration); err != nil {
		return err
	}

	status, err := store.Status(ctx)
	if err != nil {
		return err
	}

	if status.Bucket() != configuration.Bucket {
		return errors.New(
			"The authoritative CreateNode journal store is absent or does not have its immutable R3 configuration.")
	}

	stream, err := keyValue.Stream(ctx, "KV_"+configuration.Bucket)
	if err != nil {
		return err
	}

	info, err := stream.Info(ctx)
	if err != nil {
		return err
	}

	if err := NatsOperationJournalStore.ValidateConfiguration(info.Config, configuration); err != nil {
		return err
	}

	if client != nil {
		return natsOperationJournalValidateBatchPublishDisabled(ctx, client, configuration)
	}

	return nil
}

// ValidateConfiguration mirrors the C# ValidateConfiguration.
func (natsOperationJournalStore) ValidateConfiguration(
	actual jetstream.StreamConfig,
	configuration jetstream.KeyValueConfig,
) error {
	if err := natsOperationJournalValidateExpected(configuration); err != nil {
		return err
	}

	return NatsOperationJournalStore.ValidateExactStreamConfiguration(
		actual, natsOperationJournalCanonicalStream(configuration))
}

// ValidateExactStreamConfiguration mirrors the C# ValidateExactStreamConfiguration.
func (natsOperationJournalStore) ValidateExactStreamConfiguration(
	actual jetstream.StreamConfig,
	expected jetstream.StreamConfig,
) error {
	actualSubjects := append([]string(nil), actual.Subjects...)
	expectedSubjects := append([]string(nil), expected.Subjects...)
	sort.Strings(actualSubjects)
	sort.Strings(expectedSubjects)
	subjectsEqual := len(actualSubjects) == len(expectedSubjects)
	if subjectsEqual {
		for index := range actualSubjects {
			if actualSubjects[index] != expectedSubjects[index] {
				subjectsEqual = false
				break
			}
		}
	}

	invalid := actual.Name != expected.Name ||
		actual.Description != expected.Description ||
		!subjectsEqual ||
		actual.SubjectTransform != nil ||
		actual.Retention != expected.Retention ||
		actual.MaxConsumers != expected.MaxConsumers || actual.MaxMsgs != expected.MaxMsgs ||
		actual.MaxMsgsPerSubject != expected.MaxMsgsPerSubject || actual.MaxBytes != expected.MaxBytes ||
		actual.MaxAge != expected.MaxAge || actual.MaxMsgSize != expected.MaxMsgSize ||
		actual.Storage != expected.Storage || actual.Compression != expected.Compression ||
		actual.Replicas != expected.Replicas || actual.NoAck != expected.NoAck ||
		actual.Discard != expected.Discard ||
		actual.Duplicates != expected.Duplicates ||
		actual.Placement != nil ||
		actual.Mirror != nil || len(actual.Sources) > 0 || actual.Sealed != expected.Sealed ||
		actual.DenyDelete != expected.DenyDelete || actual.DenyPurge != expected.DenyPurge ||
		actual.AllowRollup != expected.AllowRollup || actual.AllowDirect != expected.AllowDirect ||
		actual.MirrorDirect != expected.MirrorDirect ||
		actual.RePublish != nil ||
		actual.DiscardNewPerSubject != expected.DiscardNewPerSubject ||
		actual.AllowMsgTTL != expected.AllowMsgTTL ||
		actual.SubjectDeleteMarkerTTL != expected.SubjectDeleteMarkerTTL ||
		actual.AllowMsgCounter != expected.AllowMsgCounter ||
		actual.AllowMsgSchedules != expected.AllowMsgSchedules ||
		actual.AllowAtomicPublish != expected.AllowAtomicPublish

	if !invalid {
		for key := range actual.Metadata {
			if len(key) >= len("_nats.") && key[:len("_nats.")] == "_nats." {
				continue
			}

			invalid = true
			break
		}
	}

	if invalid {
		return errors.New(
			"The authoritative CreateNode journal store is absent or does not have its immutable R3 configuration.")
	}

	return nil
}

// ValidateExactObjectConfiguration mirrors the C#
// ValidateExactObjectConfiguration.
func (natsOperationJournalStore) ValidateExactObjectConfiguration(
	actual jetstream.StreamConfig,
	configuration jetstream.ObjectStoreConfig,
) error {
	maxBytes := int64(-1)
	if configuration.MaxBytes != 0 {
		maxBytes = configuration.MaxBytes
	}

	expected := jetstream.StreamConfig{
		Name:                   "OBJ_" + configuration.Bucket,
		Subjects:               []string{"$O." + configuration.Bucket + ".C.>", "$O." + configuration.Bucket + ".M.>"},
		Description:            configuration.Description,
		Retention:              jetstream.LimitsPolicy,
		MaxConsumers:           -1,
		MaxMsgs:                -1,
		MaxMsgsPerSubject:      -1,
		MaxBytes:               maxBytes,
		MaxAge:                 0,
		MaxMsgSize:             -1,
		Storage:                jetstream.FileStorage,
		Compression:            jetstream.NoCompression,
		Replicas:               configuration.Replicas,
		NoAck:                  false,
		Discard:                jetstream.DiscardNew,
		Duplicates:             2 * time.Minute,
		Sealed:                 false,
		DenyDelete:             false,
		DenyPurge:              false,
		AllowRollup:            true,
		AllowDirect:            true,
		MirrorDirect:           false,
		DiscardNewPerSubject:   false,
		AllowMsgTTL:            false,
		SubjectDeleteMarkerTTL: 0,
		AllowMsgCounter:        false,
		AllowMsgSchedules:      false,
		AllowAtomicPublish:     false,
	}

	if err := NatsOperationJournalStore.ValidateExactStreamConfiguration(actual, expected); err != nil {
		return err
	}

	if !hasExpectedNatsMetadata(actual.Metadata) {
		return errors.New("The regional object store configuration carries unexpected metadata.")
	}

	return nil
}

// CanonicalStream mirrors the C# CanonicalStream.
func (natsOperationJournalStore) CanonicalStream(configuration jetstream.KeyValueConfig) jetstream.StreamConfig {
	return jetstream.StreamConfig{
		Name:              "KV_" + configuration.Bucket,
		Subjects:          []string{"$KV." + configuration.Bucket + ".>"},
		Description:       configuration.Description,
		Retention:         jetstream.LimitsPolicy,
		MaxConsumers:      -1,
		MaxMsgs:           -1,
		MaxMsgsPerSubject: int64(configuration.History),
		MaxBytes:          configuration.MaxBytes,
		MaxAge:            configuration.TTL,
		MaxMsgSize:        configuration.MaxValueSize,
		Storage:           jetstream.FileStorage,
		Compression:       jetstream.NoCompression,
		Replicas:          configuration.Replicas,
		NoAck:             false,
		Discard:           jetstream.DiscardNew,
		Duplicates:        2 * time.Minute,
		Sealed:            false,
		DenyDelete:        true,
		DenyPurge:         true,
		// CAS uses Nats-Expected-Last-Subject-Sequence, not rollups. Refuse any
		// Nats-Rollup header so a writer cannot erase retained operation history.
		AllowRollup:            false,
		AllowDirect:            true,
		MirrorDirect:           false,
		DiscardNewPerSubject:   false,
		AllowMsgTTL:            false,
		SubjectDeleteMarkerTTL: 0,
		AllowMsgCounter:        false,
		AllowMsgSchedules:      false,
		AllowAtomicPublish:     false,
	}
}

func natsOperationJournalCanonicalStream(configuration jetstream.KeyValueConfig) jetstream.StreamConfig {
	return NatsOperationJournalStore.CanonicalStream(configuration)
}

// CanonicalKeyValueStream mirrors the C# CanonicalKeyValueStream.
func (natsOperationJournalStore) CanonicalKeyValueStream(configuration jetstream.KeyValueConfig) jetstream.StreamConfig {
	history := int64(configuration.History)
	if history == 0 {
		history = 1
	}

	maxBytes := configuration.MaxBytes
	if maxBytes == 0 {
		maxBytes = -1
	}

	maxValueSize := configuration.MaxValueSize
	if maxValueSize == 0 {
		maxValueSize = -1
	}

	replicas := configuration.Replicas
	if replicas <= 0 {
		replicas = 1
	}

	storage := jetstream.FileStorage
	if configuration.Storage == jetstream.MemoryStorage {
		storage = jetstream.MemoryStorage
	}

	return jetstream.StreamConfig{
		Name:                   "KV_" + configuration.Bucket,
		Subjects:               []string{"$KV." + configuration.Bucket + ".>"},
		Description:            configuration.Description,
		Retention:              jetstream.LimitsPolicy,
		MaxConsumers:           -1,
		MaxMsgs:                -1,
		MaxMsgsPerSubject:      history,
		MaxBytes:               maxBytes,
		MaxAge:                 configuration.TTL,
		MaxMsgSize:             maxValueSize,
		Storage:                storage,
		Compression:            map[bool]jetstream.StoreCompression{true: jetstream.S2Compression, false: jetstream.NoCompression}[configuration.Compression],
		Replicas:               replicas,
		NoAck:                  false,
		Discard:                jetstream.DiscardNew,
		Duplicates:             2 * time.Minute,
		Sealed:                 false,
		DenyDelete:             true,
		DenyPurge:              false,
		AllowRollup:            true,
		AllowDirect:            true,
		MirrorDirect:           false,
		DiscardNewPerSubject:   false,
		AllowMsgTTL:            configuration.LimitMarkerTTL > 0,
		SubjectDeleteMarkerTTL: configuration.LimitMarkerTTL,
		AllowMsgCounter:        false,
		AllowMsgSchedules:      false,
		AllowAtomicPublish:     false,
	}
}

// ValidatePlainTopologyKeyValueConfiguration mirrors the C# method.
func (natsOperationJournalStore) ValidatePlainTopologyKeyValueConfiguration(
	actual jetstream.StreamConfig,
	configuration jetstream.KeyValueConfig,
) error {
	if configuration.Bucket != "ORCH_LEADERS" && configuration.Bucket != "ORCH_RUNTIME" &&
		configuration.Bucket != "ORCH_DELIVERY" && configuration.Bucket != "ORCH_COMMAND_REPLAY" ||
		configuration.RePublish != nil || configuration.Placement != nil ||
		configuration.Mirror != nil || len(configuration.Sources) > 0 ||
		len(configuration.Metadata) > 0 {
		return errors.New(
			"The regional topology KV configuration must be closed. (Parameter 'configuration')")
	}

	if err := NatsOperationJournalStore.ValidateExactStreamConfiguration(
		actual, NatsOperationJournalStore.CanonicalKeyValueStream(configuration)); err != nil {
		return err
	}

	if actual.Metadata != nil && !hasExpectedNatsMetadata(actual.Metadata) {
		return errors.New("The regional topology KV configuration carries unexpected metadata.")
	}

	return nil
}

func hasExpectedNatsMetadata(metadata map[string]string) bool {
	if len(metadata) != 3 {
		return false
	}

	level, hasLevel := metadata["_nats.level"]
	requestedLevel, hasRequested := metadata["_nats.req.level"]
	version, hasVersion := metadata["_nats.ver"]

	return hasLevel && hasRequested && hasVersion &&
		isNonnegativeInteger(level) && isNonnegativeInteger(requestedLevel) &&
		isNonnegativeVersion(version)
}

func isNonnegativeInteger(value string) bool {
	parsed, err := strconv.Atoi(value)
	return err == nil && parsed >= 0
}

func isNonnegativeVersion(value string) bool {
	parts := parseVersionParts(value)
	if len(parts) == 0 {
		return false
	}

	for _, part := range parts {
		if part < 0 {
			return false
		}
	}

	return true
}

func parseVersionParts(value string) []int {
	if value == "" {
		return nil
	}

	parts := []int{}
	current := 0
	negative := false
	started := false
	for _, character := range value {
		switch {
		case character == '-':
			negative = true
		case character == '.':
			if negative {
				current = -current
			}

			parts = append(parts, current)
			current = 0
			negative = false
			started = false
		case character >= '0' && character <= '9':
			current = current*10 + int(character-'0')
			started = true
		default:
			return nil
		}
	}

	if !started {
		return nil
	}

	if negative {
		current = -current
	}

	return append(parts, current)
}

func natsOperationJournalSetBatchPublishDisabled(
	ctx context.Context,
	client *nats.Conn,
	configuration jetstream.KeyValueConfig,
) error {
	config := map[string]interface{}{}
	serialized, err := json.Marshal(natsOperationJournalCanonicalStream(configuration))
	if err != nil {
		return errors.New("Unable to serialize the operation journal stream configuration.")
	}

	if err := json.Unmarshal(serialized, &config); err != nil {
		return errors.New("Unable to serialize the operation journal stream configuration.")
	}

	// NATS.Net serializes the default enum value as persist_mode: 0, whereas
	// nats-server 2.14 requires its named wire value. The same server revision
	// exposes batch publishing as allow_batched rather than the older
	// allow_batch_publish spelling. Send the explicit, fail-closed wire form.
	config["persist_mode"] = "default"
	config["allow_batched"] = false

	body, err := json.Marshal(config)
	if err != nil {
		return err
	}

	response, err := client.Request("$JS.API.STREAM.UPDATE.KV_"+configuration.Bucket, body, 15*time.Second)
	if err != nil {
		return err
	}

	var root map[string]json.RawMessage
	if err := json.Unmarshal(response.Data, &root); err != nil {
		return err
	}

	if errRoot, hasError := root["error"]; hasError {
		return fmt.Errorf("JetStream operation journal stream mutation failed: %s", string(errRoot))
	}

	return natsOperationJournalValidateBatchPublishDisabled(ctx, client, configuration)
}

func natsOperationJournalValidateBatchPublishDisabled(
	ctx context.Context,
	client *nats.Conn,
	configuration jetstream.KeyValueConfig,
) error {
	response, err := client.Request("$JS.API.STREAM.INFO.KV_"+configuration.Bucket, nil, 15*time.Second)
	if err != nil {
		return err
	}

	var document map[string]json.RawMessage
	if err := json.Unmarshal(response.Data, &document); err != nil {
		return err
	}

	if errRoot, hasError := document["error"]; hasError {
		return fmt.Errorf(
			"JetStream operation journal stream mutation failed: %s", string(errRoot))
	}

	return natsOperationJournalValidateBatchPublish(response.Data)
}

// ValidateBatchPublish mirrors the C# ValidateBatchPublish.
func (natsOperationJournalStore) ValidateBatchPublish(response []byte) error {
	return natsOperationJournalValidateBatchPublish(response)
}

func natsOperationJournalValidateBatchPublish(response []byte) error {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(response, &root); err != nil {
		return errors.New(
			"Authoritative CreateNode journal stores must set allow_batch_publish to false.")
	}

	config, hasConfig := root["config"]
	if !hasConfig {
		return errors.New(
			"Authoritative CreateNode journal stores must set allow_batch_publish to false.")
	}

	var configObject map[string]json.RawMessage
	if err := json.Unmarshal(config, &configObject); err != nil {
		return errors.New(
			"Authoritative CreateNode journal stores must set allow_batch_publish to false.")
	}

	// nats-server 2.14 omits the false default from STREAM.INFO. An explicit
	// value is still required to be false; omission therefore denotes that
	// documented, fail-closed server default rather than an unknown value.
	enabled, hasEnabled := configObject["allow_batched"]
	if !hasEnabled {
		enabled, hasEnabled = configObject["allow_batch_publish"]
	}

	if !hasEnabled {
		return nil
	}

	var enabledValue bool
	if err := json.Unmarshal(enabled, &enabledValue); err != nil || enabledValue {
		return errors.New(
			"Authoritative CreateNode journal stores must set allow_batch_publish to false.")
	}

	return nil
}

func natsOperationJournalValidateExpected(configuration jetstream.KeyValueConfig) error {
	isOperationJournal := configuration.Bucket == "ORCH_OPERATIONS" &&
		int(configuration.History) == 2 && configuration.TTL == 0 &&
		configuration.MaxValueSize == 16*1024 && configuration.MaxBytes == 256*1024*1024
	isProofConsumption := configuration.Bucket == "ORCH_OPERATION_PROOFS" &&
		int(configuration.History) == 1 && configuration.TTL == 5*time.Minute &&
		configuration.MaxValueSize == 256 && configuration.MaxBytes == 8*1024*1024

	if (isOperationJournal || isProofConsumption) && configuration.Replicas == 3 &&
		configuration.Storage != jetstream.MemoryStorage {
		return nil
	}

	return errors.New(
		"The authoritative CreateNode journal store configuration must be exact R3. (Parameter 'configuration')")
}
