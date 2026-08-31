package journal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
)

// NatsOperationJournalStore mirrors the C# static class: infrastructure
// provisions this bucket; controller identities only open and validate it.
var NatsOperationJournalStore natsOperationJournalStore

type natsOperationJournalStore struct{}

var closedBucketPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

func isNilBoundary(value any) bool {
	if value == nil {
		return true
	}
	kind := reflect.ValueOf(value).Kind()
	switch kind {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return reflect.ValueOf(value).IsNil()
	default:
		return false
	}
}

// ProvisionAsync mirrors the C# ProvisionAsync.
func (natsOperationJournalStore) ProvisionAsync(
	ctx context.Context,
	client *nats.Conn,
	js jetstream.JetStream,
	keyValue jetstream.JetStream,
	configuration jetstream.KeyValueConfig,
) (jetstream.KeyValue, error) {
	if isNilBoundary(ctx) {
		return nil, &errs.Argument{Param: "ctx", Message: "(Parameter 'ctx')"}
	}
	if client == nil {
		return nil, &errs.Argument{Param: "client", Message: "(Parameter 'client')"}
	}
	if isNilBoundary(js) {
		return nil, &errs.Argument{Param: "js", Message: "(Parameter 'js')"}
	}
	if isNilBoundary(keyValue) {
		return nil, &errs.Argument{Param: "keyValue", Message: "(Parameter 'keyValue')"}
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
	if isNilBoundary(ctx) {
		return nil, &errs.Argument{Param: "ctx", Message: "(Parameter 'ctx')"}
	}
	if isNilBoundary(keyValue) {
		return nil, &errs.Argument{Param: "keyValue", Message: "(Parameter 'keyValue')"}
	}
	if client == nil {
		return nil, &errs.Argument{Param: "client", Message: "(Parameter 'client')"}
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
	if isNilBoundary(ctx) {
		return &errs.Argument{Param: "ctx", Message: "(Parameter 'ctx')"}
	}
	if isNilBoundary(keyValue) {
		return &errs.Argument{Param: "keyValue", Message: "(Parameter 'keyValue')"}
	}
	if isNilBoundary(store) {
		return &errs.Argument{Param: "store", Message: "(Parameter 'store')"}
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
		actual.FirstSeq != expected.FirstSeq ||
		actual.Placement != nil ||
		actual.Mirror != nil || len(actual.Sources) > 0 || actual.Sealed != expected.Sealed ||
		actual.DenyDelete != expected.DenyDelete || actual.DenyPurge != expected.DenyPurge ||
		actual.AllowRollup != expected.AllowRollup || actual.AllowDirect != expected.AllowDirect ||
		actual.MirrorDirect != expected.MirrorDirect ||
		actual.ConsumerLimits != expected.ConsumerLimits ||
		actual.Template != expected.Template ||
		actual.RePublish != nil ||
		actual.DiscardNewPerSubject != expected.DiscardNewPerSubject ||
		actual.AllowMsgTTL != expected.AllowMsgTTL ||
		actual.SubjectDeleteMarkerTTL != expected.SubjectDeleteMarkerTTL ||
		actual.AllowMsgCounter != expected.AllowMsgCounter ||
		actual.AllowMsgSchedules != expected.AllowMsgSchedules ||
		actual.AllowAtomicPublish != expected.AllowAtomicPublish ||
		actual.PersistMode != expected.PersistMode ||
		actual.AllowBatchPublish != expected.AllowBatchPublish ||
		len(expected.Metadata) != 0 ||
		!hasClosedStreamMetadata(actual.Metadata)

	if invalid {
		return errors.New(
			"The authoritative CreateNode journal store is absent or does not have its immutable R3 configuration.")
	}

	return nil
}

func hasClosedStreamMetadata(metadata map[string]string) bool {
	return len(metadata) == 0 || hasExpectedNatsMetadata(metadata)
}

// ValidateExactObjectConfiguration mirrors the C#
// ValidateExactObjectConfiguration.
func (natsOperationJournalStore) ValidateExactObjectConfiguration(
	actual jetstream.StreamConfig,
	configuration jetstream.ObjectStoreConfig,
) error {
	if err := validateClosedObjectStoreConfiguration(configuration); err != nil {
		return err
	}
	expected := canonicalObjectStoreStream(configuration)
	if err := NatsOperationJournalStore.ValidateExactStreamConfiguration(actual, expected); err != nil {
		return err
	}

	if !hasExpectedNatsMetadata(actual.Metadata) {
		return errors.New("The topology object store configuration carries unexpected metadata.")
	}

	return nil
}

func validateClosedObjectStoreConfiguration(configuration jetstream.ObjectStoreConfig) error {
	if !closedBucketPattern.MatchString(configuration.Bucket) || configuration.TTL < 0 ||
		configuration.MaxBytes < 0 || !validReplicaCount(configuration.Replicas) ||
		!validStorage(configuration.Storage) || configuration.Placement != nil ||
		len(configuration.Metadata) != 0 {
		return &errs.Argument{
			Param:   "configuration",
			Message: "The topology object store configuration must be closed. (Parameter 'configuration')",
		}
	}
	return nil
}

func validReplicaCount(replicas int) bool {
	return replicas >= 0 && replicas <= 5
}

func validStorage(storage jetstream.StorageType) bool {
	return storage == jetstream.FileStorage || storage == jetstream.MemoryStorage
}

func canonicalObjectStoreStream(configuration jetstream.ObjectStoreConfig) jetstream.StreamConfig {
	maxBytes := int64(-1)
	if configuration.MaxBytes != 0 {
		maxBytes = configuration.MaxBytes
	}
	replicas := configuration.Replicas
	if replicas == 0 {
		replicas = 1
	}
	compression := jetstream.NoCompression
	if configuration.Compression {
		compression = jetstream.S2Compression
	}
	duplicates := 2 * time.Minute
	if configuration.TTL > 0 && configuration.TTL < duplicates {
		duplicates = configuration.TTL
	}

	return jetstream.StreamConfig{
		Name:                   "OBJ_" + configuration.Bucket,
		Subjects:               []string{"$O." + configuration.Bucket + ".C.>", "$O." + configuration.Bucket + ".M.>"},
		Description:            configuration.Description,
		Retention:              jetstream.LimitsPolicy,
		MaxConsumers:           -1,
		MaxMsgs:                -1,
		MaxMsgsPerSubject:      -1,
		MaxBytes:               maxBytes,
		MaxAge:                 configuration.TTL,
		MaxMsgSize:             -1,
		Storage:                configuration.Storage,
		Compression:            compression,
		Replicas:               replicas,
		NoAck:                  false,
		Discard:                jetstream.DiscardNew,
		Duplicates:             duplicates,
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
	if !closedBucketPattern.MatchString(configuration.Bucket) || configuration.History > 64 ||
		configuration.TTL < 0 || configuration.MaxValueSize < -1 || configuration.MaxBytes < 0 ||
		configuration.LimitMarkerTTL < 0 || !validReplicaCount(configuration.Replicas) ||
		!validStorage(configuration.Storage) ||
		configuration.RePublish != nil || configuration.Placement != nil ||
		configuration.Mirror != nil || len(configuration.Sources) > 0 ||
		len(configuration.Metadata) > 0 {
		return &errs.Argument{
			Param:   "configuration",
			Message: "The topology KV configuration must be closed. (Parameter 'configuration')",
		}
	}

	if err := NatsOperationJournalStore.ValidateExactStreamConfiguration(
		actual, NatsOperationJournalStore.CanonicalKeyValueStream(configuration)); err != nil {
		return err
	}

	if len(actual.Metadata) > 0 && !hasExpectedNatsMetadata(actual.Metadata) {
		return errors.New("The topology KV configuration carries unexpected metadata.")
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
	return isUnsignedDecimal(value)
}

func isNonnegativeVersion(value string) bool {
	if value == "" {
		return false
	}
	for _, part := range strings.Split(value, ".") {
		if !isUnsignedDecimal(part) {
			return false
		}
	}
	return true
}

func isUnsignedDecimal(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	_, err := strconv.ParseUint(value, 10, 64)
	return err == nil
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

	requestCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	response, err := client.RequestWithContext(
		requestCtx, "$JS.API.STREAM.UPDATE.KV_"+configuration.Bucket, body)
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
	requestCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	response, err := client.RequestWithContext(
		requestCtx, "$JS.API.STREAM.INFO.KV_"+configuration.Bucket, nil)
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
	invalid := func() error {
		return errors.New(
			"Authoritative CreateNode journal stores must set allow_batch_publish to false.")
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(response, &root); err != nil {
		return invalid()
	}
	if _, hasError := root["error"]; hasError {
		return invalid()
	}

	config, hasConfig := root["config"]
	if !hasConfig {
		return invalid()
	}

	var configObject map[string]json.RawMessage
	if err := json.Unmarshal(config, &configObject); err != nil || configObject == nil {
		return invalid()
	}

	// nats-server 2.14 omits the false default from STREAM.INFO. An explicit
	// value is still required to be false; omission therefore denotes that
	// documented, fail-closed server default rather than an unknown value.
	modern, hasModern := configObject["allow_batched"]
	legacy, hasLegacy := configObject["allow_batch_publish"]
	if !hasModern && !hasLegacy {
		return nil
	}
	for _, enabled := range []json.RawMessage{modern, legacy} {
		if enabled == nil {
			continue
		}
		var enabledValue *bool
		if err := json.Unmarshal(enabled, &enabledValue); err != nil ||
			enabledValue == nil || *enabledValue {
			return invalid()
		}
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

	closed := configuration.Storage == jetstream.FileStorage && !configuration.Compression &&
		configuration.Placement == nil && configuration.RePublish == nil &&
		configuration.Mirror == nil && len(configuration.Sources) == 0 &&
		configuration.LimitMarkerTTL == 0 && len(configuration.Metadata) == 0
	if (isOperationJournal || isProofConsumption) && configuration.Replicas == 3 && closed {
		return nil
	}

	return &errs.Argument{
		Param: "configuration",
		Message: "The authoritative CreateNode journal store configuration must be exact R3. " +
			"(Parameter 'configuration')",
	}
}
