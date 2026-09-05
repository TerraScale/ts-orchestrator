package restoredrill

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// SnapshotRestoreEvidence is observed from an isolated restored broker. It
// proves neither writer fencing nor candidate control-plane authority.
type SnapshotRestoreEvidence struct {
	Stream        string                     `json:"stream"`
	ConfigSHA256  string                     `json:"configSha256"`
	RecordsSHA256 string                     `json:"recordsSha256"`
	Messages      uint64                     `json:"messages"`
	Bytes         uint64                     `json:"bytes"`
	FirstSequence uint64                     `json:"firstSequence"`
	LastSequence  uint64                     `json:"lastSequence"`
	Deleted       int                        `json:"deleted"`
	Consumers     []SnapshotConsumerEvidence `json:"consumers"`
}
type SnapshotConsumerEvidence struct {
	Name              string `json:"name"`
	ConfigSHA256      string `json:"configSha256"`
	DeliveredConsumer uint64 `json:"deliveredConsumer"`
	DeliveredStream   uint64 `json:"deliveredStream"`
	AckFloorConsumer  uint64 `json:"ackFloorConsumer"`
	AckFloorStream    uint64 `json:"ackFloorStream"`
	AckPending        int    `json:"ackPending"`
	Pending           uint64 `json:"pending"`
	Redelivered       int    `json:"redelivered"`
}

// RestorePreliminarySnapshot validates the exact v4 envelope, observes an
// existing stream or restores an absent one, and reads all retained content.
// A caller compares this result to a separate reference restore of the same
// archive before accepting a replay. Conflicting existing streams are never
// replaced. The connection must belong to the caller's isolated private broker.
func RestorePreliminarySnapshot(ctx context.Context, nc *nats.Conn, stream string, envelope []byte, maximum int64) (SnapshotRestoreEvidence, error) {
	if ctx == nil || nc == nil || nc.IsClosed() || maximum < 1024 || maximum > 1<<30 {
		return SnapshotRestoreEvidence{}, ErrSnapshotVerification
	}
	manifest, archive, err := decodeJetStreamSnapshotEnvelope(envelope, stream, maximum)
	if err != nil {
		return SnapshotRestoreEvidence{}, err
	}
	js, err := jetstream.New(nc)
	if err != nil {
		return SnapshotRestoreEvidence{}, err
	}
	target, err := js.Stream(ctx, stream)
	if errors.Is(err, jetstream.ErrStreamNotFound) {
		if err := restoreSnapshotArchive(ctx, nc, manifest, archive); err != nil {
			return SnapshotRestoreEvidence{}, err
		}
		target, err = js.Stream(ctx, stream)
	}
	if err != nil {
		return SnapshotRestoreEvidence{}, err
	}
	return observeRestoredSnapshot(ctx, nc, target, manifest, maximum)
}
func restoreSnapshotArchive(ctx context.Context, nc *nats.Conn, manifest jetStreamSnapshotManifest, archive []byte) error {
	payload, err := json.Marshal(struct {
		Config json.RawMessage    `json:"config"`
		State  *natsSnapshotState `json:"state"`
	}{manifest.Config, manifest.State})
	if err != nil {
		return err
	}
	reply, err := nc.RequestWithContext(ctx, "$JS.API.STREAM.RESTORE."+manifest.Stream, payload)
	if err != nil {
		return err
	}
	var response struct {
		Type    string        `json:"type"`
		Error   *natsAPIError `json:"error"`
		Subject string        `json:"deliver_subject"`
	}
	if snapshotResponseDecode(reply.Data, &response) != nil || response.Error != nil || response.Type != "io.nats.jetstream.api.v1.stream_restore_response" {
		return fmt.Errorf("%w: restore request refused", ErrSnapshotVerification)
	}
	parts := strings.Split(response.Subject, ".")
	if len(parts) != 5 || parts[0] != "$JS" || parts[1] != "SNAPSHOT" || parts[2] != "RESTORE" || parts[3] != manifest.Stream || !snapshotNonce(parts[4]) {
		return fmt.Errorf("%w: restore reply subject differs", ErrSnapshotVerification)
	}
	for offset := 0; offset < len(archive); offset += 128 << 10 {
		end := offset + (128 << 10)
		if end > len(archive) {
			end = len(archive)
		}
		reply, err := nc.RequestWithContext(ctx, response.Subject, archive[offset:end])
		if err != nil {
			return err
		}
		if len(reply.Data) != 0 || len(reply.Header) != 0 {
			return fmt.Errorf("%w: restore chunk refused", ErrSnapshotVerification)
		}
	}
	reply, err = nc.RequestWithContext(ctx, response.Subject, nil)
	if err != nil {
		return err
	}
	var completed struct {
		Type  string        `json:"type"`
		Error *natsAPIError `json:"error"`
	}
	if snapshotResponseDecode(reply.Data, &completed) != nil || completed.Error != nil || completed.Type != "io.nats.jetstream.api.v1.stream_create_response" {
		return fmt.Errorf("%w: restore completion refused", ErrSnapshotVerification)
	}
	return nil
}
func observeRestoredSnapshot(ctx context.Context, nc *nats.Conn, target jetstream.Stream, manifest jetStreamSnapshotManifest, maximum int64) (SnapshotRestoreEvidence, error) {
	fail := func(reason string) (SnapshotRestoreEvidence, error) {
		return SnapshotRestoreEvidence{}, fmt.Errorf("%w: restored %s %s", ErrSnapshotVerification, manifest.Stream, reason)
	}
	before, err := target.Info(ctx)
	if err != nil {
		return SnapshotRestoreEvidence{}, err
	}
	var expected jetstream.StreamConfig
	if json.Unmarshal(manifest.Config, &expected) != nil || !sameRestoredConfig(before.Config, expected) {
		return fail("configuration differs")
	}
	persistent := 0
	for _, consumer := range manifest.Consumers {
		if !consumer.MemoryStorage {
			persistent++
		}
	}
	state := manifest.State
	matchState := func(actual jetstream.StreamState) bool {
		return actual.Msgs == state.Msgs && actual.Bytes == state.Bytes && actual.FirstSeq == state.FirstSeq && actual.LastSeq == state.LastSeq && actual.NumDeleted == state.NumDeleted && actual.Consumers == persistent && actual.FirstTime.Equal(state.FirstTime) && actual.LastTime.Equal(state.LastTime)
	}
	if !matchState(before.State) {
		return fail("allocator, retained state or persistent consumer count differs")
	}
	configBytes, err := json.Marshal(before.Config)
	if err != nil {
		return SnapshotRestoreEvidence{}, err
	}
	configHash := sha256.Sum256(configBytes)
	evidence := SnapshotRestoreEvidence{Stream: manifest.Stream, ConfigSHA256: hex.EncodeToString(configHash[:]), Messages: state.Msgs, Bytes: state.Bytes, FirstSequence: state.FirstSeq, LastSequence: state.LastSeq, Deleted: state.NumDeleted, Consumers: []SnapshotConsumerEvidence{}}
	evidence.RecordsSHA256, err = snapshotRecordsDigest(ctx, target, before.State, maximum)
	if err != nil {
		return SnapshotRestoreEvidence{}, err
	}
	if evidence.RecordsSHA256 != manifest.RecordsSHA256 {
		return fail("records differ from source")
	}
	observed, err := (&NATSJetStreamSnapshotter{connection: nc, stream: manifest.Stream}).consumerInventory(ctx)
	if err != nil {
		return SnapshotRestoreEvidence{}, err
	}
	if len(observed) != persistent {
		return fail("consumer inventory differs")
	}
	expectedConsumers := map[string]natsSnapshotConsumer{}
	for _, consumer := range manifest.Consumers {
		if !consumer.MemoryStorage {
			expectedConsumers[consumer.Name] = consumer
		}
	}
	for _, identity := range observed {
		expected, ok := expectedConsumers[identity.Name]
		if !ok || identity.MemoryStorage || identity.Durable != expected.Durable || !identity.Created.Equal(expected.Created) {
			return fail("consumer identity differs")
		}
		consumer, err := target.Consumer(ctx, identity.Name)
		if err != nil {
			return SnapshotRestoreEvidence{}, err
		}
		info, err := consumer.Info(ctx)
		if err != nil {
			return SnapshotRestoreEvidence{}, err
		}
		checkpoint, err := snapshotConsumerEvidence(*info)
		if err != nil {
			return SnapshotRestoreEvidence{}, err
		}
		if expected.Checkpoint == nil || checkpoint != *expected.Checkpoint {
			return fail("consumer checkpoint differs from source")
		}
		evidence.Consumers = append(evidence.Consumers, checkpoint)
	}
	after, err := target.Info(ctx)
	if err != nil {
		return SnapshotRestoreEvidence{}, err
	}
	if !matchState(after.State) || !reflect.DeepEqual(before.Config, after.Config) {
		return fail("state changed during verification")
	}
	return evidence, nil
}

// SnapshotEnvelopeRequest reads only a fully validated envelope. Candidate
// staging uses it to bind downloaded bytes to the historical source request.
func SnapshotEnvelopeRequest(envelope []byte, stream string, maximum int64) (SnapshotRequest, time.Time, error) {
	manifest, _, err := decodeJetStreamSnapshotEnvelope(envelope, stream, maximum)
	if err != nil {
		return SnapshotRequest{}, time.Time{}, err
	}
	return manifest.Request, manifest.CreatedAt, nil
}

func SameSnapshotRestoreEvidence(a, b SnapshotRestoreEvidence) bool {
	left, err := json.Marshal(a)
	if err != nil {
		return false
	}
	right, err := json.Marshal(b)
	return err == nil && bytes.Equal(left, right)
}

// NATS injects these two read-only version observations into API responses;
// snapshot config contains only the stored metadata. All stored keys remain bound.
func sameRestoredConfig(a, b jetstream.StreamConfig) bool {
	normalize := func(c jetstream.StreamConfig) jetstream.StreamConfig {
		metadata := make(map[string]string, len(c.Metadata))
		for k, v := range c.Metadata {
			if k != "_nats.level" && k != "_nats.ver" {
				metadata[k] = v
			}
		}
		if len(metadata) == 0 {
			metadata = nil
		}
		c.Metadata = metadata
		return c
	}
	return reflect.DeepEqual(normalize(a), normalize(b))
}
