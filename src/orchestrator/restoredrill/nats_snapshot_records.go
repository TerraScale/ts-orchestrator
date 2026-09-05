package restoredrill

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	jsonv1 "encoding/json"
	"encoding/json/v2"
	"fmt"
	"reflect"

	"github.com/nats-io/nats.go/jetstream"
)

func snapshotRecordDigestValid(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == sha256.Size && hex.EncodeToString(raw) == value
}

// Hash the same SDK record encoding used by restored-content evidence. Sequence
// numbers bind deleted gaps without issuing one request per deleted sequence.
func snapshotRecordsDigest(ctx context.Context, target jetstream.Stream, state jetstream.StreamState, maximum int64) (string, error) {
	if maximum < 1024 || maximum > 1<<30 {
		return "", ErrSnapshotVerification
	}
	records := sha256.New()
	sequence, count := state.FirstSeq, uint64(0)
	remaining := maximum * 8
	for sequence > 0 && sequence <= state.LastSeq && count < state.Msgs {
		message, err := target.GetMsg(ctx, sequence, jetstream.WithGetMsgSubject(">"))
		if err != nil {
			return "", err
		}
		if message.Sequence < sequence || message.Sequence > state.LastSeq || message.Time.IsZero() {
			return "", fmt.Errorf("%w: source/restore record ordering differs", ErrSnapshotVerification)
		}
		// Keep the SDK's existing nil-header representation and deterministic
		// header ordering. Hash only; record contents never enter diagnostics.
		raw, err := json.Marshal(message, jsonv1.DefaultOptionsV1())
		if err != nil || int64(len(raw))+1 > remaining {
			return "", fmt.Errorf("%w: source/restore record evidence exceeds bound", ErrSnapshotVerification)
		}
		remaining -= int64(len(raw)) + 1
		_, _ = records.Write(raw)
		_, _ = records.Write([]byte{'\n'})
		count++
		if message.Sequence == ^uint64(0) {
			sequence = 0
		} else {
			sequence = message.Sequence + 1
		}
	}
	if count != state.Msgs {
		return "", fmt.Errorf("%w: source/restore record count differs", ErrSnapshotVerification)
	}
	return hex.EncodeToString(records.Sum(nil)), nil
}

func (s *NATSJetStreamSnapshotter) sourceRecordsDigest(ctx context.Context, response natsSnapshotResponse) (string, error) {
	js, err := jetstream.New(s.connection)
	if err != nil {
		return "", err
	}
	target, err := js.Stream(ctx, s.stream)
	if err != nil {
		return "", err
	}
	return observeSourceRecords(ctx, target, response, s.maxBytes)
}

func observeSourceRecords(ctx context.Context, target jetstream.Stream, response natsSnapshotResponse, maximum int64) (string, error) {
	before, err := target.Info(ctx)
	if err != nil {
		return "", err
	}
	var expected jetstream.StreamConfig
	if json.Unmarshal(response.Config, &expected, jsonv1.DefaultOptionsV1()) != nil || !sameRestoredConfig(before.Config, expected) || response.State == nil {
		return "", ErrSnapshotVerification
	}
	state := response.State
	matches := func(actual jetstream.StreamState) bool {
		return actual.Msgs == state.Msgs && actual.Bytes == state.Bytes && actual.FirstSeq == state.FirstSeq && actual.LastSeq == state.LastSeq && actual.NumDeleted == state.NumDeleted && actual.Consumers == state.Consumers && actual.FirstTime.Equal(state.FirstTime) && actual.LastTime.Equal(state.LastTime)
	}
	if !matches(before.State) {
		return "", fmt.Errorf("%w: source state differs from snapshot", ErrSnapshotVerification)
	}
	digest, err := snapshotRecordsDigest(ctx, target, before.State, maximum)
	if err != nil {
		return "", err
	}
	after, err := target.Info(ctx)
	if err != nil {
		return "", err
	}
	if !matches(after.State) || !after.Created.Equal(before.Created) || !reflect.DeepEqual(after.Config, before.Config) {
		return "", fmt.Errorf("%w: source changed during record verification", ErrSnapshotVerification)
	}
	return digest, nil
}
