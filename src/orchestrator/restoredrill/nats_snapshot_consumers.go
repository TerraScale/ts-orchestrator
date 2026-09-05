package restoredrill

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/nats-io/nats.go/jetstream"
	"io"
	"reflect"
	"slices"
	"time"
)

const maximumSnapshotConsumers = 256

// Memory-backed ephemeral watchers are deliberately absent from a NATS file
// snapshot. Record their API identities explicitly; a durable memory consumer
// is an unrestorable checkpoint obligation and must stop the capture.
type natsSnapshotConsumer struct {
	Name          string                    `json:"name"`
	Created       time.Time                 `json:"created"`
	Durable       string                    `json:"durable"`
	MemoryStorage bool                      `json:"memoryStorage"`
	Checkpoint    *SnapshotConsumerEvidence `json:"checkpoint,omitempty"`
}

func (s *NATSJetStreamSnapshotter) consumerInventory(ctx context.Context) ([]natsSnapshotConsumer, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	names := []string{}
	total := -1
	for offset := 0; ; {
		payload, _ := json.Marshal(struct {
			Offset int `json:"offset"`
		}{offset})
		reply, err := s.connection.RequestWithContext(ctx, "$JS.API.CONSUMER.NAMES."+s.stream, payload)
		if err != nil {
			return nil, err
		}
		var response struct {
			Type      string        `json:"type"`
			Error     *natsAPIError `json:"error"`
			Total     *int          `json:"total"`
			Offset    *int          `json:"offset"`
			Consumers []string      `json:"consumers"`
		}
		if snapshotResponseDecode(reply.Data, &response) != nil || response.Error != nil || response.Type != "io.nats.jetstream.api.v1.consumer_names_response" || response.Offset == nil || response.Total == nil || *response.Offset != offset || *response.Total < 0 || *response.Total > maximumSnapshotConsumers || (total != -1 && total != *response.Total) || len(response.Consumers) > *response.Total-offset {
			return nil, fmt.Errorf("%w: consumer names inventory", ErrSnapshotVerification)
		}
		total = *response.Total
		names = append(names, response.Consumers...)
		offset += len(response.Consumers)
		if offset == total {
			break
		}
		if len(response.Consumers) == 0 {
			return nil, fmt.Errorf("%w: incomplete consumer names inventory", ErrSnapshotVerification)
		}
	}
	slices.Sort(names)
	inventory := make([]natsSnapshotConsumer, 0, len(names))
	for i, name := range names {
		if !validNATSStreamName(name) || (i > 0 && name == names[i-1]) {
			return nil, fmt.Errorf("%w: invalid consumer identity", ErrSnapshotVerification)
		}
		reply, err := s.connection.RequestWithContext(ctx, "$JS.API.CONSUMER.INFO."+s.stream+"."+name, nil)
		if err != nil {
			return nil, err
		}
		var response struct {
			Type        string                    `json:"type"`
			Error       *natsAPIError             `json:"error"`
			Stream      string                    `json:"stream_name"`
			Name        string                    `json:"name"`
			Created     time.Time                 `json:"created"`
			Config      *jetstream.ConsumerConfig `json:"config"`
			Delivered   *jetstream.SequenceInfo   `json:"delivered"`
			AckFloor    *jetstream.SequenceInfo   `json:"ack_floor"`
			AckPending  *int                      `json:"num_ack_pending"`
			Pending     *uint64                   `json:"num_pending"`
			Redelivered *int                      `json:"num_redelivered"`
		}
		if snapshotResponseDecode(reply.Data, &response) != nil || response.Error != nil || response.Type != "io.nats.jetstream.api.v1.consumer_info_response" || response.Stream != s.stream || response.Name != name || response.Created.IsZero() || response.Config == nil || response.Config.MemoryStorage && response.Config.Durable != "" {
			return nil, fmt.Errorf("%w: consumer %s has no restorable identity", ErrSnapshotVerification, name)
		}
		item := natsSnapshotConsumer{Name: name, Created: response.Created, Durable: response.Config.Durable, MemoryStorage: response.Config.MemoryStorage}
		if !item.MemoryStorage {
			if response.Delivered == nil || response.AckFloor == nil || response.AckPending == nil || response.Pending == nil || response.Redelivered == nil {
				return nil, fmt.Errorf("%w: source consumer checkpoint missing", ErrSnapshotVerification)
			}
			checkpoint, err := snapshotConsumerEvidence(jetstream.ConsumerInfo{Name: name, Config: *response.Config, Delivered: *response.Delivered, AckFloor: *response.AckFloor, NumAckPending: *response.AckPending, NumPending: *response.Pending, NumRedelivered: *response.Redelivered})
			if err != nil || !validSnapshotCheckpoint(checkpoint, name) {
				return nil, fmt.Errorf("%w: source consumer checkpoint invalid", ErrSnapshotVerification)
			}
			item.Checkpoint = &checkpoint
		}
		inventory = append(inventory, item)
	}
	return inventory, nil
}
func snapshotResponseDecode(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if decoder.Decode(target) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return ErrSnapshotVerification
	}
	return nil
}
func sameSnapshotConsumers(a, b []natsSnapshotConsumer) bool { return reflect.DeepEqual(a, b) }
