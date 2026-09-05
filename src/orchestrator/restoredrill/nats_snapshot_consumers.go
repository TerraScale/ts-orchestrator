package restoredrill

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"sort"
	"time"
)

const maximumSnapshotConsumers = 256

// Memory-backed ephemeral watchers are deliberately absent from a NATS file
// snapshot. Record their API identities explicitly; a durable memory consumer
// is an unrestorable checkpoint obligation and must stop the capture.
type natsSnapshotConsumer struct {
	Name          string    `json:"name"`
	Created       time.Time `json:"created"`
	Durable       string    `json:"durable"`
	MemoryStorage bool      `json:"memoryStorage"`
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
	sort.Strings(names)
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
			Type    string        `json:"type"`
			Error   *natsAPIError `json:"error"`
			Stream  string        `json:"stream_name"`
			Name    string        `json:"name"`
			Created time.Time     `json:"created"`
			Config  *struct {
				Durable       string `json:"durable_name"`
				MemoryStorage bool   `json:"mem_storage"`
			} `json:"config"`
		}
		if snapshotResponseDecode(reply.Data, &response) != nil || response.Error != nil || response.Type != "io.nats.jetstream.api.v1.consumer_info_response" || response.Stream != s.stream || response.Name != name || response.Created.IsZero() || response.Config == nil || response.Config.MemoryStorage && response.Config.Durable != "" {
			return nil, fmt.Errorf("%w: consumer %s has no restorable identity", ErrSnapshotVerification, name)
		}
		inventory = append(inventory, natsSnapshotConsumer{Name: name, Created: response.Created, Durable: response.Config.Durable, MemoryStorage: response.Config.MemoryStorage})
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
