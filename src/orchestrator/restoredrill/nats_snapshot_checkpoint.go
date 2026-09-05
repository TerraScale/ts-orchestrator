package restoredrill

import (
	"crypto/sha256"
	"encoding/hex"
	jsonv1 "encoding/json"
	"encoding/json/v2"

	"github.com/nats-io/nats.go/jetstream"
)

// Snapshot checkpoints omit transient request counts and observation timestamps.
// Capture requires stable source checkpoints; restoration must preserve them.
func snapshotConsumerEvidence(info jetstream.ConsumerInfo) (SnapshotConsumerEvidence, error) {
	// The NATS SDK wire type uses v1 duration and omission semantics. Preserve
	// that encoding, including deterministic metadata-map order, in its digest.
	raw, err := json.Marshal(info.Config, jsonv1.DefaultOptionsV1())
	if err != nil {
		return SnapshotConsumerEvidence{}, err
	}
	sum := sha256.Sum256(raw)
	return SnapshotConsumerEvidence{Name: info.Name, ConfigSHA256: hex.EncodeToString(sum[:]), DeliveredConsumer: info.Delivered.Consumer, DeliveredStream: info.Delivered.Stream, AckFloorConsumer: info.AckFloor.Consumer, AckFloorStream: info.AckFloor.Stream, AckPending: info.NumAckPending, Pending: info.NumPending, Redelivered: info.NumRedelivered}, nil
}

func validSnapshotCheckpoint(c SnapshotConsumerEvidence, name string) bool {
	digest, err := hex.DecodeString(c.ConfigSHA256)
	return c.Name == name && err == nil && len(digest) == sha256.Size && hex.EncodeToString(digest) == c.ConfigSHA256 && c.AckPending >= 0 && c.Redelivered >= 0 && c.AckFloorConsumer <= c.DeliveredConsumer && c.AckFloorStream <= c.DeliveredStream
}
