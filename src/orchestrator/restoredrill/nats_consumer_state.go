package restoredrill

import (
	"encoding/binary"
	"math"
)

// NATS v2.14.6 emits consumer state format 2 (server/store.go). Validate it
// before exposing an archive to a broker, whose decoder trusts entry counts.
const maximumConsumerCheckpointBytes = 64 << 20
const maximumConsumerCheckpointEntries = 1 << 20

type consumerStateReader struct {
	raw []byte
	bad bool
}

func (r *consumerStateReader) unsigned() uint64 {
	v, n := binary.Uvarint(r.raw)
	var canonical [binary.MaxVarintLen64]byte
	if n <= 0 || n != binary.PutUvarint(canonical[:], v) {
		r.bad = true
		return 0
	}
	r.raw = r.raw[n:]
	return v
}

func (r *consumerStateReader) signed() int64 {
	v, n := binary.Varint(r.raw)
	var canonical [binary.MaxVarintLen64]byte
	if n <= 0 || n != binary.PutVarint(canonical[:], v) {
		r.bad = true
		return 0
	}
	r.raw = r.raw[n:]
	return v
}

func stateSequence(offset, floor, ceiling uint64) (uint64, bool) {
	if offset == 0 || offset > math.MaxUint64-floor {
		return 0, false
	}
	sequence := floor + offset
	return sequence, sequence > 0 && sequence <= ceiling
}

func validConsumerState(raw []byte, expected *SnapshotConsumerEvidence) bool {
	if expected == nil || len(raw) < 8 || len(raw) > maximumConsumerCheckpointBytes || raw[0] != 22 || raw[1] != 2 {
		return false
	}
	r := consumerStateReader{raw: raw[2:]}
	ackConsumer, ackStream := r.unsigned(), r.unsigned()
	deliveredConsumer, deliveredStream := r.unsigned(), r.unsigned()
	if r.bad || ackConsumer != expected.AckFloorConsumer || ackStream != expected.AckFloorStream || deliveredConsumer != expected.DeliveredConsumer || deliveredStream != expected.DeliveredStream || ackConsumer > deliveredConsumer || ackStream > deliveredStream || deliveredStream > math.MaxInt64 {
		return false
	}
	pending := r.unsigned()
	if r.bad || expected.AckPending < 0 || pending != uint64(expected.AckPending) || pending > maximumConsumerCheckpointEntries || pending > uint64(len(r.raw)/3) {
		return false
	}
	if pending > 0 {
		base := r.signed()
		seen := make(map[uint64]bool, int(pending))
		for range pending {
			stream, streamOK := stateSequence(r.unsigned(), ackStream, deliveredStream)
			_, consumerOK := stateSequence(r.unsigned(), ackConsumer, deliveredConsumer)
			delta := r.signed()
			if r.bad || !streamOK || !consumerOK || seen[stream] || delta > 0 && base < math.MinInt64+delta || delta < 0 && base > math.MaxInt64+delta {
				return false
			}
			seconds := base - delta
			if seconds > math.MaxInt64/1_000_000_000 || seconds < math.MinInt64/1_000_000_000 {
				return false
			}
			seen[stream] = true
		}
	}
	redelivered := r.unsigned()
	if r.bad || expected.Redelivered < 0 || redelivered != uint64(expected.Redelivered) || redelivered > maximumConsumerCheckpointEntries || redelivered > uint64(len(r.raw)/2) {
		return false
	}
	seen := make(map[uint64]bool, int(redelivered))
	for range redelivered {
		stream, valid := stateSequence(r.unsigned(), ackStream, deliveredStream)
		count := r.unsigned()
		if r.bad || !valid || count == 0 || count > deliveredConsumer || seen[stream] {
			return false
		}
		seen[stream] = true
	}
	return !r.bad && len(r.raw) == 0
}
