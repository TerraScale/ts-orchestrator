package observability

import (
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

func TestHostMetricStreamPublishesNearPayloadLimitWithHeaders(t *testing.T) {
	stream := hostMetricTestStream(t, hostMetricBroker(t, t.TempDir(), -1))
	random := rand.New(rand.NewSource(1))
	token := func() string {
		var value [63]byte
		for index := range value {
			value[index] = byte('a' + random.Intn(26))
		}
		return string(value[:])
	}
	batch := HostMetricBatch{Version: HostMetricBatchVersion, At: time.Now().UTC().Truncate(HostMetricInterval), Epoch: 1}
	for range 2000 {
		batch.Samples = append(batch.Samples, Sample{Metric: HistServiceMemoryUsed,
			Labels: L("member", token(), "service", token()), Value: float64(random.Int63n(1 << 44))})
	}
	// Find a fitting prefix, then tune one final sample near the payload boundary.
	low, high := 0, len(batch.Samples)
	for low+1 < high {
		middle := (low + high) / 2
		candidate := batch
		candidate.Samples = batch.Samples[:middle]
		if _, err := encodeHostMetricBatch(candidate); err == nil {
			low = middle
		} else {
			high = middle
		}
	}
	prefix := batch.Samples[:low]
	extra := batch.Samples[low]
	batch.Samples = prefix
	for length := 1; length <= 63; length++ {
		candidate := extra
		candidate.Labels = L("member", extra.Labels[0].Value[:length], "service", extra.Labels[1].Value[:length])
		batch.Samples = append(prefix, candidate)
		if _, err := encodeHostMetricBatch(batch); err != nil {
			batch.Samples = prefix
			if length > 1 {
				candidate.Labels = L("member", extra.Labels[0].Value[:length-1], "service", extra.Labels[1].Value[:length-1])
				batch.Samples = append(prefix, candidate)
			}
			break
		}
	}
	bounded, dropped, err := BoundHostMetricBatch(batch)
	if err != nil || dropped != 0 {
		t.Fatalf("near-limit batch rejected or trimmed: dropped=%d err=%v", dropped, err)
	}
	data, err := encodeHostMetricBatch(bounded)
	// Publish's smallest CAS header already makes this exceed the old message limit.
	headerBytes := len("NATS/1.0\r\n" + jetstream.ExpectedLastSeqHeader + ": 0\r\n\r\n")
	if err != nil || len(data) > HostMetricBatchBytes || len(data)+headerBytes <= HostMetricBatchBytes {
		t.Fatalf("fixture does not exercise header budget: payload=%d header=%d err=%v", len(data), headerBytes, err)
	}
	info, err := stream.info(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	maximumHeaders := len("NATS/1.0\r\n" + jetstream.ExpectedLastSeqHeader + ": " + strings.Repeat("9", 20) + "\r\n\r\n")
	if len(data)+maximumHeaders > int(info.Config.MaxMsgSize) {
		t.Fatal("stream limit cannot fit the payload and a uint64 CAS header")
	}
	if confirmed, err := stream.Publish(t.Context(), bounded); err != nil || !confirmed {
		t.Fatalf("near-limit publication: confirmed=%t err=%v", confirmed, err)
	}
	if confirmed, err := stream.Publish(t.Context(), bounded); err != nil || !confirmed {
		t.Fatalf("near-limit retry: confirmed=%t err=%v", confirmed, err)
	}
	info, err = stream.info(t.Context())
	if err != nil || info.State.Msgs != 1 {
		t.Fatalf("near-limit retry duplicated the batch: %+v err=%v", info, err)
	}
}
