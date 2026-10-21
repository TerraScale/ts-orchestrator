package observability

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math/rand"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestHostMetricArchiveBoundLoss(t *testing.T) {
	for _, limit := range []string{"samples", "compressed bytes", "decoded bytes"} {
		t.Run(limit, func(t *testing.T) {
			batch := hostMetricTestBatch(time.Now().UTC().Truncate(HostMetricInterval))
			batch.Samples = nil
			count := DefaultHistorySeries
			if limit == "samples" {
				count++
			} else if limit == "compressed bytes" {
				count = 2000
			}
			random := rand.New(rand.NewSource(1))
			token := func() string {
				var token [63]byte
				for index := range token {
					token[index] = byte('a' + random.Intn(26))
				}
				return string(token[:])
			}
			for index := range count {
				member := "host-" + strconv.Itoa(index)
				sample := Sample{Metric: HistHostCPUUtilization, Labels: L("member", member), Value: .5}
				if limit == "compressed bytes" {
					sample = Sample{Metric: HistServiceMemoryUsed, Labels: L("member", token(), "service", token()),
						Value: float64(random.Int63n(1 << 44))}
				} else if limit == "decoded bytes" {
					member += strings.Repeat("a", 63-len(member))
					sample = Sample{Metric: HistServiceMemoryUsed,
						Labels: L("member", member, "service", strings.Repeat("a", 63)), Value: 1 << 44}
				}
				batch.Samples = append(batch.Samples, sample)
			}
			raw, err := json.Marshal(batch)
			if err != nil {
				t.Fatal(err)
			}
			if limit == "compressed bytes" && (len(raw) > hostMetricDecodedBytes || len(hostMetricGzip(t, raw)) <= HostMetricBatchBytes) {
				t.Fatal("fixture does not overflow only the compressed byte bound")
			}
			if limit == "decoded bytes" && (len(raw) <= hostMetricDecodedBytes || len(hostMetricGzip(t, raw)) > HostMetricBatchBytes) {
				t.Fatal("fixture does not overflow only the decoded byte bound")
			}
			for _, marked := range []bool{false, true} {
				batch.Incomplete = marked
				bounded, dropped, err := BoundHostMetricBatch(batch)
				if err != nil {
					t.Fatal(err)
				}
				kept := len(bounded.Samples)
				if !bounded.Incomplete || kept == 0 || kept >= count || dropped != uint64(count-kept) {
					t.Fatalf("marked=%t: kept=%d of %d, incomplete=%t, dropped=%d", marked, kept, count, bounded.Incomplete, dropped)
				}
				expected := batch
				expected.Samples = batch.Samples[:kept]
				expected.Incomplete = true
				if !reflect.DeepEqual(bounded, expected) {
					t.Fatal("bounding changed the retained prefix or metadata")
				}
				data, err := encodeHostMetricBatch(bounded)
				if err != nil {
					t.Fatal(err)
				}
				raw, err := json.Marshal(bounded)
				if err != nil || !bytes.Contains(raw, []byte(`"incomplete":true`)) || len(raw) > hostMetricDecodedBytes || len(data) > HostMetricBatchBytes {
					t.Fatalf("marked payload bounds: decoded=%d compressed=%d error=%v", len(raw), len(data), err)
				}
				restored, err := decodeHostMetricBatch(data)
				if err != nil || !reflect.DeepEqual(restored, bounded) {
					t.Fatalf("marker compressed roundtrip: %v", err)
				}
				rebounded, newDropped, err := BoundHostMetricBatch(restored)
				if err != nil || newDropped != 0 || !reflect.DeepEqual(rebounded, bounded) {
					t.Fatalf("bounding again changed the marker or counted prior loss: dropped=%d error=%v", newDropped, err)
				}
			}
		})
	}
	for _, marked := range []bool{false, true} {
		batch := hostMetricTestBatch(time.Now().UTC().Truncate(HostMetricInterval))
		batch.Incomplete = marked
		bounded, dropped, err := BoundHostMetricBatch(batch)
		if err != nil || dropped != 0 || !reflect.DeepEqual(bounded, batch) {
			t.Fatalf("fitting marked=%t batch changed: dropped=%d error=%v", marked, dropped, err)
		}
	}
}

func TestHostMetricArchiveIncompleteReplay(t *testing.T) {
	srv := hostMetricBroker(t, t.TempDir(), -1)
	writer := hostMetricTestStream(t, srv)
	at := time.Now().UTC().Truncate(HostMetricInterval).Add(-2 * HostMetricInterval)
	marked := hostMetricTestBatch(at)
	marked.Incomplete = true
	for _, batch := range []HostMetricBatch{marked, hostMetricTestBatch(at.Add(HostMetricInterval))} {
		if confirmed, err := writer.Publish(t.Context(), batch); err != nil || !confirmed {
			t.Fatalf("publish confirmed=%t, error=%v", confirmed, err)
		}
	}
	if writer.ArchiveIncomplete() {
		t.Fatal("publishing changed replay evidence before consumption")
	}
	for reader := range 2 {
		t.Run(strconv.Itoa(reader), func(t *testing.T) {
			stream := hostMetricTestStream(t, srv)
			if stream.ArchiveIncomplete() {
				t.Fatal("new handle has loss evidence before replay")
			}
			history := NewHistory(HistoryConfig{Interval: HostMetricInterval})
			hostMetricTail(t, stream, history)
			hostMetricWait(t, stream.CaughtUp)
			if !stream.ArchiveIncomplete() || hostMetricCount(history) != uint32(2+reader) || stream.ReplayFailures() != 0 {
				t.Fatalf("reader %d: incomplete=%t samples=%d rejected=%d", reader,
					stream.ArchiveIncomplete(), hostMetricCount(history), stream.ReplayFailures())
			}
			complete := hostMetricTestBatch(at.Add(time.Duration(2+reader) * HostMetricInterval))
			if confirmed, err := writer.Publish(t.Context(), complete); err != nil || !confirmed {
				t.Fatalf("complete publish confirmed=%t, error=%v", confirmed, err)
			}
			hostMetricWait(t, func() bool { return hostMetricCount(history) == uint32(3+reader) })
			if !stream.ArchiveIncomplete() {
				t.Fatal("later complete batch cleared archive loss")
			}
		})
	}
}

func TestHostMetricArchiveMarkerDecodedBound(t *testing.T) {
	batch := hostMetricTestBatch(time.Now().UTC().Truncate(HostMetricInterval))
	batch.Incomplete = true
	batch.Samples = nil
	for index := range DefaultHistorySeries {
		member := "host-" + strconv.Itoa(index)
		member += strings.Repeat("a", 63-len(member))
		batch.Samples = append(batch.Samples, Sample{Metric: HistServiceMemoryUsed,
			Labels: L("member", member, "service", strings.Repeat("a", 63)), Value: 1 << 44})
	}
	raw, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	// Tune valid service labels so the marker alone takes the body over the bound.
	excess := len(raw) - hostMetricDecodedBytes - 1
	if excess <= 0 {
		t.Fatal("fixture is too small to tune to the decoded bound")
	}
	for index := range batch.Samples {
		label := &batch.Samples[index].Labels[1]
		trim := min(excess, len(label.Value)-1)
		label.Value = label.Value[:len(label.Value)-trim]
		excess -= trim
		if excess == 0 {
			break
		}
	}
	raw, err = json.Marshal(batch)
	withoutMarker := bytes.Replace(raw, []byte(`,"incomplete":true`), nil, 1)
	if err != nil || len(raw) != hostMetricDecodedBytes+1 || len(withoutMarker) > hostMetricDecodedBytes || len(hostMetricGzip(t, raw)) > HostMetricBatchBytes {
		t.Fatalf("decoded boundary fixture: marked=%d without marker=%d excess=%d error=%v", len(raw), len(withoutMarker), excess, err)
	}
	hostMetricRejectArchive(t, batch)
	batch.Samples = append(batch.Samples, Sample{Metric: HistHostCPUUtilization, Labels: L("member", "extra-host"), Value: .5})
	bounded, dropped, err := BoundHostMetricBatch(batch)
	if err != nil || !bounded.Incomplete || len(bounded.Samples) != DefaultHistorySeries/2 || dropped != DefaultHistorySeries/2+1 {
		t.Fatalf("sample cap omitted marker byte cost: kept=%d dropped=%d incomplete=%t error=%v", len(bounded.Samples), dropped, bounded.Incomplete, err)
	}
	hostMetricAcceptArchive(t, bounded)
}

func TestHostMetricArchivePublishEvidence(t *testing.T) {
	for _, retainedMarker := range []bool{false, true} {
		t.Run(strconv.FormatBool(retainedMarker), func(t *testing.T) {
			srv := hostMetricBroker(t, t.TempDir(), -1)
			writer := hostMetricTestStream(t, srv)
			lostAck := &hostMetricLostAckJS{JetStream: writer.js}
			writer.js = lostAck
			batch := hostMetricTestBatch(time.Now().UTC().Truncate(HostMetricInterval))
			batch.Incomplete = retainedMarker
			if confirmed, err := writer.Publish(t.Context(), batch); confirmed || !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("lost acknowledgment confirmed=%t, error=%v", confirmed, err)
			}
			if confirmed, err := writer.Publish(t.Context(), batch); err != nil || !confirmed {
				t.Fatalf("identical retry confirmed=%t, error=%v", confirmed, err)
			}
			competitor := hostMetricTestStream(t, srv)
			other := batch
			other.Incomplete = !retainedMarker
			if confirmed, err := competitor.Publish(t.Context(), other); err != nil || confirmed {
				t.Fatalf("different marker writer confirmed=%t, error=%v", confirmed, err)
			}
			if writer.ArchiveIncomplete() || competitor.ArchiveIncomplete() {
				t.Fatal("publish attempt contaminated replay evidence")
			}
			info, err := writer.info(t.Context())
			if err != nil || info.State.Msgs != 1 || lostAck.calls.Load() != 1 {
				t.Fatalf("retry duplicated retained evidence: info=%+v calls=%d error=%v", info, lostAck.calls.Load(), err)
			}
			history := NewHistory(HistoryConfig{Interval: HostMetricInterval})
			hostMetricTail(t, competitor, history)
			hostMetricWait(t, competitor.CaughtUp)
			if competitor.ArchiveIncomplete() != retainedMarker || hostMetricCount(history) != 1 {
				t.Fatalf("replayed incomplete=%t samples=%d, want retained marker=%t", competitor.ArchiveIncomplete(), hostMetricCount(history), retainedMarker)
			}
		})
	}
}

func TestHostMetricArchiveConsumerRecreation(t *testing.T) {
	srv := hostMetricBroker(t, t.TempDir(), -1)
	stream := hostMetricTestStream(t, srv)
	at := time.Now().UTC().Truncate(HostMetricInterval).Add(-2 * HostMetricInterval)
	marked := hostMetricTestBatch(at)
	marked.Incomplete = true
	for _, batch := range []HostMetricBatch{marked, hostMetricTestBatch(at.Add(HostMetricInterval))} {
		if confirmed, err := stream.Publish(t.Context(), batch); err != nil || !confirmed {
			t.Fatalf("publish confirmed=%t, error=%v", confirmed, err)
		}
	}
	history := NewHistory(HistoryConfig{Interval: HostMetricInterval})
	var next uint64
	for iteration := range 2 {
		t.Run(strconv.Itoa(iteration), func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			result := make(chan error, 1)
			go func() { result <- stream.tailHostMetricsOnce(ctx, history, &next) }()
			t.Cleanup(func() {
				cancel()
				select {
				case err := <-result:
					if err == nil {
						t.Error("tail returned without cancellation error")
					}
				case <-time.After(3 * time.Second):
					t.Error("consumer did not stop")
				}
			})
			hostMetricWait(t, stream.CaughtUp)
			if !stream.ArchiveIncomplete() || hostMetricCount(history) != 2 || stream.ReplayFailures() != 0 {
				t.Fatalf("consumer %d: incomplete=%t samples=%d rejected=%d", iteration,
					stream.ArchiveIncomplete(), hostMetricCount(history), stream.ReplayFailures())
			}
			if iteration == 1 {
				if confirmed, err := stream.Publish(t.Context(), hostMetricTestBatch(at.Add(2*HostMetricInterval))); err != nil || !confirmed {
					t.Fatalf("complete publish confirmed=%t, error=%v", confirmed, err)
				}
				hostMetricWait(t, func() bool { return hostMetricCount(history) == 3 })
				if !stream.ArchiveIncomplete() {
					t.Fatal("recreated consumer cleared sticky loss")
				}
			}
		})
		if next != uint64(3+iteration) || stream.CaughtUp() || !stream.ArchiveIncomplete() {
			t.Fatalf("stopped consumer %d: next=%d ready=%t incomplete=%t", iteration, next, stream.CaughtUp(), stream.ArchiveIncomplete())
		}
		if iteration == 0 {
			if err := stream.stream.DeleteMsg(t.Context(), 1); err != nil {
				t.Fatal(err)
			}
		}
	}
	fresh := hostMetricTestStream(t, srv)
	freshHistory := NewHistory(HistoryConfig{Interval: HostMetricInterval})
	hostMetricTail(t, fresh, freshHistory)
	hostMetricWait(t, fresh.CaughtUp)
	if fresh.ArchiveIncomplete() || hostMetricCount(freshHistory) != 2 || !stream.ArchiveIncomplete() {
		t.Fatalf("rebuilt handle after marked record removal: fresh=%t old=%t samples=%d",
			fresh.ArchiveIncomplete(), stream.ArchiveIncomplete(), hostMetricCount(freshHistory))
	}
}

func TestHostMetricArchiveInvalidMarkedBatch(t *testing.T) {
	stream := hostMetricTestStream(t, hostMetricBroker(t, t.TempDir(), -1))
	at := time.Now().UTC().Truncate(HostMetricInterval)
	invalid := hostMetricTestBatch(at)
	invalid.Incomplete = true
	invalid.Samples[0].Value = 2
	raw, err := json.Marshal(invalid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.js.Publish(t.Context(), stream.subject, hostMetricGzip(t, raw)); err != nil {
		t.Fatal(err)
	}
	if confirmed, err := stream.Publish(t.Context(), invalid); err == nil || confirmed {
		t.Fatal("marked batch bypassed gauge validation")
	}
	valid, err := encodeHostMetricBatch(hostMetricTestBatch(at.Add(HostMetricInterval)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.js.Publish(t.Context(), stream.subject, valid); err != nil {
		t.Fatal(err)
	}
	history := NewHistory(HistoryConfig{Interval: HostMetricInterval})
	hostMetricTail(t, stream, history)
	hostMetricWait(t, stream.CaughtUp)
	if stream.ArchiveIncomplete() || stream.ReplayFailures() != 1 || hostMetricCount(history) != 1 {
		t.Fatalf("invalid marker accepted: incomplete=%t rejected=%d samples=%d",
			stream.ArchiveIncomplete(), stream.ReplayFailures(), hostMetricCount(history))
	}
}
