package observability

import (
	"bytes"
	"context"
	"encoding/json"
	"strconv"
	"testing"
	"time"
)

func TestHostMetricStreamReplayFailures(t *testing.T) {
	stream := hostMetricTestStream(t, hostMetricBroker(t, t.TempDir(), -1))
	at := time.Now().UTC().Truncate(HostMetricInterval).Add(-10 * time.Minute)
	valid, err := encodeHostMetricBatch(hostMetricTestBatch(at))
	if err != nil {
		t.Fatal(err)
	}
	badValues := hostMetricTestBatch(at)
	badValues.Samples = append(badValues.Samples,
		Sample{Metric: HistHostMemoryRatio, Labels: L("member", "host-1"), Value: 2},
		Sample{Metric: HistHostDiskRatio, Labels: L("member", "host-1"), Value: -1})
	raw, err := json.Marshal(badValues)
	if err != nil {
		t.Fatal(err)
	}
	rejected := [][]byte{
		[]byte("broken gzip"),
		valid[:len(valid)-1], // A valid body with a truncated gzip trailer.
		hostMetricGzip(t, []byte("{")),
		hostMetricGzip(t, []byte(`{"at":123,"epoch":1,"samples":[]}`)),
		hostMetricGzip(t, []byte(`{"at":"`+at.Format(time.RFC3339)+`","epoch":0,"samples":[]}`)),
		hostMetricGzip(t, raw), // Reject the whole batch, including its valid sample.
		hostMetricGzip(t, bytes.Repeat([]byte(" "), hostMetricDecodedBytes+1)),
	}
	for _, data := range append(rejected, valid) {
		if _, err := stream.js.Publish(t.Context(), stream.subject, data); err != nil {
			t.Fatal(err)
		}
	}
	if got := stream.ReplayFailures(); got != 0 {
		t.Fatalf("failures before consumption = %d, want 0", got)
	}

	// A second Tail replays retained data into a new cache without recounting loss.
	for iteration := range 2 {
		t.Run(strconv.Itoa(iteration), func(t *testing.T) {
			history := NewHistory(HistoryConfig{Interval: HostMetricInterval})
			hostMetricTail(t, stream, history)
			hostMetricWait(t, func() bool {
				return stream.CaughtUp() && hostMetricCount(history) == uint32(iteration+1)
			})
			if got := stream.ReplayFailures(); got != uint64(len(rejected)) {
				t.Fatalf("replayed failures = %d, want %d", got, len(rejected))
			}
			batch := hostMetricTestBatch(at.Add(time.Duration(iteration+1) * HostMetricInterval))
			if confirmed, err := stream.Publish(t.Context(), batch); err != nil || !confirmed {
				t.Fatalf("future publish confirmed=%t, error=%v", confirmed, err)
			}
			hostMetricWait(t, func() bool { return hostMetricCount(history) == uint32(iteration+2) })
			if got := stream.ReplayFailures(); got != uint64(len(rejected)) {
				t.Fatalf("valid future batch changed failures to %d", got)
			}
		})
	}
}

func TestHostMetricStreamReplayFailuresConsumerRecreation(t *testing.T) {
	stream := hostMetricTestStream(t, hostMetricBroker(t, t.TempDir(), -1))
	history := NewHistory(HistoryConfig{Interval: HostMetricInterval})
	var next uint64
	at := time.Now().UTC().Truncate(HostMetricInterval)
	valid, err := encodeHostMetricBatch(hostMetricTestBatch(at))
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{[]byte("broken gzip"), valid, []byte("broken gzip")} {
		if _, err := stream.js.Publish(t.Context(), stream.subject, data); err != nil {
			t.Fatal(err)
		}
	}
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
			if got := stream.ReplayFailures(); got != 2 || hostMetricCount(history) != 1 {
				t.Fatalf("consumer %d: failures=%d, samples=%d", iteration, got, hostMetricCount(history))
			}
			if iteration == 1 {
				future, err := encodeHostMetricBatch(hostMetricTestBatch(at.Add(HostMetricInterval)))
				if err != nil {
					t.Fatal(err)
				}
				for _, data := range [][]byte{[]byte("broken gzip"), future} {
					if _, err := stream.js.Publish(t.Context(), stream.subject, data); err != nil {
						t.Fatal(err)
					}
				}
				hostMetricWait(t, func() bool { return hostMetricCount(history) == 2 && stream.ReplayFailures() == 3 })
			}
		})
		if want := uint64(4 + iteration*2); next != want {
			t.Fatalf("consumer %d resume sequence = %d, want %d", iteration, next, want)
		}
		if stream.CaughtUp() {
			t.Fatal("stopped consumer remains caught up")
		}
	}
}
