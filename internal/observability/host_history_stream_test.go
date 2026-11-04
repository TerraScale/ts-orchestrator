package observability

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func hostMetricBroker(t *testing.T, store string, port int) *server.Server {
	t.Helper()
	srv, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: port,
		JetStream: true, StoreDir: store, NoLog: true, NoSigs: true})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("host metric broker did not start")
	}
	t.Cleanup(func() { srv.Shutdown(); srv.WaitForShutdown() })
	return srv
}

func hostMetricTestStream(t *testing.T, srv *server.Server) *HostMetricStream {
	t.Helper()
	conn, err := nats.Connect(srv.ClientURL(), nats.MaxReconnects(-1), nats.ReconnectWait(10*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := OpenHostMetricStream(t.Context(), js, "gru", 1)
	if err != nil {
		t.Fatal(err)
	}
	return stream
}

func hostMetricTestBatch(at time.Time) HostMetricBatch {
	return HostMetricBatch{Version: HostMetricBatchVersion, At: at, Epoch: 1, Samples: []Sample{
		{Metric: HistHostCPUUtilization, Labels: L("member", "host-1"), Value: .25},
	}}
}

func hostMetricWait(t *testing.T, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if ready() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("host metric condition not reached in 10 seconds")
}

func hostMetricTail(t *testing.T, stream *HostMetricStream, history *History) context.CancelFunc {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() { result <- stream.Tail(ctx, history) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-result:
			if !errors.Is(err, context.Canceled) {
				t.Errorf("tail cancellation = %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("tail did not stop on cancellation")
		}
	})
	return cancel
}

func hostMetricCount(history *History) uint32 {
	history.mu.RLock()
	defer history.mu.RUnlock()
	var count uint32
	for _, series := range history.series {
		for _, bucket := range series.tiers[Tier1h].buckets() {
			count += bucket.Count
		}
	}
	return count
}

type hostMetricResetPublishJS struct {
	jetstream.JetStream
	reset func()
}

func (js *hostMetricResetPublishJS) Publish(ctx context.Context, subject string, data []byte, opts ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
	js.reset()
	return js.JetStream.Publish(ctx, subject, data, opts...)
}

func TestHostMetricStreamRejectsInFlightWritesAcrossRecreation(t *testing.T) {
	for _, populated := range []bool{false, true} {
		t.Run(fmt.Sprint(populated), func(t *testing.T) {
			old := hostMetricTestStream(t, hostMetricBroker(t, t.TempDir(), -1))
			at := time.Now().UTC().Truncate(HostMetricInterval).Add(-3 * HostMetricInterval)
			if populated {
				if confirmed, err := old.Publish(t.Context(), hostMetricTestBatch(at)); err != nil || !confirmed {
					t.Fatalf("initial batch: confirmed=%t, error=%v", confirmed, err)
				}
			}
			original := old.js
			var fresh *HostMetricStream
			old.js = &hostMetricResetPublishJS{JetStream: original, reset: func() {
				if err := original.DeleteStream(t.Context(), HostMetricStreamName); err != nil {
					t.Fatal(err)
				}
				var err error
				fresh, err = OpenHostMetricStream(t.Context(), original, "gru", 1)
				if err != nil {
					t.Fatal(err)
				}
				if populated {
					if confirmed, err := fresh.Publish(t.Context(), hostMetricTestBatch(at.Add(HostMetricInterval))); err != nil || !confirmed {
						t.Fatalf("fresh batch: confirmed=%t, error=%v", confirmed, err)
					}
				}
			}}
			gap := hostMetricTestBatch(at.Add(2 * HostMetricInterval))
			gap.Incomplete = true
			if confirmed, err := old.Publish(t.Context(), gap); err == nil || confirmed {
				t.Fatalf("old in-flight write reached new generation: confirmed=%t, error=%v", confirmed, err)
			}
			if old.subject == fresh.subject {
				t.Fatal("recreation reused the old generation subject")
			}
			info, err := fresh.info(t.Context())
			want := uint64(0)
			if populated {
				want = 1
			}
			if err != nil || info.State.Msgs != want {
				t.Fatalf("old gap contaminated fresh archive: %+v, %v", info, err)
			}
		})
	}
}

// Force both writers to finish reading the same last sequence before publishing.
type hostMetricRacingJS struct {
	jetstream.JetStream
	arrivals  atomic.Int32
	conflicts atomic.Int32
	barrier   chan struct{}
}

func (js *hostMetricRacingJS) Publish(ctx context.Context, subject string, data []byte, opts ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
	arrival := js.arrivals.Add(1)
	if arrival == 2 {
		close(js.barrier)
	}
	if arrival <= 2 {
		select {
		case <-js.barrier:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	ack, err := js.JetStream.Publish(ctx, subject, data, opts...)
	var apiErr *jetstream.APIError
	if errors.As(err, &apiErr) && (apiErr.ErrorCode == jetstream.JSErrCodeStreamWrongLastSequence ||
		apiErr.ErrorCode == jetstream.JSErrCodeStreamWrongLastSequenceConstant) {
		js.conflicts.Add(1)
	}
	return ack, err
}

func TestHostMetricStreamTwoWritersCAS(t *testing.T) {
	one := hostMetricTestStream(t, hostMetricBroker(t, t.TempDir(), -1))
	race := &hostMetricRacingJS{JetStream: one.js, barrier: make(chan struct{})}
	two, err := OpenHostMetricStream(t.Context(), race, "gru", 1)
	if err != nil {
		t.Fatal(err)
	}
	one.js = race
	at := time.Now().In(time.FixedZone("local", -3*60*60)).Truncate(time.Minute).Add(39 * time.Second)
	type publishResult struct {
		epoch     uint64
		confirmed bool
		err       error
	}
	results := make(chan publishResult, 2)
	for index, writer := range []*HostMetricStream{one, two} {
		go func() {
			batch := hostMetricTestBatch(at)
			batch.Epoch = uint64(index + 1)
			confirmed, err := writer.Publish(t.Context(), batch)
			results <- publishResult{batch.Epoch, confirmed, err}
		}()
	}
	confirmedEpoch := uint64(0)
	for range 2 {
		result := <-results
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.confirmed {
			if confirmedEpoch != 0 {
				t.Fatal("both different-epoch writers confirmed stored")
			}
			confirmedEpoch = result.epoch
		}
	}
	if confirmedEpoch == 0 {
		t.Fatal("neither writer confirmed stored")
	}
	if race.conflicts.Load() != 1 {
		t.Fatalf("CAS conflicts = %d, want 1", race.conflicts.Load())
	}
	for _, epoch := range []uint64{1, 2} {
		duplicate := hostMetricTestBatch(at)
		duplicate.Epoch = epoch
		if confirmed, err := two.Publish(t.Context(), duplicate); err != nil || confirmed != (epoch == confirmedEpoch) {
			t.Fatalf("duplicate epoch %d confirmed=%t, error=%v; winner epoch=%d", epoch, confirmed, err, confirmedEpoch)
		}
	}
	older := hostMetricTestBatch(at.Add(-time.Minute))
	older.Epoch = confirmedEpoch
	if confirmed, err := two.Publish(t.Context(), older); err != nil || confirmed {
		t.Fatalf("older minute confirmed=%t, error=%v", confirmed, err)
	}
	info, err := one.info(t.Context())
	if err != nil || info.State.Msgs != 1 {
		t.Fatalf("duplicate minute stored: %+v, %v", info, err)
	}
	message, err := one.message(t.Context(), info.State.LastSeq)
	if err != nil {
		t.Fatal(err)
	}
	batch, err := decodeHostMetricBatch(message.Data)
	if err != nil || !batch.At.Equal(at.UTC().Truncate(time.Minute)) || batch.At.Location() != time.UTC || batch.Epoch != confirmedEpoch {
		t.Fatalf("stored time=%v, epoch=%d, error=%v; confirmed epoch=%d", batch.At, batch.Epoch, err, confirmedEpoch)
	}
	if confirmed, err := two.Publish(t.Context(), hostMetricTestBatch(at.Add(time.Minute))); err != nil || !confirmed {
		t.Fatalf("publish confirmed=%t, error=%v", confirmed, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if confirmed, err := one.Publish(ctx, hostMetricTestBatch(at)); !errors.Is(err, context.Canceled) || confirmed {
		t.Fatalf("publish cancellation confirmed=%t, error=%v", confirmed, err)
	}
}

func hostMetricGzip(t *testing.T, raw []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	if _, err := writer.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func TestHostMetricStreamReplayRestartAndResume(t *testing.T) {
	store := t.TempDir()
	srv := hostMetricBroker(t, store, -1)
	port := srv.Addr().(*net.TCPAddr).Port
	stream := hostMetricTestStream(t, srv)
	at := time.Now().UTC().Truncate(time.Minute)
	old := hostMetricTestBatch(at.Add(-3 * 24 * time.Hour))
	if confirmed, err := stream.Publish(t.Context(), old); err != nil || !confirmed {
		t.Fatalf("publish confirmed=%t, error=%v", confirmed, err)
	}
	for _, data := range [][]byte{
		[]byte("broken gzip"),
		hostMetricGzip(t, bytes.Repeat([]byte(" "), hostMetricDecodedBytes+1)),
	} {
		if _, err := stream.js.Publish(t.Context(), stream.subject, data); err != nil {
			t.Fatal(err)
		}
	}
	// Malformed latest data must not allow a writer to bypass the minute guard.
	if confirmed, err := stream.Publish(t.Context(), hostMetricTestBatch(at)); err == nil || confirmed {
		t.Fatal("publication bypassed malformed latest record")
	}
	current, err := encodeHostMetricBatch(hostMetricTestBatch(at))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.js.Publish(t.Context(), stream.subject, current); err != nil {
		t.Fatal(err)
	}
	history := NewHistory(HistoryConfig{Interval: HostMetricInterval})
	hostMetricTail(t, stream, history)
	hostMetricWait(t, func() bool { return stream.CaughtUp() && hostMetricCount(history) == 2 })
	checkOld := func(history *History) {
		t.Helper()
		result := history.Range(HistoryQuery{Metric: HistHostCPUUtilization, Start: old.At.Add(-time.Hour), End: old.At.Add(time.Hour), Tier: Tier1h})
		if len(result.Series) != 1 || len(result.Series[0].Points) != 1 || result.Series[0].Points[0].Value != .25 ||
			!result.Series[0].Points[0].Time.Equal(old.At.Truncate(time.Hour)) {
			t.Fatalf("older hourly replay = %+v", result)
		}
	}
	checkOld(history)
	srv.Shutdown()
	srv.WaitForShutdown()
	hostMetricWait(t, func() bool { return !stream.CaughtUp() })
	srv = hostMetricBroker(t, store, port)
	hostMetricWait(t, func() bool { return stream.js.Conn().IsConnected() && stream.CaughtUp() })
	if count := hostMetricCount(history); count != 2 {
		t.Fatalf("reconnect duplicated rollup count: %d", count)
	}
	// A second independent member rebuilds everything from retained file storage.
	two := hostMetricTestStream(t, srv)
	secondHistory := NewHistory(HistoryConfig{Interval: HostMetricInterval})
	hostMetricTail(t, two, secondHistory)
	hostMetricWait(t, func() bool { return two.CaughtUp() && hostMetricCount(secondHistory) == 2 })
	checkOld(secondHistory)
	if confirmed, err := two.Publish(t.Context(), hostMetricTestBatch(at)); err != nil || !confirmed {
		t.Fatalf("publish confirmed=%t, error=%v", confirmed, err)
	}
	if confirmed, err := two.Publish(t.Context(), hostMetricTestBatch(at.Add(time.Minute))); err != nil || !confirmed {
		t.Fatalf("publish confirmed=%t, error=%v", confirmed, err)
	}
	hostMetricWait(t, func() bool { return hostMetricCount(history) == 3 && hostMetricCount(secondHistory) == 3 })
	info, err := two.info(t.Context())
	if err != nil || info.State.Msgs != 5 {
		t.Fatalf("retained sequence after restart = %+v, %v", info, err)
	}
}
