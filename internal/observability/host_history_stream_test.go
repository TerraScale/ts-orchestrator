package observability

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"math"
	"math/rand"
	"net"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
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
	return HostMetricBatch{At: at, Epoch: 1, Samples: []Sample{
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

func TestHostMetricStreamConfigAndQuota(t *testing.T) {
	stream := hostMetricTestStream(t, hostMetricBroker(t, t.TempDir(), -1))
	info, err := stream.info(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	subject, err := protocol.ObservabilitySubject("gru", "host-metrics")
	if err != nil {
		t.Fatal(err)
	}
	config := info.Config
	if config.Name != HostMetricStreamName || config.Storage != jetstream.FileStorage || config.Replicas != 1 ||
		config.Retention != jetstream.LimitsPolicy || config.Discard != jetstream.DiscardNew ||
		config.MaxAge != HistoryRetention || config.MaxBytes != HostMetricStreamBytes || config.MaxMsgs != -1 ||
		config.MaxMsgSize != HostMetricBatchBytes+hostMetricHeaderBytes || !reflect.DeepEqual(config.Subjects, []string{subject}) {
		t.Fatalf("stream config = %+v", config)
	}
	if required := int64(HistoryRetention/HostMetricInterval+1) * (HostMetricBatchBytes + hostMetricHeaderBytes + 4096); required > config.MaxBytes {
		t.Fatalf("quota %d cannot hold full retention plus headers: %d", config.MaxBytes, required)
	}
	if stream.CaughtUp() {
		t.Fatal("new stream is caught up before consumer installation")
	}
	for _, replicas := range []int{0, 6} {
		if _, err := OpenHostMetricStream(t.Context(), stream.js, "gru", replicas); err == nil {
			t.Fatalf("accepted replicas %d", replicas)
		}
	}
	if _, err := OpenHostMetricStream(t.Context(), nil, "gru", 1); err == nil {
		t.Fatal("accepted nil JetStream")
	}
	if _, err := OpenHostMetricStream(t.Context(), stream.js, "bad.cell", 1); err == nil {
		t.Fatal("accepted invalid cell")
	}
	if _, err := stream.js.Publish(t.Context(), stream.subject, make([]byte, HostMetricBatchBytes+hostMetricHeaderBytes+1)); err == nil {
		t.Fatal("broker accepted oversized payload")
	}
	// A smaller quota exercises DiscardNew without filling 1.5 GiB in a test.
	config.MaxBytes = 1024
	if _, err := stream.js.UpdateStream(t.Context(), config); err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Truncate(HostMetricInterval)
	if confirmed, err := stream.Publish(t.Context(), hostMetricTestBatch(at)); err != nil || !confirmed {
		t.Fatalf("publish confirmed=%t, error=%v", confirmed, err)
	}
	first, err := stream.message(t.Context(), 1)
	if err != nil {
		t.Fatal(err)
	}
	refused := false
	for index := 1; index < 20; index++ {
		if confirmed, err := stream.Publish(t.Context(), hostMetricTestBatch(at.Add(time.Duration(index)*HostMetricInterval))); err != nil {
			if confirmed {
				t.Fatal("rejected quota write confirmed stored")
			}
			refused = true
			break
		}
	}
	if !refused {
		t.Fatal("full stream did not refuse writes")
	}
	retained, err := stream.message(t.Context(), 1)
	if err != nil || !bytes.Equal(first.Data, retained.Data) {
		t.Fatalf("full stream erased oldest batch: %v", err)
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

type hostMetricLostAckJS struct {
	jetstream.JetStream
	lostAck atomic.Bool
	calls   atomic.Int32
}

func (js *hostMetricLostAckJS) Publish(ctx context.Context, subject string, data []byte, opts ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
	js.calls.Add(1)
	ack, err := js.JetStream.Publish(ctx, subject, data, opts...)
	if err == nil && js.lostAck.CompareAndSwap(false, true) {
		return nil, context.DeadlineExceeded // The broker stored the batch before its acknowledgment was lost.
	}
	return ack, err
}

func TestHostMetricStreamPublishLostAck(t *testing.T) {
	srv := hostMetricBroker(t, t.TempDir(), -1)
	stream := hostMetricTestStream(t, srv)
	lostAck := &hostMetricLostAckJS{JetStream: stream.js}
	stream.js = lostAck
	at := time.Now().UTC().Truncate(time.Minute)
	batch := hostMetricTestBatch(at.Add(39 * time.Second).In(time.FixedZone("local", -3*60*60)))
	if confirmed, err := stream.Publish(t.Context(), batch); confirmed || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lost acknowledgment confirmed=%t, error=%v", confirmed, err)
	}
	batch.At = at
	if confirmed, err := stream.Publish(t.Context(), batch); err != nil || !confirmed {
		t.Fatalf("lost acknowledgment retry confirmed=%t, error=%v", confirmed, err)
	}
	info, err := stream.info(t.Context())
	if err != nil || info.State.Msgs != 1 || lostAck.calls.Load() != 1 {
		t.Fatalf("lost acknowledgment retry retained=%+v, publish calls=%d, error=%v", info, lostAck.calls.Load(), err)
	}
	other := hostMetricTestStream(t, srv)
	for _, change := range []string{"epoch", "body", "epoch and body"} {
		different := hostMetricTestBatch(at)
		if change != "body" {
			different.Epoch++
		}
		if change != "epoch" {
			different.Samples[0].Value = .5
		}
		if confirmed, err := other.Publish(t.Context(), different); err != nil || confirmed {
			t.Fatalf("other writer with different %s confirmed=%t, error=%v", change, confirmed, err)
		}
	}
	info, err = stream.info(t.Context())
	if err != nil || info.State.Msgs != 1 {
		t.Fatalf("other writer duplicated minute: %+v, %v", info, err)
	}
	next := hostMetricTestBatch(at.Add(time.Minute))
	if confirmed, err := stream.Publish(t.Context(), next); err != nil || !confirmed {
		t.Fatalf("next minute confirmed=%t, error=%v", confirmed, err)
	}
	if confirmed, err := stream.Publish(t.Context(), batch); err != nil || confirmed {
		t.Fatalf("retry after later minute confirmed=%t, error=%v", confirmed, err)
	}
	info, err = stream.info(t.Context())
	if err != nil || info.State.Msgs != 2 || lostAck.calls.Load() != 2 {
		t.Fatalf("next minute retained=%+v, publish calls=%d, error=%v", info, lostAck.calls.Load(), err)
	}
}

type hostMetricContendedJS struct {
	jetstream.JetStream
	attempts int
	code     jetstream.ErrorCode
}

func (js *hostMetricContendedJS) Publish(ctx context.Context, _ string, _ []byte, _ ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
	js.attempts++
	return nil, &jetstream.APIError{Code: 400, ErrorCode: js.code}
}

func TestHostMetricStreamPublishRetryBound(t *testing.T) {
	stream := hostMetricTestStream(t, hostMetricBroker(t, t.TempDir(), -1))
	for _, code := range []jetstream.ErrorCode{jetstream.JSErrCodeStreamWrongLastSequence, jetstream.JSErrCodeStreamWrongLastSequenceConstant} {
		contended := &hostMetricContendedJS{JetStream: stream.js, code: code}
		writer := &HostMetricStream{stream: stream.stream, js: contended, subject: stream.subject}
		if confirmed, err := writer.Publish(t.Context(), hostMetricTestBatch(time.Now())); err == nil || confirmed {
			t.Fatal("unbounded contention was accepted")
		}
		if contended.attempts != hostMetricPublishAttempts {
			t.Fatalf("CAS attempts = %d", contended.attempts)
		}
	}
}

func TestHostMetricBatchValidation(t *testing.T) {
	at := time.Now().UTC().Truncate(time.Minute)
	for _, value := range []float64{0, 1} {
		batch := HostMetricBatch{At: at, Epoch: 1, Samples: []Sample{
			{Metric: HistHostCPUUtilization, Labels: L("member", "host-1"), Value: value},
			{Metric: HistHostMemoryRatio, Labels: L("member", "host-1"), Value: value},
			{Metric: HistHostDiskRatio, Labels: L("member", "host-1"), Value: value},
			{Metric: HistServiceCPUCores, Labels: L("service", "terra-base", "member", "host-1"), Value: value * 1024},
			{Metric: HistServiceMemoryUsed, Labels: L("member", "host-1", "service", "terra-base"), Value: value * (1 << 44)},
		}}
		data, err := encodeHostMetricBatch(batch)
		if err != nil {
			t.Fatal(err)
		}
		restored, err := decodeHostMetricBatch(data)
		if err != nil || !reflect.DeepEqual(batch, restored) {
			t.Fatalf("valid batch roundtrip = %+v, %v", restored, err)
		}
	}
	cases := map[string]func(*HostMetricBatch){
		"zero time":    func(b *HostMetricBatch) { b.At = time.Time{} },
		"unaligned":    func(b *HostMetricBatch) { b.At = b.At.Add(time.Second) },
		"non UTC":      func(b *HostMetricBatch) { b.At = b.At.In(time.FixedZone("local", 3600)) },
		"zero epoch":   func(b *HostMetricBatch) { b.Epoch = 0 },
		"wrong metric": func(b *HostMetricBatch) { b.Samples[0].Metric = HistAuthorityEpoch },
		"counter":      func(b *HostMetricBatch) { b.Samples[0].Counter = true },
		"negative":     func(b *HostMetricBatch) { b.Samples[0].Value = -.01 },
		"ratio high":   func(b *HostMetricBatch) { b.Samples[0].Value = 1.01 },
		"NaN":          func(b *HostMetricBatch) { b.Samples[0].Value = math.NaN() },
		"infinite":     func(b *HostMetricBatch) { b.Samples[0].Value = math.Inf(1) },
		"cores high": func(b *HostMetricBatch) {
			b.Samples[0] = Sample{Metric: HistServiceCPUCores, Labels: L("member", "host-1", "service", "terra-base"), Value: 1025}
		},
		"memory high": func(b *HostMetricBatch) {
			b.Samples[0] = Sample{Metric: HistServiceMemoryUsed, Labels: L("member", "host-1", "service", "terra-base"), Value: (1 << 44) + 1}
		},
		"uppercase member": func(b *HostMetricBatch) { b.Samples[0].Labels[0].Value = "HOST-1" },
		"long member":      func(b *HostMetricBatch) { b.Samples[0].Labels[0].Value = strings.Repeat("a", 64) },
		"invalid token":    func(b *HostMetricBatch) { b.Samples[0].Labels[0].Value = "host.*" },
		"missing member":   func(b *HostMetricBatch) { b.Samples[0].Labels = nil },
		"empty member":     func(b *HostMetricBatch) { b.Samples[0].Labels[0].Value = "" },
		"extra host label": func(b *HostMetricBatch) { b.Samples[0].Labels = L("member", "host-1", "service", "terra-base") },
		"duplicate label":  func(b *HostMetricBatch) { b.Samples[0].Labels = L("member", "host-1", "member", "host-1") },
		"missing service":  func(b *HostMetricBatch) { b.Samples[0].Metric = HistServiceCPUCores },
		"invalid service": func(b *HostMetricBatch) {
			b.Samples[0] = Sample{Metric: HistServiceCPUCores, Labels: L("member", "host-1", "service", "bad.service")}
		},
		"long service": func(b *HostMetricBatch) {
			b.Samples[0] = Sample{Metric: HistServiceCPUCores, Labels: L("member", "host-1", "service", strings.Repeat("a", 64))}
		},
		"duplicate series": func(b *HostMetricBatch) {
			b.Samples = []Sample{
				{Metric: HistServiceCPUCores, Labels: L("member", "host-1", "service", "terra-base")},
				{Metric: HistServiceCPUCores, Labels: L("service", "terra-base", "member", "host-1")},
			}
		},
		"too many samples": func(b *HostMetricBatch) { b.Samples = make([]Sample, DefaultHistorySeries+1) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			batch := hostMetricTestBatch(at)
			mutate(&batch)
			if _, err := encodeHostMetricBatch(batch); err == nil {
				t.Fatal("invalid batch accepted for publication")
			}
			if _, _, err := BoundHostMetricBatch(batch); err == nil || errors.Is(err, errHostMetricBatchSize) {
				t.Fatalf("bounding hid validation error: %v", err)
			}
			if raw, err := json.Marshal(batch); err == nil {
				if _, err := decodeHostMetricBatch(hostMetricGzip(t, raw)); err == nil {
					t.Fatal("invalid persisted batch accepted")
				}
			}
		})
	}
	if IsHostMetric(HistCPUUtilization) || IsHostMetric("") {
		t.Fatal("unrelated metric selected")
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

func TestBoundHostMetricBatch(t *testing.T) {
	batch := hostMetricTestBatch(time.Now().UTC().Truncate(time.Minute))
	batch.Samples = nil
	for index := range 62 * (3 + 2*32) {
		member := "host-" + strconv.Itoa(index)
		member += strings.Repeat("a", 63-len(member))
		batch.Samples = append(batch.Samples, Sample{Metric: HistHostCPUUtilization,
			Labels: L("member", member), Value: .5})
	}
	for _, count := range []int{0, 1, DefaultHistorySeries, len(batch.Samples)} {
		t.Run(strconv.Itoa(count), func(t *testing.T) {
			input := batch
			input.Samples = batch.Samples[:count]
			bounded, dropped, err := BoundHostMetricBatch(input)
			if err != nil {
				t.Fatal(err)
			}
			want := min(count, DefaultHistorySeries)
			expected := input
			expected.Samples = input.Samples[:want]
			expected.Incomplete = count > want
			if !reflect.DeepEqual(bounded, expected) || dropped != uint64(count-want) {
				t.Fatalf("bounded %d samples to %d, dropped %d; want prefix %d, dropped %d",
					count, len(bounded.Samples), dropped, want, count-want)
			}
			data, err := encodeHostMetricBatch(bounded)
			if err != nil {
				t.Fatal(err)
			}
			if restored, err := decodeHostMetricBatch(data); err != nil || !reflect.DeepEqual(restored, bounded) {
				t.Fatalf("bounded batch roundtrip changed prefix: %v", err)
			}
			if count > DefaultHistorySeries {
				if _, err := encodeHostMetricBatch(input); err == nil {
					t.Fatal("direct encoding accepted sample overflow")
				}
				input.Samples[DefaultHistorySeries-1].Value = math.NaN()
				if _, _, err := BoundHostMetricBatch(input); err == nil || errors.Is(err, errHostMetricBatchSize) {
					t.Fatalf("sample cap hid invalid retained sample: %v", err)
				}
			}
		})
	}
	batch.Samples = nil
	if bounded, dropped, err := BoundHostMetricBatch(batch); err != nil || dropped != 0 || !reflect.DeepEqual(bounded, batch) {
		t.Fatalf("nil samples changed: %+v, %d, %v", bounded, dropped, err)
	}
}

func TestHostMetricBatchSizeAndMalformedRecords(t *testing.T) {
	at := time.Now().UTC().Truncate(time.Minute)
	batch := hostMetricTestBatch(at)
	batch.Samples = nil
	for index := range DefaultHistorySeries {
		batch.Samples = append(batch.Samples, Sample{Metric: HistHostCPUUtilization,
			Labels: L("member", "host-"+strconv.Itoa(index)), Value: .5})
	}
	data, err := encodeHostMetricBatch(batch)
	if err != nil {
		t.Fatalf("exact sample limit rejected: %v", err)
	}
	restored, err := decodeHostMetricBatch(data)
	if err != nil || len(restored.Samples) != DefaultHistorySeries {
		t.Fatalf("sample limit roundtrip = %d, %v", len(restored.Samples), err)
	}
	checkBounded := func(batch HostMetricBatch) {
		t.Helper()
		bounded, dropped, err := BoundHostMetricBatch(batch)
		if err != nil {
			t.Fatal(err)
		}
		kept := len(bounded.Samples)
		if kept == 0 || kept >= len(batch.Samples) || dropped != uint64(len(batch.Samples)-kept) {
			t.Fatalf("kept %d of %d samples, dropped %d", kept, len(batch.Samples), dropped)
		}
		expected := batch
		expected.Samples = batch.Samples[:kept]
		expected.Incomplete = true
		if !reflect.DeepEqual(bounded, expected) {
			t.Fatal("bounding changed prefix or metadata")
		}
		data, err := encodeHostMetricBatch(bounded)
		if err != nil {
			t.Fatal(err)
		}
		if restored, err := decodeHostMetricBatch(data); err != nil || !reflect.DeepEqual(restored, bounded) {
			t.Fatalf("bounded batch roundtrip changed prefix: %v", err)
		}
		// Validation must fail even for a malformed tail that sizing would omit.
		batch.Samples[len(batch.Samples)-1].Counter = true
		if _, _, err := BoundHostMetricBatch(batch); err == nil || errors.Is(err, errHostMetricBatchSize) {
			t.Fatalf("payload bounding hid invalid sample: %v", err)
		}
		batch.Samples[len(batch.Samples)-1].Counter = false
	}
	random := rand.New(rand.NewSource(1))
	token := func() string {
		var token [63]byte
		for index := range token {
			token[index] = byte('a' + random.Intn(26))
		}
		return string(token[:])
	}
	batch.Samples = nil
	for range 2000 {
		batch.Samples = append(batch.Samples, Sample{Metric: HistServiceMemoryUsed,
			Labels: L("member", token(), "service", token()), Value: float64(random.Int63n(1 << 44))})
	}
	raw, err := json.Marshal(batch)
	if err != nil || len(raw) >= hostMetricDecodedBytes {
		t.Fatalf("compressed-limit fixture = %d bytes, %v", len(raw), err)
	}
	if compressed := hostMetricGzip(t, raw); len(compressed) <= HostMetricBatchBytes {
		t.Fatalf("compressed-limit fixture = %d bytes", len(compressed))
	}
	if _, err := encodeHostMetricBatch(batch); !errors.Is(err, errHostMetricBatchSize) {
		t.Fatalf("oversized compressed batch error = %v", err)
	}
	checkBounded(batch)
	for len(batch.Samples) < DefaultHistorySeries {
		batch.Samples = append(batch.Samples, Sample{Metric: HistServiceMemoryUsed,
			Labels: L("member", token(), "service", token()), Value: 1 << 44})
	}
	raw, err = json.Marshal(batch)
	if err != nil || len(raw) <= hostMetricDecodedBytes {
		t.Fatalf("decoded-limit fixture = %d bytes, %v", len(raw), err)
	}
	if _, err := encodeHostMetricBatch(batch); !errors.Is(err, errHostMetricBatchSize) {
		t.Fatalf("oversized decoded batch error = %v", err)
	}
	checkBounded(batch)
	valid, err := encodeHostMetricBatch(hostMetricTestBatch(at))
	if err != nil {
		t.Fatal(err)
	}
	corrupt := bytes.Clone(valid)
	corrupt[len(corrupt)-1] ^= 1
	for name, data := range map[string][]byte{
		"plain JSON":         []byte(`{"at":"2026-10-01T00:00:00Z"}`),
		"bad JSON":           hostMetricGzip(t, []byte("not JSON")),
		"trailing JSON":      hostMetricGzip(t, []byte(`{} {}`)),
		"checksum":           corrupt,
		"truncated gzip":     valid[:len(valid)-4],
		"oversized payload":  make([]byte, HostMetricBatchBytes+1),
		"decompression bomb": hostMetricGzip(t, bytes.Repeat([]byte(" "), hostMetricDecodedBytes+1)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeHostMetricBatch(data); err == nil {
				t.Fatal("malformed record accepted")
			}
		})
	}
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

func TestHostMetricStreamConsumerRecreationAndEmptyReadiness(t *testing.T) {
	stream := hostMetricTestStream(t, hostMetricBroker(t, t.TempDir(), -1))
	history := NewHistory(HistoryConfig{Interval: HostMetricInterval})
	var next uint64
	at := time.Now().UTC().Truncate(time.Minute)
	for iteration := range 2 {
		ctx, cancel := context.WithCancel(t.Context())
		result := make(chan error, 1)
		go func() { result <- stream.tailHostMetricsOnce(ctx, history, &next) }()
		hostMetricWait(t, stream.CaughtUp)
		if iteration == 0 {
			if confirmed, err := stream.Publish(t.Context(), hostMetricTestBatch(at)); err != nil || !confirmed {
				t.Fatalf("publish confirmed=%t, error=%v", confirmed, err)
			}
			hostMetricWait(t, func() bool { return hostMetricCount(history) == 1 })
		}
		cancel()
		select {
		case <-result:
		case <-time.After(3 * time.Second):
			t.Fatal("consumer did not stop")
		}
		if stream.CaughtUp() {
			t.Fatal("stopped tail remains caught up")
		}
		if count := hostMetricCount(history); count != 1 {
			t.Fatalf("consumer %d rollup count = %d", iteration, count)
		}
	}
	if next != 2 {
		t.Fatalf("resume sequence = %d, want 2", next)
	}
	if err := stream.Tail(t.Context(), nil); err == nil {
		t.Fatal("accepted nil history")
	}
}

type hostMetricReplayStream struct {
	jetstream.Stream
	purge     bool
	paused    chan struct{}
	release   chan struct{}
	consumers atomic.Int32
}

func (stream *hostMetricReplayStream) OrderedConsumer(ctx context.Context, config jetstream.OrderedConsumerConfig) (jetstream.Consumer, error) {
	stream.consumers.Add(1)
	if stream.purge {
		// Deterministically remove the captured LastSeq before consumer creation.
		if err := stream.Stream.Purge(ctx); err != nil {
			return nil, err
		}
	}
	consumer, err := stream.Stream.OrderedConsumer(ctx, config)
	if err != nil || stream.paused == nil {
		return consumer, err
	}
	return &hostMetricPausedConsumer{Consumer: consumer, ctx: ctx, paused: stream.paused, release: stream.release}, nil
}

type hostMetricPausedConsumer struct {
	jetstream.Consumer
	ctx     context.Context
	paused  chan struct{}
	release chan struct{}
}

func (consumer *hostMetricPausedConsumer) Messages(opts ...jetstream.PullMessagesOpt) (jetstream.MessagesContext, error) {
	messages, err := consumer.Consumer.Messages(opts...)
	if err != nil {
		return nil, err
	}
	return &hostMetricPausedMessages{MessagesContext: messages, consumer: consumer}, nil
}

type hostMetricPausedMessages struct {
	jetstream.MessagesContext
	consumer *hostMetricPausedConsumer
	calls    int
}

func (messages *hostMetricPausedMessages) Next(opts ...jetstream.NextOpt) (jetstream.Msg, error) {
	messages.calls++
	if messages.calls == 1 {
		return nil, context.DeadlineExceeded
	}
	if messages.calls == 2 {
		// The timeout refresh has completed; keep the retained record undelivered.
		close(messages.consumer.paused)
		select {
		case <-messages.consumer.release:
		case <-messages.consumer.ctx.Done():
			return nil, messages.consumer.ctx.Err()
		}
	}
	return messages.MessagesContext.Next(opts...)
}

func TestHostMetricStreamIdleEmptyReplayReadiness(t *testing.T) {
	for _, purge := range []bool{false, true} {
		name := "initially empty"
		if purge {
			name = "last record removed after Info"
		}
		t.Run(name, func(t *testing.T) {
			stream := hostMetricTestStream(t, hostMetricBroker(t, t.TempDir(), -1))
			at := time.Now().UTC().Truncate(time.Minute)
			if purge {
				if confirmed, err := stream.Publish(t.Context(), hostMetricTestBatch(at)); err != nil || !confirmed {
					t.Fatalf("publish confirmed=%t, error=%v", confirmed, err)
				}
			}
			replay := &hostMetricReplayStream{Stream: stream.stream, purge: purge}
			stream.stream = replay
			history := NewHistory(HistoryConfig{Interval: HostMetricInterval})
			hostMetricTail(t, stream, history)
			hostMetricWait(t, stream.CaughtUp)
			// An idle, ready iterator must survive longer than the replay wait.
			time.Sleep(2 * hostMetricReplayWait)
			if !stream.CaughtUp() || replay.consumers.Load() != 1 || hostMetricCount(history) != 0 {
				t.Fatalf("idle replay: ready=%t, consumers=%d, samples=%d", stream.CaughtUp(), replay.consumers.Load(), hostMetricCount(history))
			}
			if confirmed, err := stream.Publish(t.Context(), hostMetricTestBatch(at.Add(time.Minute))); err != nil || !confirmed {
				t.Fatalf("publish confirmed=%t, error=%v", confirmed, err)
			}
			hostMetricWait(t, func() bool { return stream.CaughtUp() && hostMetricCount(history) == 1 })
			if replay.consumers.Load() != 1 {
				t.Fatal("timeout recreated the ordered consumer")
			}
		})
	}
}

func TestHostMetricStreamReplayTimeoutWaitsForRetainedRecord(t *testing.T) {
	stream := hostMetricTestStream(t, hostMetricBroker(t, t.TempDir(), -1))
	if confirmed, err := stream.Publish(t.Context(), hostMetricTestBatch(time.Now())); err != nil || !confirmed {
		t.Fatalf("publish confirmed=%t, error=%v", confirmed, err)
	}
	replay := &hostMetricReplayStream{Stream: stream.stream, paused: make(chan struct{}), release: make(chan struct{})}
	stream.stream = replay
	history := NewHistory(HistoryConfig{Interval: HostMetricInterval})
	hostMetricTail(t, stream, history)
	select {
	case <-replay.paused:
	case <-time.After(10 * time.Second):
		t.Fatal("iterator did not resume after the replay timeout")
	}
	if stream.CaughtUp() || hostMetricCount(history) != 0 {
		t.Fatal("timeout marked an undelivered retained record ready")
	}
	close(replay.release)
	hostMetricWait(t, func() bool { return stream.CaughtUp() && hostMetricCount(history) == 1 })
	if replay.consumers.Load() != 1 {
		t.Fatal("timeout recreated the ordered consumer")
	}
}

func TestHostMetricStreamConcurrentPublishAndReplay(t *testing.T) {
	stream := hostMetricTestStream(t, hostMetricBroker(t, t.TempDir(), -1))
	history := NewHistory(HistoryConfig{Interval: HostMetricInterval})
	hostMetricTail(t, stream, history)
	at := time.Now().UTC().Truncate(time.Minute).Add(-30 * time.Minute)
	for index := range 30 {
		if confirmed, err := stream.Publish(t.Context(), hostMetricTestBatch(at.Add(time.Duration(index)*time.Minute))); err != nil || !confirmed {
			t.Fatalf("publish confirmed=%t, error=%v", confirmed, err)
		}
	}
	hostMetricWait(t, func() bool { return stream.CaughtUp() && hostMetricCount(history) == 30 })
}
