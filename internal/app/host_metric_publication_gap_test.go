package app

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostload"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
)

func publicationGapLoad(t *testing.T, now *time.Time) (*hostTelemetry, *metricTestFence) {
	t.Helper()
	fence := &metricTestFence{}
	fence.set(authority.Snapshot{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Ready: true, Leader: true, Epoch: 1, Revision: 1, ExpiresAt: time.Now().Add(time.Hour)})
	load := &hostTelemetry{fencer: fence, load: hostload.NewAggregator(hostload.AggregatorConfig{
		Now: func() time.Time { return *now },
	})}
	publicationGapReport(t, load, 0.25)
	return load, fence
}

func publicationGapReport(t *testing.T, load *hostTelemetry, cpu float64) {
	t.Helper()
	if err := load.record(hostload.Origin{Cell: "gru", Environment: "production", Node: "host-a"},
		hostload.Report{SchemaVersion: hostload.SchemaVersion, Host: hostload.HostUsage{CPU: &cpu}}); err != nil {
		t.Fatal(err)
	}
}

func publicationGapStored(t *testing.T, js jetstream.JetStream, sequence uint64) observability.HostMetricBatch {
	t.Helper()
	stream, err := js.Stream(t.Context(), observability.HostMetricStreamName)
	if err != nil {
		t.Fatal(err)
	}
	message, err := stream.GetMsg(t.Context(), sequence)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := gzip.NewReader(bytes.NewReader(message.Data))
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	var batch observability.HostMetricBatch
	if err := json.NewDecoder(reader).Decode(&batch); err != nil {
		t.Fatal(err)
	}
	return batch
}

func TestHostMetricPublicationRequiresRestartAfterArchiveRecreation(t *testing.T) {
	js := testRolloutJetStream(t)
	stream, err := observability.OpenHostMetricStream(t.Context(), js, "gru", 1)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now().UTC().Truncate(time.Minute).Add(-3 * time.Minute)
	clock := start
	load, _ := publicationGapLoad(t, &clock)
	legacy := load.archiveBatch(start)
	legacy.Version = 0
	raw, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	archive, err := js.Stream(t.Context(), observability.HostMetricStreamName)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := js.Publish(t.Context(), archive.CachedInfo().Config.Subjects[0], compressed.Bytes()); err != nil {
		t.Fatal(err)
	}
	h, state, events := &hostMetricHistory{}, &hostMetricPublication{}, observability.NewEventBus(16)
	h.publishStep(t.Context(), stream, load, events, state, start)
	h.publishStep(t.Context(), stream, load, events, state, start.Add(time.Minute))
	if !state.gap || h.failures.Load() != 2 {
		t.Fatalf("unversioned rejection did not retain publication gap: %+v", state)
	}
	if err := js.DeleteStream(t.Context(), observability.HostMetricStreamName); err != nil {
		t.Fatal(err)
	}
	recreated, err := observability.OpenHostMetricStream(t.Context(), js, "gru", 1)
	if err != nil {
		t.Fatal(err)
	}
	h.publishStep(t.Context(), stream, load, events, state, start.Add(time.Minute+10*time.Second))
	if h.failures.Load() != 3 || !state.gap {
		t.Fatal("old publisher carried its pending gap into the recreated archive")
	}
	fresh, err := js.Stream(t.Context(), observability.HostMetricStreamName)
	if err != nil {
		t.Fatal(err)
	}
	info, err := fresh.Info(t.Context())
	if err != nil || info.State.Msgs != 0 {
		t.Fatalf("old publisher wrote into the fresh stream: %+v, %v", info, err)
	}
	// An in-place controller restart opens a new handle and publication state.
	clock = start.Add(2 * time.Minute)
	load.load.Reset()
	publicationGapReport(t, load, .5)
	h.publishStep(t.Context(), recreated, load, events, &hostMetricPublication{}, clock)
	if stored := publicationGapStored(t, js, 1); stored.Incomplete || stored.Version != 1 || stored.At != clock {
		t.Fatalf("restarted publisher did not create complete v1 history: %+v", stored)
	}
	reader := &hostMetricHistory{local: observability.NewHistory(observability.HistoryConfig{}),
		shared: observability.NewHistory(observability.HistoryConfig{Interval: observability.HostMetricInterval})}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { reader.run(ctx, js, "gru", 1, nil, nil); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if replay := reader.stream.Load(); replay != nil && replay.CaughtUp() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("recreated archive replay did not catch up")
		}
	}
	result := reader.Range(observability.HistoryQuery{Metric: observability.HistHostCPUUtilization,
		Labels: map[string]string{"member": "host-a"}, Start: start, End: clock})
	if result.Pending || result.Incomplete || len(result.Series) != 1 || len(result.Series[0].Points) != 1 || result.Series[0].Points[0].Value != .5 {
		t.Fatalf("old publication gap contaminated recreated history: %+v", result)
	}
	var metrics bytes.Buffer
	reader.writeMetrics(&metrics)
	if !strings.Contains(metrics.String(), "ts_orch_host_history_replay_ready 1\n") ||
		!strings.Contains(metrics.String(), "ts_orch_host_history_archive_incomplete 0\n") {
		t.Fatalf("recreated archive retained a coverage warning: %s", metrics.String())
	}
}

func TestHostMetricPublicationGapSurvivesRecoveryAndReplay(t *testing.T) {
	js := testRolloutJetStream(t)
	stream, err := observability.OpenHostMetricStream(t.Context(), js, "gru", 1)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now().UTC().Truncate(time.Minute).Add(-3 * time.Minute)
	clock := start
	load, _ := publicationGapLoad(t, &clock)
	h, state, events := &hostMetricHistory{}, &hostMetricPublication{}, observability.NewEventBus(16)
	failed := metricPublishFunc(func(context.Context, observability.HostMetricBatch) (bool, error) {
		return false, errors.New("store unavailable")
	})
	h.publishStep(t.Context(), failed, load, events, state, start)
	h.publishStep(t.Context(), failed, load, events, state, start.Add(time.Minute))
	h.publishStep(t.Context(), stream, load, events, state, start.Add(time.Minute+10*time.Second))
	if state.gap || !state.pending.At.IsZero() || h.failures.Load() != 2 || h.droppedSamples.Load() != 0 {
		t.Fatalf("recovery state=%+v failures=%d dropped=%d", state, h.failures.Load(), h.droppedSamples.Load())
	}
	h.publishStep(t.Context(), stream, load, events, state, start.Add(2*time.Minute))
	marked, complete := publicationGapStored(t, js, 1), publicationGapStored(t, js, 2)
	if marked.At != start.Add(time.Minute) || !marked.Incomplete || complete.Incomplete {
		t.Fatalf("stored recovery marker=%+v next=%+v", marked, complete)
	}
	// Fresh readers derive coverage only from the durable records, without local failures.
	for range 2 {
		reader := &hostMetricHistory{local: observability.NewHistory(observability.HistoryConfig{}),
			shared: observability.NewHistory(observability.HistoryConfig{Interval: observability.HostMetricInterval})}
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() { reader.run(ctx, js, "gru", 1, nil, nil); close(done) }()
		t.Cleanup(func() { cancel(); <-done })
		for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
			if replay := reader.stream.Load(); replay != nil && replay.CaughtUp() {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("recovery marker replay did not catch up")
			}
		}
		result := reader.Range(observability.HistoryQuery{Metric: observability.HistHostCPUUtilization,
			Labels: map[string]string{"member": "host-a"}, Start: start, End: start.Add(2 * time.Minute)})
		if result.Pending || !result.Incomplete || len(result.Series) != 1 || len(result.Series[0].Points) != 2 {
			t.Fatalf("abandoned minute hidden by recovered history: %+v", result)
		}
		var metrics bytes.Buffer
		reader.writeMetrics(&metrics)
		if !strings.Contains(metrics.String(), "ts_orch_host_history_replay_ready 0\n") ||
			!strings.Contains(metrics.String(), "ts_orch_host_history_archive_incomplete 1\n") {
			t.Fatalf("replayed gap absent from readiness: %s", metrics.String())
		}
		if reader.failures.Load() != 0 || reader.droppedSamples.Load() != 0 ||
			reader.shared.Stats().Dropped != 0 || reader.stream.Load().ReplayFailures() != 0 {
			t.Fatal("whole-batch coverage gap altered sample-drop or failure counters")
		}
		cancel()
		<-done
	}
}

func TestHostMetricPublicationGapSurvivesCompetingWriterSkip(t *testing.T) {
	for _, test := range []struct {
		name       string
		failed     bool
		nextMinute bool
		wantGap    bool
	}{
		{name: "replacement skipped", failed: true, nextMinute: true, wantGap: true},
		{name: "failed retry skipped", failed: true, wantGap: true},
		{name: "simple skip"},
	} {
		t.Run(test.name, func(t *testing.T) {
			js := testRolloutJetStream(t)
			stream, err := observability.OpenHostMetricStream(t.Context(), js, "gru", 1)
			if err != nil {
				t.Fatal(err)
			}
			start := time.Now().UTC().Truncate(time.Minute).Add(-3 * time.Minute)
			clock := start
			load, _ := publicationGapLoad(t, &clock)
			h, state, events := &hostMetricHistory{}, &hostMetricPublication{}, observability.NewEventBus(16)
			if test.failed {
				h.publishStep(t.Context(), metricPublishFunc(func(context.Context, observability.HostMetricBatch) (bool, error) {
					return false, errors.New("store unavailable")
				}), load, events, state, start)
			}
			skipAt := start
			if test.nextMinute {
				skipAt = skipAt.Add(time.Minute)
			}
			competing := load.archiveBatch(skipAt)
			competing.Epoch = 2
			if confirmed, err := stream.Publish(t.Context(), competing); err != nil || !confirmed {
				t.Fatalf("competing publication: confirmed=%t err=%v", confirmed, err)
			}
			h.publishStep(t.Context(), stream, load, events, state, skipAt)
			if state.gap != test.wantGap || state.published != skipAt || h.droppedSamples.Load() != 0 {
				t.Fatalf("skip state=%+v dropped=%d", state, h.droppedSamples.Load())
			}
			if stored := publicationGapStored(t, js, 1); stored.Incomplete || stored.Epoch != 2 {
				t.Fatalf("skip changed competing batch: %+v", stored)
			}
			h.publishStep(t.Context(), stream, load, events, state, skipAt.Add(time.Minute))
			if stored := publicationGapStored(t, js, 2); stored.Incomplete != test.wantGap || state.gap {
				t.Fatalf("skip lost or invented coverage marker: %+v state=%+v", stored, state)
			}
		})
	}
}

type publicationGapLostAckJS struct {
	jetstream.JetStream
	calls int
}

func (js *publicationGapLostAckJS) Publish(ctx context.Context, subject string, data []byte,
	opts ...jetstream.PublishOpt,
) (*jetstream.PubAck, error) {
	js.calls++
	ack, err := js.JetStream.Publish(ctx, subject, data, opts...)
	if err == nil && js.calls == 1 {
		return nil, context.DeadlineExceeded
	}
	return ack, err
}

func TestHostMetricPublicationGapLostAck(t *testing.T) {
	for _, abandon := range []bool{false, true} {
		name := "immutable same-minute retry"
		if abandon {
			name = "uncertain earlier batch conservatively marked"
		}
		t.Run(name, func(t *testing.T) {
			js := testRolloutJetStream(t)
			lostAck := &publicationGapLostAckJS{JetStream: js}
			stream, err := observability.OpenHostMetricStream(t.Context(), lostAck, "gru", 1)
			if err != nil {
				t.Fatal(err)
			}
			start := time.Now().UTC().Truncate(time.Minute).Add(-2 * time.Minute)
			clock := start
			load, _ := publicationGapLoad(t, &clock)
			h, state, events := &hostMetricHistory{}, &hostMetricPublication{}, observability.NewEventBus(16)
			var bodies [][]byte
			publisher := metricPublishFunc(func(ctx context.Context, batch observability.HostMetricBatch) (bool, error) {
				body, err := json.Marshal(batch)
				if err != nil {
					t.Fatal(err)
				}
				bodies = append(bodies, body)
				return stream.Publish(ctx, batch)
			})
			h.publishStep(t.Context(), publisher, load, events, state, start)
			if state.pending.At.IsZero() || h.failures.Load() != 1 {
				t.Fatalf("lost ACK did not preserve pending batch: %+v", state)
			}
			retryAt := start.Add(10 * time.Second)
			if abandon {
				retryAt = start.Add(time.Minute)
			}
			clock = retryAt
			load.load.Reset()
			publicationGapReport(t, load, 0.5)
			h.publishStep(t.Context(), publisher, load, events, state, retryAt)
			if state.gap || !state.pending.At.IsZero() || h.droppedSamples.Load() != 0 {
				t.Fatalf("lost ACK recovery state=%+v dropped=%d", state, h.droppedSamples.Load())
			}
			first := publicationGapStored(t, js, 1)
			if first.Incomplete || first.Samples[0].Value != 0.25 {
				t.Fatalf("lost ACK changed stored complete batch: %+v", first)
			}
			if abandon {
				second := publicationGapStored(t, js, 2)
				if !second.Incomplete || second.Samples[0].Value != 0.5 || lostAck.calls != 2 {
					t.Fatalf("abandonment failed to mark uncertainty: %+v calls=%d", second, lostAck.calls)
				}
			} else {
				if !bytes.Equal(bodies[0], bodies[1]) || lostAck.calls != 1 {
					t.Fatalf("same-minute retry changed bytes or duplicated store: calls=%d bodies=%q", lostAck.calls, bodies)
				}
				h.publishStep(t.Context(), publisher, load, events, state, start.Add(time.Minute))
				if next := publicationGapStored(t, js, 2); next.Incomplete || next.Samples[0].Value != 0.5 {
					t.Fatalf("confirmed retry invented a later gap: %+v", next)
				}
			}
		})
	}
}

type publicationGapGuardFence struct {
	*metricTestFence
	beforeGuard func()
}

func (f *publicationGapGuardFence) Guard(ctx context.Context, epoch uint64) error {
	if f.beforeGuard != nil {
		before := f.beforeGuard
		f.beforeGuard = nil
		before()
	}
	return f.metricTestFence.Guard(ctx, epoch)
}

func TestHostMetricPublicationGapEpochReplacementIsFenced(t *testing.T) {
	js := testRolloutJetStream(t)
	stream, err := observability.OpenHostMetricStream(t.Context(), js, "gru", 1)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now().UTC().Truncate(time.Minute).Add(-time.Minute)
	clock := start
	load, fence := publicationGapLoad(t, &clock)
	h, state, events := &hostMetricHistory{}, &hostMetricPublication{}, observability.NewEventBus(16)
	h.publishStep(t.Context(), metricPublishFunc(func(context.Context, observability.HostMetricBatch) (bool, error) {
		return false, errors.New("store unavailable")
	}), load, events, state, start)
	leader := fence.Current()
	leader.Epoch = 2
	fence.set(leader)
	calls := 0
	publisher := metricPublishFunc(func(ctx context.Context, batch observability.HostMetricBatch) (bool, error) {
		calls++
		return stream.Publish(ctx, batch)
	})
	// Authority changes reset telemetry; the old pending epoch must not publish.
	h.publishStep(t.Context(), publisher, load, events, state, start.Add(10*time.Second))
	if calls != 0 {
		t.Fatal("old epoch published without fresh reports")
	}
	clock = start.Add(20 * time.Second)
	publicationGapReport(t, load, 0.5)
	load.fencer = &publicationGapGuardFence{metricTestFence: fence, beforeGuard: func() { fence.set(authority.Snapshot{}) }}
	h.publishStep(t.Context(), publisher, load, events, state, start.Add(20*time.Second))
	if calls != 0 || !state.pending.Incomplete || state.pending.Epoch != 2 || h.failures.Load() != 2 {
		t.Fatalf("new epoch snapshot escaped fence or lost gap: calls=%d state=%+v", calls, state)
	}
	fence.set(leader)
	h.publishStep(t.Context(), publisher, load, events, state, start.Add(30*time.Second))
	stored := publicationGapStored(t, js, 1)
	if calls != 1 || stored.Epoch != 2 || !stored.Incomplete || stored.Samples[0].Value != 0.5 || state.gap || h.droppedSamples.Load() != 0 {
		t.Fatalf("new authority failed to carry gap: calls=%d stored=%+v state=%+v", calls, stored, state)
	}
}
