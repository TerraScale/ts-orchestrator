package observability

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

const (
	HostMetricBatchVersion          = 1
	HostMetricStreamName            = "TS_HOST_METRIC_HISTORY"
	HostMetricStreamBytes     int64 = 1536 << 20
	HostMetricBatchBytes            = 64 << 10
	hostMetricHeaderBytes           = 128 // NATS framing and the uint64 expected-last-sequence header.
	HostMetricInterval              = time.Minute
	hostMetricDecodedBytes          = 1 << 20
	hostMetricPublishAttempts       = 8
	hostMetricReplayWait            = time.Second
	hostMetricReplayChunk           = 64
	hostMetricMaxFilesystems        = 37 // Five host roots and at most 32 managed roles.
)

// HostMetricBatch is one regional minute of telemetry. Epoch records its
// publisher's epoch; historical telemetry is never authority evidence.
type HostMetricBatch struct {
	Version    int       `json:"version"`
	At         time.Time `json:"at"`
	Epoch      uint64    `json:"epoch"`
	Samples    []Sample  `json:"samples"`
	Incomplete bool      `json:"incomplete"`
}

var errHostMetricBatchSize = errors.New("host metric batch exceeds payload size bound")

// BoundHostMetricBatch retains an ordered prefix that fits the sample and
// payload bounds, marking omissions and returning the number newly omitted.
// Nonempty valid batches retain at least one sample; encoder validation errors
// are returned.
func BoundHostMetricBatch(batch HostMetricBatch) (HostMetricBatch, uint64, error) {
	original := len(batch.Samples)
	if original > DefaultHistorySeries {
		batch.Samples = batch.Samples[:DefaultHistorySeries]
	}
	for {
		batch.Incomplete = batch.Incomplete || len(batch.Samples) < original
		_, err := encodeHostMetricBatch(batch)
		if err == nil {
			return batch, uint64(original - len(batch.Samples)), nil
		}
		if !errors.Is(err, errHostMetricBatchSize) || len(batch.Samples) <= 1 {
			return HostMetricBatch{}, 0, err
		}
		batch.Samples = batch.Samples[:len(batch.Samples)/2]
	}
}

// IsHostMetric selects the host and service gauges persisted regionally.
func IsHostMetric(metric string) bool {
	switch metric {
	case HistHostCPUUtilization, HistHostMemoryRatio, HistHostDiskRatio,
		HistHostCPUCores, HistHostMemoryTotal, HistHostReceivedAt, HistHostFSIncomplete, HistHostFSUsed, HistHostFSSize, HistHostFSRatio,
		HistHostFSFiles, HistHostFSFilesFree,
		HistServiceCPUCores, HistServiceMemoryUsed:
		return true
	}
	return false
}

// HostMetricStream stores and replays regional host telemetry.
type HostMetricStream struct {
	streamMu          sync.Mutex // The NATS stream caches Info without synchronization.
	stream            jetstream.Stream
	createdAt         time.Time
	js                jetstream.JetStream
	subject           string
	caughtUp          atomic.Bool
	archiveIncomplete atomic.Bool
	replayFailures    atomic.Uint64
	lastRejectedSeq   atomic.Uint64
}

// CaughtUp reports replay readiness, never controller or authority readiness.
func (stream *HostMetricStream) CaughtUp() bool {
	return stream.caughtUp.Load() && stream.js.Conn().IsConnected()
}

// ReplayFailures reports cumulative rejected batches on this stream handle.
// Cursor readiness does not imply complete history when this count is nonzero.
func (stream *HostMetricStream) ReplayFailures() uint64 {
	return stream.replayFailures.Load()
}

// ArchiveIncomplete reports whether replay observed a valid batch with omissions.
// It remains set for this handle; a new handle rebuilds from retained records.
func (stream *HostMetricStream) ArchiveIncomplete() bool {
	return stream.archiveIncomplete.Load()
}

func (stream *HostMetricStream) rejectReplayBatch(sequence uint64) {
	// Ordered replay can revisit old sequences after a new Tail call.
	for previous := stream.lastRejectedSeq.Load(); sequence > previous; previous = stream.lastRejectedSeq.Load() {
		if stream.lastRejectedSeq.CompareAndSwap(previous, sequence) {
			stream.replayFailures.Add(1)
			return
		}
	}
}

func OpenHostMetricStream(ctx context.Context, js jetstream.JetStream, cell string, replicas int) (*HostMetricStream, error) {
	if js == nil {
		return nil, errors.New("host metric stream requires JetStream")
	}
	if replicas < 1 || replicas > 5 {
		return nil, errors.New("host metric stream replica count is out of range")
	}
	subject, err := protocol.ObservabilitySubject(cell, "host-metrics")
	if err != nil {
		return nil, err
	}
	stream, err := js.CreateStream(ctx, jetstream.StreamConfig{
		Name:        HostMetricStreamName,
		Description: "Regional host metric history",
		Subjects:    []string{subject + "." + strings.ToLower(rand.Text())},
		Storage:     jetstream.FileStorage,
		Replicas:    replicas,
		Retention:   jetstream.LimitsPolicy,
		Discard:     jetstream.DiscardNew,
		MaxAge:      HistoryRetention,
		MaxBytes:    HostMetricStreamBytes,
		MaxMsgs:     -1,
		MaxMsgSize:  HostMetricBatchBytes + hostMetricHeaderBytes,
	})
	if errors.Is(err, jetstream.ErrStreamNameAlreadyInUse) {
		stream, err = js.Stream(ctx, HostMetricStreamName)
	}
	if err != nil {
		return nil, fmt.Errorf("open host metric stream: %w", err)
	}
	info := stream.CachedInfo()
	if len(info.Config.Subjects) != 1 || !strings.HasPrefix(info.Config.Subjects[0], subject+".") ||
		protocol.ValidateSubjectToken(strings.TrimPrefix(info.Config.Subjects[0], subject+".")) != nil {
		return nil, errors.New("host metric stream lacks a v1 generation subject; delete and recreate it")
	}
	config := info.Config
	if config.Storage != jetstream.FileStorage || config.Replicas != replicas || config.Retention != jetstream.LimitsPolicy ||
		config.Discard != jetstream.DiscardNew || config.MaxAge != HistoryRetention || config.MaxBytes != HostMetricStreamBytes ||
		config.MaxMsgs != -1 || config.MaxMsgSize != HostMetricBatchBytes+hostMetricHeaderBytes || config.NoAck ||
		config.SubjectTransform != nil || config.Mirror != nil || len(config.Sources) != 0 || config.RePublish != nil {
		return nil, errors.New("host metric stream contract differs from v1; delete and recreate it")
	}
	// The server rejects old-generation writes even when recreation races an in-flight request.
	return &HostMetricStream{stream: stream, createdAt: info.Created, js: js, subject: info.Config.Subjects[0]}, nil
}

func (stream *HostMetricStream) info(ctx context.Context) (*jetstream.StreamInfo, error) {
	stream.streamMu.Lock()
	defer stream.streamMu.Unlock()
	info, err := stream.stream.Info(ctx)
	if err == nil && (!info.Created.Equal(stream.createdAt) || len(info.Config.Subjects) != 1 || info.Config.Subjects[0] != stream.subject) {
		return nil, errors.New("host metric stream was recreated; restart controller to reset publication and replay state")
	}
	return info, err
}

func (stream *HostMetricStream) message(ctx context.Context, sequence uint64) (*jetstream.RawStreamMsg, error) {
	stream.streamMu.Lock()
	defer stream.streamMu.Unlock()
	return stream.stream.GetMsg(ctx, sequence)
}

// Publish stores at most one batch per regional minute across all writers.
// It reports whether this normalized batch is confirmed stored, including retries
// after a lost acknowledgment. Skipped batches belonging to other writers are false.
// The caller must check publication authority before invoking it.
func (stream *HostMetricStream) Publish(ctx context.Context, batch HostMetricBatch) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	batch.At = batch.At.UTC().Truncate(HostMetricInterval)
	data, err := encodeHostMetricBatch(batch)
	if err != nil {
		return false, err
	}
	for range hostMetricPublishAttempts {
		info, err := stream.info(ctx)
		if err != nil {
			return false, err
		}
		lastSeq := info.State.LastSeq
		if info.State.Msgs > 0 {
			message, err := stream.message(ctx, lastSeq)
			if errors.Is(err, jetstream.ErrMsgNotFound) {
				continue // Retention may have expired the message after Info.
			}
			if err != nil {
				return false, err
			}
			if message.Subject != stream.subject {
				return false, errors.New("host metric publication crossed stream generation")
			}
			last, err := decodeHostMetricBatch(message.Data)
			if err != nil {
				return false, fmt.Errorf("read latest host metric batch: %w", err)
			}
			if !batch.At.After(last.At) {
				return bytes.Equal(message.Data, data), nil
			}
		}
		_, err = stream.js.Publish(ctx, stream.subject, data, jetstream.WithExpectLastSequence(lastSeq))
		if err == nil {
			return true, nil
		}
		var apiErr *jetstream.APIError
		if !errors.As(err, &apiErr) || (apiErr.ErrorCode != jetstream.JSErrCodeStreamWrongLastSequence &&
			apiErr.ErrorCode != jetstream.JSErrCodeStreamWrongLastSequenceConstant) {
			return false, err
		}
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return false, errors.New("host metric publish contention exceeded retry bound")
}

func validateHostMetricBatch(batch HostMetricBatch) error {
	if batch.Version != HostMetricBatchVersion {
		return errors.New("host metric batch requires format version 1")
	}
	_, offset := batch.At.Zone()
	if batch.At.IsZero() || offset != 0 || !batch.At.Equal(batch.At.Truncate(HostMetricInterval)) || batch.Epoch == 0 {
		return errors.New("host metric batch requires a UTC minute and positive epoch")
	}
	if len(batch.Samples) > DefaultHistorySeries {
		return errors.New("host metric batch exceeds sample bound")
	}
	seen := make(map[string]bool, len(batch.Samples))
	filesystems := make(map[string]map[string]float64)
	filesystemIdentities := make(map[string]string)
	filesystemCounts := make(map[string]int)
	for _, sample := range batch.Samples {
		if !IsHostMetric(sample.Metric) || sample.Counter {
			return errors.New("host metric batch contains an unsupported gauge")
		}
		limit := 1.0
		service := sample.Metric == HistServiceCPUCores || sample.Metric == HistServiceMemoryUsed
		filesystem := sample.Metric == HistHostFSUsed || sample.Metric == HistHostFSSize || sample.Metric == HistHostFSRatio ||
			sample.Metric == HistHostFSFiles || sample.Metric == HistHostFSFilesFree
		switch sample.Metric {
		case HistServiceCPUCores, HistHostCPUCores:
			limit = 1024
		case HistServiceMemoryUsed, HistHostMemoryTotal:
			limit = 1 << 44
		case HistHostFSUsed, HistHostFSSize, HistHostFSFiles, HistHostFSFilesFree:
			limit = 1 << 50
		case HistHostReceivedAt:
			limit = float64(batch.At.Add(HostMetricInterval).UnixMilli())
		}
		if math.IsNaN(sample.Value) || math.IsInf(sample.Value, 0) || sample.Value < 0 || sample.Value > limit {
			return errors.New("host metric value is out of bounds")
		}
		if (sample.Metric == HistHostCPUCores || sample.Metric == HistHostMemoryTotal ||
			sample.Metric == HistHostFSSize || sample.Metric == HistHostReceivedAt) && sample.Value == 0 {
			return errors.New("host metric capacity and receive time must be positive")
		}
		if sample.Metric != HistHostCPUUtilization && sample.Metric != HistHostMemoryRatio &&
			sample.Metric != HistHostDiskRatio && sample.Metric != HistHostFSRatio &&
			sample.Metric != HistServiceCPUCores && math.Trunc(sample.Value) != sample.Value {
			return errors.New("host metric cores, bytes, inode counts and timestamps must be integers")
		}
		member, serviceName, role, path, device := "", "", "", "", ""
		for _, label := range sample.Labels {
			switch label.Name {
			case "path":
				if len(label.Value) > 4096 || !utf8.ValidString(label.Value) ||
					!filepath.IsAbs(label.Value) || filepath.Clean(label.Value) != label.Value ||
					strings.ContainsFunc(label.Value, unicode.IsControl) {
					return errors.New("host metric filesystem path is invalid")
				}
			case "device":
				value, err := strconv.ParseUint(label.Value, 10, 64)
				if err != nil || strconv.FormatUint(value, 10) != label.Value {
					return errors.New("host metric filesystem device is not a canonical uint64")
				}
			default:
				if protocol.ValidateSubjectToken(label.Value) != nil {
					return errors.New("host metric label is not a valid token")
				}
			}
			switch {
			case label.Name == "member" && member == "":
				member = label.Value
			case label.Name == "service" && service && serviceName == "":
				serviceName = label.Value
			case label.Name == "role" && filesystem && role == "":
				role = label.Value
			case label.Name == "path" && filesystem && path == "":
				path = label.Value
			case label.Name == "device" && filesystem && device == "":
				device = label.Value
			default:
				return errors.New("host metric labels must be precisely member, member/service, or member/role/path/device")
			}
		}
		if member == "" || service && serviceName == "" || filesystem && (role == "" || path == "" || device == "") {
			return errors.New("host metric required label is missing")
		}
		key := seriesKey(sample.Metric, sortedLabels(sample.Labels))
		if seen[key] {
			return errors.New("host metric batch contains a duplicate series")
		}
		seen[key] = true
		if filesystem {
			identity := member + "\x00" + role
			if previous, ok := filesystemIdentities[identity]; ok && previous != path+"\x00"+device {
				return errors.New("host metric filesystem role has inconsistent path or device")
			}
			filesystemIdentities[identity] = path + "\x00" + device
			if filesystems[identity] == nil {
				filesystemCounts[member]++
				if filesystemCounts[member] > hostMetricMaxFilesystems {
					return errors.New("host metric batch exceeds filesystem role bound")
				}
				filesystems[identity] = make(map[string]float64)
			}
			filesystems[identity][sample.Metric] = sample.Value
		}
	}
	for _, filesystem := range filesystems {
		size, hasSize := filesystem[HistHostFSSize]
		used, hasUsed := filesystem[HistHostFSUsed]
		if hasSize && hasUsed {
			if used > size {
				return errors.New("host metric filesystem usage exceeds size")
			}
			if ratio, hasRatio := filesystem[HistHostFSRatio]; hasRatio && ratio != used/size {
				return errors.New("host metric filesystem ratio disagrees with bytes")
			}
		}
		files, hasFiles := filesystem[HistHostFSFiles]
		free, hasFree := filesystem[HistHostFSFilesFree]
		if hasFiles && hasFree && free > files {
			return errors.New("host metric filesystem free inode count exceeds total")
		}
	}
	return nil
}

func encodeHostMetricBatch(batch HostMetricBatch) ([]byte, error) {
	if err := validateHostMetricBatch(batch); err != nil {
		return nil, err
	}
	data, err := json.Marshal(batch)
	if err != nil {
		return nil, err
	}
	if len(data) > hostMetricDecodedBytes {
		return nil, fmt.Errorf("host metric batch exceeds decoded size bound: %w", errHostMetricBatchSize)
	}
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	if _, err := writer.Write(data); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	if buffer.Len() > HostMetricBatchBytes {
		return nil, fmt.Errorf("host metric batch exceeds compressed size bound: %w", errHostMetricBatchSize)
	}
	return buffer.Bytes(), nil
}

func decodeHostMetricBatch(data []byte) (HostMetricBatch, error) {
	var batch HostMetricBatch
	if len(data) > HostMetricBatchBytes {
		return batch, errors.New("host metric batch exceeds compressed size bound")
	}
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return batch, err
	}
	defer reader.Close()
	decoded, err := io.ReadAll(io.LimitReader(reader, hostMetricDecodedBytes+1))
	if err != nil {
		return batch, err
	}
	if len(decoded) > hostMetricDecodedBytes {
		return batch, errors.New("host metric batch exceeds decoded size bound")
	}
	if !utf8.Valid(decoded) {
		return batch, errors.New("host metric batch contains invalid UTF-8")
	}
	if err := json.Unmarshal(decoded, &batch); err != nil {
		return batch, err
	}
	return batch, validateHostMetricBatch(batch)
}

// Tail replays the whole retained stream, then follows new batches until
// cancellation. Consumer recreation resumes after the last handled sequence.
func (stream *HostMetricStream) Tail(ctx context.Context, history *History) error {
	stream.caughtUp.Store(false)
	defer stream.caughtUp.Store(false)
	if history == nil {
		return errors.New("host metric tail requires history")
	}
	var next uint64
	backoff := time.Second
	for ctx.Err() == nil {
		err := stream.tailHostMetricsOnce(ctx, history, &next)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		slog.Debug("host metric stream tail restarting", ComponentKey, "observability", "error", err)
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		backoff = min(backoff*2, 30*time.Second)
	}
	return ctx.Err()
}

func (stream *HostMetricStream) tailHostMetricsOnce(ctx context.Context, history *History, next *uint64) error {
	stream.caughtUp.Store(false)
	defer stream.caughtUp.Store(false)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	connection := stream.js.Conn()
	statuses := connection.StatusChanged(nats.RECONNECTING, nats.DISCONNECTED, nats.CLOSED)
	defer connection.RemoveStatusListener(statuses)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(hostMetricReplayWait)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-statuses:
				stream.caughtUp.Store(false)
				cancel()
				return
			case <-ticker.C:
				checkCtx, cancelCheck := context.WithTimeout(ctx, hostMetricReplayWait)
				_, err := stream.info(checkCtx)
				cancelCheck()
				if err != nil {
					stream.caughtUp.Store(false)
					cancel()
					return
				}
			}
		}
	}()
	defer func() { cancel(); <-done }()
	info, err := stream.info(ctx)
	if err != nil {
		return err
	}
	caughtUp := info.State.LastSeq
	config := jetstream.OrderedConsumerConfig{DeliverPolicy: jetstream.DeliverAllPolicy, FilterSubjects: []string{stream.subject}}
	if *next != 0 {
		config.DeliverPolicy, config.OptStartSeq = jetstream.DeliverByStartSequencePolicy, *next
	}
	consumer, err := stream.stream.OrderedConsumer(ctx, config)
	if err != nil {
		return err
	}
	messages, err := consumer.Messages()
	if err != nil {
		return err
	}
	defer messages.Stop()
	stop := context.AfterFunc(ctx, messages.Stop)
	defer stop()
	if ctx.Err() == nil && (info.State.Msgs == 0 || *next > caughtUp) {
		stream.caughtUp.Store(true)
	}
	type replayRecord struct {
		sequence uint64
		data     []byte
	}
	// Bound buffered payloads and validate one generation per chunk, not per minute.
	pending := make([]replayRecord, 0, hostMetricReplayChunk)
	readNext := *next
	flush := func() (*jetstream.StreamInfo, error) {
		info, err := stream.info(ctx)
		if err != nil {
			return nil, err
		}
		for _, record := range pending {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if batch, err := decodeHostMetricBatch(record.data); err == nil {
				if batch.Incomplete {
					stream.archiveIncomplete.Store(true)
				}
				history.Append(batch.At, batch.Samples)
			} else {
				stream.rejectReplayBatch(record.sequence)
			}
			*next = record.sequence + 1
		}
		clear(pending)
		pending = pending[:0]
		if ctx.Err() == nil && *next > caughtUp {
			stream.caughtUp.Store(true)
		}
		return info, nil
	}
	for {
		nextCtx, cancelNext := context.WithTimeout(ctx, hostMetricReplayWait)
		message, err := messages.Next(jetstream.NextContext(nextCtx))
		cancelNext()
		if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
			info, err := flush()
			if err != nil {
				return err
			}
			// Retention may remove the replay target before it can be delivered.
			if ctx.Err() == nil && (info.State.Msgs == 0 || *next > info.State.LastSeq) {
				stream.caughtUp.Store(true)
			}
			continue // NextContext deadlines leave the iterator usable.
		}
		if err != nil {
			return err
		}
		if message.Subject() != stream.subject {
			return errors.New("host metric replay crossed stream generation")
		}
		metadata, err := message.Metadata()
		if err != nil {
			return err
		}
		sequence := metadata.Sequence.Stream
		if sequence < readNext {
			continue
		}
		pending = append(pending, replayRecord{sequence: sequence, data: message.Data()})
		readNext = sequence + 1
		if len(pending) == hostMetricReplayChunk || sequence >= caughtUp {
			if _, err := flush(); err != nil {
				return err
			}
		}
	}
}
