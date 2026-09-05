package restoredrill

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/klauspost/compress/s2"
	"github.com/nats-io/nats.go"

	"terrascale.tech/orchestrator/src/orchestrator/delivery"
)

const (
	defaultJetStreamSnapshotBytes   = 64 << 20
	defaultJetStreamSnapshotTimeout = 10 * time.Minute
)

var snapshotSHA256Pattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// SnapshotObjectStore is the durable provider boundary required by the NATS
// snapshot adapter. HEAD is mandatory because an acknowledged PUT alone is
// not proof that the snapshot is readable from Object Storage.
// Put must atomically create an immutable object without overwriting an existing
// key. A retry may succeed only when the stored bytes are identical. This
// requirement applies across snapshotter instances and process restarts.
type SnapshotObjectStore interface {
	delivery.RegionObjectStore
	delivery.RegionObjectStoreInspector
	GetSnapshot(context.Context, string, string, string) ([]byte, bool, error)
}

type NATSJetStreamSnapshotterConfig struct {
	Connection *nats.Conn
	Stream     string
	Store      SnapshotObjectStore
	Region     string
	Bucket     string
	MaxBytes   int64
	Timeout    time.Duration
	Now        func() time.Time
}

// NATSJetStreamSnapshotter requests the server's binary stream snapshot and
// uploads a versioned envelope containing those exact bytes and the API metadata
// needed to restore them to the control Region's Object Storage bucket.
type NATSJetStreamSnapshotter struct {
	connection *nats.Conn
	stream     string
	store      SnapshotObjectStore
	region     string
	bucket     string
	maxBytes   int64
	timeout    time.Duration
	now        func() time.Time
	mu         sync.Mutex
}

func NewNATSJetStreamSnapshotter(config NATSJetStreamSnapshotterConfig) (*NATSJetStreamSnapshotter, error) {
	if config.Connection == nil || config.Connection.IsClosed() || config.Store == nil ||
		!validNATSStreamName(config.Stream) || config.Region == "" || config.Bucket == "" {
		return nil, fmt.Errorf("%w: NATS JetStream snapshotter", ErrProductionDependency)
	}
	if config.MaxBytes == 0 {
		config.MaxBytes = defaultJetStreamSnapshotBytes
	}
	if config.MaxBytes < 1024 || config.MaxBytes > 1<<30 {
		return nil, ErrInvalidSnapshotIdentity
	}
	if config.Timeout == 0 {
		config.Timeout = defaultJetStreamSnapshotTimeout
	}
	if config.Timeout <= 0 || config.Timeout > defaultJetStreamSnapshotTimeout {
		return nil, ErrInvalidSnapshotIdentity
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &NATSJetStreamSnapshotter{
		connection: config.Connection, stream: config.Stream, store: config.Store,
		region: config.Region, bucket: config.Bucket, maxBytes: config.MaxBytes,
		timeout: config.Timeout, now: config.Now,
	}, nil
}

func (s *NATSJetStreamSnapshotter) Snapshot(ctx context.Context, request SnapshotRequest) (ControlStateSnapshot, error) {
	if s == nil || s.connection == nil || s.store == nil {
		return ControlStateSnapshot{}, fmt.Errorf("%w: NATS JetStream snapshotter", ErrProductionDependency)
	}
	if ctx == nil {
		return ControlStateSnapshot{}, errors.New("restore drill: snapshot context is required")
	}
	if !validToken(request.RunID) || !validToken(request.ObjectKey) || !validToken(request.IdempotencyKey) ||
		request.RunID != request.IdempotencyKey || request.ControlEpoch == 0 ||
		!strings.HasSuffix(request.ObjectKey, ".epoch-"+strconv.FormatUint(request.ControlEpoch, 10)+".snapshot") {
		return ControlStateSnapshot{}, ErrInvalidSnapshotIdentity
	}
	operationCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, found, err := s.store.Head(operationCtx, s.region, s.bucket, request.ObjectKey); err != nil {
		return ControlStateSnapshot{}, err
	} else if found {
		body, bodyFound, readErr := s.store.GetSnapshot(operationCtx, s.region, s.bucket, request.ObjectKey)
		if readErr != nil {
			return ControlStateSnapshot{}, readErr
		}
		if !bodyFound || int64(len(body)) != existing.Size || !delivery.SameDigest(delivery.SHA256Digest(body), existing.Digest) {
			return ControlStateSnapshot{}, ErrSnapshotVerification
		}
		manifest, _, err := decodeJetStreamSnapshotEnvelope(body, s.stream, s.maxBytes)
		if err != nil {
			return ControlStateSnapshot{}, err
		}
		if manifest.Request != request {
			return ControlStateSnapshot{}, ErrSnapshotVerification
		}
		return s.snapshotIdentity(request, existing, manifest.CreatedAt)
	}

	archive, response, err := s.streamSnapshot(operationCtx)
	if err != nil {
		return ControlStateSnapshot{}, err
	}
	manifest := jetStreamSnapshotManifest{Version: 3, Stream: s.stream, Request: request, CreatedAt: s.now().UTC(), Config: response.Config, State: response.State, Consumers: response.Consumers, ArchiveSHA256: delivery.SHA256Digest(archive), ArchiveSize: int64(len(archive))}
	data, err := encodeJetStreamSnapshotEnvelope(manifest, archive, s.maxBytes)
	if err != nil {
		return ControlStateSnapshot{}, err
	}
	if _, _, err := decodeJetStreamSnapshotEnvelope(data, s.stream, s.maxBytes); err != nil {
		return ControlStateSnapshot{}, err
	}
	if err := s.store.Put(operationCtx, s.region, s.bucket, request.ObjectKey, data); err != nil {
		return ControlStateSnapshot{}, err
	}
	identity, found, err := s.store.Head(operationCtx, s.region, s.bucket, request.ObjectKey)
	if err != nil {
		return ControlStateSnapshot{}, err
	}
	want := delivery.ObjectIdentity{Digest: delivery.SHA256Digest(data), Size: int64(len(data))}
	if !found || identity.Size != want.Size || !delivery.SameDigest(identity.Digest, want.Digest) || identity.ETag == "" {
		return ControlStateSnapshot{}, ErrSnapshotVerification
	}
	stored, readable, err := s.store.GetSnapshot(operationCtx, s.region, s.bucket, request.ObjectKey)
	if err != nil {
		return ControlStateSnapshot{}, err
	}
	if !readable || !bytes.Equal(stored, data) {
		return ControlStateSnapshot{}, ErrSnapshotVerification
	}
	return s.snapshotIdentity(request, identity, manifest.CreatedAt)
}

type natsSnapshotRequest struct {
	DeliverSubject string `json:"deliver_subject"`
	NoConsumers    bool   `json:"no_consumers,omitempty"`
	ChunkSize      int    `json:"chunk_size,omitempty"`
	CheckMessages  bool   `json:"jsck,omitempty"`
}

type natsSnapshotResponse struct {
	Consumers []natsSnapshotConsumer `json:"-"`
	Type      string                 `json:"type"`
	Error     *natsAPIError          `json:"error,omitempty"`
	Config    json.RawMessage        `json:"config,omitempty"`
	State     *natsSnapshotState     `json:"state,omitempty"`
}

type natsSnapshotState = nats.StreamState

type natsAPIError struct {
	Code        int    `json:"code"`
	ErrCode     int    `json:"err_code"`
	Description string `json:"description"`
}

func (s *NATSJetStreamSnapshotter) streamSnapshot(ctx context.Context) ([]byte, natsSnapshotResponse, error) {
	before, err := s.consumerInventory(ctx)
	if err != nil {
		return nil, natsSnapshotResponse{}, err
	}
	inbox := nats.NewInbox()
	subscription, err := s.connection.SubscribeSync(inbox)
	if err != nil {
		return nil, natsSnapshotResponse{}, err
	}
	defer subscription.Unsubscribe()
	if err := s.connection.FlushWithContext(ctx); err != nil {
		return nil, natsSnapshotResponse{}, err
	}
	payload, err := json.Marshal(natsSnapshotRequest{
		DeliverSubject: inbox, NoConsumers: false, ChunkSize: snapshotChunkBytes, CheckMessages: true,
	})
	if err != nil {
		return nil, natsSnapshotResponse{}, err
	}
	reply, err := s.connection.RequestWithContext(ctx, "$JS.API.STREAM.SNAPSHOT."+s.stream, payload)
	if err != nil {
		return nil, natsSnapshotResponse{}, err
	}
	var response natsSnapshotResponse
	decoder := json.NewDecoder(bytes.NewReader(reply.Data))
	if err := decoder.Decode(&response); err != nil {
		return nil, natsSnapshotResponse{}, errors.New("restore drill: JetStream snapshot response is malformed")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, natsSnapshotResponse{}, errors.New("restore drill: JetStream snapshot response has trailing data")
	}
	if response.Error != nil {
		return nil, natsSnapshotResponse{}, fmt.Errorf("restore drill: JetStream snapshot request failed with code %d", response.Error.ErrCode)
	}
	if response.Type != "io.nats.jetstream.api.v1.stream_snapshot_response" || len(response.Config) == 0 || response.State == nil {
		return nil, natsSnapshotResponse{}, errors.New("restore drill: JetStream snapshot response has no stream state")
	}

	var snapshot bytes.Buffer
	transfer := snapshotTransfer{stream: s.stream}
	for {
		message, err := subscription.NextMsgWithContext(ctx)
		if err != nil {
			return nil, natsSnapshotResponse{}, err
		}
		complete, err := transfer.accept(message)
		if err != nil {
			return nil, natsSnapshotResponse{}, err
		}
		if complete {
			break
		}
		if int64(snapshot.Len()) > s.maxBytes-int64(len(message.Data)) {
			return nil, natsSnapshotResponse{}, errors.New("restore drill: JetStream snapshot exceeds the configured limit")
		}
		if _, err := snapshot.Write(message.Data); err != nil {
			return nil, natsSnapshotResponse{}, err
		}
		if message.Reply != "" {
			if err := message.Respond(nil); err != nil {
				return nil, natsSnapshotResponse{}, err
			}
		}
	}
	if snapshot.Len() == 0 {
		return nil, natsSnapshotResponse{}, errors.New("restore drill: JetStream returned an empty snapshot")
	}
	after, err := s.consumerInventory(ctx)
	if err != nil {
		return nil, natsSnapshotResponse{}, err
	}
	if !sameSnapshotConsumers(before, after) || len(before) != response.State.Consumers {
		return nil, natsSnapshotResponse{}, fmt.Errorf("%w: consumer inventory changed during snapshot", ErrSnapshotVerification)
	}
	response.Consumers = before
	return snapshot.Bytes(), response, nil
}

func (s *NATSJetStreamSnapshotter) snapshotIdentity(request SnapshotRequest, identity delivery.ObjectIdentity, createdAt time.Time) (ControlStateSnapshot, error) {
	if identity.Size <= 0 || !snapshotSHA256Pattern.MatchString(identity.Digest) || identity.ETag == "" {
		return ControlStateSnapshot{}, ErrSnapshotVerification
	}
	digest := strings.TrimPrefix(identity.Digest, "sha256:")
	return ControlStateSnapshot{
		ID: "jetstream-" + digest[:16], ObjectKey: request.ObjectKey,
		Checksum: identity.Digest, Size: identity.Size,
		ControlEpoch: request.ControlEpoch,
		CreatedAt:    createdAt,
	}, nil
}

func validNATSStreamName(value string) bool {
	if value == "" || len(value) > 255 {
		return false
	}
	for _, current := range value {
		if (current < 'A' || current > 'Z') && (current < 'a' || current > 'z') &&
			(current < '0' || current > '9') && current != '_' && current != '-' {
			return false
		}
	}
	return true
}

func validateJetStreamSnapshot(data []byte, stream string, maximum int64, config json.RawMessage, state *natsSnapshotState, inventory []natsSnapshotConsumer) error {
	if len(data) == 0 || int64(len(data)) > maximum || state == nil {
		return ErrSnapshotVerification
	}
	compressed := s2.NewReader(bytes.NewReader(data))
	expandedReader := &io.LimitedReader{R: compressed, N: maximum*8 + 1}
	archive := tar.NewReader(expandedReader)
	if state.Msgs == 0 {
		if state.Bytes != 0 || (state.LastSeq == 0 && state.FirstSeq != 0) || (state.LastSeq > 0 && (state.LastSeq == ^uint64(0) || state.FirstSeq != state.LastSeq+1)) {
			return ErrSnapshotVerification
		}
	} else if state.Bytes == 0 || state.FirstSeq == 0 || state.LastSeq < state.FirstSeq || state.Msgs > state.LastSeq-state.FirstSeq+1 {
		return ErrSnapshotVerification
	}
	meta, checksum, messages := false, false, false
	seen := map[string]bool{}
	consumers := map[string]map[string]bool{}
	expectedConsumers := map[string]natsSnapshotConsumer{}
	if inventory == nil || len(inventory) != state.Consumers || len(inventory) > maximumSnapshotConsumers {
		return fmt.Errorf("%w: consumer inventory missing", ErrSnapshotVerification)
	}
	for i, c := range inventory {
		if !validNATSStreamName(c.Name) || c.Created.IsZero() || (i > 0 && c.Name <= inventory[i-1].Name) || c.MemoryStorage && c.Durable != "" {
			return fmt.Errorf("%w: consumer inventory invalid", ErrSnapshotVerification)
		}
		if c.MemoryStorage && c.Checkpoint != nil || !c.MemoryStorage && (c.Checkpoint == nil || !validSnapshotCheckpoint(*c.Checkpoint, c.Name)) {
			return fmt.Errorf("%w: consumer checkpoint evidence invalid", ErrSnapshotVerification)
		}
		if !c.MemoryStorage {
			expectedConsumers[c.Name] = c
		}
	}
	var expanded int64
	for {
		header, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil || header == nil || header.Name == "" || path.IsAbs(header.Name) || path.Clean(header.Name) != header.Name || strings.HasPrefix(header.Name, "../") || header.Name == ".." || seen[header.Name] || header.Size < 0 ||
			(header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA) {
			return ErrSnapshotVerification
		}
		seen[header.Name] = true
		if expanded > maximum*8-header.Size {
			return ErrSnapshotVerification
		}
		expanded += header.Size
		switch {
		case header.Name == "meta.inf":
			body, err := io.ReadAll(io.LimitReader(archive, header.Size+1))
			if err != nil || int64(len(body)) != header.Size {
				return ErrSnapshotVerification
			}
			var archived, expected map[string]json.RawMessage
			if json.Unmarshal(body, &archived) != nil || json.Unmarshal(config, &expected) != nil || archived == nil || expected == nil {
				return ErrSnapshotVerification
			}
			delete(archived, "Created")
			actualJSON, _ := json.Marshal(archived)
			actualJSON, _ = canonicalSnapshotJSON(actualJSON)
			expectedJSON, _ := canonicalSnapshotJSON(config)
			if !bytes.Equal(actualJSON, expectedJSON) {
				return ErrSnapshotVerification
			}
			var name string
			if json.Unmarshal(expected["name"], &name) != nil || name != stream {
				return ErrSnapshotVerification
			}
			meta = true
		case header.Name == "meta.sum":
			if _, err := io.Copy(io.Discard, archive); err != nil {
				return ErrSnapshotVerification
			}
			checksum = header.Size > 0
		case strings.HasPrefix(header.Name, "msgs/") && strings.HasSuffix(header.Name, ".blk") && header.Size > 0:
			if _, err := io.Copy(io.Discard, archive); err != nil {
				return ErrSnapshotVerification
			}
			messages = true
		case strings.HasPrefix(header.Name, "obs/"):
			parts := strings.Split(header.Name, "/")
			if len(parts) != 3 || !validNATSStreamName(parts[1]) || (parts[2] != "meta.inf" && parts[2] != "meta.sum" && parts[2] != "o.dat") || header.Size == 0 {
				return ErrSnapshotVerification
			}
			expected, known := expectedConsumers[parts[1]]
			if !known {
				return fmt.Errorf("%w: unexpected archived consumer", ErrSnapshotVerification)
			}
			if parts[2] == "meta.inf" {
				body, err := io.ReadAll(io.LimitReader(archive, header.Size+1))
				var metadata struct {
					StoredName    string `json:"Name"`
					Name          string `json:"name"`
					Durable       string `json:"durable_name"`
					MemoryStorage bool   `json:"mem_storage"`
				}
				if err != nil || int64(len(body)) != header.Size || json.Unmarshal(body, &metadata) != nil || metadata.StoredName != expected.Name || metadata.Name != expected.Name || metadata.Durable != expected.Durable || metadata.MemoryStorage {
					return fmt.Errorf("%w: archived consumer metadata differs", ErrSnapshotVerification)
				}
			}
			if consumers[parts[1]] == nil {
				consumers[parts[1]] = map[string]bool{}
			}
			consumers[parts[1]][parts[2]] = true
			if _, err := io.Copy(io.Discard, archive); err != nil {
				return ErrSnapshotVerification
			}
		default:
			if !strings.HasPrefix(header.Name, "msgs/") {
				return ErrSnapshotVerification
			}
			if _, err := io.Copy(io.Discard, archive); err != nil {
				return ErrSnapshotVerification
			}
		}
	}
	// Force the S2 decoder through its trailer: tar EOF alone does not check
	// truncated compressed frames or bytes concatenated after the tar archive.
	trailing, err := io.ReadAll(io.LimitReader(expandedReader, 1))
	if err != nil || len(trailing) != 0 || expandedReader.N == 0 {
		return ErrSnapshotVerification
	}
	if len(consumers) != len(expectedConsumers) {
		return ErrSnapshotVerification
	}
	for _, files := range consumers {
		if len(files) != 3 {
			return ErrSnapshotVerification
		}
	}
	if !meta || !checksum || ((!messages) && (state.Msgs != 0 || state.FirstSeq != 0 || state.LastSeq != 0)) {
		return ErrSnapshotVerification
	}
	return nil
}

var _ JetStreamSnapshotter = (*NATSJetStreamSnapshotter)(nil)
