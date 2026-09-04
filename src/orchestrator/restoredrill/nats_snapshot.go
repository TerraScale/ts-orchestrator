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
// uploads those exact bytes to the control Region's Object Storage bucket.
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
		request.RunID != request.IdempotencyKey || request.ControlEpoch == 0 || request.RestoreEpoch == 0 ||
		request.ControlEpoch != request.RestoreEpoch ||
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
		if err := validateJetStreamSnapshot(body, s.stream, s.maxBytes); err != nil {
			return ControlStateSnapshot{}, err
		}
		return s.snapshotIdentity(request, existing)
	}

	data, err := s.streamSnapshot(operationCtx)
	if err != nil {
		return ControlStateSnapshot{}, err
	}
	if err := validateJetStreamSnapshot(data, s.stream, s.maxBytes); err != nil {
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
	return s.snapshotIdentity(request, identity)
}

type natsSnapshotRequest struct {
	DeliverSubject string `json:"deliver_subject"`
	NoConsumers    bool   `json:"no_consumers,omitempty"`
	ChunkSize      int    `json:"chunk_size,omitempty"`
	CheckMessages  bool   `json:"jsck,omitempty"`
}

type natsSnapshotResponse struct {
	Type   string             `json:"type"`
	Error  *natsAPIError      `json:"error,omitempty"`
	Config json.RawMessage    `json:"config,omitempty"`
	State  *natsSnapshotState `json:"state,omitempty"`
}

type natsSnapshotState struct {
	Messages uint64 `json:"messages"`
}

type natsAPIError struct {
	Code        int    `json:"code"`
	ErrCode     int    `json:"err_code"`
	Description string `json:"description"`
}

func (s *NATSJetStreamSnapshotter) streamSnapshot(ctx context.Context) ([]byte, error) {
	inbox := nats.NewInbox()
	subscription, err := s.connection.SubscribeSync(inbox)
	if err != nil {
		return nil, err
	}
	defer subscription.Unsubscribe()
	if err := s.connection.FlushWithContext(ctx); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(natsSnapshotRequest{
		DeliverSubject: inbox, NoConsumers: false, ChunkSize: 1 << 20, CheckMessages: true,
	})
	if err != nil {
		return nil, err
	}
	reply, err := s.connection.RequestWithContext(ctx, "$JS.API.STREAM.SNAPSHOT."+s.stream, payload)
	if err != nil {
		return nil, err
	}
	var response natsSnapshotResponse
	decoder := json.NewDecoder(bytes.NewReader(reply.Data))
	if err := decoder.Decode(&response); err != nil {
		return nil, errors.New("restore drill: JetStream snapshot response is malformed")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, errors.New("restore drill: JetStream snapshot response has trailing data")
	}
	if response.Error != nil {
		return nil, fmt.Errorf("restore drill: JetStream snapshot request failed with code %d", response.Error.ErrCode)
	}
	if response.Type != "io.nats.jetstream.api.v1.stream_snapshot_response" || len(response.Config) == 0 || response.State == nil || response.State.Messages == 0 {
		return nil, errors.New("restore drill: JetStream snapshot response has no stream state")
	}

	var snapshot bytes.Buffer
	for {
		message, err := subscription.NextMsgWithContext(ctx)
		if err != nil {
			return nil, err
		}
		if len(message.Data) == 0 {
			break
		}
		if int64(snapshot.Len()) > s.maxBytes-int64(len(message.Data)) {
			return nil, errors.New("restore drill: JetStream snapshot exceeds the configured limit")
		}
		if _, err := snapshot.Write(message.Data); err != nil {
			return nil, err
		}
		if message.Reply != "" {
			if err := message.Respond(nil); err != nil {
				return nil, err
			}
		}
	}
	if snapshot.Len() == 0 {
		return nil, errors.New("restore drill: JetStream returned an empty snapshot")
	}
	return snapshot.Bytes(), nil
}

func (s *NATSJetStreamSnapshotter) snapshotIdentity(request SnapshotRequest, identity delivery.ObjectIdentity) (ControlStateSnapshot, error) {
	if identity.Size <= 0 || !snapshotSHA256Pattern.MatchString(identity.Digest) || identity.ETag == "" {
		return ControlStateSnapshot{}, ErrSnapshotVerification
	}
	digest := strings.TrimPrefix(identity.Digest, "sha256:")
	return ControlStateSnapshot{
		ID: "jetstream-" + digest[:16], ObjectKey: request.ObjectKey,
		Checksum: identity.Digest, Size: identity.Size,
		ControlEpoch: request.ControlEpoch, RestoreEpoch: request.RestoreEpoch,
		CreatedAt: s.now().UTC(),
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

func validateJetStreamSnapshot(data []byte, stream string, maximum int64) error {
	if len(data) == 0 || int64(len(data)) > maximum {
		return ErrSnapshotVerification
	}
	archive := tar.NewReader(s2.NewReader(bytes.NewReader(data)))
	meta, checksum, messages := false, false, false
	var expanded int64
	for {
		header, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil || header == nil || header.Name == "" || path.IsAbs(header.Name) || path.Clean(header.Name) != header.Name || header.Size < 0 ||
			(header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA) {
			return ErrSnapshotVerification
		}
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
			var config struct {
				Name string `json:"name"`
			}
			if json.Unmarshal(body, &config) != nil || config.Name != stream {
				return ErrSnapshotVerification
			}
			meta = true
		case header.Name == "meta.sum":
			if _, err := io.Copy(io.Discard, archive); err != nil {
				return ErrSnapshotVerification
			}
			checksum = header.Size > 0
		case strings.HasPrefix(header.Name, "msgs/") && header.Size > 0:
			if _, err := io.Copy(io.Discard, archive); err != nil {
				return ErrSnapshotVerification
			}
			messages = true
		default:
			if _, err := io.Copy(io.Discard, archive); err != nil {
				return ErrSnapshotVerification
			}
		}
	}
	if !meta || !checksum || !messages {
		return ErrSnapshotVerification
	}
	return nil
}

var _ JetStreamSnapshotter = (*NATSJetStreamSnapshotter)(nil)
