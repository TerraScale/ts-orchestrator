package delivery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const (
	AdmissionBucket = "TS_DELIVERY_ADMISSIONS"
	OperationBucket = "TS_DELIVERY_OPERATIONS"
	IntentStream    = "TS_DELIVERY_INTENTS"
	IntentConsumer  = "TS_DELIVERY_WORKER"
)

// VerifiedEnvelope is returned only after a trusted signature was verified
// over the exact payload bytes.
type VerifiedEnvelope struct {
	Payload []byte
	Actor   string
}

type Signer interface {
	Sign(context.Context, []byte) ([]byte, error)
}

type Verifier interface {
	Verify(context.Context, []byte) (VerifiedEnvelope, error)
}

type ArtifactSigner interface {
	SignArtifact(context.Context, ArtifactRecord) ([]byte, error)
}

type ArtifactVerifier interface {
	VerifyArtifact(context.Context, []byte) (ArtifactRecord, string, error)
	VerifyArchivedArtifact(context.Context, []byte) (ArtifactRecord, string, error)
}

type Fencer interface {
	Current() authority.Snapshot
	Guard(context.Context, uint64) error
}

type Planner interface {
	Plan(context.Context, Intent) ([]host.Desired, error)
}

type DesiredWriter interface {
	ApplyDesired(context.Context, host.Desired) (host.Receipt, error)
}

type Config struct {
	Conn                  *nats.Conn
	JS                    jetstream.JetStream
	Cell                  string
	Replicas              int
	ArtifactStoreMaxBytes int64
	Signer                Signer
	Verifier              Verifier
	ArtifactSigner        ArtifactSigner
	ArtifactVerifier      ArtifactVerifier
	AuthorizeArtifact     func(context.Context, string, ArtifactRecord) error
	Authorize             func(context.Context, string, Intent) error
	Fencer                Fencer
	Planner               Planner
	Writer                DesiredWriter
}

type Service struct {
	js         jetstream.JetStream
	artifacts  jetstream.ObjectStore
	admissions jetstream.KeyValue
	operations jetstream.KeyValue
	consumer   jetstream.Consumer
	config     Config
}

// Receipt is a durable admission outcome. "accepted" means each planned host
// desired write was accepted; it does not claim the guest is running or ready.
// Host reports provide observed runtime readiness separately.
type Receipt struct {
	OperationID    string `json:"operationId"`
	Fingerprint    string `json:"fingerprint"`
	Status         string `json:"status"`
	Error          string `json:"error,omitempty"`
	ArtifactDigest string `json:"artifactDigest"`
	ManifestDigest string `json:"manifestDigest"`
	Cell           string `json:"cell"`
	Role           string `json:"role"`
	Environment    string `json:"environment"`
	Generation     uint64 `json:"generation"`
	AuthorityEpoch uint64 `json:"authorityEpoch"`
}

type operation struct {
	Intent      Intent         `json:"intent"`
	Fingerprint string         `json:"fingerprint"`
	Actor       string         `json:"actor"`
	Plan        []host.Desired `json:"plan"`
	Receipt     *Receipt       `json:"receipt,omitempty"`
}

func IntentSubject(cell string) string { return "ts.orch.v1." + cell + ".delivery.intent" }

// ConnectClient binds existing regional resources without managing topology.
// Operator and CI identities should use this path with only their specific
// artifact, admission, operation-read and intent-publish permissions.
func ConnectClient(ctx context.Context, cfg Config) (*Service, error) {
	if cfg.Conn == nil || cfg.JS == nil || !nameRE.MatchString(cfg.Cell) {
		return nil, fmt.Errorf("%w: delivery client configuration", ErrInvalid)
	}
	s := &Service{js: cfg.JS, config: cfg}
	var err error
	s.artifacts, err = cfg.JS.ObjectStore(ctx, ArtifactBucket)
	if err != nil {
		return nil, fmt.Errorf("bind artifact store: %w", err)
	}
	s.admissions, err = cfg.JS.KeyValue(ctx, AdmissionBucket)
	if err != nil {
		return nil, fmt.Errorf("bind artifact admissions: %w", err)
	}
	s.operations, err = cfg.JS.KeyValue(ctx, OperationBucket)
	if err != nil {
		return nil, fmt.Errorf("bind delivery operations: %w", err)
	}
	return s, nil
}

// Open provisions the durable regional resources and may be used by CLI
// commands without starting a consumer. Serve requires the controller ports.
func Open(ctx context.Context, cfg Config) (*Service, error) {
	if cfg.Conn == nil || cfg.JS == nil || !nameRE.MatchString(cfg.Cell) || cfg.Replicas != 1 && cfg.Replicas != 3 && cfg.Replicas != 5 || cfg.ArtifactStoreMaxBytes < 0 {
		return nil, fmt.Errorf("%w: delivery service configuration", ErrInvalid)
	}
	artifactStoreMaxBytes := cfg.ArtifactStoreMaxBytes
	if artifactStoreMaxBytes == 0 {
		artifactStoreMaxBytes = DefaultArtifactStoreMaxBytes
	}
	s := &Service{js: cfg.JS, config: cfg}
	var err error
	s.artifacts, err = cfg.JS.CreateOrUpdateObjectStore(ctx, jetstream.ObjectStoreConfig{Bucket: ArtifactBucket, Storage: jetstream.FileStorage, Replicas: cfg.Replicas, MaxBytes: artifactStoreMaxBytes})
	if err != nil {
		return nil, fmt.Errorf("artifact store: %w", err)
	}
	stream, err := cfg.JS.Stream(ctx, "OBJ_"+ArtifactBucket)
	if err != nil {
		return nil, fmt.Errorf("inspect artifact store limits: %w", err)
	}
	streamInfo, err := stream.Info(ctx)
	if err != nil {
		return nil, fmt.Errorf("inspect artifact store limits: %w", err)
	}
	if streamInfo.Config.MaxBytes != artifactStoreMaxBytes || streamInfo.Config.Discard != jetstream.DiscardNew {
		return nil, fmt.Errorf("%w: artifact store must enforce the configured byte quota with discard-new", ErrInvalid)
	}
	s.admissions, err = cfg.JS.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: AdmissionBucket, Storage: jetstream.FileStorage, Replicas: cfg.Replicas, History: 1})
	if err != nil {
		return nil, fmt.Errorf("artifact admissions: %w", err)
	}
	s.operations, err = cfg.JS.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: OperationBucket, Storage: jetstream.FileStorage, Replicas: cfg.Replicas, History: 4})
	if err != nil {
		return nil, fmt.Errorf("delivery operations: %w", err)
	}
	_, err = cfg.JS.CreateOrUpdateStream(ctx, jetstream.StreamConfig{Name: IntentStream, Subjects: []string{IntentSubject(cfg.Cell)}, Storage: jetstream.FileStorage, Replicas: cfg.Replicas, Retention: jetstream.WorkQueuePolicy, Discard: jetstream.DiscardNew, MaxMsgs: 100_000, MaxBytes: 1 << 30, MaxMsgSize: MaxIntentBytes + 8192, Duplicates: 2 * time.Minute})
	if err != nil {
		return nil, fmt.Errorf("delivery intent stream: %w", err)
	}
	s.consumer, err = cfg.JS.CreateOrUpdateConsumer(ctx, IntentStream, jetstream.ConsumerConfig{Durable: IntentConsumer, FilterSubject: IntentSubject(cfg.Cell), AckPolicy: jetstream.AckExplicitPolicy, AckWait: 30 * time.Second, MaxDeliver: -1, MaxAckPending: 32, MaxRequestBatch: 1})
	if err != nil {
		return nil, fmt.Errorf("delivery intent consumer: %w", err)
	}
	return s, nil
}

// Submit signs exact serialized intent bytes and waits for JetStream publish
// acknowledgement. Status returns the later durable acceptance receipt.
func (s *Service) Submit(ctx context.Context, intent Intent) error {
	if s == nil || s.config.Signer == nil {
		return errors.New("delivery signer is not configured")
	}
	if err := intent.Validate(); err != nil {
		return err
	}
	if intent.Cell != s.config.Cell {
		return fmt.Errorf("%w: wrong cell", ErrInvalid)
	}
	b, err := json.Marshal(intent)
	if err != nil {
		return err
	}
	fingerprint, err := intent.fingerprint()
	if err != nil {
		return err
	}
	if existing, readErr := s.getOperation(ctx, operationKey(intent.OperationID)); readErr == nil {
		var op operation
		if err := json.Unmarshal(existing.Value(), &op); err != nil {
			return err
		}
		if op.Fingerprint != fingerprint {
			return ErrConflict
		}
	} else if !errors.Is(readErr, jetstream.ErrKeyNotFound) {
		return readErr
	}
	wire, err := s.config.Signer.Sign(ctx, b)
	if err != nil {
		return fmt.Errorf("sign delivery intent: %w", err)
	}
	if len(wire) > MaxIntentBytes+8192 {
		return fmt.Errorf("%w: signed intent too large", ErrInvalid)
	}
	_, err = s.js.Publish(ctx, IntentSubject(intent.Cell), wire, jetstream.WithMsgID(intent.OperationID+"."+fingerprint))
	if err != nil {
		return fmt.Errorf("publish delivery intent: %w", err)
	}
	return nil
}

func operationKey(id string) string {
	sum := sha256.Sum256([]byte(id))
	return "o_" + hex.EncodeToString(sum[:])
}

type operationValue struct {
	value    []byte
	revision uint64
}

func (e operationValue) Value() []byte    { return e.value }
func (e operationValue) Revision() uint64 { return e.revision }

// getOperation asks the stream leader for this exact KV subject. The normal
// KeyValue.Get path can use a follower when direct reads are enabled.
func (s *Service) getOperation(ctx context.Context, key string) (*operationValue, error) {
	if s == nil || s.config.Conn == nil {
		return nil, errors.New("delivery operation leader read requires NATS connection")
	}
	js, err := s.config.Conn.JetStream()
	if err != nil {
		return nil, err
	}
	subject := "$KV." + OperationBucket + "." + key
	msg, err := js.GetLastMsg("KV_"+OperationBucket, subject, nats.Context(ctx))
	if errors.Is(err, nats.ErrMsgNotFound) {
		return nil, jetstream.ErrKeyNotFound
	}
	if err != nil {
		return nil, err
	}
	return operationValueFromMsg(subject, msg)
}

func operationValueFromMsg(subject string, msg *nats.RawStreamMsg) (*operationValue, error) {
	if msg == nil || msg.Subject != subject || msg.Sequence == 0 {
		return nil, errors.New("invalid delivery operation state")
	}
	if operation := msg.Header.Get("KV-Operation"); operation != "" {
		if operation == "DEL" || operation == "PURGE" {
			return nil, jetstream.ErrKeyNotFound
		}
		return nil, errors.New("invalid delivery operation marker")
	}
	if marker := msg.Header.Get(jetstream.MarkerReasonHeader); marker != "" {
		if marker == "MaxAge" || marker == "Purge" || marker == "Remove" {
			return nil, jetstream.ErrKeyNotFound
		}
		return nil, errors.New("invalid delivery operation marker")
	}
	if len(msg.Data) == 0 {
		return nil, errors.New("invalid delivery operation body")
	}
	return &operationValue{value: msg.Data, revision: msg.Sequence}, nil
}

func (s *Service) Status(ctx context.Context, operationID string) (Receipt, error) {
	if s == nil || !opRE.MatchString(operationID) {
		return Receipt{}, ErrInvalid
	}
	e, err := s.getOperation(ctx, operationKey(operationID))
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return Receipt{}, ErrPending
	}
	if err != nil {
		return Receipt{}, err
	}
	var op operation
	if err := json.Unmarshal(e.Value(), &op); err != nil {
		return Receipt{}, fmt.Errorf("decode delivery status: %w", err)
	}
	if op.Intent.OperationID != operationID {
		return Receipt{}, ErrConflict
	}
	fingerprint, err := op.Intent.Fingerprint()
	if err != nil || fingerprint != op.Fingerprint {
		return Receipt{}, fmt.Errorf("%w: invalid durable operation fingerprint", ErrInvalid)
	}
	if op.Receipt == nil {
		return Receipt{}, ErrPending
	}
	if op.Receipt.OperationID != operationID || op.Receipt.Fingerprint != fingerprint || op.Receipt.ArtifactDigest != op.Intent.ArtifactDigest || op.Receipt.ManifestDigest != op.Intent.ManifestDigest {
		return Receipt{}, fmt.Errorf("%w: invalid durable delivery receipt", ErrInvalid)
	}
	return *op.Receipt, nil
}

func (s *Service) StatusFor(ctx context.Context, intent Intent) (Receipt, error) {
	fingerprint, err := intent.Fingerprint()
	if err != nil {
		return Receipt{}, err
	}
	r, err := s.Status(ctx, intent.OperationID)
	if err != nil {
		return Receipt{}, err
	}
	if r.Fingerprint != fingerprint {
		return Receipt{}, ErrConflict
	}
	return r, nil
}
