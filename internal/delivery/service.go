package delivery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const (
	AdmissionBucket = "TS_DELIVERY_ADMISSIONS"
	OperationBucket = "TS_DELIVERY_OPERATIONS"
	IntentStream    = "TS_DELIVERY_INTENTS"
	IntentConsumer  = "TS_DELIVERY_WORKER"

	intentPublishTimeout        = 10 * time.Second
	intentPublishAttemptTimeout = 2 * time.Second
	intentPublishInitialBackoff = 100 * time.Millisecond
	intentPublishMaxBackoff     = 800 * time.Millisecond
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

// ShapedPlanner is an optional Planner extension for roles whose replica count
// and host desired generation are owned by a continuous reconciler. The shape
// is recorded with the operation so a resumed delivery validates the same plan.
type ShapedPlanner interface {
	PlanShaped(context.Context, Intent) (PlanShape, []host.Desired, error)
}

// PlanShape is the desired generation and active replica count of a plan.
type PlanShape struct {
	Generation uint64 `json:"generation"`
	Replicas   int    `json:"replicas"`
}

type DesiredWriter interface {
	ApplyDesired(context.Context, host.Desired) (host.Receipt, error)
}

type Config struct {
	// ContainerApply admits the exact signed OCI release through SwarmKit and
	// returns only after application readiness. Replays must be idempotent.
	ContainerApply          func(context.Context, Intent) error
	CaptureContainerProfile func(context.Context, Intent) (string, error)
	Conn                    *nats.Conn
	JS                      jetstream.JetStream
	Cell                    string
	Replicas                int
	ArtifactStoreMaxBytes   int64
	Signer                  Signer
	Verifier                Verifier
	ArtifactSigner          ArtifactSigner
	ArtifactVerifier        ArtifactVerifier
	AuthorizeArtifact       func(context.Context, string, ArtifactRecord) error
	Authorize               func(context.Context, string, Intent) error
	Fencer                  Fencer
	Planner                 Planner
	Writer                  DesiredWriter
	// MaxPlannerAttempts bounds deliveries of an intent the planner keeps
	// refusing, such as a missing profile or no eligible host, before it is
	// held with a durable receipt. Zero uses DefaultMaxPlannerAttempts.
	// Transport and leadership failures never count toward it.
	MaxPlannerAttempts int
}

// DefaultMaxPlannerAttempts holds a planner-refused intent after roughly
// half an hour of capped redelivery backoff.
const DefaultMaxPlannerAttempts = 30

type Service struct {
	// recovery overrides deliveryConsumerRecovery, for tests.
	recovery   consumerRecovery
	js         jetstream.JetStream
	artifacts  jetstream.ObjectStore
	admissions jetstream.KeyValue
	operations jetstream.KeyValue
	consumer   jetstream.Consumer
	config     Config
	// plannerRefusals bounds an intent the planner keeps refusing.
	plannerRefusals plannerRefusalCounter
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
	ProfileRecord string         `json:"profileRecord,omitempty"`
	Intent        Intent         `json:"intent"`
	Fingerprint   string         `json:"fingerprint"`
	Actor         string         `json:"actor"`
	Plan          []host.Desired `json:"plan"`
	Shape         *PlanShape     `json:"shape,omitempty"`
	Receipt       *Receipt       `json:"receipt,omitempty"`
}

func IntentSubject(cell string) string { return protocol.DeliveryIntentSubject(cell) }

// validCell accepts a cell the protocol subject builders accept: a name
// token that is a canonical region and not the reserved global scope.
// Otherwise every delivery subject would be empty and fail far from the
// configuration as an opaque invalid-subject error.
func validCell(cell string) bool {
	if !nameRE.MatchString(cell) || cell == protocol.GlobalScope {
		return false
	}
	_, err := protocol.CanonicalRegion(cell)
	return err == nil
}

// ConnectClient binds existing regional resources without managing topology.
// Operator and CI identities should use this path with only their specific
// artifact, admission, operation-read and intent-publish permissions.
func ConnectClient(ctx context.Context, cfg Config) (*Service, error) {
	if cfg.Conn == nil || cfg.JS == nil || !validCell(cfg.Cell) {
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
	if cfg.Conn == nil || cfg.JS == nil || !validCell(cfg.Cell) || cfg.Replicas != 1 && cfg.Replicas != 3 && cfg.Replicas != 5 || cfg.ArtifactStoreMaxBytes < 0 {
		return nil, fmt.Errorf("%w: delivery service configuration", ErrInvalid)
	}
	artifactStoreMaxBytes := cfg.ArtifactStoreMaxBytes
	if artifactStoreMaxBytes == 0 {
		artifactStoreMaxBytes = DefaultArtifactStoreMaxBytes
	}
	// A larger quota already in force came from the cell spec
	// (artifact_store), which the leader re-applies; a restart must not
	// shrink the store under an upload before then.
	if existing, err := cfg.JS.Stream(ctx, "OBJ_"+ArtifactBucket); err == nil {
		artifactStoreMaxBytes = max(artifactStoreMaxBytes, existing.CachedInfo().Config.MaxBytes)
	} else if !errors.Is(err, jetstream.ErrStreamNotFound) {
		return nil, fmt.Errorf("inspect artifact store limits: %w", err)
	}
	s := &Service{js: cfg.JS, config: cfg}
	var err error
	s.artifacts, err = cfg.JS.CreateOrUpdateObjectStore(ctx, artifactStoreConfig(cfg.Replicas, artifactStoreMaxBytes))
	if err != nil {
		return nil, fmt.Errorf("artifact store: %w", err)
	}
	stream, err := cfg.JS.Stream(ctx, "OBJ_"+ArtifactBucket)
	if err != nil {
		if errors.Is(err, jetstream.ErrStreamNotFound) {
			return nil, fmt.Errorf("%w: inspect artifact store limits: %w", ErrStoreNotReady, err)
		}
		return nil, fmt.Errorf("inspect artifact store limits: %w", err)
	}
	streamInfo, err := stream.Info(ctx)
	if err != nil {
		if errors.Is(err, jetstream.ErrStreamNotFound) {
			return nil, fmt.Errorf("%w: inspect artifact store limits: %w", ErrStoreNotReady, err)
		}
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
	s.consumer, err = cfg.JS.CreateOrUpdateConsumer(ctx, IntentStream, intentConsumerConfig(cfg.Cell))
	if err != nil {
		return nil, fmt.Errorf("delivery intent consumer: %w", err)
	}
	return s, nil
}

// intentConsumerConfig keeps redelivery unbounded at the broker: a broker
// MaxDeliver would drop an intent without a receipt. The consumer bounds
// planner refusals itself and records a durable held receipt instead.
func intentConsumerConfig(cell string) jetstream.ConsumerConfig {
	return jetstream.ConsumerConfig{Durable: IntentConsumer, FilterSubject: IntentSubject(cell), AckPolicy: jetstream.AckExplicitPolicy, AckWait: 30 * time.Second, MaxDeliver: -1, MaxAckPending: 32, MaxRequestBatch: 1}
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
	if len(b) > MaxIntentBytes {
		return fmt.Errorf("%w: intent too large", ErrInvalid)
	}
	fingerprint, err := intent.fingerprint()
	if err != nil {
		return err
	}
	key := operationKey(intent.OperationID)
	if existing, readErr := retrySubmitOperationRead(ctx, func(readCtx context.Context) (*operationValue, error) {
		return s.getOperation(readCtx, key)
	}); readErr == nil {
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
	err = s.publishIntent(ctx, IntentSubject(intent.Cell), wire, intent.OperationID+"."+fingerprint)
	if err != nil {
		return fmt.Errorf("publish delivery intent: %w", err)
	}
	return nil
}

// SubmitVerified submits intent for actor, whose authority the controller
// already verified in process: a CI-signed release claim (TS-610). It
// records the intent's exact bytes as verified, as the consumer does after a
// signature check, then publishes them; the consumer authorizes actor again.
// Unsigned bytes without that record are rejected like any bad signature.
func (s *Service) SubmitVerified(ctx context.Context, intent Intent, actor string) error {
	if s == nil || s.operations == nil || s.config.Authorize == nil || actor == "" {
		return errors.New("verified delivery submission is not configured")
	}
	if err := intent.Validate(); err != nil {
		return err
	}
	if intent.Cell != s.config.Cell {
		return fmt.Errorf("%w: wrong cell", ErrInvalid)
	}
	if err := s.config.Authorize(ctx, actor, intent.Clone()); err != nil {
		return err
	}
	wire, err := json.Marshal(intent)
	if err != nil {
		return err
	}
	if len(wire) > MaxIntentBytes {
		return fmt.Errorf("%w: intent too large", ErrInvalid)
	}
	fingerprint, err := intent.fingerprint()
	if err != nil {
		return err
	}
	verified, err := json.Marshal(struct {
		Intent Intent `json:"intent"`
		Actor  string `json:"actor"`
	}{intent, actor})
	if err != nil {
		return err
	}
	sum := sha256.Sum256(wire)
	if _, err := s.operations.Create(ctx, entityid.Derive("delivery-verified", hex.EncodeToString(sum[:])), verified); err != nil && !errors.Is(err, jetstream.ErrKeyExists) {
		return fmt.Errorf("record verified delivery intent: %w", err)
	}
	if err := s.publishIntent(ctx, IntentSubject(intent.Cell), wire, intent.OperationID+"."+fingerprint); err != nil {
		return fmt.Errorf("publish delivery intent: %w", err)
	}
	return nil
}

// A transient leader-read failure must not turn a valid submit into a failed
// operation during cluster recovery. Only the read is retried; signing and
// publishing remain a single idempotent Submit pass after it succeeds.
func retrySubmitOperationRead(ctx context.Context, read func(context.Context) (*operationValue, error)) (*operationValue, error) {
	retryCtx, cancel := context.WithTimeout(ctx, intentPublishTimeout)
	defer cancel()

	backoff := intentPublishInitialBackoff
	var lastErr error
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := retryCtx.Err(); err != nil {
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, err
		}
		attemptCtx, stop := context.WithTimeout(retryCtx, intentPublishAttemptTimeout)
		value, err := read(attemptCtx)
		attemptExpired := errors.Is(attemptCtx.Err(), context.DeadlineExceeded)
		stop()
		if err == nil {
			return value, nil
		}
		lastErr = err
		if parentErr := ctx.Err(); parentErr != nil {
			return nil, parentErr
		}
		if retryCtx.Err() != nil || !retryableSubmitOperationReadError(err, attemptExpired) {
			return nil, err
		}
		timer := time.NewTimer(backoff)
		select {
		case <-timer.C:
		case <-retryCtx.Done():
			timer.Stop()
			if parentErr := ctx.Err(); parentErr != nil {
				return nil, parentErr
			}
			return nil, err
		}
		backoff = min(backoff*2, intentPublishMaxBackoff)
	}
}

func retryableSubmitOperationReadError(err error, attemptDeadlineExpired bool) bool {
	if errors.Is(err, nats.ErrNoResponders) || errors.Is(err, nats.ErrTimeout) ||
		errors.Is(err, nats.ErrDisconnected) || errors.Is(err, nats.ErrNoServers) {
		return true
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return attemptDeadlineExpired
	}
	if apiErr, ok := errors.AsType[*nats.APIError](err); ok {
		return apiErr.Code == 503 && apiErr.ErrorCode == 10008
	}
	return false
}

func (s *Service) publishIntent(ctx context.Context, subject string, wire []byte, msgID string) error {
	retryCtx, cancel := context.WithTimeout(ctx, intentPublishTimeout)
	defer cancel()

	backoff := intentPublishInitialBackoff
	var lastErr error
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := retryCtx.Err(); err != nil {
			if lastErr != nil {
				return lastErr
			}
			return err
		}

		attemptCtx, cancelAttempt := context.WithTimeout(retryCtx, intentPublishAttemptTimeout)
		_, publishErr := s.js.Publish(attemptCtx, subject, wire, jetstream.WithMsgID(msgID), jetstream.WithRetryAttempts(0))
		attemptErr := attemptCtx.Err()
		cancelAttempt()
		if publishErr == nil {
			return nil
		}
		lastErr = publishErr
		if err := ctx.Err(); err != nil {
			return err
		}
		if retryCtx.Err() != nil {
			return publishErr
		}
		if !retryableIntentPublishError(publishErr, errors.Is(attemptErr, context.DeadlineExceeded)) {
			return publishErr
		}
		timer := time.NewTimer(backoff)
		select {
		case <-timer.C:
		case <-retryCtx.Done():
			timer.Stop()
			if err := ctx.Err(); err != nil {
				return err
			}
			return publishErr
		}
		backoff = min(backoff*2, intentPublishMaxBackoff)
	}
}

func retryableIntentPublishError(err error, attemptDeadlineExpired bool) bool {
	if errors.Is(err, jetstream.ErrNoStreamResponse) ||
		errors.Is(err, nats.ErrNoResponders) ||
		errors.Is(err, nats.ErrTimeout) ||
		errors.Is(err, nats.ErrDisconnected) ||
		errors.Is(err, nats.ErrNoServers) {
		return true
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return attemptDeadlineExpired
	}
	if errors.Is(err, jetstream.ErrJetStreamNotEnabled) || errors.Is(err, jetstream.ErrJetStreamNotEnabledForAccount) {
		return false
	}
	if apiErr, ok := errors.AsType[*jetstream.APIError](err); ok {
		return apiErr.Code >= 500 && apiErr.Code < 600
	}
	return false
}

func operationKey(id string) string {
	return entityid.Derive("delivery-operation", id)
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
	return s.status(ctx, operationID, "")
}

func (s *Service) status(ctx context.Context, operationID, expectedFingerprint string) (Receipt, error) {
	if s == nil || !entityid.Valid(operationID) {
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
	if expectedFingerprint != "" && fingerprint != expectedFingerprint {
		return Receipt{}, ErrConflict
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
	return s.status(ctx, intent.OperationID, fingerprint)
}

// AcceptedIntent finds the exact accepted release identity for a serving
// baseline that predates the native good-history index. It never infers
// acceptance from host desired state alone.
func (s *Service) AcceptedIntent(ctx context.Context, target Intent) (Intent, error) {
	legacy, err := s.config.Conn.JetStream()
	if err != nil {
		return Intent{}, err
	}
	messages, err := lastMessages(ctx, s.js, legacy, "KV_"+OperationBucket, "$KV."+OperationBucket+".>")
	if err != nil {
		return Intent{}, err
	}
	var found *Intent
	for _, message := range messages {
		if message.Header.Get("KV-Operation") != "" {
			continue
		}
		var op operation
		if err := jsonv2.Unmarshal(message.Data, &op); err != nil {
			return Intent{}, fmt.Errorf("decode baseline delivery: %w", err)
		}
		i := op.Intent
		if i.OperationID == "" || message.Subject != "$KV."+OperationBucket+"."+operationKey(i.OperationID) {
			continue
		}
		if i.Cell != target.Cell || i.Role != target.Role || i.Environment != target.Environment ||
			i.ArtifactDigest != target.ArtifactDigest || i.ConfigDigest != target.ConfigDigest || i.Generation != target.Generation {
			continue
		}
		receipt, err := s.StatusFor(ctx, i)
		if err != nil {
			return Intent{}, err
		}
		if receipt.Status != "accepted" {
			continue
		}
		if found != nil {
			return Intent{}, fmt.Errorf("%w: ambiguous accepted baseline", ErrConflict)
		}
		found = &i
	}
	if found == nil {
		return Intent{}, ErrPending
	}
	return *found, nil
}
