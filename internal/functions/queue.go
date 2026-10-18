package functions

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// QueueWorker shares a single durable pull consumer between processes for one
// tenant/function/revision. Broker credentials must authorize only this scope;
// possession of the publishing subject is not authentication.
type QueueWorker struct {
	worker   Invoker
	manifest Manifest
	subject  string
	consumer jetstream.Consumer
	receipts jetstream.KeyValue
	running  atomic.Bool
}

// QueueScope is the deterministic scope consumed by automatic broker admission.
// Names locate resources; broker authorization must grant only these resources.
type QueueScope struct{ Subject, Stream, ReceiptBucket string }

func QueueIdentity(manifest Manifest) (QueueScope, error) {
	if err := manifest.Validate(); err != nil {
		return QueueScope{}, err
	}
	subject := protocol.FunctionQueueSubject(manifest.TenantID, manifest.FunctionID, manifest.Revision)
	digest := sha256.Sum256([]byte(subject))
	identity := hex.EncodeToString(digest[:])
	return QueueScope{Subject: subject, Stream: "TS_FUNCTION_" + identity, ReceiptBucket: "TS_FUNCTION_RECEIPTS_" + identity}, nil
}

// ProvisionQueue is called by the trusted regional material producer before the
// worker is launched. Worker credentials must not grant stream/consumer mutation.
func ProvisionQueue(ctx context.Context, nc *nats.Conn, admitted release.VerifiedFunction) error {
	if !admitted.Valid() {
		return ErrScope
	}
	claim := admitted.Claim()
	manifest := Manifest{ABI: claim.ABI, TenantID: claim.TenantID, FunctionID: claim.FunctionID, Revision: claim.Revision, Digest: claim.Digest, Capabilities: claim.Capabilities}
	ctx, cancel := context.WithDeadline(ctx, admitted.ExpiresAt())
	defer cancel()
	return provisionQueue(ctx, nc, manifest)
}

func provisionQueue(ctx context.Context, nc *nats.Conn, manifest Manifest) error {
	if nc == nil {
		return fmt.Errorf("%w: broker required", ErrInvalid)
	}
	scope, err := QueueIdentity(manifest)
	if err != nil {
		return err
	}
	js, err := jetstream.New(nc)
	if err != nil {
		return err
	}
	_, err = js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{Name: scope.Stream, Subjects: []string{scope.Subject},
		Storage: jetstream.FileStorage, Replicas: 3, Retention: jetstream.WorkQueuePolicy, Discard: jetstream.DiscardNew,
		MaxAge: time.Hour, MaxMsgs: 10000, MaxBytes: 64 << 20, MaxMsgSize: MaxPayloadBytes + 8192, Duplicates: 2 * time.Minute})
	if err != nil {
		return fmt.Errorf("function queue: %w", err)
	}
	_, err = js.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: scope.ReceiptBucket, Storage: jetstream.FileStorage, Replicas: 3, History: 1, TTL: 24 * time.Hour, MaxBytes: 64 << 20, MaxValueSize: 512})
	if err != nil {
		return fmt.Errorf("function receipts: %w", err)
	}
	_, err = js.CreateOrUpdateConsumer(ctx, scope.Stream, jetstream.ConsumerConfig{Durable: "worker", FilterSubject: scope.Subject, AckPolicy: jetstream.AckExplicitPolicy, AckWait: 30 * time.Second, MaxDeliver: -1, MaxAckPending: 1, MaxWaiting: 32, MaxRequestBatch: 1, MaxRequestExpires: time.Second})
	if err != nil {
		return fmt.Errorf("function consumer: %w", err)
	}
	return nil
}

// NewQueueWorker binds only preprovisioned resources. Subject-restricted NATS
// grants cannot constrain mutation API bodies, so workers never create resources.
func NewQueueWorker(ctx context.Context, nc *nats.Conn, worker Invoker) (*QueueWorker, error) {
	if nc == nil || worker == nil {
		return nil, fmt.Errorf("%w: broker and worker required", ErrInvalid)
	}
	manifest := worker.Manifest()
	scope, err := QueueIdentity(manifest)
	if err != nil {
		return nil, err
	}
	js, err := jetstream.New(nc)
	if err != nil {
		return nil, err
	}
	stream, err := js.Stream(ctx, scope.Stream)
	if err != nil {
		return nil, fmt.Errorf("bind function queue: %w", err)
	}
	config := stream.CachedInfo().Config
	if len(config.Subjects) != 1 || config.Subjects[0] != scope.Subject || config.Storage != jetstream.FileStorage || config.Replicas != 3 || config.Retention != jetstream.WorkQueuePolicy || config.Discard != jetstream.DiscardNew || config.MaxAge != time.Hour || config.MaxMsgs != 10000 || config.MaxBytes != 64<<20 || config.MaxMsgSize != MaxPayloadBytes+8192 {
		return nil, fmt.Errorf("%w: function stream policy", ErrScope)
	}
	consumer, err := stream.Consumer(ctx, "worker")
	if err != nil {
		return nil, fmt.Errorf("bind function consumer: %w", err)
	}
	cc := consumer.CachedInfo().Config
	if cc.Durable != "worker" || cc.MemoryStorage || (cc.Replicas != 0 && cc.Replicas != 3) || cc.FilterSubject != scope.Subject || cc.AckPolicy != jetstream.AckExplicitPolicy || cc.AckWait != 30*time.Second || cc.MaxAckPending != 1 || cc.MaxRequestBatch != 1 || cc.MaxWaiting != 32 || cc.MaxDeliver != -1 || cc.MaxRequestExpires != time.Second {
		return nil, fmt.Errorf("%w: function consumer policy", ErrScope)
	}
	receipts, err := js.KeyValue(ctx, scope.ReceiptBucket)
	if err != nil {
		return nil, fmt.Errorf("bind function receipts: %w", err)
	}
	receiptStream, err := js.Stream(ctx, "KV_"+scope.ReceiptBucket)
	if err != nil {
		return nil, err
	}
	rc := receiptStream.CachedInfo().Config
	if !rc.AllowDirect || rc.Storage != jetstream.FileStorage || rc.Replicas != 3 || rc.MaxBytes != 64<<20 || rc.MaxMsgSize != 512 || rc.MaxAge != 24*time.Hour || rc.MaxMsgsPerSubject != 1 || len(rc.Subjects) != 1 || rc.Subjects[0] != "$KV."+scope.ReceiptBucket+".>" {
		return nil, fmt.Errorf("%w: function receipt policy", ErrScope)
	}
	return &QueueWorker{worker: worker, manifest: manifest, subject: scope.Subject, consumer: consumer, receipts: receipts}, nil
}

func (q *QueueWorker) Subject() string { return q.subject }

// Run acknowledges only durable successes, retries transient failures and
// terminates invalid or trapped invocations. MaxAckPending=1 serializes normal
// deliveries across workers. A crash after effects but before recording a receipt
// can repeat effects: delivery is at least once, never exactly once.
func (q *QueueWorker) Run(ctx context.Context) error {
	if !q.running.CompareAndSwap(false, true) {
		return ErrBusy
	}
	defer q.running.Store(false)
	for ctx.Err() == nil {
		batch, err := q.consumer.Fetch(1, jetstream.FetchMaxWait(time.Second))
		if err != nil {
			return err
		}
		for msg := range batch.Messages() {
			if err := q.process(ctx, msg); err != nil {
				return err
			}
		}
		if err := batch.Error(); err != nil && !errors.Is(err, nats.ErrTimeout) && !errors.Is(err, jetstream.ErrNoMessages) {
			return err
		}
	}
	return ctx.Err()
}

func (q *QueueWorker) process(ctx context.Context, msg jetstream.Msg) error {
	invocation := Invocation{TenantID: q.manifest.TenantID, FunctionID: q.manifest.FunctionID, Revision: q.manifest.Revision,
		ID: msg.Headers().Get(nats.MsgIdHdr), Trigger: "queue", Payload: msg.Data()}
	if msg.Subject() != q.subject || invocation.Validate(q.manifest) != nil {
		return msg.Term()
	}
	digest := sha256.Sum256(invocation.Payload)
	entry, err := q.receipts.Get(ctx, invocation.ID)
	if err == nil {
		if len(entry.Value()) != sha256.Size || !bytes.Equal(entry.Value(), digest[:]) {
			return msg.Term()
		}
		return msg.DoubleAck(ctx)
	}
	if !errors.Is(err, jetstream.ErrKeyNotFound) {
		return msg.NakWithDelay(time.Second)
	}
	status, err := q.receipts.Status(ctx)
	if err != nil {
		return msg.NakWithDelay(time.Second)
	}
	// Reserve room for the digest and worst-case subject/header overhead.
	if status.Bytes()+1024 > 64<<20 {
		return errors.New("function receipt storage exhausted")
	}
	invokeCtx, cancel := context.WithTimeout(ctx, InvocationTimeout)
	_, err = q.worker.Invoke(invokeCtx, invocation)
	cancel()
	if err != nil {
		if errors.Is(err, ErrBusy) || errors.Is(err, ErrClosed) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return msg.NakWithDelay(time.Second)
		}
		return msg.Term()
	}
	if _, err := q.receipts.Create(ctx, invocation.ID, digest[:]); err != nil {
		return fmt.Errorf("record function success: %w", err)
	}
	return msg.DoubleAck(ctx)
}
