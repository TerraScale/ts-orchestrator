package functions

import (
	"sync/atomic"

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
