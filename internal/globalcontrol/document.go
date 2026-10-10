package globalcontrol

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go/jetstream"
)

// Document is a document the home region relays to every region. A
// KindCellSpec document is the exact bytes an operator submitted for one
// regional cell: the relay adds no authority, the global writer only orders
// and fences the record, and every region verifies the bytes against its own
// trust roots before acting on them, so a document no region would accept
// from an operator directly is refused the same way when it arrives through
// the mirror. KindBudget and KindCapacity are the global writer's own
// documents under the global cell, trusted like the roster.
type Document struct {
	Payload []byte
	// Generation counts the record's payloads; it is not the document's
	// own generation, which only its verifier may trust.
	Generation uint64
	Epoch      uint64
	Sequence   uint64
}

var errDocumentKey = errors.New("global document needs a document kind and a matching cell")

func validDocument(kind Kind, cell string) bool {
	switch kind {
	case KindCellSpec:
		return cellToken.MatchString(cell) && cell != protocol.GlobalScope
	case KindBudget, KindCapacity:
		return cell == protocol.GlobalScope
	}
	return false
}

// PutDocument relays payload for cell as kind's next generation. A payload
// equal to the stored one is an idempotent retry. admit, when set, sees the
// stored payload (nil when there is none) and may refuse the write; the
// append is conditional on that exact record, so no other write can land
// between the check and the append.
func (w *Writer) PutDocument(ctx context.Context, epoch uint64, kind Kind, cell string, payload []byte,
	admit func(prior []byte) error,
) (uint64, error) {
	if !validDocument(kind, cell) {
		return 0, errDocumentKey
	}
	if len(payload) == 0 || len(payload) > maxRecordBytes {
		return 0, errors.New("global document must hold 1 byte to 64 KiB")
	}
	return w.put(ctx, epoch, kind, cell, 0, payload, admit)
}

// Document returns kind's current document for cell.
func (r *Reader) Document(ctx context.Context, kind Kind, cell string) (Document, error) {
	if !validDocument(kind, cell) {
		return Document{}, errDocumentKey
	}
	stored, sequence, err := r.read(ctx, kind, cell)
	if err != nil {
		return Document{}, err
	}
	if len(stored.Payload) == 0 || len(stored.Payload) > maxRecordBytes {
		return Document{}, ErrRecordCorrupt
	}
	return Document{Payload: stored.Payload, Generation: stored.Generation, Epoch: stored.Epoch, Sequence: sequence}, nil
}

// Follow offers kind's current document for cell to apply when Follow
// starts, each time the record changes and every recheck, so apply must be
// idempotent: a document the caller cannot act on yet, on a follower or
// after a transient error, is simply offered again. A watch on the local
// stream (the home stream or this region's mirror) makes changes immediate;
// every read is still the verified read, so a mirror missing home records
// offers nothing. Failures are logged once each. Follow returns when ctx
// ends.
func (r *Reader) Follow(ctx context.Context, kind Kind, cell string, recheck time.Duration,
	apply func(context.Context, Document),
) error {
	if !validDocument(kind, cell) {
		return errDocumentKey
	}
	if recheck <= 0 {
		return errors.New("global document recheck must be positive")
	}
	changed := make(chan struct{}, 1)
	var watch jetstream.ConsumeContext
	defer func() {
		if watch != nil {
			watch.Stop()
		}
	}()
	ticker := time.NewTicker(recheck)
	defer ticker.Stop()
	var failure string
	for {
		var watchErr error
		if watch == nil {
			watch, watchErr = r.watch(ctx, subject(kind, cell), changed)
		}
		document, err := r.Document(ctx, kind, cell)
		switch {
		case err == nil:
			apply(ctx, document)
		case errors.Is(err, ErrNotFound):
			err = nil
		}
		if err = errors.Join(watchErr, err); err != nil && err.Error() != failure && ctx.Err() == nil {
			slog.Warn("global document unavailable", observability.ComponentKey, "globalcontrol",
				"kind", kind, "cell", cell, "error", err)
		}
		failure = ""
		if err != nil {
			failure = err.Error()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
		case <-ticker.C:
		}
	}
}

// watch signals changed for every record stored on subject, starting with
// the current one, through an ordered consumer on the local stream.
func (r *Reader) watch(ctx context.Context, subject string, changed chan<- struct{}) (jetstream.ConsumeContext, error) {
	if r == nil || r.stream == nil {
		return nil, errors.New("global control reader is not open")
	}
	createCtx, cancel := context.WithTimeout(ctx, apiTimeout)
	defer cancel()
	consumer, err := r.stream.OrderedConsumer(createCtx, jetstream.OrderedConsumerConfig{
		FilterSubjects: []string{subject}, DeliverPolicy: jetstream.DeliverLastPerSubjectPolicy,
	})
	if err != nil {
		return nil, err
	}
	return consumer.Consume(func(jetstream.Msg) {
		select {
		case changed <- struct{}{}:
		default:
		}
	})
}
