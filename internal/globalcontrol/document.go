package globalcontrol

import (
	"context"
	"errors"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
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

func validDocument(kind Kind, cell string) bool {
	switch kind {
	case KindCellSpec:
		return cellToken.MatchString(cell) && cell != protocol.GlobalScope
	case KindBudget, KindCapacity:
		return cell == protocol.GlobalScope
	}
	return false
}
