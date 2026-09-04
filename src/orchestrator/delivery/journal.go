package delivery

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Operation states.
const (
	OperationRunning = "running"
	OperationDone    = "done"
)

// Operation is one durable delivery operation: the request, its canonical
// digest (idempotency), and the terminal receipt once it exists.
type Operation struct {
	OperationID   string
	Request       *Request
	RequestDigest string
	State         string
	Receipt       *Receipt
	StartedAt     time.Time
	FinishedAt    time.Time
	UpdatedAt     time.Time
}

// Journal is the delivery operation journal backing idempotency and receipt
// polling.
//
// ponytail: process-local map; durability across orchestrator restarts lands
// with the JetStream control store when the delivery role joins the control
// plane. In-flight operations are rare (one per green develop push) and every
// step is idempotent, so a restart replays safely from the receipt's absence.
type Journal struct {
	mu         sync.Mutex
	operations map[string]*Operation
	clock      func() time.Time
}

// NewJournal returns an empty journal.
func NewJournal() *Journal {
	return &Journal{operations: make(map[string]*Operation)}
}

// Begin admits one operation. An existing record with the same request
// digest is returned with exists=true (idempotent replay); the same
// operation ID with a different request is a conflict, never a restart.
func (j *Journal) Begin(request *Request) (operation *Operation, exists bool, err error) {
	if j == nil {
		return nil, false, errors.New("delivery: journal is not configured")
	}
	if request == nil {
		return nil, false, errors.New("delivery: journal requires a request")
	}
	digest, err := requestDigest(request)
	if err != nil {
		return nil, false, err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if existing, ok := j.operations[request.OperationID]; ok {
		if existing.RequestDigest != digest {
			return nil, false, fmt.Errorf("delivery: operation %s exists with a different request", request.OperationID)
		}
		return cloneOperation(existing), true, nil
	}
	now := j.now()
	operation = &Operation{
		OperationID:   request.OperationID,
		Request:       request,
		RequestDigest: digest,
		State:         OperationRunning,
		StartedAt:     now,
		UpdatedAt:     now,
	}
	j.operations[request.OperationID] = operation
	return cloneOperation(operation), false, nil
}

// Finish records the terminal receipt of one operation. A terminal operation
// is immutable: replaying the same receipt is fine, replacing it is not.
func (j *Journal) Finish(operationID, requestDigest string, receipt *Receipt) error {
	if j == nil || receipt == nil {
		return errors.New("delivery: journal finish requires a receipt")
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	operation, ok := j.operations[operationID]
	if !ok {
		return fmt.Errorf("delivery: operation %s was never begun", operationID)
	}
	if operation.RequestDigest != requestDigest {
		return fmt.Errorf("delivery: operation %s digest changed", operationID)
	}
	if operation.State == OperationDone {
		if operation.Receipt == nil || operation.Receipt.Status != receipt.Status {
			return fmt.Errorf("delivery: operation %s is already terminal", operationID)
		}
		return nil
	}
	now := j.now()
	operation.State = OperationDone
	operation.Receipt = receipt
	operation.FinishedAt = now
	operation.UpdatedAt = now
	return nil
}

// Get returns a copy of one operation by ID.
func (j *Journal) Get(operationID string) (*Operation, bool) {
	if j == nil {
		return nil, false
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	operation, ok := j.operations[operationID]
	if !ok {
		return nil, false
	}
	return cloneOperation(operation), true
}

// Snapshot lists every operation, oldest first, for rollout status output.
func (j *Journal) Snapshot() []Operation {
	if j == nil {
		return nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	operations := make([]Operation, 0, len(j.operations))
	for _, operation := range j.operations {
		operations = append(operations, *cloneOperation(operation))
	}
	for i := 1; i < len(operations); i++ {
		for k := i; k > 0 && operations[k-1].StartedAt.After(operations[k].StartedAt); k-- {
			operations[k-1], operations[k] = operations[k], operations[k-1]
		}
	}
	return operations
}

func (j *Journal) now() time.Time {
	if j.clock != nil {
		return j.clock()
	}
	return time.Now()
}

func cloneOperation(operation *Operation) *Operation {
	copied := *operation
	if operation.Receipt != nil {
		receipt := *operation.Receipt
		copied.Receipt = &receipt
	}
	return &copied
}

// requestDigest is the canonical idempotency identity of a request: the
// sha256 of its compact JSON form (struct field order is deterministic).
func requestDigest(request *Request) (string, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:]), nil
}
