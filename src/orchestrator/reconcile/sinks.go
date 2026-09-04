package reconcile

import (
	"context"
	"encoding/json"
	"io"
	"sync"

	"terrascale.tech/orchestrator/src/orchestrator/estate"
)

// AuditEntry is one recorded transition of the reconciler: every planned,
// applied, skipped, or failed action produces exactly one entry, in order.
type AuditEntry struct {
	At     string             `json:"at"`
	Ref    estate.ResourceRef `json:"ref"`
	Action ActionKind         `json:"action"`
	Result string             `json:"result"` // planned | applied | skipped | failed
	Detail string             `json:"detail,omitempty"`
}

// AuditSink receives the audit trail. Implementations must be safe for
// concurrent use.
type AuditSink interface {
	Append(ctx context.Context, entry AuditEntry) error
}

// LogAuditSink writes the audit trail as structured JSON lines.
type LogAuditSink struct {
	mu     sync.Mutex
	writer io.Writer
}

// NewLogAuditSink returns a JSON-lines audit sink.
func NewLogAuditSink(writer io.Writer) *LogAuditSink {
	return &LogAuditSink{writer: writer}
}

func (s *LogAuditSink) Append(_ context.Context, entry AuditEntry) error {
	payload, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.writer.Write(append(payload, '\n'))
	return err
}

// DriftEvent is one structured drift alert: a resource whose observed state
// differs from the declared estate.
type DriftEvent struct {
	At       string             `json:"at"`
	Ref      estate.ResourceRef `json:"ref"`
	Action   ActionKind         `json:"action"`
	Changes  []Change           `json:"changes,omitempty"`
	Declared string             `json:"declared,omitempty"`
	Observed string             `json:"observed,omitempty"`
}

// DriftSink receives the drift event stream of every pass with a non-empty
// plan. Implementations must be safe for concurrent use.
type DriftSink interface {
	PublishDrift(ctx context.Context, events []DriftEvent) error
}

// LogDriftSink writes drift events as structured JSON lines.
type LogDriftSink struct {
	mu     sync.Mutex
	writer io.Writer
}

// NewLogDriftSink returns a JSON-lines drift sink.
func NewLogDriftSink(writer io.Writer) *LogDriftSink {
	return &LogDriftSink{writer: writer}
}

func (s *LogDriftSink) PublishDrift(_ context.Context, events []DriftEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	encoder := json.NewEncoder(s.writer)
	for _, event := range events {
		if err := encoder.Encode(event); err != nil {
			return err
		}
	}
	return nil
}

// driftEvents renders a plan as one drift event per action.
func driftEvents(at string, plan Plan) []DriftEvent {
	events := make([]DriftEvent, 0, len(plan.Actions))
	for _, action := range plan.Actions {
		event := DriftEvent{At: at, Ref: action.Ref, Action: action.Kind, Changes: action.Changes}
		if action.Kind == ActionDelete {
			event.Observed = attributesSummary(action.Attributes)
		} else {
			event.Declared = attributesSummary(action.Attributes)
		}
		events = append(events, event)
	}
	return events
}

func attributesSummary(attributes []Attribute) string {
	summary := ""
	for i, attribute := range normalizeAttributes(attributes) {
		if i > 0 {
			summary += ";"
		}
		summary += attribute.Name + "=" + attribute.Value
	}
	return summary
}
