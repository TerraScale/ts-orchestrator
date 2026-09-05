package reconcile

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"terrascale.tech/orchestrator/src/orchestrator/estate"
	"terrascale.tech/orchestrator/src/orchestrator/natspolicy"
)

// CellEventsStream is the regional replayable observation history the drift
// event stream lands in (semantic class Replayable; published by the regional
// controller, readable by the read-only monitoring accounts).
const CellEventsStream = "CELL_EVENTS"

// JetStreamPublisher is the publishing surface of a JetStream context.
type JetStreamPublisher interface {
	PublishMsg(ctx context.Context, message *nats.Msg, options ...jetstream.PublishOpt) (*jetstream.PubAck, error)
}

// NatsDriftSink publishes the drift event stream to the v1 control bus: one
// message per event, on the Region's estate-drift observation subject, into
// the CELL_EVENTS stream. The message ID is the digest of the drift identity
// — every event field except the observation timestamp — so the same drift
// reported on consecutive passes collapses inside the stream's dedup window
// and a changed plan always lands as a new event.
type NatsDriftSink struct {
	subject string
	publish JetStreamPublisher
}

// NewNatsDriftSink binds the sink to one Region's observation subject.
func NewNatsDriftSink(cell string, publisher JetStreamPublisher) (*NatsDriftSink, error) {
	if publisher == nil {
		return nil, fmt.Errorf("reconcile: drift publisher is nil")
	}
	subject, err := natspolicy.NatsSubjectTaxonomy.EstateDriftSubject(cell)
	if err != nil {
		return nil, fmt.Errorf("reconcile: estate drift subject for %q: %w", cell, err)
	}
	return &NatsDriftSink{subject: subject, publish: publisher}, nil
}

// Subject is the v1 subject this sink publishes on.
func (s *NatsDriftSink) Subject() string { return s.subject }

func (s *NatsDriftSink) PublishDrift(ctx context.Context, events []DriftEvent) error {
	for _, event := range events {
		payload, err := json.Marshal(event)
		if err != nil {
			return fmt.Errorf("reconcile: drift event encoding: %w", err)
		}
		messageID, err := driftMessageID(event)
		if err != nil {
			return fmt.Errorf("reconcile: drift event identity: %w", err)
		}
		_, err = s.publish.PublishMsg(
			ctx,
			&nats.Msg{Subject: s.subject, Data: payload},
			jetstream.WithMsgID(messageID),
			jetstream.WithExpectStream(CellEventsStream),
		)
		if err != nil {
			return fmt.Errorf("reconcile: drift publish to %s: %w", s.subject, err)
		}
	}
	return nil
}

// driftMessageID derives the JetStream message ID from the drift identity:
// every event field except the observation timestamp. Unchanged drift keeps
// its ID across passes and deduplicates inside the stream's duplicate
// window; any change to the ref, action, changes, or summaries lands as a
// new event.
func driftMessageID(event DriftEvent) (string, error) {
	identity, err := json.Marshal(struct {
		Ref      estate.ResourceRef `json:"ref"`
		Action   ActionKind         `json:"action"`
		Changes  []Change           `json:"changes,omitempty"`
		Declared string             `json:"declared,omitempty"`
		Observed string             `json:"observed,omitempty"`
	}{event.Ref, event.Action, event.Changes, event.Declared, event.Observed})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(identity)
	return "estate-drift-" + hex.EncodeToString(digest[:16]), nil
}
