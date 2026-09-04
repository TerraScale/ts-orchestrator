package reconcile

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"terrascale.tech/orchestrator/src/orchestrator/protocol"
)

// CellEventsStream is the regional replayable observation history the drift
// event stream lands in (semantic class Replayable; published by the regional
// controller, readable by the read-only monitoring accounts).
const CellEventsStream = "CELL_EVENTS"

// JetStreamPublisher is the publishing surface of a JetStream context.
type JetStreamPublisher interface {
	PublishMsg(ctx context.Context, message *nats.Msg, options ...jetstream.PublishOpt) (*jetstream.PubAck, error)
}

// NatsDriftSink publishes the drift event stream to the v2 control bus: one
// message per event, on the Region's estate-drift observation subject, into
// the CELL_EVENTS stream. The message ID is the content digest, so identical
// consecutive passes collapse inside the stream dedup window and a changed
// plan always lands as a new event.
type NatsDriftSink struct {
	subject string
	publish JetStreamPublisher
}

// NewNatsDriftSink binds the sink to one Region's observation subject.
func NewNatsDriftSink(cell string, publisher JetStreamPublisher) (*NatsDriftSink, error) {
	if publisher == nil {
		return nil, fmt.Errorf("reconcile: drift publisher is nil")
	}
	subject, err := protocol.NatsSubjectTaxonomy.EstateDriftSubject(cell)
	if err != nil {
		return nil, fmt.Errorf("reconcile: estate drift subject for %q: %w", cell, err)
	}
	return &NatsDriftSink{subject: subject, publish: publisher}, nil
}

// Subject is the v2 subject this sink publishes on.
func (s *NatsDriftSink) Subject() string { return s.subject }

func (s *NatsDriftSink) PublishDrift(ctx context.Context, events []DriftEvent) error {
	for _, event := range events {
		payload, err := json.Marshal(event)
		if err != nil {
			return fmt.Errorf("reconcile: drift event encoding: %w", err)
		}
		digest := sha256.Sum256(payload)
		messageID := "estate-drift-" + hex.EncodeToString(digest[:16])
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
