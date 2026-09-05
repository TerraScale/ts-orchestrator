package reconcile

import (
	"context"
	"testing"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"terrascale.tech/orchestrator/src/orchestrator/estate"
	"terrascale.tech/orchestrator/src/orchestrator/natspolicy"
)

type capturePublisher struct {
	messages []*nats.Msg
	options  [][]jetstream.PublishOpt
	err      error
}

func (p *capturePublisher) PublishMsg(_ context.Context, message *nats.Msg, options ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
	p.messages = append(p.messages, message)
	p.options = append(p.options, options)
	return nil, p.err
}

func TestNatsDriftSinkPublishesOnTheV2ObservationSubject(t *testing.T) {
	publisher := &capturePublisher{}
	sink, err := NewNatsDriftSink("gru", publisher)
	if err != nil {
		t.Fatalf("sink creation failed: %v", err)
	}
	wantSubject, err := natspolicy.NatsSubjectTaxonomy.EstateDriftSubject("gru")
	if err != nil {
		t.Fatalf("subject derivation failed: %v", err)
	}
	if sink.Subject() != wantSubject || wantSubject != "ts.orch.v1.gru.observation.estate.drift" {
		t.Fatalf("drift subject = %q, want the v1 regional observation subject", sink.Subject())
	}
	events := []DriftEvent{
		{At: "2026-09-04T00:00:00Z", Ref: estate.ResourceRef{Kind: estate.ResourceBucket, Region: "gru", Name: "backups"}, Action: ActionCreate},
		{At: "2026-09-04T00:00:00Z", Ref: estate.ResourceRef{Kind: estate.ResourceDNS, Name: "api.terrascale.tech"}, Action: ActionUpdate},
	}
	if err := sink.PublishDrift(context.Background(), events); err != nil {
		t.Fatalf("drift publish failed: %v", err)
	}
	if len(publisher.messages) != len(events) {
		t.Fatalf("published %d messages, want one per event", len(publisher.messages))
	}
	for i, message := range publisher.messages {
		if message.Subject != wantSubject {
			t.Fatalf("message %d subject = %q", i, message.Subject)
		}
		if len(message.Data) == 0 {
			t.Fatalf("message %d has no payload", i)
		}
	}
}

func TestNatsDriftSinkRejectsBadCellsAndNilPublishers(t *testing.T) {
	if _, err := NewNatsDriftSink("gru", nil); err == nil {
		t.Fatal("nil publisher must be rejected")
	}
	// The reserved global scope token is not a Region cell.
	if _, err := NewNatsDriftSink("global", &capturePublisher{}); err == nil {
		t.Fatal("the reserved global scope must not name a drift subject")
	}
}

// The message ID must key on the drift identity, not the timestamp: the same
// drift on consecutive passes keeps one ID and deduplicates in JetStream,
// while any change to the drift lands as a new event.
func TestDriftMessageIDKeysOnIdentityNotTimestamp(t *testing.T) {
	base := DriftEvent{
		At:     "2026-09-04T00:00:00Z",
		Ref:    estate.ResourceRef{Kind: estate.ResourceBucket, Region: "gru", Name: "backups"},
		Action: ActionUpdate,
		Changes: []Change{
			{Name: "bucket.lifecycle-rule", Declared: "expire-history|delete|35", Observed: "expire-history|delete|7"},
		},
		Declared: "bucket.purpose=database-backup",
	}
	first, err := driftMessageID(base)
	if err != nil {
		t.Fatalf("message ID derivation failed: %v", err)
	}
	replayed := base
	replayed.At = "2026-09-04T00:01:00Z"
	second, err := driftMessageID(replayed)
	if err != nil {
		t.Fatalf("message ID derivation failed: %v", err)
	}
	if first != second {
		t.Fatalf("unchanged drift changed message ID: %q vs %q", first, second)
	}

	changed := base
	changed.Changes[0].Observed = "expire-history|delete|14"
	third, err := driftMessageID(changed)
	if err != nil {
		t.Fatalf("message ID derivation failed: %v", err)
	}
	if third == first {
		t.Fatal("changed drift kept the same message ID")
	}

	other := base
	other.Ref.Name = "releases"
	fourth, err := driftMessageID(other)
	if err != nil {
		t.Fatalf("message ID derivation failed: %v", err)
	}
	if fourth == first {
		t.Fatal("a different resource kept the same message ID")
	}
}
