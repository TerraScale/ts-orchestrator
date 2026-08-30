package delivery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

type JournalDisposition uint8

const (
	JournalUnspecified JournalDisposition = iota
	JournalAccepted
	JournalDuplicate
	JournalDeliveryCollision
	JournalPayloadReplay
)

type JournalReceipt struct{ Disposition JournalDisposition }

func (r JournalReceipt) CanAcknowledge() bool {
	return r.Disposition == JournalAccepted || r.Disposition == JournalDuplicate
}

type LedgerEntry struct {
	Value    []byte
	Revision uint64
	Key      string
}
type Ledger interface {
	Get(context.Context, string) (*LedgerEntry, error)
	Create(context.Context, string, []byte) (LedgerEntry, error)
	Update(context.Context, string, []byte, uint64) (LedgerEntry, error)
}
type RetentionLedger interface {
	Ledger
	Keys(context.Context, string) ([]string, error)
	Delete(context.Context, string, uint64) error
}

var ErrLedgerConflict = errors.New("delivery ledger changed concurrently")

type MemoryLedger struct {
	mu       sync.Mutex
	entries  map[string]LedgerEntry
	revision uint64
}

func NewMemoryLedger() *MemoryLedger { return &MemoryLedger{entries: map[string]LedgerEntry{}} }
func (m *MemoryLedger) Get(ctx context.Context, key string) (*LedgerEntry, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.entries[key]
	if !ok {
		return nil, nil
	}
	v.Value = append([]byte(nil), v.Value...)
	return &v, nil
}
func (m *MemoryLedger) Create(ctx context.Context, key string, value []byte) (LedgerEntry, error) {
	if e := ctx.Err(); e != nil {
		return LedgerEntry{}, e
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.entries[key]; ok {
		return LedgerEntry{}, ErrLedgerConflict
	}
	m.revision++
	v := LedgerEntry{Value: append([]byte(nil), value...), Revision: m.revision, Key: key}
	m.entries[key] = v
	return v, nil
}
func (m *MemoryLedger) Update(ctx context.Context, key string, value []byte, revision uint64) (LedgerEntry, error) {
	if e := ctx.Err(); e != nil {
		return LedgerEntry{}, e
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	old, ok := m.entries[key]
	if !ok || old.Revision != revision {
		return LedgerEntry{}, ErrLedgerConflict
	}
	m.revision++
	v := LedgerEntry{Value: append([]byte(nil), value...), Revision: m.revision, Key: key}
	m.entries[key] = v
	return v, nil
}
func (m *MemoryLedger) Keys(ctx context.Context, prefix string) ([]string, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []string{}
	for k := range m.entries {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out, nil
}
func (m *MemoryLedger) Delete(ctx context.Context, key string, revision uint64) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.entries[key]
	if !ok || v.Revision != revision {
		return ErrLedgerConflict
	}
	delete(m.entries, key)
	return nil
}

type EventPublisher interface {
	Publish(context.Context, *WebhookEnvelope) error
}
type NatsEventPublisher struct {
	JS      jetstream.JetStream
	Subject string
	Stream  string
}

func (p NatsEventPublisher) Publish(ctx context.Context, e *WebhookEnvelope) error {
	if p.JS == nil || e == nil {
		return errors.New("NATS publisher dependencies are missing")
	}
	subject := p.Subject
	if subject == "" {
		subject = "ts.orch.v2.global.release.ci.forgejo"
	}
	stream := p.Stream
	if stream == "" {
		stream = "GLOBAL_CI"
	}
	body, err := json.Marshal(eventDocument{SchemaVersion: 1, DeliveryID: e.DeliveryID, Kind: e.Kind, Action: e.Action, Repository: e.Repository, SourceRepository: e.SourceRepository, BaseRevision: e.BaseRevision, Revision: e.Revision, SourceRef: e.SourceRef, TargetRef: e.TargetRef, PullRequestNumber: e.PullRequestNumber, IsDeletion: e.IsDeletion, PayloadSHA256: e.PayloadSHA256, DedupeKey: e.DedupeKey()})
	if err != nil {
		return err
	}
	_, err = p.JS.PublishMsg(ctx, &nats.Msg{Subject: subject, Data: body, Header: nats.Header{"TS-Protocol-Version": []string{"1"}, "TS-Event-Id": []string{e.DedupeKey()}, "TS-Event-Kind": []string{kindString(e.Kind)}}}, jetstream.WithMsgID(e.DedupeKey()), jetstream.WithExpectStream(stream))
	return err
}

type eventDocument struct {
	SchemaVersion                                                                      int         `json:"schemaVersion"`
	DeliveryID                                                                         string      `json:"deliveryId"`
	Kind                                                                               WebhookKind `json:"kind"`
	Action, Repository, SourceRepository, BaseRevision, Revision, SourceRef, TargetRef string
	PullRequestNumber                                                                  int64 `json:"pullRequestNumber,omitempty"`
	IsDeletion                                                                         bool  `json:"isDeletion"`
	PayloadSHA256, DedupeKey                                                           string
}

func kindString(k WebhookKind) string {
	if k == WebhookPush {
		return "Push"
	}
	if k == WebhookPullRequest {
		return "PullRequest"
	}
	return "Unspecified"
}

type WebhookJournal struct {
	Ledger                 Ledger
	Publisher              EventPublisher
	HistoryCap, PruneEvery int
	mu                     sync.Mutex
	accepted               int
}

func NewWebhookJournal(ledger Ledger, publisher EventPublisher) *WebhookJournal {
	if publisher == nil {
		publisher = noopPublisher{}
	}
	return &WebhookJournal{Ledger: ledger, Publisher: publisher, HistoryCap: 4096, PruneEvery: 32}
}
func (j *WebhookJournal) Accept(ctx context.Context, e *WebhookEnvelope) (JournalReceipt, error) {
	if j == nil || j.Ledger == nil || e == nil {
		return JournalReceipt{}, errors.New("journal dependencies are missing")
	}
	if j.HistoryCap < 2 || j.HistoryCap > 262144 {
		return JournalReceipt{}, errors.New("invalid journal history cap")
	}
	pending := journalDocument{SchemaVersion: 1, State: "pending", Envelope: *e, DeliveryKey: e.DeliveryKey(), DedupeKey: e.DedupeKey()}
	payload, err := j.ensure(ctx, "payload."+e.PayloadSHA256, pending)
	if err != nil {
		return JournalReceipt{}, err
	}
	if !payload.Match {
		return JournalReceipt{Disposition: JournalPayloadReplay}, nil
	}
	delivery, err := j.ensure(ctx, "delivery."+hash(e.DeliveryKey()), pending)
	if err != nil {
		return JournalReceipt{}, err
	}
	if !delivery.Match {
		return JournalReceipt{Disposition: JournalDeliveryCollision}, nil
	}
	complete := payload.Doc.State == "accepted" && delivery.Doc.State == "accepted"
	if !complete {
		if err := j.Publisher.Publish(ctx, e); err != nil {
			return JournalReceipt{}, err
		}
		if err := j.mark(ctx, "payload."+e.PayloadSHA256, payload); err != nil {
			return JournalReceipt{}, err
		}
		if err := j.mark(ctx, "delivery."+hash(e.DeliveryKey()), delivery); err != nil {
			return JournalReceipt{}, err
		}
	}
	if complete {
		return JournalReceipt{Disposition: JournalDuplicate}, nil
	}
	j.prune(ctx)
	return JournalReceipt{Disposition: JournalAccepted}, nil
}

type reservation struct {
	Match    bool
	Doc      journalDocument
	Revision uint64
}

func (j *WebhookJournal) ensure(ctx context.Context, key string, p journalDocument) (reservation, error) {
	for i := 0; i < 8; i++ {
		cur, err := j.Ledger.Get(ctx, key)
		if err != nil {
			return reservation{}, err
		}
		if cur != nil {
			d, e := decodeJournal(cur.Value)
			if e != nil {
				return reservation{}, e
			}
			return reservation{Match: d.matches(p), Doc: d, Revision: cur.Revision}, nil
		}
		b, _ := json.Marshal(p)
		v, err := j.Ledger.Create(ctx, key, b)
		if err == nil {
			return reservation{Match: true, Doc: p, Revision: v.Revision}, nil
		}
		if !errors.Is(err, ErrLedgerConflict) {
			return reservation{}, err
		}
	}
	return reservation{}, errors.New("journal reservation conflicts exceeded")
}
func (j *WebhookJournal) mark(ctx context.Context, key string, r reservation) error {
	if r.Doc.State == "accepted" {
		return nil
	}
	r.Doc.State = "accepted"
	for i := 0; i < 8; i++ {
		b, _ := json.Marshal(r.Doc)
		_, err := j.Ledger.Update(ctx, key, b, r.Revision)
		if err == nil {
			return nil
		}
		if !errors.Is(err, ErrLedgerConflict) {
			return err
		}
		cur, e := j.Ledger.Get(ctx, key)
		if e != nil {
			return e
		}
		if cur == nil {
			return errors.New("journal reservation disappeared")
		}
		d, e := decodeJournal(cur.Value)
		if e != nil {
			return e
		}
		if !d.matches(r.Doc) {
			return errors.New("journal reservation identity changed")
		}
		r.Doc = d
		r.Revision = cur.Revision
	}
	return errors.New("journal commit conflicts exceeded")
}
func (j *WebhookJournal) prune(ctx context.Context) {
	j.mu.Lock()
	j.accepted++
	do := j.PruneEvery > 0 && j.accepted%j.PruneEvery == 0
	j.mu.Unlock()
	r, ok := j.Ledger.(RetentionLedger)
	if !ok || !do {
		return
	}
	for _, prefix := range []string{"payload.", "delivery."} {
		keys, e := r.Keys(ctx, prefix)
		if e != nil || len(keys) <= j.HistoryCap {
			continue
		}
		sort.Strings(keys)
		for _, k := range keys[:len(keys)-j.HistoryCap] {
			if x, e := j.Ledger.Get(ctx, k); e == nil && x != nil {
				_ = r.Delete(ctx, k, x.Revision)
			}
		}
	}
}

type noopPublisher struct{}

func (noopPublisher) Publish(context.Context, *WebhookEnvelope) error { return nil }

type journalDocument struct {
	SchemaVersion          int             `json:"schemaVersion"`
	State                  string          `json:"state"`
	Envelope               WebhookEnvelope `json:"envelope"`
	DeliveryKey, DedupeKey string          `json:"deliveryKey" json:"dedupeKey"`
}

func (d journalDocument) matches(p journalDocument) bool {
	d.State = p.State
	return d.SchemaVersion == p.SchemaVersion && d.Envelope.DeliveryID == p.Envelope.DeliveryID && d.Envelope.Kind == p.Envelope.Kind && d.Envelope.Repository == p.Envelope.Repository && d.Envelope.SourceRepository == p.Envelope.SourceRepository && d.Envelope.BaseRevision == p.Envelope.BaseRevision && d.Envelope.Revision == p.Envelope.Revision && d.Envelope.SourceRef == p.Envelope.SourceRef && d.Envelope.TargetRef == p.Envelope.TargetRef && d.Envelope.PayloadSHA256 == p.Envelope.PayloadSHA256 && d.DeliveryKey == p.DeliveryKey && d.DedupeKey == p.DedupeKey
}
func decodeJournal(b []byte) (journalDocument, error) {
	var d journalDocument
	if e := json.Unmarshal(b, &d); e != nil {
		return d, fmt.Errorf("invalid webhook journal: %w", e)
	}
	if d.SchemaVersion != 1 || d.State != "pending" && d.State != "accepted" || !ValidRepository(d.Envelope.Repository) || d.DeliveryKey != d.Envelope.DeliveryKey() || d.DedupeKey != d.Envelope.DedupeKey() {
		return d, errors.New("invalid webhook journal identity")
	}
	return d, nil
}
func hash(s string) string { d := sha256.Sum256([]byte(s)); return hex.EncodeToString(d[:]) }

type NatsLedger struct{ Store jetstream.KeyValue }

func (n NatsLedger) Get(ctx context.Context, key string) (*LedgerEntry, error) {
	v, e := n.Store.Get(ctx, key)
	if e != nil {
		if errors.Is(e, jetstream.ErrKeyNotFound) {
			return nil, nil
		}
		return nil, e
	}
	return &LedgerEntry{Value: append([]byte(nil), v.Value()...), Revision: v.Revision(), Key: key}, nil
}
func (n NatsLedger) Create(ctx context.Context, key string, b []byte) (LedgerEntry, error) {
	r, e := n.Store.Create(ctx, key, b)
	if e != nil {
		return LedgerEntry{}, ErrLedgerConflict
	}
	return LedgerEntry{Value: b, Revision: r, Key: key}, nil
}
func (n NatsLedger) Update(ctx context.Context, key string, b []byte, rev uint64) (LedgerEntry, error) {
	r, e := n.Store.Update(ctx, key, b, rev)
	if e != nil {
		return LedgerEntry{}, ErrLedgerConflict
	}
	return LedgerEntry{Value: b, Revision: r, Key: key}, nil
}
