package authority

import (
	"cmp"
	"context"
	"errors"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go/jetstream"
)

const hostHistoryLimit = 16384

// HostHistory caches a startup baseline and one hour of incremental changes.
// Queries never replay mutations preceding the baseline.
type HostHistory struct {
	once     sync.Once
	gate     chan struct{}
	since    time.Time
	updated  time.Time
	next     uint64
	baseline map[string]LogEntry
	changes  []LogEntry
}

func (h *HostHistory) lock(ctx context.Context) error {
	h.once.Do(func() { h.gate = make(chan struct{}, 1) })
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case h.gate <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Seed reads only the latest state per subject, regardless of lifetime churn.
func (h *HostHistory) Seed(ctx context.Context, stream jetstream.Stream, scope string, info *jetstream.StreamInfo) error {
	if err := h.lock(ctx); err != nil {
		return err
	}
	defer func() { <-h.gate }()
	if !h.since.IsZero() && time.Since(h.updated) < time.Hour {
		return nil
	}
	baseline := map[string]LogEntry{}
	var newest time.Time
	for _, subject := range slices.Sorted(maps.Keys(info.State.Subjects)) {
		if !strings.HasPrefix(subject, mutationSubject(scope, MutationRegistration, scope+".")) && !strings.HasPrefix(subject, mutationSubject(scope, MutationDesired, scope+".")) {
			continue
		}
		entry, err := stream.GetLastMsgForSubject(ctx, subject)
		if err != nil {
			return err
		}
		value, err := decodeHostHistoryEntry(entry, scope)
		if err != nil || entry.Subject != subject {
			return errors.Join(err, errors.New("host history baseline identity is invalid"))
		}
		baseline[subject] = value
		if entry.Time.After(newest) {
			newest = entry.Time
		}
		if len(baseline) > hostHistoryLimit {
			return errors.New("host history exceeds inventory bound")
		}
	}
	h.baseline, h.next = baseline, info.State.LastSeq+1
	h.changes = nil
	h.since = time.Now().UTC()
	h.updated = h.since
	if newest.After(h.since) {
		h.since = newest
	}
	return nil
}

// Window advances the checkpoint only through watermark, then reads the cache.
func (h *HostHistory) Window(ctx context.Context, stream jetstream.Stream, scope string, from, to time.Time, watermark uint64) ([]LogEntry, error) {
	if err := h.lock(ctx); err != nil {
		return nil, err
	}
	defer func() { <-h.gate }()
	if h.since.IsZero() || time.Since(h.updated) >= time.Hour || from.Before(h.since) || !from.Before(to) {
		return nil, errors.New("inventory window predates the cached baseline")
	}
	if err := h.advance(ctx, stream, scope, watermark); err != nil {
		return nil, err
	}
	if from.Before(h.since) {
		return nil, errors.New("inventory window has expired")
	}
	baseline := maps.Clone(h.baseline)
	for _, entry := range baseline {
		if entry.Sequence > watermark {
			return nil, errors.New("inventory baseline exceeds the selected watermark")
		}
	}
	var result []LogEntry
	for _, entry := range h.changes {
		if entry.Sequence > watermark {
			continue
		}
		if entry.CreatedAt.Before(from) {
			baseline[mutationSubject(scope, entry.Kind, entry.SubjectKey)] = entry
		} else if entry.CreatedAt.Before(to) {
			result = append(result, entry)
		}
	}
	result = append(result, slices.Collect(maps.Values(baseline))...)
	slices.SortFunc(result, func(a, b LogEntry) int { return cmp.Compare(a.Sequence, b.Sequence) })
	return result, nil
}

// Advance keeps the cache current even when there are no usage queries.
func (h *HostHistory) Advance(ctx context.Context, stream jetstream.Stream, scope string, watermark uint64) error {
	if err := h.lock(ctx); err != nil {
		return err
	}
	defer func() { <-h.gate }()
	if h.since.IsZero() {
		return errors.New("inventory baseline unavailable")
	}
	return h.advance(ctx, stream, scope, watermark)
}

func (h *HostHistory) advance(ctx context.Context, stream jetstream.Stream, scope string, watermark uint64) error {
	cutoff := time.Now().Add(-time.Hour)
	if cutoff.After(h.since) {
		kept := h.changes[:0]
		for _, entry := range h.changes {
			if entry.CreatedAt.Before(cutoff) {
				h.baseline[mutationSubject(scope, entry.Kind, entry.SubjectKey)] = entry
			} else {
				kept = append(kept, entry)
			}
		}
		clear(h.changes[len(kept):])
		h.changes, h.since = kept, cutoff
	}
	filter := protocol.Control(scope, "host") + ".>"
	for h.next <= watermark {
		entry, err := stream.GetMsg(ctx, h.next, jetstream.WithGetMsgSubject(filter))
		if errors.Is(err, jetstream.ErrMsgNotFound) || err == nil && entry.Sequence > watermark {
			h.next = watermark + 1
			break
		}
		if err != nil {
			return err
		}
		if entry.Sequence < h.next {
			return errors.New("host history sequence is invalid")
		}
		value, err := decodeHostHistoryEntry(entry, scope)
		if err != nil {
			return err
		}
		prior := h.baseline[entry.Subject]
		// Seed reads can overlap newer commits; never replace them with older state.
		if value.Sequence > prior.Sequence {
			if len(h.baseline)+len(h.changes) >= hostHistoryLimit && (prior.Sequence == 0 || !value.CreatedAt.Before(h.since)) {
				return errors.New("host history exceeds inventory bound")
			}
			if value.CreatedAt.Before(h.since) {
				h.baseline[entry.Subject] = value
			} else {
				h.changes = append(h.changes, value)
			}
		}
		h.next = entry.Sequence + 1
	}
	h.updated = time.Now().UTC()
	return nil
}

func decodeHostHistoryEntry(entry *jetstream.RawStreamMsg, scope string) (LogEntry, error) {
	record, err := decodeControlRecord(entry.Data)
	if err != nil || entry.Sequence == 0 || entry.Time.IsZero() || record.Scope != scope || (record.Kind != MutationRegistration && record.Kind != MutationDesired) || record.Epoch == 0 || entry.Subject != mutationSubject(scope, record.Kind, record.SubjectKey) || validateMutationKey(record.Kind, record.SubjectKey) != nil {
		return LogEntry{}, errors.New("host history control entry is invalid")
	}
	return LogEntry{Kind: record.Kind, SubjectKey: record.SubjectKey, OperationID: record.OperationID, Epoch: record.Epoch, Sequence: entry.Sequence, CreatedAt: entry.Time, Payload: record.Payload}, nil
}
