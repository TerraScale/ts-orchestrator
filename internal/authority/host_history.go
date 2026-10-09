package authority

import (
	"cmp"
	"context"
	"errors"
	"maps"
	"slices"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

// ReadHostMutationWindow returns each subject's last state before from and
// its changes in [from,to), using a pinned control-log watermark.
func ReadHostMutationWindow(ctx context.Context, stream jetstream.Stream, scope string,
	kind HostMutationKind, from, to time.Time, watermark uint64,
) ([]LogEntry, error) {
	if stream == nil || !from.Before(to) || (kind != MutationRegistration && kind != MutationDesired) {
		return nil, ErrInvalidTransition
	}
	filter := mutationSubject(scope, kind, scope+".") + ">"
	baseline := map[string]LogEntry{}
	var changes []LogEntry
	for next := uint64(1); next <= watermark; {
		entry, err := stream.GetMsg(ctx, next, jetstream.WithGetMsgSubject(filter))
		if errors.Is(err, jetstream.ErrMsgNotFound) {
			break
		}
		if err != nil {
			return nil, err
		}
		if entry.Sequence < next || entry.Time.IsZero() {
			return nil, errors.New("host history sequence or timestamp is invalid")
		}
		if entry.Sequence > watermark || !entry.Time.Before(to) {
			break
		}
		record, err := decodeControlRecord(entry.Data)
		if err != nil || record.Scope != scope || record.Kind != kind || record.Epoch == 0 ||
			entry.Subject != mutationSubject(scope, kind, record.SubjectKey) ||
			validateMutationKey(kind, record.SubjectKey) != nil {
			return nil, errors.New("host history control entry is invalid")
		}
		value := LogEntry{Kind: kind, SubjectKey: record.SubjectKey, OperationID: record.OperationID,
			Epoch: record.Epoch, Sequence: entry.Sequence, CreatedAt: entry.Time, Payload: record.Payload}
		if entry.Time.Before(from) {
			baseline[record.SubjectKey] = value
		} else {
			changes = append(changes, value)
		}
		if len(baseline)+len(changes) > 16384 {
			return nil, errors.New("host history window exceeds inventory bound")
		}
		next = entry.Sequence + 1
	}
	result := append(slices.Collect(maps.Values(baseline)), changes...)
	slices.SortFunc(result, func(a, b LogEntry) int {
		return cmp.Compare(a.Sequence, b.Sequence)
	})
	return result, nil
}
