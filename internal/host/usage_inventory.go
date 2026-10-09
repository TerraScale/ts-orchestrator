package host

import (
	"context"
	"errors"
	"maps"
	"slices"
	"sort"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go/jetstream"
)

func (c *Controller) InitializeUsageHistory(ctx context.Context) error {
	if err := c.lockControlLog(ctx); err != nil {
		return err
	}
	defer func() { <-c.controlLogInfoGate }()
	info, err := c.controlLog.Info(ctx, jetstream.WithSubjectFilter(protocol.Control(c.cell, "host")+".>"))
	if err != nil {
		return err
	}
	if err := c.usageHistory.Seed(ctx, c.controlLog, c.cell, info); err != nil {
		return err
	}
	return c.usageHistory.Advance(ctx, c.controlLog, c.cell, info.State.LastSeq)
}

// ExpectedUsage reads timestamped admission, allocation and retirement history
// without letting later changes rewrite an earlier window's expectations.
func (c *Controller) ExpectedUsage(ctx context.Context, from, to time.Time) ([]string, error) {
	if c == nil || c.controlLog == nil || !from.Before(to) {
		return nil, errors.New("historical host inventory is unavailable")
	}
	if err := c.lockControlLog(ctx); err != nil {
		return nil, err
	}
	defer func() { <-c.controlLogInfoGate }()
	info, err := c.controlLog.Info(ctx)
	if err != nil {
		return nil, err
	}
	expected := map[string]bool{}
	entries, err := c.usageHistory.Window(ctx, c.controlLog, c.cell, from, to, info.State.LastSeq)
	if err != nil {
		return nil, err
	}
	active, err := c.activeUsageIntervals(entries, from, to)
	if err != nil {
		return nil, err
	}
	ends := map[string]time.Time{}
	for _, entry := range slices.Backward(entries) {
		if entry.Kind == authority.MutationRetirement {
			continue
		}
		key := string(entry.Kind) + "/" + entry.SubjectKey
		end, ok := ends[key]
		if !ok {
			end = to
		}
		ends[key] = entry.CreatedAt
		if !end.After(from) || !entry.CreatedAt.Before(end) {
			continue
		}
		if entry.Kind == authority.MutationRegistration {
			var registration Registration
			if err := decodeStrict(entry.Payload, &registration); err != nil {
				return nil, err
			}
			if entry.SubjectKey != registrationSubjectKey(c.cell, registration.Node) {
				return nil, errors.New("historical registration identity mismatch")
			}
			if err := validateRegistration(registration, c.cell); err != nil {
				return nil, err
			}
			if overlapsActiveUsage(active, registrationSubjectKey(c.cell, registration.Node), laterTime(from, entry.CreatedAt), end) {
				expected[registration.Node] = true
			}
		} else {
			var desired Desired
			if err := decodeStrict(entry.Payload, &desired); err != nil {
				return nil, err
			}
			if desired.Cell != c.cell || desired.AuthorityEpoch != entry.Epoch ||
				entry.SubjectKey != desiredSubjectKey(c.cell, desired.Node, desired.Role) {
				return nil, errors.New("historical desired identity or epoch mismatch")
			}
			if !desired.Withdrawn && overlapsActiveUsage(active, registrationSubjectKey(c.cell, desired.Node), laterTime(from, entry.CreatedAt), end) {
				expected[desired.Node+"/"+desired.Role] = true
			}
		}
	}
	return slices.Sorted(maps.Keys(expected)), nil
}

type usageInterval struct{ from, to time.Time }

func laterTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

func (c *Controller) activeUsageIntervals(entries []authority.LogEntry, from, to time.Time) (map[string][]usageInterval, error) {
	active := map[string][]usageInterval{}
	retired := map[string]bool{}
	cursor := map[string]time.Time{}
	for _, entry := range entries {
		if entry.Kind != authority.MutationRetirement {
			continue
		}
		node, ok := strings.CutPrefix(entry.SubjectKey, c.cell+".")
		if !ok || validateToken(node, "node") != nil {
			return nil, errors.New("historical retirement identity mismatch")
		}
		mark, err := decodeRetirement(entry.Payload)
		if err != nil {
			return nil, err
		}
		start := cursor[entry.SubjectKey]
		if start.IsZero() {
			start = from
			active[entry.SubjectKey] = nil
		}
		if !retired[entry.SubjectKey] && start.Before(entry.CreatedAt) {
			active[entry.SubjectKey] = append(active[entry.SubjectKey], usageInterval{start, entry.CreatedAt})
		}
		retired[entry.SubjectKey] = mark.Retired
		cursor[entry.SubjectKey] = laterTime(from, entry.CreatedAt)
	}
	for key, state := range retired {
		if !state && cursor[key].Before(to) {
			active[key] = append(active[key], usageInterval{cursor[key], to})
		}
	}
	return active, nil
}

func overlapsActiveUsage(active map[string][]usageInterval, key string, from, to time.Time) bool {
	if !from.Before(to) {
		return false
	}
	intervals, known := active[key]
	if !known {
		return true
	}
	i := sort.Search(len(intervals), func(i int) bool { return intervals[i].to.After(from) })
	return i < len(intervals) && intervals[i].from.Before(to)
}
