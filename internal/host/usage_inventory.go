package host

import (
	"context"
	"errors"
	"slices"
	"sort"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostload"
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
func (c *Controller) ExpectedUsage(ctx context.Context, from, to time.Time) ([]hostload.UsageInterval, error) {
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
	expected := []hostload.UsageInterval{}
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
			for _, interval := range intersectActiveUsage(active, registrationSubjectKey(c.cell, registration.Node), laterTime(from, entry.CreatedAt), end) {
				expected = append(expected, hostload.UsageInterval{Node: registration.Node, Environment: registration.Environment, From: interval.from, To: interval.to})
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
			if !desired.Withdrawn {
				for _, interval := range intersectActiveUsage(active, registrationSubjectKey(c.cell, desired.Node), laterTime(from, entry.CreatedAt), end) {
					expected = append(expected, hostload.UsageInterval{Node: desired.Node, Environment: desired.Environment, Role: desired.Role, From: interval.from, To: interval.to})
				}
			}
		}
	}
	slices.SortFunc(expected, func(a, b hostload.UsageInterval) int {
		if order := strings.Compare(a.Node+"/"+a.Environment+"/"+a.Role, b.Node+"/"+b.Environment+"/"+b.Role); order != 0 {
			return order
		}
		return a.From.Compare(b.From)
	})
	merged := expected[:0]
	for _, interval := range expected {
		if len(merged) > 0 {
			last := &merged[len(merged)-1]
			if last.Node == interval.Node && last.Environment == interval.Environment && last.Role == interval.Role && !last.To.Before(interval.From) {
				last.To = laterTime(last.To, interval.To)
				continue
			}
		}
		merged = append(merged, interval)
	}
	return merged, nil
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

func intersectActiveUsage(active map[string][]usageInterval, key string, from, to time.Time) []usageInterval {
	if !from.Before(to) {
		return nil
	}
	intervals, known := active[key]
	if !known {
		return []usageInterval{{from, to}}
	}
	i := sort.Search(len(intervals), func(i int) bool { return intervals[i].to.After(from) })
	var overlap []usageInterval
	for ; i < len(intervals) && intervals[i].from.Before(to); i++ {
		end := to
		if intervals[i].to.Before(end) {
			end = intervals[i].to
		}
		overlap = append(overlap, usageInterval{laterTime(from, intervals[i].from), end})
	}
	return overlap
}
