package host

import (
	"context"
	"errors"
	"maps"
	"slices"
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

// ExpectedUsage reads timestamped registration/allocation history, so later
// admissions and withdrawals cannot change an earlier window's expectations.
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
	ends := map[string]time.Time{}
	for _, entry := range slices.Backward(entries) {
		end, ok := ends[entry.SubjectKey]
		if !ok {
			end = to
		}
		ends[entry.SubjectKey] = entry.CreatedAt
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
			expected[registration.Node] = true
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
				expected[desired.Node+"/"+desired.Role] = true
			}
		}
	}
	return slices.Sorted(maps.Keys(expected)), nil
}
