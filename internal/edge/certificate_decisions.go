package edge

import (
	"log/slog"
	"time"
)

func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func renewalDue(until, from time.Time) time.Time {
	return until.Add(-min(30*24*time.Hour, until.Sub(from)/3))
}

func (c *certificateCache) deferRenewal(key, reason string, attrs ...any) error {
	if last, ok := c.decisions.Swap(key, reason); !ok || last != reason {
		name, variant := certificateVariant(key)
		slog.Info("edge certificate renewal deferred", append([]any{"name", name, "variant", variant, "reason", reason}, attrs...)...)
	}
	return errIssueHeld
}
