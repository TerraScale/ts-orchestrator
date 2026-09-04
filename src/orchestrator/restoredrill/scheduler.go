package restoredrill

import (
	"context"
	"time"
)

// TickerScheduler is the production timing adapter. The first callback is
// after interval; a failed callback does not stop future daily proofs because
// the drill itself pages and durably records the failure.
type TickerScheduler struct{}

func (TickerScheduler) Every(ctx context.Context, interval time.Duration, f func(context.Context, time.Time) error) error {
	if interval <= 0 || f == nil {
		return ErrInvalidConfig
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case at := <-ticker.C:
			_ = f(ctx, at)
		}
	}
}

var _ SchedulerPort = TickerScheduler{}
