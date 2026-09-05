package restoredrill

import (
	"context"
	"time"
)

// TickerScheduler is the production timing adapter. The first callback is
// after interval. Callback failures return to process supervision: failures
// before durable journal access cannot be assumed to have been recorded or paged.
type TickerScheduler struct{}

func (TickerScheduler) Every(ctx context.Context, interval time.Duration, f func(context.Context, time.Time) error) error {
	if ctx == nil || interval <= 0 || f == nil {
		return ErrInvalidConfig
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case at := <-ticker.C:
			if err := f(ctx, at); err != nil {
				return err
			}
		}
	}
}

var _ SchedulerPort = TickerScheduler{}
