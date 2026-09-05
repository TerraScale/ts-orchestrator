package nodebootstrap

import (
	"context"
	"errors"
	"time"
)

// WaitInitialServices requires three consecutive observations of the actual
// pinned versions and active units. The caller supplies a bounded context and
// keeps receiver ownership while observing; a command receipt is insufficient.
func WaitInitialServices(ctx context.Context, observe func(context.Context) (bool, error)) error {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	stable := 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		ready, err := observe(ctx)
		if err != nil {
			return err
		}
		if ready {
			stable++
		} else {
			stable = 0
		}
		if stable >= 3 {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.Join(errors.New("nodebootstrap: initial services did not become ready"), ctx.Err())
		case <-ticker.C:
		}
	}
}
